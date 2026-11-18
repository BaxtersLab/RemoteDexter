//! `HostController` — the only thing that may create a listener, start capture,
//! or open input devices.
//!
//! ## Why it owns a thread
//!
//! A GUI event loop and a Tokio runtime deadlock each other readily: the UI
//! blocks waiting on an async result, the runtime blocks waiting for the UI
//! thread to release something. The rule here is that they never share a stack.
//! The controller runs on **one** dedicated thread with its own current-thread
//! runtime, and the only things crossing the boundary are `HostCommand` in and
//! `HostEvent` out. The UI never holds a socket, a key, a task handle or a lock
//! belonging to the controller.
//!
//! That also makes the whole lifecycle testable with no GUI at all: the tests
//! below drive the same public API the UI drives.

use crate::backend::{HostBackend, ServeDispatch};
use crate::bind;
use crate::source::{retry_delay, DialFailure, DialOut, ListenSource, PeerSource};
use crate::state::Reach;
use crate::state::{HostCommand, HostEvent, HostState};
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long a relay connection must hold before losing it counts as a fresh
/// outage rather than one more in a row.
///
/// A relay that accepts the host and drops it at once would otherwise be
/// re-dialled in a tight loop — hammering someone else's server, and burning
/// this machine, for as long as the fault lasts. Losses closer together than
/// this back off with the same schedule as a failed dial.
const RELAY_STABLE_AFTER: Duration = Duration::from_secs(60);

/// How many relay losses in a row this one makes, given how long the
/// connection that just ended had lived. A connection that held for
/// [`RELAY_STABLE_AFTER`] ends a run of losses; anything shorter extends it.
fn next_relay_losses(losses: u32, lived: Option<Duration>) -> u32 {
    let before = if lived.is_some_and(|d| d >= RELAY_STABLE_AFTER) {
        0
    } else {
        losses
    };
    before.saturating_add(1)
}

/// What a finished dial task hands back: the dialler, so the next attempt can
/// use it, and what this attempt produced.
///
/// **The dialler always comes back.** It holds the relay address and the host's
/// credential, and a controller that lost it would answer every later
/// `StartViaRelay` with "no relay is configured" — which is not true, and would
/// send the operator looking for a setting they never changed.
type DialResult = (Box<dyn DialOut>, Result<Box<dyn PeerSource>, DialFailure>);

/// A dial-out in progress: connecting right now, or waiting to try again.
enum DialAttempt {
    InFlight(JoinHandle<DialResult>),
    Waiting(Pin<Box<tokio::time::Sleep>>),
}

/// What the dial arm of the select loop produced.
enum DialStep {
    /// An attempt finished, for better or worse.
    Done(DialResult),
    /// The backoff elapsed: time for the next attempt.
    Again,
    /// The dial task itself died. Only reachable if it panicked — the
    /// controller never aborts one, because aborting is what would destroy the
    /// dialler mid-flight.
    Lost,
}

/// Await whatever the dial is doing, or never finish when it is doing nothing.
///
/// Cancel-safe both ways: a `JoinHandle` polled again after its future was
/// dropped still yields the task's value, and the `Sleep` is owned here rather
/// than recreated, so a dropped poll does not restart the backoff.
async fn dial_step(state: &mut Option<DialAttempt>) -> DialStep {
    match state {
        None => std::future::pending().await,
        Some(DialAttempt::InFlight(task)) => match (&mut *task).await {
            Ok(result) => DialStep::Done(result),
            Err(_) => DialStep::Lost,
        },
        Some(DialAttempt::Waiting(sleep)) => {
            sleep.as_mut().await;
            DialStep::Again
        }
    }
}

/// Await a dial the operator has already stopped waiting for.
///
/// A TCP connect to a machine that is not answering takes minutes to fail, and
/// nothing can un-dial it. So Stop stops the *host* at once — no source is
/// brought up whatever this returns — and the attempt is left here to finish on
/// its own. When it does, its connection is dropped immediately, which closes
/// it and lets the relay free the slot rather than waiting out a keepalive, and
/// the dialler comes back for the next Start.
async fn reclaim(stray: &mut Option<JoinHandle<DialResult>>) -> Option<DialResult> {
    match stray {
        None => std::future::pending().await,
        Some(task) => (&mut *task).await.ok(),
    }
}

/// Handle to a running controller thread. Dropping it shuts the host down.
pub struct HostHandle {
    cmd_tx: mpsc::UnboundedSender<HostCommand>,
    evt_rx: mpsc::UnboundedReceiver<HostEvent>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HostHandle {
    /// Send a command. `Err` means the controller thread is gone.
    pub fn send(&self, cmd: HostCommand) -> Result<(), HostCommand> {
        self.cmd_tx.send(cmd).map_err(|e| e.0)
    }

    /// Take the next event if one is already queued.
    pub fn try_next_event(&mut self) -> Option<HostEvent> {
        self.evt_rx.try_recv().ok()
    }

    /// Block until an event arrives or `timeout` elapses.
    ///
    /// Used by the UI's bounded shutdown wait and by every test below, so the
    /// tests exercise the same path the product does.
    pub fn wait_for_event(&mut self, timeout: Duration) -> Option<HostEvent> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(e) = self.evt_rx.try_recv() {
                return Some(e);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Block until a `StateChanged` matching `pred` arrives, or time out.
    /// Returns the matching state.
    pub fn wait_for_state(
        &mut self,
        timeout: Duration,
        pred: impl Fn(&HostState) -> bool,
    ) -> Option<HostState> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match self.wait_for_event(remaining) {
                Some(HostEvent::StateChanged(s)) if pred(&s) => return Some(s),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Ask the controller to shut down and wait, bounded, for the thread.
    ///
    /// Returns `true` if the thread exited within `timeout`. The bound is the
    /// point: a host that will not close must not be able to hold a window
    /// open, and the process can always be killed. Never blocks forever.
    pub fn shutdown_and_join(&mut self, timeout: Duration) -> bool {
        let _ = self.cmd_tx.send(HostCommand::Shutdown);
        let Some(handle) = self.thread.take() else {
            return true;
        };
        let deadline = std::time::Instant::now() + timeout;
        while !handle.is_finished() {
            if std::time::Instant::now() >= deadline {
                // Deliberately leaks the JoinHandle rather than blocking the
                // caller. The OS closes the socket and destroys uinput devices
                // when the process exits; a hung task cannot hold them open
                // past that.
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        handle.join().is_ok()
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.shutdown_and_join(Duration::from_secs(5));
        }
    }
}

/// Start a controller on its own thread with the given backend.
pub fn spawn(backend: impl HostBackend) -> HostHandle {
    spawn_with(move || backend)
}

/// Start a controller, building the backend **on the controller thread inside
/// its runtime**.
///
/// The real backend needs a Tokio runtime to exist before it can be built (it
/// starts the session-expiry sweep). Constructing it on the UI thread and
/// moving it across would either need a second runtime or a
/// `block_on` from inside the GUI event loop — the exact shape that deadlocks.
pub fn spawn_with<B: HostBackend>(build: impl FnOnce() -> B + Send + 'static) -> HostHandle {
    spawn_inner(build, None)
}

/// Start a controller that can ALSO dial out to a relay.
///
/// The dial-out is injected rather than built here because this crate owns no
/// wire protocol: the relay control grammar is spoken by the caller. A
/// controller built with [`spawn_with`] simply refuses `StartViaRelay`, which is
/// the honest answer — it has no way to reach a relay.
pub fn spawn_with_dial_out<B: HostBackend>(
    build: impl FnOnce() -> B + Send + 'static,
    dial_out: impl DialOut,
) -> HostHandle {
    spawn_inner(build, Some(Box::new(dial_out)))
}

fn spawn_inner<B: HostBackend>(
    build: impl FnOnce() -> B + Send + 'static,
    dial_out: Option<Box<dyn DialOut>>,
) -> HostHandle {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel();
    let thread = std::thread::Builder::new()
        .name("rd-host-controller".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = evt_tx.send(HostEvent::Fault {
                        message: format!("controller runtime failed to start: {e}"),
                    });
                    return;
                }
            };
            let backend = rt.block_on(async { build() });
            rt.block_on(run(backend, dial_out, cmd_rx, evt_tx));
        })
        .expect("controller thread");
    HostHandle {
        cmd_tx,
        evt_rx,
        thread: Some(thread),
    }
}

/// What an `Authenticated` signal should do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthOutcome {
    /// Record the peer and announce it.
    Announce,
    /// The backend signalled twice. Ignore the second.
    Duplicate,
    /// The connection ALREADY ENDED before its authentication was handled.
    /// Announcing now would create a Connected row nothing can ever remove.
    AlreadyGone,
}

/// Decide what to do with an `Authenticated` signal.
///
/// THE RACE THIS EXISTS FOR. Authentication and completion arrive on two
/// SEPARATE unbounded channels, and `tokio::select!` picks at random among
/// whichever arms are ready. A session that authenticates and then immediately
/// ends queues both signals, so `Gone` can be handled first — and the `Gone`
/// arm discarded any peer it did not already know, on the reasonable-looking
/// ground that "a TCP connection that failed to prove itself was never a peer".
/// That is correct for a connection that never authenticated, and it is exactly
/// what hid this: the `Authenticated` signal was then handled, pushed the peer,
/// and left a Connected row for a dead socket that nothing would ever remove.
///
/// It does not keep the socket alive. It makes the security UI lie about who is
/// attached — and that list is what the operator reads before deciding whom to
/// revoke, so a stale row is worse than a cosmetic defect.
///
/// Peer labels are `addr.to_string()`, which includes the ephemeral port, so a
/// label identifies ONE TCP connection and a tombstone cannot suppress a later
/// legitimate one.
pub(crate) fn auth_outcome(
    peers: &[String],
    gone_before_auth: &std::collections::HashSet<String>,
    peer: &str,
) -> AuthOutcome {
    if gone_before_auth.contains(peer) {
        AuthOutcome::AlreadyGone
    } else if peers.iter().any(|p| p == peer) {
        AuthOutcome::Duplicate
    } else {
        AuthOutcome::Announce
    }
}

/// Which of the host's two ways in a source is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteKind {
    /// The LAN listener the operator started on an interface.
    Lan,
    /// The control connection this host dialled to a relay.
    Relay,
}

/// One live way in: its source's accept task and the handles that steer it.
///
/// Each route has its OWN pre-auth bound (it lives in its accept task). That is
/// deliberate: strangers flooding the relay cannot lock the operator out of the
/// LAN route, or the other way round. The total is at most twice
/// [`PreAuthLimit::MAX_PENDING`].
struct Route {
    kind: RouteKind,
    /// How this route alone reaches the host: `Bound` or `ViaRelay`.
    reach: Reach,
    /// Cancels this route's accept loop and every connection it accepted.
    cancel: tokio::sync::watch::Sender<bool>,
    /// Requests cancellation of one connection without affecting the route.
    disconnect: mpsc::UnboundedSender<String>,
    /// Forwards "this peer authenticated" to the accept task, which is what
    /// releases its pre-auth slot and cancels its deadline. Sent to every route:
    /// a route ignores a label it never accepted. The controller loop stays the
    /// single consumer of the backend's auth channel; this is a forward, not a
    /// second source of truth.
    authed: mpsc::UnboundedSender<String>,
    accept: tokio::task::JoinHandle<()>,
}

/// Everything the controller owns while a host is running.
///
/// There is always at least one route. Capture and input belong to the RUN,
/// not to a route: they come up with the first route and go down with the
/// last, so adding or losing one route never touches them.
struct Running {
    routes: Vec<Route>,
    peers: Vec<String>,
    /// Peers whose connection ENDED before their authentication was handled.
    ///
    /// Bounded by construction: an entry is added only when a `Gone` arrives
    /// for an unknown peer, and removed the moment the matching `Authenticated`
    /// is seen. The only entries that linger are connections that died without
    /// ever authenticating, which is the ordinary case and costs one label.
    gone_before_auth: std::collections::HashSet<String>,
    /// The run's channels, kept so a route added later reports into the same
    /// places as the first. A notification from an earlier run cannot arrive
    /// on them: every Start installs fresh ones.
    peer_tx: mpsc::UnboundedSender<PeerSignal>,
    auth_tx: mpsc::UnboundedSender<String>,
    notice_tx: mpsc::UnboundedSender<String>,
}

impl Running {
    /// How the host is reachable, derived from the routes rather than stored
    /// beside them — a second field tracking the same fact is a second field
    /// that can disagree with it.
    fn reach(&self) -> Reach {
        let bound = self.routes.iter().find_map(|r| r.reach.bound());
        let relay = self
            .routes
            .iter()
            .find_map(|r| r.reach.relay().map(|(a, s)| (a, s.to_string())));
        Reach::from_routes(bound, relay).expect("a running host always has a route")
    }

    fn has(&self, kind: RouteKind) -> bool {
        self.routes.iter().any(|r| r.kind == kind)
    }

    /// The state a running host reports: Pairable with no peers, else
    /// Connected.
    fn state(&self) -> HostState {
        let reach = self.reach();
        match self.peers.len() {
            0 => HostState::Pairable { reach },
            peers => HostState::Connected { reach, peers },
        }
    }

    /// Start serving `source` as `kind`, on this run's channels.
    fn open_route(
        &self,
        kind: RouteKind,
        source: Box<dyn PeerSource>,
        backend: &mut impl HostBackend,
    ) -> Route {
        let reach = source.reach();
        let (cancel, _) = tokio::sync::watch::channel(false);
        let (disconnect, disconnect_rx) = mpsc::unbounded_channel::<String>();
        // The backend is owned by the controller loop, so the accept task
        // cannot borrow it. It gets a dispatch closure instead: the backend
        // hands out one connection future per socket and keeps no borrow.
        let dispatch = backend.dispatch(self.auth_tx.clone(), self.notice_tx.clone());
        let (authed, authed_rx) = mpsc::unbounded_channel::<String>();
        let accept = spawn_accept(
            kind,
            source,
            cancel.subscribe(),
            disconnect_rx,
            self.peer_tx.clone(),
            dispatch,
            authed_rx,
        );
        Route {
            kind,
            reach,
            cancel,
            disconnect,
            authed,
            accept,
        }
    }

    /// Close one route and wait for its accept task, and every connection it
    /// accepted, to exit. `false` if the host had no such route.
    async fn close_route(&mut self, kind: RouteKind) -> bool {
        let Some(i) = self.routes.iter().position(|r| r.kind == kind) else {
            return false;
        };
        let route = self.routes.remove(i);
        let _ = route.cancel.send(true);
        // Bounded: a wedged accept task must not wedge the controller.
        let _ = tokio::time::timeout(Duration::from_secs(5), route.accept).await;
        true
    }
}

async fn run(
    mut backend: impl HostBackend,
    mut dial_out: Option<Box<dyn DialOut>>,
    mut cmd_rx: mpsc::UnboundedReceiver<HostCommand>,
    evt_tx: mpsc::UnboundedSender<HostEvent>,
) {
    let mut running: Option<Running> = None;
    // Fresh channels are installed for every run and dropped when it ends. A
    // delayed notification from an old connection can therefore never enter a
    // later run.
    let mut peer_rx = None;
    let mut auth_rx = None;
    let mut notice_rx = None;
    // Whether this controller was BUILT with a relay, which never changes.
    // `dial_out` goes empty while an attempt is in flight, and "the dialler is
    // busy" must not be reported as "you have no relay".
    let relay_configured = dial_out.is_some();
    let mut dialling: Option<DialAttempt> = None;
    let mut stray: Option<JoinHandle<DialResult>> = None;
    // Which attempt of the current dial this is, 1-based. Reset by every new
    // `StartViaRelay`, so an operator who clicks again gets an immediate
    // attempt rather than inheriting a minute of someone else's backoff.
    let mut attempt: u32 = 0;
    // Relay connections lost in a row, each within RELAY_STABLE_AFTER of the
    // one before, and when the current one came up.
    let mut relay_losses: u32 = 0;
    let mut relay_up_since: Option<std::time::Instant> = None;

    // Emitting is also how the controller learns the UI is gone: an unbounded
    // send only fails when the receiver is dropped. That is the "UI-channel
    // drop cancels" rule, and it lives here rather than in a watchdog so it
    // cannot be forgotten on a new code path.
    macro_rules! emit {
        ($e:expr) => {
            if evt_tx.send($e).is_err() {
                teardown(&mut backend, &mut running).await;
                return;
            }
        };
    }
    // The controller does not keep a copy of the state: `running` is the only
    // authority on whether a listener exists, and a second field tracking the
    // same fact is a second field that can disagree with it.
    macro_rules! set_state {
        ($s:expr) => {{
            emit!(HostEvent::StateChanged($s));
        }};
    }

    // Abandon any dial in progress. An attempt in flight cannot be un-dialled,
    // so it is left to finish in `stray`, which closes whatever it produces; a
    // backoff timer is simply dropped.
    macro_rules! cancel_dial {
        () => {{
            attempt = 0;
            if let Some(DialAttempt::InFlight(task)) = dialling.take() {
                stray = Some(task);
            }
        }};
    }

    // A start that did not happen. Only a host with nothing else under way is
    // in Error: one already serving, or still dialling the relay, is exactly
    // what it was a moment ago, and an Error state would tell the operator it
    // had stopped.
    macro_rules! start_failed {
        ($message:expr) => {{
            let message: String = $message;
            emit!(HostEvent::Fault {
                message: message.clone()
            });
            if running.is_none() && dialling.is_none() {
                set_state!(HostState::Error { message });
            }
        }};
    }

    // The FIRST route of a run: everything a Start does once it has a source,
    // shared by both routes.
    //
    // Capture and input come up only once a source exists, and either failing
    // tears the source back down — a host that is reachable but cannot serve is
    // worse than one that plainly did not start. For the same reason a dial
    // still in flight is abandoned: it would only bring the same failure back.
    macro_rules! bring_up {
        ($kind:expr, $source:expr) => {{
            let source: Box<dyn PeerSource> = $source;
            if let Err(f) = backend.start_capture() {
                drop(source);
                cancel_dial!();
                start_failed!(f.0);
                continue;
            }
            if let Err(f) = backend.open_input() {
                backend.stop_capture();
                drop(source);
                cancel_dial!();
                start_failed!(f.0);
                continue;
            }
            let (peer_tx, run_peer_rx) = mpsc::unbounded_channel::<PeerSignal>();
            let (auth_tx, run_auth_rx) = mpsc::unbounded_channel::<String>();
            // News from inside a running session. `BackendFault` cannot carry
            // it: it is returned only by start_capture, open_input and
            // create_invite, all of which happen before a peer exists.
            let (notice_tx, run_notice_rx) = mpsc::unbounded_channel::<String>();
            let mut run = Running {
                routes: Vec::new(),
                peers: Vec::new(),
                gone_before_auth: std::collections::HashSet::new(),
                peer_tx,
                auth_tx,
                notice_tx,
            };
            let route = run.open_route($kind, source, &mut backend);
            run.routes.push(route);
            peer_rx = Some(run_peer_rx);
            auth_rx = Some(run_auth_rx);
            notice_rx = Some(run_notice_rx);
            let state = run.state();
            running = Some(run);
            set_state!(state);
        }};
    }

    // A second way in for a host that is ALREADY serving. Capture and input
    // are up already, and the outstanding invite still names a live route, so
    // it stands.
    macro_rules! add_route {
        ($kind:expr, $source:expr) => {{
            let source: Box<dyn PeerSource> = $source;
            if let Some(r) = running.as_mut() {
                let route = r.open_route($kind, source, &mut backend);
                r.routes.push(route);
            }
            let state = running.as_ref().map(Running::state);
            if let Some(state) = state {
                set_state!(state);
            }
        }};
    }

    // One route of a host that keeps serving on the other is gone, or closed.
    //
    // The outstanding invite may name the route that went, and the controller
    // does not know which routes it names, so it is revoked rather than
    // guessed about: a code for a dead route is a credential outliving the
    // thing it granted access to.
    macro_rules! lose_route {
        ($kind:expr) => {{
            if let Some(r) = running.as_mut() {
                r.close_route($kind).await;
            }
            backend.revoke_invite();
            emit!(HostEvent::InviteWithdrawn);
            let state = running.as_ref().map(Running::state);
            if let Some(state) = state {
                set_state!(state);
            }
        }};
    }

    // Dial the relay again after its connection ended. Scheduled rather than
    // started inline, with the loss counted, so a relay that keeps dropping
    // the host is dialled at 0, 1, 2, 4 … 60 s intervals instead of in a loop.
    // RelayRetrying is emitted even for the immediate first attempt: the
    // operator's question is "is it coming back", and silence reads as "no".
    macro_rules! redial_after_loss {
        ($why:expr) => {{
            relay_losses =
                next_relay_losses(relay_losses, relay_up_since.take().map(|t| t.elapsed()));
            let delay = retry_delay(relay_losses);
            emit!(HostEvent::RelayRetrying {
                attempt: relay_losses,
                in_seconds: delay.as_secs(),
                why: $why,
            });
            attempt = 0;
            dialling = Some(DialAttempt::Waiting(Box::pin(tokio::time::sleep(delay))));
        }};
    }

    // Begin one dial attempt, on its own task.
    //
    // **Not awaited here.** Dialling a relay that is not answering takes as
    // long as a TCP connect takes, and this loop is the only thing that reads
    // the command channel: awaiting it inline is a console whose Stop button
    // does nothing for two minutes.
    macro_rules! start_dial {
        () => {{
            let Some(mut dialler) = dial_out.take() else {
                // Unreachable through the command paths, which all check first.
                // Stated rather than unwrapped: a panic here takes the whole
                // host down, including a session that is serving.
                emit!(HostEvent::Fault {
                    message: "the previous relay attempt has not finished — try again in a moment"
                        .into(),
                });
                continue;
            };
            attempt += 1;
            dialling = Some(DialAttempt::InFlight(tokio::spawn(async move {
                let result = dialler.connect().await;
                (dialler, result)
            })));
        }};
    }

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    // Command sender dropped: the UI is gone.
                    teardown(&mut backend, &mut running).await;
                    return;
                };
                match cmd {
                    HostCommand::Start { bind } => {
                        // One listener at a time. Moving to another interface is
                        // Stop listening then Start, so the old socket is
                        // provably gone before the new one appears.
                        if running.as_ref().is_some_and(|r| r.has(RouteKind::Lan)) {
                            emit!(HostEvent::Fault {
                                message: "already listening — stop listening before starting on another interface".into(),
                            });
                            continue;
                        }
                        let addr = match bind::validate(bind) {
                            Ok(a) => a,
                            Err(reason) => {
                                emit!(HostEvent::bind_rejected(reason));
                                continue;
                            }
                        };
                        // A host serving through the relay stays Pairable or
                        // Connected while the listener comes up beside it; only
                        // a host with nothing running is Starting.
                        if running.is_none() {
                            set_state!(HostState::Starting);
                        }
                        let listener = match tokio::net::TcpListener::bind(addr).await {
                            Ok(l) => l,
                            Err(e) => {
                                start_failed!(format!("could not bind: {}", e.kind()));
                                continue;
                            }
                        };
                        let bound = match listener.local_addr() {
                            Ok(a) => a,
                            Err(e) => {
                                start_failed!(format!("bound socket has no address: {}", e.kind()));
                                continue;
                            }
                        };
                        let source = Box::new(ListenSource::new(listener, bound));
                        if running.is_some() {
                            add_route!(RouteKind::Lan, source);
                        } else {
                            bring_up!(RouteKind::Lan, source);
                        }
                    }
                    HostCommand::StartViaRelay => {
                        if running.as_ref().is_some_and(|r| r.has(RouteKind::Relay)) {
                            emit!(HostEvent::Fault {
                                message: "already connected to the relay".into(),
                            });
                            continue;
                        }
                        // A controller built without a dial-out says so rather
                        // than inventing a route. There is no fallback to
                        // binding: the two are different exposures and the
                        // operator chose one.
                        if !relay_configured {
                            emit!(HostEvent::Fault {
                                message: "no relay is configured — this host cannot dial out".into(),
                            });
                            continue;
                        }
                        // Already dialling. Not a fault worth an Error state:
                        // the thing the operator asked for is already happening,
                        // and tearing it down to start it again would only add
                        // a minute.
                        if dialling.is_some() {
                            emit!(HostEvent::Fault {
                                message: "already connecting to the relay".into(),
                            });
                            continue;
                        }
                        // The dialler is still inside an attempt the operator
                        // stopped. Distinct from having no relay at all, which
                        // would send them looking for a setting they never
                        // changed.
                        if dial_out.is_none() {
                            emit!(HostEvent::Fault {
                                message: "the previous relay connection is still closing — try again in a moment"
                                    .into(),
                            });
                            continue;
                        }
                        if running.is_none() {
                            set_state!(HostState::Starting);
                        }
                        attempt = 0;
                        relay_losses = 0;
                        start_dial!();
                    }
                    HostCommand::StopListening => {
                        let refusal = match running.as_ref() {
                            None => Some("not running"),
                            Some(r) if !r.has(RouteKind::Lan) => Some("not listening"),
                            Some(r) if r.routes.len() == 1 => Some(
                                "the listener is this host's only route — use Stop to stop the host",
                            ),
                            Some(_) => None,
                        };
                        if let Some(message) = refusal {
                            emit!(HostEvent::Fault { message: message.into() });
                            continue;
                        }
                        lose_route!(RouteKind::Lan);
                    }
                    HostCommand::Stop => {
                        // Stop while still connecting. The operator gets what
                        // they asked for NOW: nothing will be brought up, and
                        // the state says Stopped rather than Starting.
                        let was_dialling = dialling.is_some();
                        cancel_dial!();
                        relay_losses = 0;
                        relay_up_since = None;
                        if running.is_none() {
                            if was_dialling {
                                set_state!(HostState::Stopped);
                            } else {
                                emit!(HostEvent::Fault { message: "not running".into() });
                            }
                            continue;
                        }
                        set_state!(HostState::Stopping);
                        teardown(&mut backend, &mut running).await;
                        peer_rx = None;
                        auth_rx = None;
                        notice_rx = None;
                        set_state!(HostState::Stopped);
                    }
                    HostCommand::CreateInvite => {
                        // An invite names a route, so there must be one. The
                        // previous implementation had no such requirement and
                        // discovered an address by probing a public resolver.
                        let Some(r) = running.as_ref() else {
                            emit!(HostEvent::Fault {
                                message: "start the host before creating a pairing code".into(),
                            });
                            continue;
                        };
                        // The invite names how the host is ALREADY reachable.
                        // Nothing here discovers, guesses or probes for an
                        // endpoint — v3 did, by opening a UDP socket to a public
                        // resolver, and advertised what came back.
                        let reach = r.reach();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        match backend.create_invite(&reach, now) {
                            Ok(view) => emit!(HostEvent::InviteReady(view)),
                            Err(f) => emit!(HostEvent::Fault { message: f.0 }),
                        }
                    }
                    HostCommand::RevokePeer { peer } => {
                        // A live disconnect. Durable revocation is Block 9.
                        // Every route is asked; only the one that accepted the
                        // peer holds it.
                        match running.as_ref() {
                            Some(r) if r.peers.iter().any(|p| *p == peer) => {
                                let mut sent = false;
                                for route in &r.routes {
                                    sent |= route.disconnect.send(peer.clone()).is_ok();
                                }
                                if !sent {
                                    emit!(HostEvent::Fault {
                                        message: "connection task is no longer available".into(),
                                    });
                                }
                            }
                            _ => emit!(HostEvent::Fault {
                                message: "no such connected peer".into(),
                            }),
                        }
                    }
                    HostCommand::Shutdown => {
                        if running.is_some() {
                            set_state!(HostState::Stopping);
                        }
                        // The process is ending, so an unfinished dial is
                        // abandoned rather than waited for: the OS closes its
                        // socket, and a host that took two minutes to quit
                        // because a relay was not answering would be a worse
                        // bug than the one this avoids.
                        if let Some(DialAttempt::InFlight(task)) = dialling.take() {
                            task.abort();
                        }
                        if let Some(task) = stray.take() {
                            task.abort();
                        }
                        teardown(&mut backend, &mut running).await;
                        let _ = evt_tx.send(HostEvent::StateChanged(HostState::Stopped));
                        return;
                    }
                }
            }
            // A dial attempt finished, or its backoff elapsed.
            step = dial_step(&mut dialling) => {
                match step {
                    DialStep::Again => {
                        dialling = None;
                        start_dial!();
                    }
                    DialStep::Lost => {
                        dialling = None;
                        start_failed!("the relay connection task ended unexpectedly".to_string());
                    }
                    DialStep::Done((dialler, result)) => {
                        dialling = None;
                        dial_out = Some(dialler);
                        match result {
                            Ok(source) => {
                                attempt = 0;
                                relay_up_since = Some(std::time::Instant::now());
                                if running.is_some() {
                                    add_route!(RouteKind::Relay, source);
                                } else {
                                    bring_up!(RouteKind::Relay, source);
                                }
                            }
                            // Worth another go: the relay was unreachable, not
                            // unwilling. A host with nothing running stays
                            // `Starting`, because that is what is happening — an
                            // `Error` here would tell the operator the attempt
                            // was over while the host was still trying.
                            Err(failure) if failure.worth_retrying() => {
                                let delay = retry_delay(attempt + 1);
                                emit!(HostEvent::RelayRetrying {
                                    attempt,
                                    in_seconds: delay.as_secs(),
                                    why: failure.message,
                                });
                                dialling = Some(DialAttempt::Waiting(Box::pin(
                                    tokio::time::sleep(delay),
                                )));
                            }
                            // The relay answered and said no. Retrying would
                            // hammer it with a credential it has already
                            // rejected, and each attempt would overwrite the
                            // reason before the operator could read it.
                            //
                            // Its own event, not a Fault: "the relay refused
                            // this host" needs a human, and "the relay is
                            // unreachable, retrying" does not. The console has
                            // to be able to tell them apart without reading
                            // the text of a message.
                            Err(failure) => {
                                attempt = 0;
                                relay_losses = 0;
                                emit!(HostEvent::RelayRefused {
                                    why: failure.message.clone(),
                                });
                                if running.is_none() && dialling.is_none() {
                                    set_state!(HostState::Error { message: failure.message });
                                }
                            }
                        }
                    }
                }
            }
            // A dial the operator already stopped waiting for came back.
            reclaimed = reclaim(&mut stray) => {
                stray = None;
                if let Some((dialler, result)) = reclaimed {
                    dial_out = Some(dialler);
                    // Dropping the source closes the control connection it
                    // registered with, so the relay frees the slot now instead
                    // of at its next keepalive. Nothing is reported: the
                    // operator stopped this, and it did what they asked.
                    drop(result.ok());
                }
            }
            // A peer AUTHENTICATED. This is the only path to Connected.
            authed = receive_if_running(&mut auth_rx) => {
                let Some(peer) = authed else {
                    auth_rx = None;
                    continue;
                };
                let Some(r) = running.as_mut() else { continue };
                let outcome = auth_outcome(&r.peers, &r.gone_before_auth, &peer);
                if outcome == AuthOutcome::Duplicate {
                    continue;
                }
                // Release the pre-auth slot and cancel the deadline BEFORE
                // announcing the peer: an authenticated session must never be
                // torn down by a bound meant for strangers.
                for route in &r.routes {
                    let _ = route.authed.send(peer.clone());
                }
                if outcome == AuthOutcome::AlreadyGone {
                    // The socket is already closed. Releasing the pre-auth
                    // slot is still correct and harmless — the receiver is
                    // gone — but announcing would strand a Connected row.
                    r.gone_before_auth.remove(&peer);
                    continue;
                }
                r.peers.push(peer.clone());
                let count = r.peers.len();
                let state = r.state();
                emit!(HostEvent::PeerConnected { peer, count });
                set_state!(state);
            }
            // A running session has something the OPERATOR needs to see. The
            // case this exists for is the Windows UIPI refusal: the host gives
            // a control grant back because input is not reaching the desktop,
            // and until this channel existed it told the phone and the log and
            // left the console silent.
            //
            // Raised as a Fault rather than a new variant: the UI already
            // renders Fault, and the operator's question is "why did control
            // stop", which is what a fault line answers.
            notice = receive_if_running(&mut notice_rx) => {
                let Some(message) = notice else {
                    notice_rx = None;
                    continue;
                };
                // A notice from a connection whose host has already stopped is
                // dropped rather than shown: the operator stopped it, and an
                // error about the thing they just turned off is noise.
                if running.is_none() { continue }
                emit!(HostEvent::Fault { message });
            }
            // A connection task ended. It may never have authenticated, in
            // which case there is nothing to report: a TCP connection that
            // failed to prove itself was never a peer.
            signal = receive_if_running(&mut peer_rx) => {
                let peer = match signal {
                    Some(PeerSignal::Gone(peer)) => peer,
                    Some(PeerSignal::SourceEnded(kind, why)) => {
                        // A route this host no longer has — closed on purpose
                        // while its end was already on the way — is history.
                        let Some(r) = running.as_ref() else { continue };
                        if !r.has(kind) {
                            continue;
                        }
                        if r.routes.len() == 1 && kind == RouteKind::Relay {
                            // The relay was this host's only way in, and the
                            // operator chose to be reachable through it: losing
                            // it is an outage to recover from, not a decision to
                            // stop. Found 2026-09-17, when a host lost its relay
                            // at 09:32 and was unreachable for ten hours.
                            //
                            // Capture and input go with the run — a host with no
                            // route must hold neither — and come back with the
                            // relay. The code on screen named this session, so it
                            // is withdrawn, and a relay that refuses the next
                            // dial ends the attempt with the refusal named.
                            emit!(HostEvent::Fault {
                                message: format!("{why} — reconnecting"),
                            });
                            teardown(&mut backend, &mut running).await;
                            peer_rx = None;
                            auth_rx = None;
                            notice_rx = None;
                            emit!(HostEvent::InviteWithdrawn);
                            set_state!(HostState::Starting);
                            redial_after_loss!(why);
                            continue;
                        }
                        if r.routes.len() == 1 {
                            // The LAST way in is gone and it was the listener:
                            // the run is over, as it always was. A listener is
                            // never reopened — starting one is the operator's
                            // decision.
                            cancel_dial!();
                            set_state!(HostState::Stopping);
                            teardown(&mut backend, &mut running).await;
                            peer_rx = None;
                            auth_rx = None;
                            notice_rx = None;
                            emit!(HostEvent::Fault { message: why.clone() });
                            set_state!(HostState::Error { message: why });
                            continue;
                        }
                        // The other route is still serving, so the host stays
                        // up and says what it lost.
                        let still = match kind {
                            RouteKind::Relay => "reconnecting; still reachable on the LAN",
                            RouteKind::Lan => "still reachable through the relay",
                        };
                        emit!(HostEvent::Fault { message: format!("{why} — {still}") });
                        lose_route!(kind);
                        // A relay drop on a laptop that changed network is
                        // ordinary, and the operator already chose to be
                        // reachable through it: dial again, with the usual
                        // backoff. A lost listener is not reopened — starting
                        // one is always the operator's decision.
                        if kind == RouteKind::Relay && dialling.is_none() {
                            redial_after_loss!(why);
                        }
                        continue;
                    }
                    None => {
                        peer_rx = None;
                        continue;
                    }
                };
                let Some(r) = running.as_mut() else { continue };
                let Some(i) = r.peers.iter().position(|p| *p == peer) else {
                    // Not a known peer. Either it never authenticated — the
                    // ordinary case, and nothing to report — or its
                    // `Authenticated` has not been handled YET, because these
                    // are two channels and `select!` chose this one first.
                    // Remembered so that signal cannot strand a Connected row.
                    r.gone_before_auth.insert(peer);
                    continue;
                };
                r.peers.remove(i);
                let count = r.peers.len();
                let state = r.state();
                emit!(HostEvent::PeerDisconnected { peer, count });
                set_state!(state);
            }
        }
    }
}

/// Resolves when a connection has been unauthenticated for too long, and never
/// resolves once it authenticates.
///
/// Separated from the accept loop and given the duration as a PARAMETER so it
/// can be tested in milliseconds. The alternative — reading
/// `PreAuthLimit::DEADLINE` inside and adding a test-only override — puts a knob
/// in product code that exists solely to make a test fast, and the knob is then
/// one careless change away from being the value that ships.
///
/// The authenticated branch parks forever rather than returning: returning would
/// resolve the future, and in the caller's `select!` that would tear down the
/// very session that just proved who it was.
async fn pre_auth_deadline(
    within: std::time::Duration,
    authed: tokio::sync::oneshot::Receiver<()>,
) {
    let sleep = tokio::time::sleep(within);
    tokio::pin!(sleep);
    tokio::select! {
        _ = &mut sleep => {}
        res = authed => {
            if res.is_ok() {
                // Authenticated. Park forever: RESOLVING here would tear down
                // the very session that just proved who it was.
                std::future::pending::<()>().await
            } else {
                // The sender was DROPPED without signalling. That is not
                // authentication -- it is the accept loop's bookkeeping
                // changing, or a slot being reclaimed -- so the deadline stands
                // and keeps running from where it was.
                //
                // The first version treated any resolution as authentication,
                // `Err` included, which meant a dropped sender silently
                // disabled the bound for that connection. Caught by
                // `a_dropped_sender_still_lets_the_deadline_fire`, written
                // because oneshot has two ways to resolve and only one of them
                // means what the name says.
                sleep.await
            }
        }
    }
}

/// Bounds on sessions that have ALREADY authenticated.
///
/// `PreAuthLimit` bounds strangers. Nothing bounded what happened after a peer
/// proved itself: a copied enrolled identity could open sessions without limit
/// and drive task, memory, log and serialized-disk pressure. `SESSION_ACTIVE`
/// looked like a guard and is not — it is telemetry, a bool nobody consults for
/// exclusion. Found by an outside security review, 2026-09-07.
///
/// WHEN THE CAP IS REACHED, THE NEWEST IS REFUSED. There are only two
/// behaviours available and neither is free: refusing lets a flood deny the
/// owner their own desktop, while evicting the oldest lets anyone holding the
/// key silently kick the owner off. Refusal wins because it is VISIBLE and
/// recoverable — the operator can stop the host and start it again — whereas an
/// eviction race is silent and leaves no evidence of which session won.
/// `PreAuthLimit` also rate-limits arrivals to 4 concurrent with a 10s
/// deadline, so a flood is already throttled before it reaches this cap.
///
/// THE LIMIT OF THE PER-DEVICE CAP, stated because it would otherwise read as
/// stronger than it is: on a single-phone deployment a COPIED KEY IS THE
/// OWNER'S DEVICE IDENTITY. The cap bounds resource use; it does not
/// distinguish an attacker from the owner. What it buys is that one identity
/// cannot consume every slot and lock out the operator's other devices.
///
/// Following `PreAuthLimit`, this bans nobody and remembers nothing. A
/// blocklist needs state that outlives a connection and a policy for forgetting,
/// and both are ways to lock out the operator's own phone.
pub struct SessionLimit;

impl SessionLimit {
    /// Authenticated sessions that may exist at once, across all devices.
    pub const MAX_TOTAL: usize = 8;

    /// Authenticated sessions one enrolled device may hold at once.
    ///
    /// More than one is deliberate: a reconnect often overlaps a session the
    /// host has not yet noticed is dead, and refusing that would make a flaky
    /// network look like a broken product.
    pub const MAX_PER_DEVICE: usize = 3;

    /// Whether one more authenticated session may be admitted.
    ///
    /// Takes the CURRENT counts so a caller cannot forget to decrement — the
    /// slot is released by dropping its guard, including on a panic.
    pub fn admits(total_now: usize, for_this_device: usize) -> bool {
        total_now < Self::MAX_TOTAL && for_this_device < Self::MAX_PER_DEVICE
    }
}

/// How much work an unauthenticated peer may cost the host.
///
/// ## The gap this closes
///
/// `docs/THREAT_MODEL.md` P8 has said "pre-auth work is bounded — connection-limit
/// tests" since the model was written. The audit on 2026-09-01 found there were
/// no connection-limit tests because there were no connection limits. Message
/// SIZE was bounded in three places; the number of connections a stranger could
/// open, and how long each could sit half-open, were not bounded at all.
///
/// A LAN peer — adversary §5.2, already in the model — could therefore open
/// sockets and make the host perform Noise handshakes indefinitely without ever
/// proving who it was. Every accepted connection spawned a task with no ceiling
/// and no deadline.
///
/// ## Why these two numbers
///
/// **Four pending.** RemoteDexter serves one phone. More than one connection in
/// the pre-auth window at a time is already unusual — it happens when a client
/// retries after a dropped link, which is why the bound is not one. Four leaves
/// room for a retry storm from a legitimate client and still caps the work a
/// stranger can demand.
///
/// **Ten seconds.** A Noise XX handshake plus token redemption over Wi-Fi is
/// well under a second. Ten is two orders of magnitude of headroom, so a slow
/// phone on a bad link is never cut off, while a peer that opens a socket and
/// says nothing is gone in ten seconds instead of never.
///
/// ## What it deliberately does NOT do
///
/// It does not ban an address, count failures per peer, or grow a blocklist.
/// Those need state that outlives a connection and a policy for when to forget,
/// and both are ways to lock out the operator's own phone. The bound here is on
/// concurrent work, which needs no memory of anyone.
pub struct PreAuthLimit;

impl PreAuthLimit {
    /// Connections that may be in the pre-auth window at once.
    pub const MAX_PENDING: usize = 4;

    /// How long a connection may stay unauthenticated before it is dropped.
    pub const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    /// Whether one more unauthenticated connection may be admitted.
    ///
    /// Takes the CURRENT count so the caller cannot forget to decrement:
    /// authenticated peers leave the pending set, so a live session never
    /// consumes a slot and a long-running client cannot lock out a reconnect.
    pub fn admits(pending: usize) -> bool {
        pending < Self::MAX_PENDING
    }
}

/// What the accept task and the auth channel tell the controller loop.
enum PeerSignal {
    /// The connection task ended (disconnect, failure, or cancellation).
    /// Whether it was ever counted is decided in the loop, not here.
    Gone(String),
    /// The SOURCE itself is finished: the relay control connection dropped, or
    /// the listener died. The host has no route to a client any more.
    ///
    /// A dialled-out host has a route that can fail on its own, which a bound
    /// one does not. Without this the host would keep reporting `Pairable`
    /// while nothing could ever reach it, and the invite already issued would
    /// name a session the relay has released.
    SourceEnded(RouteKind, String),
}

fn spawn_accept(
    kind: RouteKind,
    mut source: Box<dyn PeerSource>,
    mut cancel: tokio::sync::watch::Receiver<bool>,
    mut disconnect: mpsc::UnboundedReceiver<String>,
    peers: mpsc::UnboundedSender<PeerSignal>,
    serve: ServeDispatch,
    mut authed: mpsc::UnboundedReceiver<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<String>();
        let mut tasks = tokio::task::JoinSet::new();
        let mut sessions: std::collections::HashMap<String, tokio::sync::oneshot::Sender<()>> =
            std::collections::HashMap::new();
        // Peers accepted but not yet authenticated. Each holds the sender that
        // cancels its own pre-auth deadline; dropping or sending on it lets the
        // connection live as long as it likes.
        let mut pending: std::collections::HashMap<String, tokio::sync::oneshot::Sender<()>> =
            std::collections::HashMap::new();
        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    if *cancel.borrow() { break; }
                }
                Some(peer) = disconnect.recv() => {
                    if let Some(cancel_one) = sessions.remove(&peer) {
                        let _ = cancel_one.send(());
                    }
                }
                Some(peer) = done_rx.recv() => {
                    sessions.remove(&peer);
                    // A task that ended releases its slot too, whether it
                    // authenticated, failed, or was dropped on the deadline.
                    pending.remove(&peer);
                }
                Some(peer) = authed.recv() => {
                    // Authenticated: free the slot and cancel the deadline.
                    if let Some(cancel_deadline) = pending.remove(&peer) {
                        let _ = cancel_deadline.send(());
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                next = source.next_peer() => {
                    let Some((stream, addr, label)) = next else {
                        // The source is finished, not merely quiet. Say so once
                        // and stop: a loop that kept selecting on a dead source
                        // would spin, and a host that kept reporting Pairable
                        // would be lying about being reachable.
                        let why = match kind {
                            RouteKind::Lan => "the LAN listener closed",
                            RouteKind::Relay => "the relay connection closed",
                        };
                        let _ = peers.send(PeerSignal::SourceEnded(kind, why.to_string()));
                        break;
                    };

                    // THE PRE-AUTH BOUND. Refuse rather than queue: a refused
                    // connection costs one accept and one close, while a queued
                    // one costs a task, a handshake buffer and a slot in the
                    // JoinSet for as long as the peer cares to hold it. Dropping
                    // `stream` closes it immediately.
                    if !PreAuthLimit::admits(pending.len()) {
                        drop(stream);
                        eprintln!(
                            "[host] refused {label}: {} connections already awaiting authentication",
                            pending.len()
                        );
                        continue;
                    }

                    // NO `PeerSignal::Connected` HERE. Accepting a TCP
                    // connection proves nothing about who is on the other end.
                    // The backend signals through AuthNotifier once the pinned
                    // Noise handshake AND the encrypted token redemption have
                    // both succeeded.
                    //
                    // NOTHING IS READ FROM `stream` HERE EITHER. The previous
                    // version read a byte at a time to notice disconnects,
                    // which consumed the product's own protocol bytes and meant
                    // `HostBackend::serve` was never called.
                    let fut = (serve)(stream, addr, label.clone());
                    let peers2 = peers.clone();
                    let mut cancel2 = cancel.clone();
                    let (cancel_one, cancelled) = tokio::sync::oneshot::channel();
                    sessions.insert(label.clone(), cancel_one);
                    let done = done_tx.clone();
                    let (authed_one, wait_authed) = tokio::sync::oneshot::channel::<()>();
                    pending.insert(label.clone(), authed_one);
                    tasks.spawn(async move {
                        // Fires only if this peer never authenticates. Once it
                        // does, the oneshot resolves and this future parks
                        // forever, so an established session is never on a
                        // clock.
                        let deadline = pre_auth_deadline(PreAuthLimit::DEADLINE, wait_authed);
                        tokio::select! {
                            // Cancellation is the CONTROLLER's, not the
                            // backend's: dropping the future here closes the
                            // socket and tears down the session on Stop,
                            // Shutdown, or loss of the UI channel.
                            _ = cancel2.changed() => {
                                if *cancel2.borrow() {
                                    let _ = peers2.send(PeerSignal::Gone(label));
                                    return;
                                }
                            }
                            _ = cancelled => {}
                            _ = fut => {}
                            _ = deadline => {
                                eprintln!(
                                    "[host] dropping {label}: still unauthenticated after {}s",
                                    PreAuthLimit::DEADLINE.as_secs()
                                );
                            }
                        }
                        let _ = peers2.send(PeerSignal::Gone(label.clone()));
                        let _ = done.send(label);
                    });
                }
            }
        }
        // Dropping the SOURCE here is what closes the port — or, for a
        // dial-out, the control connection. It is the last thing the accept
        // task does, so "the task exited" and "nothing is reachable any more"
        // are the same event.
        drop(source);
        // The same task owns every client future. Stop is not complete while a
        // producer can still request another capture frame.
        while tasks.join_next().await.is_some() {}
    })
}

async fn receive_if_running<T>(rx: &mut Option<mpsc::UnboundedReceiver<T>>) -> Option<T> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Close everything, in the reverse order it was opened, and wait for the
/// accept task to actually exit before returning.
async fn teardown(backend: &mut impl HostBackend, running: &mut Option<Running>) {
    // The outstanding invitation dies with the listener. A QR that names a port
    // nothing is listening on is at best confusing and at worst a credential
    // outliving the thing it granted access to.
    backend.revoke_invite();
    // Input first among the capabilities: it is the one that can leave the
    // machine in a bad state (a held button), so it is released before anything
    // can block.
    backend.close_input();
    if let Some(r) = running.take() {
        for route in &r.routes {
            let _ = route.cancel.send(true);
        }
        // Bounded: a wedged accept task must not stop the process from exiting.
        let accepts: Vec<_> = r.routes.into_iter().map(|route| route.accept).collect();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            for accept in accepts {
                let _ = accept.await;
            }
        })
        .await;
    }
    // Every session producer is gone, so none can race this release by asking
    // the shared platform capturer for one more frame.
    backend.stop_capture();
}
#[cfg(test)]
mod relay_loss_tests {
    use super::*;

    /// A relay that keeps dropping the host backs off; one that held for a
    /// while and then dropped starts the schedule again at "immediately".
    #[test]
    fn short_lived_relay_connections_extend_the_backoff_and_a_stable_one_resets_it() {
        let quick = Some(Duration::from_secs(2));
        let stable = Some(RELAY_STABLE_AFTER);
        assert_eq!(next_relay_losses(0, quick), 1);
        assert_eq!(next_relay_losses(1, quick), 2);
        assert_eq!(next_relay_losses(5, quick), 6);
        // A connection that never came up counts as short-lived.
        assert_eq!(next_relay_losses(3, None), 4);
        assert_eq!(
            next_relay_losses(7, stable),
            1,
            "a stable connection did not reset the run"
        );
        assert_eq!(
            next_relay_losses(u32::MAX, quick),
            u32::MAX,
            "the count must not overflow"
        );
        // And the schedule those counts produce: now, then 1, 2, 4 … capped.
        assert_eq!(retry_delay(next_relay_losses(0, quick)), Duration::ZERO);
        assert_eq!(
            retry_delay(next_relay_losses(1, quick)),
            Duration::from_secs(1)
        );
        assert_eq!(
            retry_delay(next_relay_losses(2, quick)),
            Duration::from_secs(2)
        );
    }
}

#[cfg(test)]
mod session_limit_tests {
    use super::*;

    #[test]
    fn an_ordinary_session_is_admitted() {
        assert!(SessionLimit::admits(0, 0));
        assert!(SessionLimit::admits(3, 1));
    }

    /// The global cap. One identity flooding must not be able to exceed it.
    #[test]
    fn the_total_is_a_hard_ceiling() {
        assert!(SessionLimit::admits(SessionLimit::MAX_TOTAL - 1, 0));
        assert!(!SessionLimit::admits(SessionLimit::MAX_TOTAL, 0));
        assert!(!SessionLimit::admits(SessionLimit::MAX_TOTAL + 1, 0));
    }

    /// The per-device cap, which is what stops ONE key consuming every slot and
    /// locking out the operator's other devices.
    #[test]
    fn one_device_cannot_take_every_slot() {
        assert!(SessionLimit::admits(0, SessionLimit::MAX_PER_DEVICE - 1));
        assert!(
            !SessionLimit::admits(0, SessionLimit::MAX_PER_DEVICE),
            "a device at its own cap is refused even with the host otherwise idle"
        );
    }

    /// Both bounds apply; neither is a substitute for the other.
    #[test]
    fn either_bound_alone_is_enough_to_refuse() {
        assert!(!SessionLimit::admits(SessionLimit::MAX_TOTAL, 0));
        assert!(!SessionLimit::admits(0, SessionLimit::MAX_PER_DEVICE));
    }

    /// A reconnect that overlaps a session the host has not yet noticed is dead
    /// must still be admitted, or a flaky network looks like a broken product.
    /// This is why the per-device cap is not 1.
    #[test]
    fn a_device_may_overlap_a_reconnect() {
        assert!(
            SessionLimit::MAX_PER_DEVICE >= 2,
            "a per-device cap of 1 would refuse every overlapping reconnect"
        );
        assert!(SessionLimit::admits(1, 1));
    }
}

#[cfg(test)]
mod auth_race_tests {
    use super::*;

    fn gone(labels: &[&str]) -> std::collections::HashSet<String> {
        labels.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn an_ordinary_authentication_is_announced() {
        assert_eq!(
            auth_outcome(&[], &gone(&[]), "10.0.0.5:51000"),
            AuthOutcome::Announce
        );
    }

    #[test]
    fn a_backend_that_signals_twice_does_not_double_count() {
        let peers = vec!["10.0.0.5:51000".to_string()];
        assert_eq!(
            auth_outcome(&peers, &gone(&[]), "10.0.0.5:51000"),
            AuthOutcome::Duplicate
        );
    }

    /// THE RACE. `Gone` arrives before `Authenticated` because they travel on
    /// separate channels and `select!` chooses at random among ready arms.
    /// Announcing now would leave a Connected row for a dead socket that
    /// nothing can ever remove — and that list is what the operator reads
    /// before deciding whom to revoke.
    #[test]
    fn a_peer_that_already_ended_is_never_announced() {
        assert_eq!(
            auth_outcome(&[], &gone(&["10.0.0.5:51000"]), "10.0.0.5:51000"),
            AuthOutcome::AlreadyGone
        );
    }

    /// The tombstone is per CONNECTION, not per device. Labels carry the
    /// ephemeral port, so a later connection from the same phone must still be
    /// announced — otherwise this fix would silently drop reconnections.
    #[test]
    fn a_later_connection_from_the_same_address_is_not_suppressed() {
        assert_eq!(
            auth_outcome(&[], &gone(&["10.0.0.5:51000"]), "10.0.0.5:51001"),
            AuthOutcome::Announce
        );
    }

    /// One dead connection must not hide another peer's authentication.
    #[test]
    fn a_tombstone_only_suppresses_its_own_peer() {
        assert_eq!(
            auth_outcome(&[], &gone(&["10.0.0.5:51000"]), "10.0.0.9:44000"),
            AuthOutcome::Announce
        );
    }
}

#[cfg(test)]
mod pre_auth_tests {
    use super::*;
    use std::time::Duration;

    /// The boundary itself. Off-by-one here is the difference between a bound
    /// and a suggestion.
    #[test]
    fn the_bound_admits_up_to_the_limit_and_no_further() {
        assert!(PreAuthLimit::admits(0), "an idle host must accept a peer");
        assert!(PreAuthLimit::admits(PreAuthLimit::MAX_PENDING - 1));
        assert!(
            !PreAuthLimit::admits(PreAuthLimit::MAX_PENDING),
            "the limit must be a limit, not a suggestion"
        );
        assert!(!PreAuthLimit::admits(PreAuthLimit::MAX_PENDING + 99));
    }

    /// The numbers themselves are the security decision, so they are asserted
    /// rather than left to be edited without anyone noticing.
    #[test]
    fn the_bound_leaves_room_for_a_retrying_client_but_is_still_a_bound() {
        assert!(
            PreAuthLimit::MAX_PENDING > 1,
            "one pending connection would lock out a client retrying after a dropped link"
        );
        assert!(
            PreAuthLimit::MAX_PENDING <= 8,
            "a bound this loose stops bounding the work a stranger can demand"
        );
        assert!(
            PreAuthLimit::DEADLINE >= Duration::from_secs(5),
            "a handshake over poor Wi-Fi must not be cut off"
        );
        assert!(
            PreAuthLimit::DEADLINE <= Duration::from_secs(30),
            "a socket that says nothing must not be held for half a minute"
        );
    }

    /// The helper takes its duration as a parameter, so these run in
    /// milliseconds against the real logic. The production constant is asserted
    /// separately above — testing the behaviour and testing the number are two
    /// claims, and conflating them is how a test ends up spending ten seconds
    /// to prove something a millisecond would have shown.
    const QUICK: Duration = Duration::from_millis(30);

    /// A peer that never authenticates is dropped.
    #[tokio::test]
    async fn a_silent_connection_is_dropped_when_the_deadline_passes() {
        let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
        let fired = tokio::time::timeout(QUICK * 20, pre_auth_deadline(QUICK, rx)).await;
        assert!(
            fired.is_ok(),
            "the deadline never fired, so a silent peer is held forever"
        );
    }

    /// A peer that authenticates is never on a clock again. This is the half
    /// that matters most: a bound meant for strangers must not tear down an
    /// established session an hour later.
    #[tokio::test]
    async fn an_authenticated_connection_is_never_dropped_by_the_deadline() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tx.send(()).expect("signal authentication");
        let fired = tokio::time::timeout(QUICK * 20, pre_auth_deadline(QUICK, rx)).await;
        assert!(
            fired.is_err(),
            "the deadline fired on a peer that had already authenticated"
        );
    }

    /// A dropped sender must not read as authentication.
    ///
    /// `oneshot::Receiver` resolves with `Err` when the sender is dropped, and a
    /// future treating that as "authenticated" would disable the deadline for
    /// exactly the connections whose bookkeeping went wrong.
    #[tokio::test]
    async fn a_dropped_sender_still_lets_the_deadline_fire() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        drop(tx);
        let fired = tokio::time::timeout(QUICK * 20, pre_auth_deadline(QUICK, rx)).await;
        assert!(
            fired.is_ok(),
            "a dropped sender was treated as authentication, disabling the deadline"
        );
    }
}

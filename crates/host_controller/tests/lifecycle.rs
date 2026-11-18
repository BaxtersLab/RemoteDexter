//! The twelve lifecycle properties, driven through the same public API the UI
//! uses. No GUI, no compositor, no seat — Article XIV means these can never be
//! allowed to need one.
//!
//! Sockets here are REAL. Every test binds a real `TcpListener` on
//! `127.0.0.1:0` and probes it with a real `TcpStream`, because "the port is
//! closed" is not a property a test double can honestly assert (Article IX.4:
//! use the closest practical real boundary). Only capture and input are behind
//! the `HostBackend` seam, because portal capture and uinput genuinely are not
//! available to a unit test on this box.

use host_controller::{
    spawn, BackendFault, HostBackend, HostCommand, HostEvent, HostState, ServeFuture,
};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const T: Duration = Duration::from_secs(5);

/// Counts what the controller asked the platform to do. Not a mock of product
/// behaviour — the real backend lives in `host_app` — but an observer of the
/// ordering contract in `backend.rs`.
#[derive(Clone, Default)]
struct Probe {
    capture_started: Arc<AtomicUsize>,
    capture_stopped: Arc<AtomicUsize>,
    input_opened: Arc<AtomicUsize>,
    input_closed: Arc<AtomicUsize>,
    fail_capture: Arc<AtomicUsize>,
    fail_input: Arc<AtomicUsize>,
    invites_minted: Arc<AtomicUsize>,
    invites_revoked: Arc<AtomicUsize>,
    /// How many sockets actually reached `serve`. Before the Block 4 repair
    /// this was structurally always zero: the controller read the socket itself
    /// and never called the backend.
    served: Arc<AtomicUsize>,
    /// Bytes the backend was able to read off the wire. If the controller is
    /// consuming product bytes, the backend sees fewer than were sent.
    bytes_seen: Arc<AtomicUsize>,
    /// When set, `serve` authenticates the peer. When clear it serves the
    /// connection and never signals — the raw-TCP case.
    authenticate: Arc<AtomicUsize>,
    /// Mode 2 parks the notifier here so a test can fire it after Stop/Start.
    deferred_auth: Arc<std::sync::Mutex<Option<host_controller::AuthNotifier>>>,
    active_serves: Arc<AtomicUsize>,
    capture_stopped_while_serving: Arc<AtomicUsize>,
    /// When set, `serve` reports a notice as the connection ends. Off by
    /// default so every other test proves the channel stays silent unless a
    /// backend deliberately speaks.
    report_notice: Arc<AtomicUsize>,
    /// How the host said it was reachable the last time it minted an invite.
    ///
    /// Recorded because "an invite was minted" is not the property that matters
    /// — what matters is that it was minted for the route the host is ACTUALLY
    /// on, and a counter cannot tell those apart.
    minted_for: Arc<std::sync::Mutex<Option<host_controller::Reach>>>,
}

impl Probe {
    fn capture_fails(&self) {
        self.fail_capture.store(1, Ordering::SeqCst);
    }
    fn input_fails(&self) {
        self.fail_input.store(1, Ordering::SeqCst);
    }
    fn n(&self, c: &Arc<AtomicUsize>) -> usize {
        c.load(Ordering::SeqCst)
    }
}

impl HostBackend for Probe {
    fn start_capture(&mut self) -> Result<(), BackendFault> {
        if self.fail_capture.load(Ordering::SeqCst) == 1 {
            return Err(BackendFault::new("screen capture unavailable"));
        }
        self.capture_started.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn stop_capture(&mut self) {
        if self.active_serves.load(Ordering::SeqCst) != 0 {
            self.capture_stopped_while_serving
                .fetch_add(1, Ordering::SeqCst);
        }
        self.capture_stopped.fetch_add(1, Ordering::SeqCst);
    }
    fn open_input(&mut self) -> Result<(), BackendFault> {
        if self.fail_input.load(Ordering::SeqCst) == 1 {
            return Err(BackendFault::new("input devices unavailable"));
        }
        self.input_opened.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn close_input(&mut self) {
        self.input_closed.fetch_add(1, Ordering::SeqCst);
    }
    fn create_invite(
        &mut self,
        reach: &host_controller::Reach,
        now: u64,
    ) -> Result<host_controller::state::InviteView, BackendFault> {
        self.invites_minted.fetch_add(1, Ordering::SeqCst);
        *self.minted_for.lock().unwrap() = Some(reach.clone());
        // The fingerprint stands in for "which invite this is". For a bound
        // host that is the port, as it always was; for a relay host there is no
        // port of ours to name, which is the whole point.
        let token_fingerprint = match reach {
            host_controller::Reach::Bound(bound) => format!("{:04x}", bound.port()),
            host_controller::Reach::ViaRelay { session, .. } => format!("relay:{session}"),
            host_controller::Reach::Both { bound, session, .. } => {
                format!("both:{:04x}:{session}", bound.port())
            }
        };
        Ok(host_controller::state::InviteView {
            qr_size: 25,
            qr_modules: vec![false; 25 * 25],
            token_fingerprint,
            expires_at: now + 60,
            carries: "the probe's route".into(),
        })
    }

    fn revoke_invite(&mut self) {
        self.invites_revoked.fetch_add(1, Ordering::SeqCst);
    }

    fn serve(
        &mut self,
        stream: tokio::net::TcpStream,
        _p: SocketAddr,
        authed: host_controller::AuthNotifier,
        notices: host_controller::NoticeNotifier,
    ) -> ServeFuture {
        self.served.fetch_add(1, Ordering::SeqCst);
        self.active_serves.fetch_add(1, Ordering::SeqCst);
        let report_notice = self.report_notice.load(Ordering::SeqCst);
        let bytes_seen = self.bytes_seen.clone();
        let authenticate = self.authenticate.load(Ordering::SeqCst);
        let deferred_auth = Arc::clone(&self.deferred_auth);
        let active_serves = Arc::clone(&self.active_serves);
        Box::pin(async move {
            struct ActiveServe(Arc<AtomicUsize>);
            impl Drop for ActiveServe {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _active = ActiveServe(active_serves);
            // Read what the client sent. This is how the test proves the
            // controller did NOT eat the product's bytes.
            let mut buf = [0u8; 64];
            loop {
                if stream.readable().await.is_err() {
                    break;
                }
                match stream.try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        bytes_seen.fetch_add(n, Ordering::SeqCst);
                        match authenticate {
                            1 => authed.authenticated(),
                            2 => {
                                *deferred_auth.lock().unwrap() = Some(authed.clone());
                            }
                            _ => {}
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
            if report_notice == 1 {
                notices.fault("probe notice: connection ended");
            }
        })
    }

    fn dispatch(
        &mut self,
        auth_tx: tokio::sync::mpsc::UnboundedSender<String>,
        notice_tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> host_controller::ServeDispatch {
        let me = self.clone();
        Arc::new(move |stream, peer, label| {
            let mut me = me.clone();
            let notifier = host_controller::AuthNotifier::new(auth_tx.clone(), label.clone());
            let notices = host_controller::NoticeNotifier::new(notice_tx.clone(), label);
            me.serve(stream, peer, notifier, notices)
        })
    }
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Can anything actually connect to this port right now?
fn port_open(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

/// A loopback address that was free a moment ago.
///
/// Learned the only way a port number can be: bind `127.0.0.1:0`, read what the
/// kernel chose, release it. See [`until_uncontended`] for why that is not the
/// end of the story.
fn free_addr() -> SocketAddr {
    let scratch = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let addr = scratch.local_addr().expect("bound address");
    drop(scratch);
    addr
}

/// Run `scenario` on a fresh port until it was not competing for one.
///
/// THE RACE THIS EXISTS FOR, because it produced a red gate that meant nothing.
/// Between [`free_addr`]'s `drop` and whatever binds the port next, the port
/// belongs to NOBODY, and the kernel will hand the same number to any other
/// `bind(0)` — the 25 other tests in this file, which run in parallel threads,
/// and every other test binary in the workspace. When that happens
/// `port_open(addr)` is true because SOMEBODY ELSE is listening, and the failure
/// reads as "the host left a listener behind", which is the one thing it does
/// not mean.
///
/// Observed in a full gate run on 2026-09-08 and not reproducible in isolation:
/// the test alone passed 5 times, the whole file 12 times.
///
/// A foreign listener and a leaked host listener are indistinguishable from a
/// `connect`, so this cannot retry the probe — it re-runs the whole scenario on
/// a new port. `scenario` returns whether it observed the property. **This does
/// not weaken anything:** a host that really leaks a listener leaks it on every
/// port, so every attempt returns false and the panic below still fires. What
/// it removes is the case where an unrelated process decides the verdict.
fn until_uncontended(what: &str, mut scenario: impl FnMut() -> bool) {
    const ATTEMPTS: usize = 8;
    for _ in 0..ATTEMPTS {
        if scenario() {
            return;
        }
    }
    panic!("{what}: still observed after {ATTEMPTS} attempts, each on a fresh port");
}

fn start_on_ephemeral(h: &mut host_controller::HostHandle) -> SocketAddr {
    h.send(HostCommand::Start {
        bind: sa("127.0.0.1:0"),
    })
    .unwrap();
    let s = h
        .wait_for_state(T, |s| matches!(s, HostState::Pairable { .. }))
        .expect("reached Pairable");
    s.bound().expect("Pairable carries a bound address")
}

// ── 1 ────────────────────────────────────────────────────────────────────
#[test]
fn initial_state_is_stopped_with_no_bind() {
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    // Nothing was started, so nothing may have been opened.
    assert_eq!(probe.n(&probe.capture_started), 0);
    assert_eq!(probe.n(&probe.input_opened), 0);
    assert_eq!(HostState::Stopped.bound(), None);
    assert!(!HostState::Stopped.is_listening());
    assert!(h.shutdown_and_join(T));
}

// ── 2 ────────────────────────────────────────────────────────────────────
#[test]
fn wildcard_ipv4_bind_is_rejected() {
    let mut h = spawn(Probe::default());
    h.send(HostCommand::Start {
        bind: sa("0.0.0.0:0"),
    })
    .unwrap();
    let e = h.wait_for_event(T).expect("a fault");
    match e {
        HostEvent::Fault { message } => {
            assert!(message.contains("0.0.0.0"), "names the rule: {message}");
            // The refusal must not be followed by a listener.
            assert!(h
                .wait_for_state(Duration::from_millis(300), |s| s.is_listening())
                .is_none());
        }
        other => panic!("expected a Fault, got {other:?}"),
    }
    assert!(h.shutdown_and_join(T));
}

// ── 3 ────────────────────────────────────────────────────────────────────
#[test]
fn wildcard_ipv6_bind_is_rejected() {
    let mut h = spawn(Probe::default());
    h.send(HostCommand::Start { bind: sa("[::]:0") }).unwrap();
    match h.wait_for_event(T).expect("a fault") {
        HostEvent::Fault { message } => {
            assert!(message.contains("bind refused"), "typed refusal: {message}")
        }
        other => panic!("expected a Fault, got {other:?}"),
    }
    assert!(h
        .wait_for_state(Duration::from_millis(300), |s| s.is_listening())
        .is_none());
    assert!(h.shutdown_and_join(T));
}

// ── 4 ────────────────────────────────────────────────────────────────────
#[test]
fn start_binds_exactly_the_selected_address() {
    let mut h = spawn(Probe::default());
    let bound = start_on_ephemeral(&mut h);
    assert_eq!(bound.ip(), sa("127.0.0.1:0").ip(), "the chosen interface");
    assert_ne!(bound.port(), 0, "the OS assigned a real port");
    assert!(port_open(bound), "and it accepts");
    assert!(h.shutdown_and_join(T));
}

// ── 5 ────────────────────────────────────────────────────────────────────
#[test]
fn a_second_start_is_refused_rather_than_rebinding() {
    let mut h = spawn(Probe::default());
    let bound = start_on_ephemeral(&mut h);
    h.send(HostCommand::Start {
        bind: sa("127.0.0.1:0"),
    })
    .unwrap();
    let mut saw_refusal = false;
    let deadline = std::time::Instant::now() + T;
    while std::time::Instant::now() < deadline {
        match h.wait_for_event(Duration::from_millis(200)) {
            Some(HostEvent::Fault { message }) if message.contains("already listening") => {
                saw_refusal = true;
                break;
            }
            Some(_) => continue,
            None => continue,
        }
    }
    assert!(saw_refusal, "a second Start must be refused");
    assert!(port_open(bound), "and the original listener is untouched");
    assert!(h.shutdown_and_join(T));
}

// ── 6 ────────────────────────────────────────────────────────────────────
#[test]
fn no_listener_exists_before_start() {
    until_uncontended("a controller that has never started opened a port", || {
        let mut h = spawn(Probe::default());
        // Take a port, learn its number, release it. Nothing should now be
        // there — unless another test grabbed it, which is what the retry is
        // for; see `until_uncontended`.
        let addr = free_addr();
        if port_open(addr) {
            return false;
        }

        // A controller that has never been started must not have opened it.
        std::thread::sleep(Duration::from_millis(200));
        if port_open(addr) {
            return false;
        }

        h.send(HostCommand::Start { bind: addr }).unwrap();
        h.wait_for_state(T, |s| matches!(s, HostState::Pairable { .. }))
            .expect("Pairable");
        assert!(port_open(addr), "the listener appears only after Start");
        assert!(h.shutdown_and_join(T));
        true
    });
}

// ── 7 ────────────────────────────────────────────────────────────────────
#[test]
fn stop_closes_the_port() {
    let mut h = spawn(Probe::default());
    let bound = start_on_ephemeral(&mut h);
    assert!(port_open(bound));

    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Stopped)
        .expect("returned to Stopped");

    // The accept task drops the listener as its last act, so Stopped and
    // closed are the same event — but assert the socket, not the state.
    let mut closed = false;
    let deadline = std::time::Instant::now() + T;
    while std::time::Instant::now() < deadline {
        if !port_open(bound) {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        closed,
        "Stop must close the port, not merely stop reporting it"
    );
    assert!(h.shutdown_and_join(T));
}

// ── 8 ────────────────────────────────────────────────────────────────────
/// NOTE: this test used to pass with a bare `TcpStream::connect` and no
/// authentication, because the controller counted every accepted socket as a
/// peer. It was asserting the defect. The probe must now authenticate, which is
/// what a real backend does only after Noise plus token redemption.
#[test]
fn peer_count_rises_and_falls_with_real_connections() {
    use std::io::Write;
    let probe = Probe::default();
    probe.authenticate.store(1, Ordering::SeqCst);
    let mut h = spawn(probe);
    let bound = start_on_ephemeral(&mut h);

    let mut c1 = TcpStream::connect(bound).unwrap();
    c1.write_all(b"auth").unwrap();
    c1.flush().unwrap();
    let s = h
        .wait_for_state(T, |s| s.peers() == 1)
        .expect("one peer connected");
    assert!(matches!(s, HostState::Connected { .. }));

    let mut c2 = TcpStream::connect(bound).unwrap();
    c2.write_all(b"auth").unwrap();
    c2.flush().unwrap();
    h.wait_for_state(T, |s| s.peers() == 2).expect("two peers");

    drop(c1);
    h.wait_for_state(T, |s| s.peers() == 1)
        .expect("back to one");

    drop(c2);
    let s = h
        .wait_for_state(T, |s| s.peers() == 0)
        .expect("back to zero");
    assert!(
        matches!(s, HostState::Pairable { .. }),
        "no peers means Pairable again, not Stopped: {s:?}"
    );
    assert!(h.shutdown_and_join(T));
}

// ── 9 ────────────────────────────────────────────────────────────────────
#[test]
fn capture_failure_enters_error_and_leaves_no_listener() {
    until_uncontended("a failed Start left a port open", || {
        let probe = Probe::default();
        probe.capture_fails();
        let mut h = spawn(probe.clone());

        let addr = free_addr();

        h.send(HostCommand::Start { bind: addr }).unwrap();
        let s = h
            .wait_for_state(T, |s| matches!(s, HostState::Error { .. }))
            .expect("Error state");
        match s {
            HostState::Error { message } => assert!(message.contains("capture")),
            other => panic!("{other:?}"),
        }
        // The listener bound a moment ago must not survive the failure. This
        // one observation is what `until_uncontended` retries on, because an
        // abandoned ephemeral port can be taken by any other test and that is
        // not this host's doing.
        let no_listener = !port_open(addr);
        // And input must never have been opened, since capture came first.
        // Asserted rather than returned: it cannot be decided by a port race,
        // so a retry would only hide it.
        assert_eq!(probe.n(&probe.input_opened), 0);
        assert!(h.shutdown_and_join(T));
        no_listener
    });
}

// ── 10 ───────────────────────────────────────────────────────────────────
#[test]
fn stop_closes_input_before_anything_else() {
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    start_on_ephemeral(&mut h);
    assert_eq!(probe.n(&probe.input_opened), 1);
    assert_eq!(probe.n(&probe.capture_started), 1);

    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Stopped).unwrap();

    assert_eq!(probe.n(&probe.input_closed), 1, "input released on Stop");
    assert_eq!(
        probe.n(&probe.capture_stopped),
        1,
        "capture stopped on Stop"
    );
    assert!(h.shutdown_and_join(T));
}

#[test]
fn stop_cancels_active_sessions_before_releasing_capture() {
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);
    let mut client = TcpStream::connect(bound).expect("real client connection");
    use std::io::Write;
    client.write_all(b"keep the backend future active").unwrap();

    let deadline = std::time::Instant::now() + T;
    while probe.n(&probe.active_serves) == 0 {
        assert!(std::time::Instant::now() < deadline, "serve did not start");
        std::thread::sleep(Duration::from_millis(2));
    }

    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Stopped).unwrap();
    assert_eq!(
        probe.n(&probe.capture_stopped_while_serving),
        0,
        "capture was released while a client session could still request a frame"
    );
    assert_eq!(probe.n(&probe.active_serves), 0);
    drop(client);
    assert!(h.shutdown_and_join(T));
}

/// Input must also be released when the *input* open is what failed — the
/// pairing of open/close has to hold on the error path too.
#[test]
fn input_failure_still_stops_capture_and_leaves_no_listener() {
    until_uncontended("an input failure left a port open", || {
        let probe = Probe::default();
        probe.input_fails();
        let mut h = spawn(probe.clone());

        let addr = free_addr();

        h.send(HostCommand::Start { bind: addr }).unwrap();
        h.wait_for_state(T, |s| matches!(s, HostState::Error { .. }))
            .expect("Error state");
        // The open/close pairing is the subject of this test and is decided by
        // the controller alone, so these stay assertions.
        assert_eq!(probe.n(&probe.capture_started), 1);
        assert_eq!(probe.n(&probe.capture_stopped), 1, "capture rolled back");
        let no_listener = !port_open(addr);
        assert!(h.shutdown_and_join(T));
        no_listener
    });
}

// ── 11 ───────────────────────────────────────────────────────────────────
#[test]
fn dropping_the_ui_channel_cancels_the_host() {
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);
    assert!(port_open(bound));

    // The UI process/thread goes away without saying goodbye.
    drop(h);

    let mut closed = false;
    let deadline = std::time::Instant::now() + T;
    while std::time::Instant::now() < deadline {
        if !port_open(bound) {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        closed,
        "losing the UI must close the host, not leave it listening invisibly"
    );
    assert_eq!(probe.n(&probe.input_closed), 1, "and release input");
}

// ── 12 ───────────────────────────────────────────────────────────────────
#[test]
fn shutdown_tears_down_and_joins_within_the_bound() {
    use std::io::Write;
    let probe = Probe::default();
    probe.authenticate.store(1, Ordering::SeqCst);
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);
    let mut peer = TcpStream::connect(bound).unwrap();
    peer.write_all(b"auth").unwrap();
    peer.flush().unwrap();
    h.wait_for_state(T, |s| s.peers() == 1).unwrap();

    let t0 = std::time::Instant::now();
    assert!(
        h.shutdown_and_join(T),
        "the controller thread must exit within the bound"
    );
    assert!(t0.elapsed() < T, "and well inside it: {:?}", t0.elapsed());

    assert_eq!(probe.n(&probe.input_closed), 1);
    assert_eq!(probe.n(&probe.capture_stopped), 1);
    assert!(
        !port_open(bound),
        "shutdown closes the port even with a peer attached"
    );
}

// ── invites (Block 4) ────────────────────────────────────────────────────

/// An invite names an address, so there must be one. The implementation this
/// replaced had no such requirement: it discovered an address by opening a UDP
/// socket to a public resolver, and would happily mint an invite for a host
/// that was not listening.
#[test]
fn an_invite_cannot_be_minted_before_the_host_is_started() {
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    h.send(HostCommand::CreateInvite).unwrap();
    match h.wait_for_event(T).expect("a fault") {
        HostEvent::Fault { message } => {
            assert!(message.contains("start the host"), "{message}")
        }
        other => panic!("expected a Fault, got {other:?}"),
    }
    assert_eq!(probe.n(&probe.invites_minted), 0);
    assert!(h.shutdown_and_join(T));
}

#[test]
fn an_invite_is_minted_for_the_bound_address_and_carries_no_token() {
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);
    h.send(HostCommand::CreateInvite).unwrap();

    let deadline = std::time::Instant::now() + T;
    let mut view = None;
    while std::time::Instant::now() < deadline && view.is_none() {
        if let Some(HostEvent::InviteReady(v)) = h.wait_for_event(Duration::from_millis(200)) {
            view = Some(v);
        }
    }
    let view = view.expect("InviteReady");
    assert_eq!(probe.n(&probe.invites_minted), 1);
    // The fingerprint the probe builds from the port proves the CONTROLLER
    // passed the real bound address through, not a guess.
    assert_eq!(view.token_fingerprint, format!("{:04x}", bound.port()));
    assert!(view.qr_size > 0);
    assert_eq!(view.qr_modules.len(), view.qr_size * view.qr_size);

    // The Debug rendering is the most likely accidental disclosure path.
    let rendered = format!("{view:?}");
    assert!(
        !rendered.contains("qr_modules"),
        "InviteView Debug must not render the modules — they are the token"
    );
    assert!(h.shutdown_and_join(T));
}

/// A QR naming a port nothing is listening on is a credential that outlived the
/// thing it granted access to.
#[test]
fn stopping_revokes_the_outstanding_invite() {
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    start_on_ephemeral(&mut h);
    h.send(HostCommand::CreateInvite).unwrap();
    h.wait_for_event(Duration::from_millis(500));

    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Stopped).unwrap();
    assert!(
        probe.n(&probe.invites_revoked) >= 1,
        "Stop must revoke the invitation"
    );
    assert!(h.shutdown_and_join(T));
}

// ── Block 4 integration repair ───────────────────────────────────────────

/// **A socket accepted by HostController reaches HostBackend::serve.**
///
/// Before the repair this could not happen: `spawn_accept` read the socket
/// itself and `serve` had zero call sites anywhere in the tree. The console's
/// listener therefore could never enter the real Noise handler.
#[test]
fn an_accepted_socket_reaches_the_backend() {
    use std::io::Write;
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);

    let mut c = TcpStream::connect(bound).unwrap();
    c.write_all(b"hello-from-the-product-protocol").unwrap();
    c.flush().unwrap();

    let deadline = std::time::Instant::now() + T;
    while std::time::Instant::now() < deadline && probe.n(&probe.served) == 0 {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        probe.n(&probe.served),
        1,
        "the accepted socket never reached HostBackend::serve"
    );
    assert!(h.shutdown_and_join(T));
}

/// **The controller must not consume the product's bytes.**
///
/// The old accept loop read one byte at a time to detect disconnects. Every
/// byte it read was a byte the real protocol handler never saw.
#[test]
fn the_controller_does_not_eat_bytes_meant_for_the_backend() {
    use std::io::Write;
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);

    let payload = b"0123456789abcdef";
    let mut c = TcpStream::connect(bound).unwrap();
    c.write_all(payload).unwrap();
    c.flush().unwrap();

    let deadline = std::time::Instant::now() + T;
    while std::time::Instant::now() < deadline && probe.n(&probe.bytes_seen) < payload.len() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        probe.n(&probe.bytes_seen),
        payload.len(),
        "the backend saw {} of {} bytes — the controller consumed the rest",
        probe.n(&probe.bytes_seen),
        payload.len()
    );
    assert!(h.shutdown_and_join(T));
}

/// **Raw TCP does not produce PeerConnected.**
///
/// The old loop emitted `PeerConnected` the instant `accept()` returned, so the
/// console reported "1 device connected" for `nc host 8082`. Only the backend,
/// after authenticating, may produce it.
#[test]
fn raw_tcp_never_counts_as_a_connected_peer() {
    use std::io::Write;
    let probe = Probe::default(); // authenticate flag NOT set
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);

    let mut c = TcpStream::connect(bound).unwrap();
    c.write_all(b"not a noise handshake").unwrap();
    c.flush().unwrap();

    // Give it every chance to wrongly report a peer.
    assert!(
        h.wait_for_state(Duration::from_millis(1500), |s| s.peers() > 0)
            .is_none(),
        "an unauthenticated TCP connection was counted as a connected peer"
    );
    // ...while the backend really did serve it.
    assert_eq!(probe.n(&probe.served), 1);
    drop(c);
    assert!(h.shutdown_and_join(T));
}

/// ...and an authenticated one does.
#[test]
fn only_an_authenticated_peer_becomes_connected() {
    use std::io::Write;
    let probe = Probe::default();
    probe.authenticate.store(1, Ordering::SeqCst);
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);

    let mut c = TcpStream::connect(bound).unwrap();
    c.write_all(b"pretend this is an authenticated session")
        .unwrap();
    c.flush().unwrap();

    let s = h
        .wait_for_state(T, |s| s.peers() == 1)
        .expect("an authenticated peer must reach Connected");
    assert!(matches!(s, HostState::Connected { .. }));

    drop(c);
    h.wait_for_state(T, |s| s.peers() == 0)
        .expect("and disconnect returns to Pairable");
    assert!(h.shutdown_and_join(T));
}

/// Stop must cancel in-flight connection tasks AND revoke the invitation.
#[test]
fn stop_cancels_connection_tasks_and_revokes_the_invite() {
    use std::io::Write;
    let probe = Probe::default();
    probe.authenticate.store(1, Ordering::SeqCst);
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);
    h.send(HostCommand::CreateInvite).unwrap();

    let mut c = TcpStream::connect(bound).unwrap();
    c.write_all(b"session").unwrap();
    c.flush().unwrap();
    h.wait_for_state(T, |s| s.peers() == 1).unwrap();

    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Stopped).unwrap();
    assert!(
        probe.n(&probe.invites_revoked) >= 1,
        "Stop must revoke the outstanding invitation"
    );
    assert!(!port_open(bound), "and close the port");
    assert!(h.shutdown_and_join(T));
}

#[test]
fn revoking_one_peer_leaves_other_sessions_and_listener_alive() {
    use std::io::{Read, Write};

    let probe = Probe::default();
    probe.authenticate.store(1, Ordering::SeqCst);
    let mut h = spawn(probe);
    let bound = start_on_ephemeral(&mut h);

    let mut first = TcpStream::connect(bound).unwrap();
    let first_label = first.local_addr().unwrap().to_string();
    first.write_all(b"auth-first").unwrap();
    h.wait_for_state(T, |state| state.peers() == 1).unwrap();

    let mut second = TcpStream::connect(bound).unwrap();
    second.write_all(b"auth-second").unwrap();
    h.wait_for_state(T, |state| state.peers() == 2).unwrap();

    h.send(HostCommand::RevokePeer {
        peer: first_label.clone(),
    })
    .unwrap();
    let deadline = std::time::Instant::now() + T;
    let mut revoked = false;
    while std::time::Instant::now() < deadline {
        if matches!(
            h.wait_for_event(Duration::from_millis(100)),
            Some(HostEvent::PeerDisconnected { peer, count: 1 }) if peer == first_label
        ) {
            revoked = true;
            break;
        }
    }
    assert!(revoked, "the selected peer was not disconnected");

    second
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut byte = [0u8; 1];
    match second.read(&mut byte) {
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        Ok(0) => panic!("revoking one peer disconnected the other peer"),
        result => panic!("unexpected read from surviving peer: {result:?}"),
    }
    assert!(port_open(bound), "revoking a peer closed the listener");

    let mut third = TcpStream::connect(bound).unwrap();
    third.write_all(b"auth-third").unwrap();
    h.wait_for_state(T, |state| state.peers() == 2)
        .expect("the listener must accept a replacement peer");
    assert!(h.shutdown_and_join(T));
}

#[test]
fn authentication_from_a_stopped_run_cannot_cross_restart() {
    use std::io::Write;

    let probe = Probe::default();
    probe.authenticate.store(2, Ordering::SeqCst);
    let mut h = spawn(probe.clone());
    let first_bound = start_on_ephemeral(&mut h);
    let mut old_connection = TcpStream::connect(first_bound).unwrap();
    old_connection.write_all(b"defer-auth").unwrap();

    let deadline = std::time::Instant::now() + T;
    while std::time::Instant::now() < deadline && probe.deferred_auth.lock().unwrap().is_none() {
        std::thread::sleep(Duration::from_millis(20));
    }
    let stale = probe
        .deferred_auth
        .lock()
        .unwrap()
        .take()
        .expect("backend received an auth notifier");

    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |state| *state == HostState::Stopped)
        .unwrap();
    start_on_ephemeral(&mut h);

    stale.authenticated();
    assert!(
        h.wait_for_state(Duration::from_millis(500), |state| state.peers() > 0)
            .is_none(),
        "an auth notification from the stopped run entered the new run"
    );
    assert!(h.shutdown_and_join(T));
}

/// P8, on real sockets: a stranger cannot make the host do unbounded work.
///
/// `docs/THREAT_MODEL.md` claimed "pre-auth work is bounded — connection-limit
/// tests" from the day it was written. The audit on 2026-09-01 found there were
/// none, because there were no limits: every accepted socket spawned a task
/// with no ceiling and no deadline, so a LAN peer could open connections and
/// make the host perform Noise handshakes indefinitely without ever proving who
/// it was.
///
/// This is that bound, exercised through the real accept loop rather than
/// through the policy type — `PreAuthLimit::admits` being correct proves
/// nothing if the loop never calls it.
#[test]
fn a_stranger_cannot_hold_more_than_the_pre_auth_bound() {
    let probe = Probe::default(); // never authenticates: these are all strangers
    let mut h = host_controller::spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);

    // Fill the pre-auth window. Held open deliberately: a connection that
    // closes returns its slot, which is the behaviour being bounded.
    let mut held = Vec::new();
    for _ in 0..host_controller::PreAuthLimit::MAX_PENDING {
        held.push(TcpStream::connect(bound).expect("a slot was available"));
    }
    let deadline = std::time::Instant::now() + T;
    while probe.n(&probe.served) < host_controller::PreAuthLimit::MAX_PENDING
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        probe.n(&probe.served),
        host_controller::PreAuthLimit::MAX_PENDING,
        "the host did not serve the connections that fit inside the bound"
    );

    // One more. The TCP handshake still completes — the kernel's backlog
    // accepts it — so the refusal shows up as an immediate EOF, which is what a
    // dropped socket looks like from the other end.
    let extra = TcpStream::connect(bound).expect("TCP connect itself still succeeds");
    extra
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1];
    let read = std::io::Read::read(&mut { &extra }, &mut buf);
    assert!(
        matches!(read, Ok(0)),
        "the connection past the bound was not closed; read returned {read:?}"
    );

    // And it never reached the backend: refusing costs one accept and one
    // close, not a task and a handshake buffer.
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        probe.n(&probe.served),
        host_controller::PreAuthLimit::MAX_PENDING,
        "the connection past the bound still reached the backend"
    );

    // Closing one returns its slot, so the bound throttles strangers without
    // permanently refusing anyone.
    drop(held.pop());
    let deadline = std::time::Instant::now() + T;
    let mut admitted = false;
    while std::time::Instant::now() < deadline {
        let c = TcpStream::connect(bound).expect("connect");
        c.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut b = [0u8; 1];
        if !matches!(std::io::Read::read(&mut { &c }, &mut b), Ok(0)) {
            admitted = true;
            held.push(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        admitted,
        "a freed slot was never reused — the bound refuses permanently instead of throttling"
    );

    h.send(HostCommand::Stop).unwrap();
}

// ── 13 ───────────────────────────────────────────────────────────────────
/// The `NoticeNotifier` half of the backend contract: something a connection
/// discovers **while serving** must reach the operator as a
/// `HostEvent::Fault`.
///
/// This is the gap the channel was added to close. `BackendFault` covers
/// `start_capture`, `open_input` and `create_invite` — every one of them at
/// setup. Nothing a live session learned could reach the console, so a session
/// that had stopped working looked, from the UI, exactly like one that was
/// fine. That is the shape of the defect the operator hit: the phone saw
/// control stop and the host said nothing.
///
/// RED PROVEN: remove the `notices.fault(..)` call from `Probe::serve` and
/// this fails on `no Fault arrived` while every other test in this file still
/// passes — measured, not assumed: 1 failed, 25 passed. None of them can see
/// this channel at all.
#[test]
fn a_notice_from_a_live_connection_reaches_the_operator() {
    use std::io::Write;
    let probe = Probe::default();
    probe.authenticate.store(1, Ordering::SeqCst);
    probe.report_notice.store(1, Ordering::SeqCst);
    let mut h = spawn(probe);
    let bound = start_on_ephemeral(&mut h);

    let mut c = TcpStream::connect(bound).unwrap();
    c.write_all(b"auth").unwrap();
    c.flush().unwrap();
    // Ending the connection is what makes the probe speak.
    drop(c);

    let deadline = std::time::Instant::now() + T;
    let mut seen = None;
    while std::time::Instant::now() < deadline {
        if let Some(HostEvent::Fault { message }) = h.wait_for_event(Duration::from_millis(200)) {
            if message.contains("probe notice") {
                seen = Some(message);
                break;
            }
        }
    }
    let message = seen.expect(
        "no Fault arrived: a notice raised by a live connection never reached the operator",
    );
    assert!(
        message.contains("connection ended"),
        "the operator gets the backend's own words, not a generic label: {message}"
    );
    assert!(h.shutdown_and_join(T));
}

// ── dial-out ─────────────────────────────────────────────────────────────
//
// The controller's half only. What SPEAKS to a relay lives in host_app, and is
// proven there against a real relay; what is proven here is that the lifecycle
// treats a dial-out route correctly — above all, that it never claims to be
// listening, and that a route which dies is reported instead of hidden.

/// A source that yields nothing and is finished immediately, standing in for a
/// relay control connection that dropped.
struct DeadSource {
    relay: SocketAddr,
}

impl host_controller::PeerSource for DeadSource {
    fn next_peer(&mut self) -> host_controller::source::PeerFuture<'_> {
        Box::pin(async { None })
    }
    fn reach(&self) -> host_controller::Reach {
        host_controller::Reach::ViaRelay {
            relay: self.relay,
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        }
    }
}

struct DeadDialOut {
    relay: SocketAddr,
}

impl host_controller::DialOut for DeadDialOut {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        let relay = self.relay;
        Box::pin(async move {
            Ok(Box::new(DeadSource { relay }) as Box<dyn host_controller::PeerSource>)
        })
    }
}

/// A source that is alive and simply has no clients yet — a host registered
/// with a relay and waiting. Distinct from [`DeadSource`], which is finished:
/// "quiet" and "gone" are different states and the controller must not confuse
/// them.
struct QuietSource {
    relay: SocketAddr,
}

impl host_controller::PeerSource for QuietSource {
    fn next_peer(&mut self) -> host_controller::source::PeerFuture<'_> {
        Box::pin(std::future::pending())
    }
    fn reach(&self) -> host_controller::Reach {
        host_controller::Reach::ViaRelay {
            relay: self.relay,
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        }
    }
}

struct QuietDialOut {
    relay: SocketAddr,
}

impl host_controller::DialOut for QuietDialOut {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        let relay = self.relay;
        Box::pin(async move {
            Ok(Box::new(QuietSource { relay }) as Box<dyn host_controller::PeerSource>)
        })
    }
}

/// A relay that answers and says no. Counts the attempts, because "it was
/// refused" is not the property that matters — how many times this host dialled
/// after being told no is.
#[derive(Clone, Default)]
struct RefusingDialOut {
    attempts: Arc<AtomicUsize>,
}

impl host_controller::DialOut for RefusingDialOut {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        let attempts = self.attempts.clone();
        Box::pin(async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err(host_controller::DialFailure::refused(
                "the relay refused this host: not enrolled",
            ))
        })
    }
}

/// A relay that cannot be reached for the first `fail_times` attempts, and then
/// answers — a laptop that woke up before its Wi-Fi did.
struct FlakyDialOut {
    relay: SocketAddr,
    attempts: Arc<AtomicUsize>,
    fail_times: usize,
}

impl host_controller::DialOut for FlakyDialOut {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        let relay = self.relay;
        let attempts = self.attempts.clone();
        let fail_times = self.fail_times;
        Box::pin(async move {
            if attempts.fetch_add(1, Ordering::SeqCst) < fail_times {
                return Err(host_controller::DialFailure::unreachable(
                    "could not reach the relay: network unreachable",
                ));
            }
            Ok(Box::new(QuietSource { relay }) as Box<dyn host_controller::PeerSource>)
        })
    }
}

/// A dial that never completes — the relay's address routes nowhere and the
/// connect sits in SYN-SENT. The operator's Stop has to work anyway.
struct HangingDialOut;

impl host_controller::DialOut for HangingDialOut {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        Box::pin(async move {
            std::future::pending::<()>().await;
            unreachable!()
        })
    }
}

/// A source that records being dropped. Dropping it is what closes the control
/// connection to the relay, so "was it dropped" is "was the relay's slot freed".
struct ClosingSource {
    relay: SocketAddr,
    dropped: Arc<AtomicUsize>,
}

impl Drop for ClosingSource {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl host_controller::PeerSource for ClosingSource {
    fn next_peer(&mut self) -> host_controller::source::PeerFuture<'_> {
        Box::pin(std::future::pending())
    }
    fn reach(&self) -> host_controller::Reach {
        host_controller::Reach::ViaRelay {
            relay: self.relay,
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        }
    }
}

/// A relay that takes a moment to answer, and then does.
struct SlowDialOut {
    relay: SocketAddr,
    delay: Duration,
    dropped: Arc<AtomicUsize>,
}

impl host_controller::DialOut for SlowDialOut {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        let relay = self.relay;
        let delay = self.delay;
        let dropped = self.dropped.clone();
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(Box::new(ClosingSource { relay, dropped }) as Box<dyn host_controller::PeerSource>)
        })
    }
}

/// Wait for the first `RelayRetrying`, ignoring everything else.
fn await_retry(
    h: &mut host_controller::HostHandle,
    within: Duration,
) -> Option<(u32, u64, String)> {
    let deadline = std::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        match h.wait_for_event(left) {
            Some(HostEvent::RelayRetrying {
                attempt,
                in_seconds,
                why,
            }) => return Some((attempt, in_seconds, why)),
            Some(_) => continue,
            None => return None,
        }
    }
}

/// **A host that dialled out is serving, and is NOT listening.**
///
/// `is_listening()` is what `scripts/vm-host-console-proof.sh` checks with `ss`,
/// and what the console shows the operator. A dial-out reporting a bound
/// address would make a host with no open port look like one with a port open.
#[test]
fn a_dialled_out_host_is_running_but_never_listening() {
    let mut h = host_controller::spawn_with_dial_out(
        Probe::default,
        DeadDialOut {
            relay: sa("203.0.113.9:9443"),
        },
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    let reached = h
        .wait_for_state(T, |s| s.is_running())
        .expect("the host never reported that it was serving");
    assert!(
        !reached.is_listening(),
        "a dialled-out host reported that it is listening"
    );
    assert_eq!(
        reached.bound(),
        None,
        "a dialled-out host reported a bound address"
    );
    assert!(h.shutdown_and_join(T));
}

/// A route that dies is reported. Staying `Pairable` with no way for a client
/// to arrive is the failure a persistent outbound connection makes possible.
#[test]
fn a_relay_route_that_keeps_dying_is_retried_visibly_and_backs_off() {
    // Changed 2026-09-17. This test used to require an Error state: a relay
    // route that ended ended the host. That is exactly what left the operator
    // unreachable for ten hours, so a lost relay is now dialled again. What
    // must still hold is that the loss is VISIBLE — the host says it lost the
    // relay and that it is trying again — and that a relay which accepts the
    // host and drops it at once is not re-dialled in a tight loop.
    let connects = Arc::new(AtomicUsize::new(0));
    let mut h = host_controller::spawn_with_dial_out(
        Probe::default,
        CountingDeadDialOut {
            relay: sa("203.0.113.9:9443"),
            connects: connects.clone(),
        },
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    let window = Duration::from_millis(3500);
    let (_, seen) = await_event(&mut h, window, |_| false);
    assert!(
        seen.iter()
            .any(|e| matches!(e, HostEvent::Fault { message } if message.contains("reconnecting"))),
        "the loss was not reported: {seen:?}"
    );
    let delays: Vec<u64> = seen
        .iter()
        .filter_map(|e| match e {
            HostEvent::RelayRetrying { in_seconds, .. } => Some(*in_seconds),
            _ => None,
        })
        .collect();
    assert!(
        delays.len() >= 3,
        "the retries were not announced: {delays:?}"
    );
    assert!(
        delays.windows(2).all(|w| w[0] <= w[1]) && *delays.last().unwrap() >= 2,
        "a relay that keeps dropping the host did not back off: {delays:?}"
    );
    let dialled = connects.load(Ordering::SeqCst);
    assert!(
        (3..=5).contains(&dialled),
        "{dialled} dials in 3.5 s: 0, 1, 2 s apart allows 4 — more is a tight loop"
    );
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, HostEvent::StateChanged(HostState::Error { .. }))),
        "a lost relay still ended the host: {seen:?}"
    );
    assert!(h.shutdown_and_join(T));
}

/// A relay that refuses is reported as a fault, and leaves nothing running.
#[test]
fn a_relay_that_refuses_leaves_the_host_stopped() {
    let dial = RefusingDialOut::default();
    let mut h = host_controller::spawn_with_dial_out(Probe::default, dial.clone());
    h.send(HostCommand::StartViaRelay).unwrap();
    let ended = h
        .wait_for_state(T, |s| matches!(s, HostState::Error { .. }))
        .expect("a refused dial-out produced no error state");
    assert!(!ended.is_listening());
    assert!(!ended.is_running());
    assert!(h.shutdown_and_join(T));
}

/// **A relay that answers and says no is dialled exactly once.**
///
/// The retry exists for a relay that could not be reached. A credential the
/// relay has already rejected will be rejected again, so retrying it hammers
/// the relay — and, worse, each attempt overwrites the reason before the
/// operator has read why they are not getting in.
#[test]
fn a_refused_credential_is_never_dialled_a_second_time() {
    let dial = RefusingDialOut::default();
    let mut h = host_controller::spawn_with_dial_out(Probe::default, dial.clone());
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, |s| matches!(s, HostState::Error { .. }))
        .expect("a refused dial-out produced no error state");
    // Well past the first backoff, which is one second.
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(
        dial.attempts.load(Ordering::SeqCst),
        1,
        "a relay that refused this host was dialled again"
    );
    assert!(h.shutdown_and_join(T));
}

/// **A relay that is merely unreachable is tried again, and the wait is
/// announced.**
///
/// This is the ordinary case on the operator's machine: the host starts with
/// `dial_on_start` before the Wi-Fi has associated. Giving up on the first
/// failure would mean an icon that is permanently "Error" until someone clicks
/// something, which is exactly what making the relay the default has to avoid.
#[test]
fn an_unreachable_relay_is_retried_until_it_answers() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut h = host_controller::spawn_with_dial_out(
        Probe::default,
        FlakyDialOut {
            relay: sa("203.0.113.9:9443"),
            attempts: attempts.clone(),
            fail_times: 1,
        },
    );
    h.send(HostCommand::StartViaRelay).unwrap();

    let (attempt, in_seconds, why) =
        await_retry(&mut h, T).expect("an unreachable relay produced no retry announcement");
    assert_eq!(
        attempt, 1,
        "the first failure was not reported as attempt 1"
    );
    assert_eq!(
        in_seconds, 1,
        "the wait before the second attempt was not the documented one second"
    );
    assert!(
        why.contains("unreachable"),
        "the retry did not carry why the last attempt failed: {why}"
    );

    let reached = h
        .wait_for_state(T, |s| s.is_running())
        .expect("a relay that came back was never dialled again");
    assert!(
        !reached.is_listening(),
        "the retried route bound a port — a dial-out binds nothing"
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "the relay was dialled a different number of times than once-failed-then-once-succeeded"
    );
    assert!(h.shutdown_and_join(T));
}

/// **Stop reaches a host that is still connecting.**
///
/// A TCP connect to a machine that is not answering takes minutes to fail. The
/// dial therefore cannot be awaited on the loop that reads commands, or the
/// console's Stop button does nothing for those minutes and the operator is
/// left with a window that ignores them.
#[test]
fn stop_is_obeyed_while_a_dial_is_still_hanging() {
    let mut h = host_controller::spawn_with_dial_out(Probe::default, HangingDialOut);
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, |s| matches!(s, HostState::Starting))
        .expect("the host never reported that it was starting");

    h.send(HostCommand::Stop).unwrap();
    let stopped = h
        .wait_for_state(Duration::from_secs(2), |s| matches!(s, HostState::Stopped))
        .expect("Stop did not reach a host that was still connecting to the relay");
    assert!(!stopped.is_running());
    assert!(h.shutdown_and_join(T));
}

/// **A relay connection that lands after Stop is closed, not served.**
///
/// The dial cannot be un-dialled, so it finishes after the operator has already
/// stopped the host. If that connection were brought up, the host would start
/// serving something the operator told it not to; if it were merely forgotten,
/// the registration would sit on the relay holding a session slot until a
/// keepalive eventually reaped it.
#[test]
fn a_relay_connection_that_arrives_after_a_stop_is_closed() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut h = host_controller::spawn_with_dial_out(
        Probe::default,
        SlowDialOut {
            relay: sa("203.0.113.9:9443"),
            delay: Duration::from_millis(300),
            dropped: dropped.clone(),
        },
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, |s| matches!(s, HostState::Starting))
        .expect("the host never reported that it was starting");
    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| matches!(s, HostState::Stopped))
        .expect("Stop did not reach a host that was still connecting");

    // The connection is still on its way. Give it well past its own delay.
    assert!(
        h.wait_for_state(Duration::from_secs(2), |s| s.is_running())
            .is_none(),
        "a host that was stopped began serving a relay connection anyway"
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "the late relay connection was never closed — the relay would hold the session slot"
    );
    assert!(h.shutdown_and_join(T));
}

/// **Stopping a dial does not cost this host its relay.**
///
/// The credential and the relay address live in the dialler, and the dialler is
/// moved into the attempt. If a stopped attempt destroyed it, every later
/// `StartViaRelay` would answer "no relay is configured" — which is false, and
/// sends the operator looking for a setting they never changed.
#[test]
fn a_host_can_dial_again_after_stopping_a_dial() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut h = host_controller::spawn_with_dial_out(
        Probe::default,
        SlowDialOut {
            relay: sa("203.0.113.9:9443"),
            delay: Duration::from_millis(200),
            dropped: dropped.clone(),
        },
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, |s| matches!(s, HostState::Starting))
        .expect("the host never reported that it was starting");
    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| matches!(s, HostState::Stopped))
        .expect("Stop did not reach a host that was still connecting");

    // Let the abandoned attempt finish and hand the dialler back.
    let deadline = std::time::Instant::now() + T;
    while dropped.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    h.send(HostCommand::StartViaRelay).unwrap();
    let reached = h
        .wait_for_state(T, |s| s.is_running())
        .expect("a host that had stopped one dial could not start another");
    assert!(!reached.is_listening());
    assert!(h.shutdown_and_join(T));
}

/// A controller with no relay says so. It does NOT fall back to binding: the
/// two routes are different exposures and the operator chose one.
#[test]
fn a_host_with_no_relay_refuses_to_dial_out_rather_than_binding() {
    let mut h = spawn(Probe::default());
    h.send(HostCommand::StartViaRelay).unwrap();
    match h.wait_for_event(T).expect("a fault") {
        HostEvent::Fault { message } => assert!(
            message.contains("relay"),
            "the refusal should name what is missing: {message}"
        ),
        other => panic!("expected a Fault, got {other:?}"),
    }
    assert!(
        h.wait_for_state(Duration::from_millis(300), |s| s.is_running())
            .is_none(),
        "a host with no relay started anyway"
    );
    assert!(h.shutdown_and_join(T));
}

/// Wait for the invite the controller emits after a `CreateInvite`.
fn await_invite(h: &mut host_controller::HostHandle) -> Option<host_controller::state::InviteView> {
    let deadline = std::time::Instant::now() + T;
    while std::time::Instant::now() < deadline {
        if let Some(HostEvent::InviteReady(v)) = h.wait_for_event(Duration::from_millis(200)) {
            return Some(v);
        }
    }
    None
}

/// **An invite names the route the host is ACTUALLY on.**
///
/// A dialled-out host has no bound address, so the invite it mints must name
/// the relay and the session — not an address invented to fill the field, which
/// is what v3 did when it probed a public resolver for a "public" one.
#[test]
fn a_dialled_out_host_mints_an_invite_for_its_relay_and_session() {
    let probe = Probe::default();
    let relay = sa("203.0.113.9:9443");
    let mut h = host_controller::spawn_with_dial_out(
        {
            let p = probe.clone();
            move || p
        },
        QuietDialOut { relay },
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, |s| s.is_running())
        .expect("the host never reported that it was serving");

    h.send(HostCommand::CreateInvite).unwrap();
    let view = await_invite(&mut h).expect("a dialled-out host minted no invite");

    assert_eq!(probe.n(&probe.invites_minted), 1);
    match probe.minted_for.lock().unwrap().clone() {
        Some(host_controller::Reach::ViaRelay { relay: r, session }) => {
            assert_eq!(r, relay, "the invite named a relay the host is not on");
            assert_eq!(session, "AAAAAAAAAAAAAAAAAAAAAA");
            assert!(
                view.token_fingerprint.starts_with("relay:"),
                "the minted invite was not the relay one: {}",
                view.token_fingerprint
            );
        }
        other => panic!("a dialled-out host minted for {other:?}"),
    }
    assert!(h.shutdown_and_join(T));
}

/// The other route still mints against the address it is bound to.
#[test]
fn a_bound_host_still_mints_for_the_address_it_is_bound_to() {
    let probe = Probe::default();
    let mut h = spawn(probe.clone());
    let bound = start_on_ephemeral(&mut h);

    h.send(HostCommand::CreateInvite).unwrap();
    await_invite(&mut h).expect("a bound host minted no invite");

    match probe.minted_for.lock().unwrap().clone() {
        Some(host_controller::Reach::Bound(addr)) => assert_eq!(addr, bound),
        other => panic!("a bound host minted for {other:?}"),
    }
    assert!(h.shutdown_and_join(T));
}

/// **Stop closes the control connection of a host that is SERVING.**
///
/// Deferred from P3, which proved only the late-arrival case: a connection that
/// lands after a Stop is closed at once. The ordinary case — running through the
/// relay, then Stop or a closed window — rode on the same teardown that
/// `stop_closes_the_port` proves for listeners, with no test of its own. If it
/// ever stopped holding, the relay would keep the host's session slot until a
/// keepalive eventually reaped it, and the operator would see a host they had
/// stopped still listed as reachable.
#[test]
fn stop_closes_the_relay_connection_of_a_serving_host() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut h = host_controller::spawn_with_dial_out(
        Probe::default,
        SlowDialOut {
            relay: sa("203.0.113.9:9443"),
            delay: Duration::from_millis(0),
            dropped: dropped.clone(),
        },
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, |s| s.is_running())
        .expect("the host never reported that it was serving through the relay");
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "the relay connection was closed while the host was still serving"
    );

    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| matches!(s, HostState::Stopped))
        .expect("the host never stopped");

    let deadline = std::time::Instant::now() + T;
    while dropped.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "Stop left the relay connection open — the relay would hold the session slot"
    );
    assert!(h.shutdown_and_join(T));
}

// ── P5: both routes at once ──────────────────────────────────────────────────
//
// The relay connects on start and the LAN listener is added by a click, so a
// running host can hold both. What must hold: adding a route never restarts
// capture or input; losing one route keeps the other serving; only the last
// route ends the host; a listener is never reopened by anything but the
// operator; and Stop still closes everything.

/// A relay route whose control connection the test can cut, and which hands
/// out REAL sockets: clients connect to its own loopback "door", and each one
/// is offered to the host as a relayed peer, labelled the way the real relay
/// source labels them.
struct LoopbackRelaySource {
    relay: SocketAddr,
    door: tokio::net::TcpListener,
    cut: Arc<tokio::sync::Notify>,
    served: usize,
    dropped: Arc<AtomicUsize>,
}

impl Drop for LoopbackRelaySource {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl host_controller::PeerSource for LoopbackRelaySource {
    fn next_peer(&mut self) -> host_controller::source::PeerFuture<'_> {
        Box::pin(async move {
            tokio::select! {
                _ = self.cut.notified() => None,
                accepted = self.door.accept() => {
                    let (stream, _) = accepted.ok()?;
                    self.served += 1;
                    Some((stream, self.relay, format!("via relay {} #{}", self.relay, self.served)))
                }
            }
        })
    }
    fn reach(&self) -> host_controller::Reach {
        host_controller::Reach::ViaRelay {
            relay: self.relay,
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        }
    }
}

#[derive(Clone)]
struct LoopbackRelay {
    relay: SocketAddr,
    connects: Arc<AtomicUsize>,
    cut: Arc<tokio::sync::Notify>,
    door: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    dropped: Arc<AtomicUsize>,
}

impl LoopbackRelay {
    fn new() -> Self {
        LoopbackRelay {
            relay: sa("203.0.113.9:9443"),
            connects: Arc::default(),
            cut: Arc::new(tokio::sync::Notify::new()),
            door: Arc::default(),
            dropped: Arc::default(),
        }
    }
    /// Where a "phone" connects to reach the host through this relay.
    fn door(&self) -> SocketAddr {
        self.door
            .lock()
            .unwrap()
            .expect("the relay was never dialled")
    }
    /// Cut the host's current connection to the relay.
    fn cut(&self) {
        self.cut.notify_one();
    }
}

impl host_controller::DialOut for LoopbackRelay {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        let me = self.clone();
        Box::pin(async move {
            let door = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| host_controller::DialFailure::unreachable(e.to_string()))?;
            *me.door.lock().unwrap() = Some(door.local_addr().unwrap());
            me.connects.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(LoopbackRelaySource {
                relay: me.relay,
                door,
                cut: me.cut.clone(),
                served: 0,
                dropped: me.dropped.clone(),
            }) as Box<dyn host_controller::PeerSource>)
        })
    }
}

fn serves_both(s: &HostState) -> bool {
    matches!(s.reach(), Some(host_controller::Reach::Both { .. }))
}

fn relay_only(s: &HostState) -> bool {
    matches!(s.reach(), Some(host_controller::Reach::ViaRelay { .. }))
}

fn lan_only(s: &HostState) -> bool {
    matches!(s.reach(), Some(host_controller::Reach::Bound(_)))
}

/// Wait for an event matching `pred`, collecting everything seen on the way.
fn await_event(
    h: &mut host_controller::HostHandle,
    within: Duration,
    pred: impl Fn(&HostEvent) -> bool,
) -> (Option<HostEvent>, Vec<HostEvent>) {
    let deadline = std::time::Instant::now() + within;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return (None, seen);
        }
        match h.wait_for_event(left) {
            Some(e) if pred(&e) => return (Some(e), seen),
            Some(e) => seen.push(e),
            None => return (None, seen),
        }
    }
}

fn await_fault(h: &mut host_controller::HostHandle, containing: &str) -> Vec<HostEvent> {
    let (hit, seen) = await_event(
        h,
        T,
        |e| matches!(e, HostEvent::Fault { message } if message.contains(containing)),
    );
    assert!(
        hit.is_some(),
        "no fault containing {containing:?}; saw {seen:?}"
    );
    seen
}

/// A relay host plus a listener, ready to test. Returns the bound address.
fn serve_both(h: &mut host_controller::HostHandle) -> SocketAddr {
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, relay_only)
        .expect("the relay route never came up");
    h.send(HostCommand::Start {
        bind: sa("127.0.0.1:0"),
    })
    .unwrap();
    let s = h
        .wait_for_state(T, serves_both)
        .expect("the host never served both routes");
    s.bound().expect("a host serving both routes is listening")
}

#[test]
fn a_relay_host_adds_a_listener_without_restarting_capture() {
    let probe = Probe::default();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        LoopbackRelay::new(),
    );
    let bound = serve_both(&mut h);
    assert!(port_open(bound), "the added listener does not accept");
    assert_eq!(
        probe.n(&probe.capture_started),
        1,
        "capture was started twice"
    );
    assert_eq!(probe.n(&probe.input_opened), 1, "input was opened twice");
    assert_eq!(probe.n(&probe.capture_stopped), 0);

    // A second listener is still refused, and the first is untouched.
    h.send(HostCommand::Start {
        bind: sa("127.0.0.1:0"),
    })
    .unwrap();
    await_fault(&mut h, "already listening");
    assert!(port_open(bound), "a refused Start disturbed the listener");
    assert!(h.shutdown_and_join(T));
}

#[test]
fn a_listening_host_adds_the_relay_and_refuses_a_second_one() {
    let probe = Probe::default();
    let relay = LoopbackRelay::new();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        relay.clone(),
    );
    let bound = start_on_ephemeral(&mut h);
    h.send(HostCommand::StartViaRelay).unwrap();
    let s = h
        .wait_for_state(T, serves_both)
        .expect("the relay was not added to a listening host");
    assert_eq!(
        s.bound(),
        Some(bound),
        "adding the relay moved the listener"
    );
    assert!(port_open(bound));
    assert_eq!(
        probe.n(&probe.capture_started),
        1,
        "capture was started twice"
    );

    h.send(HostCommand::StartViaRelay).unwrap();
    await_fault(&mut h, "already connected to the relay");
    assert_eq!(
        relay.connects.load(Ordering::SeqCst),
        1,
        "the relay was dialled twice"
    );
    assert!(h.shutdown_and_join(T));
}

/// **A relay that drops does not take the LAN route with it**, and is dialled
/// again. The outstanding code is withdrawn, because it may name the route
/// that went.
#[test]
fn losing_the_relay_keeps_the_listener_and_dials_the_relay_again() {
    let probe = Probe::default();
    let relay = LoopbackRelay::new();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        relay.clone(),
    );
    let bound = serve_both(&mut h);
    h.send(HostCommand::CreateInvite).unwrap();
    assert!(await_invite(&mut h).is_some(), "no invite was minted");

    relay.cut();
    let seen = await_fault(&mut h, "the relay connection closed — reconnecting");
    let (withdrawn, more) = await_event(&mut h, T, |e| matches!(e, HostEvent::InviteWithdrawn));
    assert!(
        withdrawn.is_some(),
        "the invite was not withdrawn; saw {seen:?} {more:?}"
    );
    assert!(
        probe.n(&probe.invites_revoked) >= 1,
        "the invite was not revoked"
    );
    let (lan, more) = await_event(
        &mut h,
        T,
        |e| matches!(e, HostEvent::StateChanged(s) if lan_only(s)),
    );
    assert!(
        lan.is_some(),
        "the host did not report the LAN route alone; saw {more:?}"
    );
    assert!(
        !more.iter().any(|e| matches!(
            e,
            HostEvent::StateChanged(
                HostState::Error { .. } | HostState::Stopped | HostState::Stopping
            )
        )),
        "losing one route ended the host: {more:?}"
    );
    assert!(port_open(bound), "losing the relay closed the listener");

    let s = h
        .wait_for_state(T, serves_both)
        .expect("the relay was not dialled again");
    assert_eq!(s.bound(), Some(bound));
    assert_eq!(relay.connects.load(Ordering::SeqCst), 2);
    assert_eq!(
        relay.dropped.load(Ordering::SeqCst),
        1,
        "the dead relay source was kept"
    );
    assert_eq!(probe.n(&probe.capture_stopped), 0, "capture was stopped");
    assert_eq!(probe.n(&probe.input_closed), 0, "input was closed");
    assert!(h.shutdown_and_join(T));
}

/// **Stop listening closes the port and the LAN sessions, and nothing else.**
/// A phone that came in through the relay stays connected.
#[test]
fn stop_listening_closes_only_the_listener_and_its_sessions() {
    use std::io::{Read, Write};
    let probe = Probe::default();
    probe.authenticate.store(1, Ordering::SeqCst);
    let relay = LoopbackRelay::new();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        relay.clone(),
    );
    let bound = serve_both(&mut h);

    let mut lan_phone = TcpStream::connect(bound).unwrap();
    let lan_label = lan_phone.local_addr().unwrap().to_string();
    lan_phone.write_all(b"auth-lan").unwrap();
    h.wait_for_state(T, |s| s.peers() == 1)
        .expect("the LAN phone");
    let mut relay_phone = TcpStream::connect(relay.door()).unwrap();
    relay_phone.write_all(b"auth-relay").unwrap();
    h.wait_for_state(T, |s| s.peers() == 2)
        .expect("the relayed phone");

    h.send(HostCommand::StopListening).unwrap();
    let (gone, seen) = await_event(
        &mut h,
        T,
        |e| matches!(e, HostEvent::PeerDisconnected { peer, count: 1 } if *peer == lan_label),
    );
    assert!(
        gone.is_some(),
        "the LAN session survived Stop listening; saw {seen:?}"
    );
    assert!(
        seen.iter().any(|e| matches!(e, HostEvent::InviteWithdrawn)),
        "no InviteWithdrawn: {seen:?}"
    );
    let s = h
        .wait_for_state(T, |s| relay_only(s) && s.peers() == 1)
        .expect("the host did not settle on the relay with one peer");
    assert!(!s.is_listening(), "the host still reports a listener");
    assert!(!port_open(bound), "the port is still open");

    relay_phone
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut byte = [0u8; 1];
    match relay_phone.read(&mut byte) {
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        Ok(0) => panic!("Stop listening disconnected the relayed phone"),
        other => panic!("unexpected read from the relayed phone: {other:?}"),
    }
    assert_eq!(
        relay.dropped.load(Ordering::SeqCst),
        0,
        "the relay route was closed"
    );
    assert_eq!(probe.n(&probe.capture_stopped), 0, "capture was stopped");
    assert!(h.shutdown_and_join(T));
}

/// Stop listening is a command about ONE route. It never quietly does more.
#[test]
fn stop_listening_is_refused_unless_another_route_is_serving() {
    let mut h = host_controller::spawn_with_dial_out(Probe::default, LoopbackRelay::new());
    h.send(HostCommand::StopListening).unwrap();
    await_fault(&mut h, "not running");

    let bound = start_on_ephemeral(&mut h);
    h.send(HostCommand::StopListening).unwrap();
    await_fault(&mut h, "only route");
    assert!(port_open(bound), "a refused Stop listening closed the port");
    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Stopped).unwrap();

    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, relay_only).unwrap();
    h.send(HostCommand::StopListening).unwrap();
    await_fault(&mut h, "not listening");
    assert!(h.shutdown_and_join(T));
}

#[test]
fn stop_closes_both_routes() {
    let probe = Probe::default();
    let relay = LoopbackRelay::new();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        relay.clone(),
    );
    let bound = serve_both(&mut h);
    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Stopped)
        .expect("Stop did not stop a host serving both routes");
    assert!(!port_open(bound), "Stop left the listener open");
    assert_eq!(
        relay.dropped.load(Ordering::SeqCst),
        1,
        "Stop left the relay connected"
    );
    assert_eq!(probe.n(&probe.capture_stopped), 1);
    assert_eq!(probe.n(&probe.input_closed), 1);
    assert!(h.shutdown_and_join(T));
}

/// Clicking Start while the relay is still being dialled is no longer refused:
/// the listener comes up, and the relay joins it when it answers.
#[test]
fn a_listener_started_while_the_relay_dials_is_joined_by_the_relay() {
    let probe = Probe::default();
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        SlowDialOut {
            relay: sa("203.0.113.9:9443"),
            delay: Duration::from_millis(400),
            dropped: dropped.clone(),
        },
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Starting).unwrap();
    h.send(HostCommand::Start {
        bind: sa("127.0.0.1:0"),
    })
    .unwrap();
    let s = h
        .wait_for_state(T, lan_only)
        .expect("the listener did not come up while the relay was dialling");
    let bound = s.bound().unwrap();
    let s = h
        .wait_for_state(T, serves_both)
        .expect("the relay did not join the listening host");
    assert_eq!(s.bound(), Some(bound));
    assert_eq!(
        probe.n(&probe.capture_started),
        1,
        "capture was started twice"
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "the relay source was thrown away"
    );
    assert!(h.shutdown_and_join(T));
}

/// A relay that refuses is reported, and a host that is already listening
/// stays exactly as it was — no Error state for a host that is serving.
#[test]
fn a_relay_that_refuses_does_not_stop_a_listening_host() {
    let refusing = RefusingDialOut::default();
    let mut h = host_controller::spawn_with_dial_out(Probe::default, refusing.clone());
    let bound = start_on_ephemeral(&mut h);
    h.send(HostCommand::StartViaRelay).unwrap();
    let (refused, seen) = await_event(
        &mut h,
        T,
        |e| matches!(e, HostEvent::RelayRefused { why } if why.contains("not enrolled")),
    );
    assert!(
        refused.is_some(),
        "the refusal was not reported as a refusal: {seen:?}"
    );
    let (bad, more) = await_event(&mut h, Duration::from_millis(500), |e| {
        matches!(e, HostEvent::StateChanged(_))
    });
    assert!(
        bad.is_none(),
        "a refused relay changed a listening host's state: {bad:?} after {seen:?} {more:?}"
    );
    assert!(port_open(bound), "a refused relay closed the listener");
    assert_eq!(refusing.attempts.load(Ordering::SeqCst), 1);
    assert!(h.shutdown_and_join(T));
}

/// A listener that cannot bind is reported, and a relay host keeps serving.
#[test]
fn a_relay_host_that_cannot_bind_keeps_serving() {
    let probe = Probe::default();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        LoopbackRelay::new(),
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, relay_only).unwrap();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    h.send(HostCommand::Start {
        bind: taken.local_addr().unwrap(),
    })
    .unwrap();
    let seen = await_fault(&mut h, "could not bind");
    assert!(
        !seen.iter().any(|e| matches!(e, HostEvent::StateChanged(_))),
        "a failed bind changed a serving host's state: {seen:?}"
    );
    h.send(HostCommand::CreateInvite).unwrap();
    assert!(
        await_invite(&mut h).is_some(),
        "the relay host stopped minting"
    );
    assert!(matches!(
        probe.minted_for.lock().unwrap().clone(),
        Some(host_controller::Reach::ViaRelay { .. })
    ));
    assert_eq!(
        probe.n(&probe.capture_stopped),
        0,
        "a failed bind stopped capture"
    );
    assert!(h.shutdown_and_join(T));
}

/// The invite is minted for the routes the host is actually serving — both.
#[test]
fn a_host_serving_both_routes_mints_for_both() {
    let probe = Probe::default();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        LoopbackRelay::new(),
    );
    let bound = serve_both(&mut h);
    h.send(HostCommand::CreateInvite).unwrap();
    assert!(await_invite(&mut h).is_some());
    assert_eq!(
        probe.minted_for.lock().unwrap().clone(),
        Some(host_controller::Reach::Both {
            bound,
            relay: sa("203.0.113.9:9443"),
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        })
    );
    assert!(h.shutdown_and_join(T));
}

/// **Each route releases its own pre-auth slots, and revokes its own peers.**
///
/// An authentication is forwarded to every route, and only the route that
/// accepted the peer holds its slot. If the forward reached only one route, the
/// other's authenticated phones would keep their slots: after
/// `PreAuthLimit::MAX_PENDING` of them that route would refuse everyone, and
/// each would be cut off at the pre-auth deadline despite having proven itself.
/// More phones than the bound are connected on EACH route to show neither
/// happens, and one peer on each route is then revoked.
#[test]
fn both_routes_release_authenticated_slots_and_revoke_their_own_peers() {
    use std::io::Write;
    let probe = Probe::default();
    probe.authenticate.store(1, Ordering::SeqCst);
    let relay = LoopbackRelay::new();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        relay.clone(),
    );
    let bound = serve_both(&mut h);
    let per_route = host_controller::PreAuthLimit::MAX_PENDING + 1;
    let mut phones = Vec::new();
    let mut labels = Vec::new();
    for i in 0..per_route {
        let mut lan = TcpStream::connect(bound).unwrap();
        labels.push(lan.local_addr().unwrap().to_string());
        lan.write_all(b"auth").unwrap();
        phones.push(lan);
        h.wait_for_state(T, |s| s.peers() == 2 * i + 1)
            .unwrap_or_else(|| panic!("LAN phone {} was not admitted", i + 1));
        let mut relayed = TcpStream::connect(relay.door()).unwrap();
        relayed.write_all(b"auth").unwrap();
        phones.push(relayed);
        h.wait_for_state(T, |s| s.peers() == 2 * i + 2)
            .unwrap_or_else(|| panic!("relayed phone {} was not admitted", i + 1));
    }
    let total = 2 * per_route;

    let relayed_label = format!("via relay {} #1", relay.relay);
    for (n, peer) in [labels[0].clone(), relayed_label].into_iter().enumerate() {
        h.send(HostCommand::RevokePeer { peer: peer.clone() })
            .unwrap();
        let (hit, seen) = await_event(
            &mut h,
            T,
            |e| matches!(e, HostEvent::PeerDisconnected { peer: p, .. } if *p == peer),
        );
        assert!(hit.is_some(), "revoking {peer} did nothing; saw {seen:?}");
        h.wait_for_state(T, |s| s.peers() == total - n - 1)
            .unwrap_or_else(|| panic!("the count did not fall after revoking {peer}"));
    }
    assert!(h.shutdown_and_join(T));
}

// ── the relay-only host keeps its relay ───────────────────────────────────────
//
// 2026-09-17: a host serving only through the relay lost its control connection
// at 09:32 and stayed unreachable until someone restarted it ten hours later.

/// A relay route that ends the moment it is up, and counts how often it is
/// dialled — a relay that accepts the host and drops it at once.
struct CountingDeadDialOut {
    relay: SocketAddr,
    connects: Arc<AtomicUsize>,
}

impl host_controller::DialOut for CountingDeadDialOut {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        let relay = self.relay;
        let connects = self.connects.clone();
        Box::pin(async move {
            connects.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(DeadSource { relay }) as Box<dyn host_controller::PeerSource>)
        })
    }
}

/// Accepts the host once, then refuses it — an enrolment withdrawn while the
/// host was connected, or a relay restarted with a different host list.
#[derive(Clone)]
struct OnceThenRefused {
    relay: LoopbackRelay,
    calls: Arc<AtomicUsize>,
}

impl host_controller::DialOut for OnceThenRefused {
    fn connect(&mut self) -> host_controller::source::DialFuture<'_> {
        let calls = self.calls.fetch_add(1, Ordering::SeqCst);
        if calls == 0 {
            return self.relay.connect();
        }
        Box::pin(async {
            Err(host_controller::DialFailure::refused(
                "the relay refused this host: not enrolled",
            ))
        })
    }
}

/// **A relay-only host whose relay connection ends dials it again**, and comes
/// back serving. Capture and input go with the lost route — a host with no way
/// in holds neither — and return with it; the code on screen is withdrawn.
#[test]
fn a_relay_only_host_dials_its_relay_again_when_the_connection_ends() {
    let probe = Probe::default();
    let relay = LoopbackRelay::new();
    let mut h = host_controller::spawn_with_dial_out(
        {
            let probe = probe.clone();
            move || probe
        },
        relay.clone(),
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, relay_only)
        .expect("the relay never came up");
    h.send(HostCommand::CreateInvite).unwrap();
    assert!(await_invite(&mut h).is_some());

    relay.cut();
    let seen = await_fault(&mut h, "the relay connection closed — reconnecting");
    let (retry, more) = await_event(&mut h, T, |e| matches!(e, HostEvent::RelayRetrying { .. }));
    let everything: Vec<_> = seen.iter().chain(more.iter()).collect();
    assert!(
        matches!(
            retry,
            Some(HostEvent::RelayRetrying {
                attempt: 1,
                in_seconds: 0,
                ..
            })
        ),
        "the first re-dial should be immediate and announced: {retry:?}"
    );
    assert!(
        everything
            .iter()
            .any(|e| matches!(e, HostEvent::InviteWithdrawn)),
        "the code naming the lost session was not withdrawn: {everything:?}"
    );
    assert!(
        everything
            .iter()
            .any(|e| matches!(e, HostEvent::StateChanged(HostState::Starting))),
        "a host with no way in did not say it was starting again: {everything:?}"
    );
    assert!(
        !everything
            .iter()
            .any(|e| matches!(e, HostEvent::StateChanged(HostState::Error { .. }))),
        "losing the relay still ended the host: {everything:?}"
    );

    h.wait_for_state(T, relay_only)
        .expect("the host did not come back through the relay");
    assert_eq!(relay.connects.load(Ordering::SeqCst), 2);
    assert_eq!(
        relay.dropped.load(Ordering::SeqCst),
        1,
        "the dead source was kept"
    );
    assert_eq!(
        probe.n(&probe.capture_stopped),
        1,
        "capture outlived the only route"
    );
    assert_eq!(
        probe.n(&probe.input_closed),
        1,
        "input outlived the only route"
    );
    assert_eq!(
        probe.n(&probe.capture_started),
        2,
        "capture did not come back with the relay"
    );
    assert_eq!(
        probe.n(&probe.input_opened),
        2,
        "input did not come back with the relay"
    );
    assert!(h.shutdown_and_join(T));
}

/// **A relay that refuses the re-dial is named as refusing, and not retried.**
/// "Unreachable, trying again" needs nothing from the operator; "refused" needs
/// a human, so it arrives as its own event and the host stops dialling.
#[test]
fn a_relay_that_refuses_the_redial_is_named_and_not_retried() {
    let relay = LoopbackRelay::new();
    let dial = OnceThenRefused {
        relay: relay.clone(),
        calls: Arc::default(),
    };
    let mut h = host_controller::spawn_with_dial_out(Probe::default, dial.clone());
    h.send(HostCommand::StartViaRelay).unwrap();
    h.wait_for_state(T, relay_only)
        .expect("the relay never came up");

    relay.cut();
    let (refused, seen) = await_event(&mut h, T, |e| matches!(e, HostEvent::RelayRefused { .. }));
    match refused {
        Some(HostEvent::RelayRefused { why }) => assert!(why.contains("not enrolled"), "{why}"),
        other => panic!("no refusal after the re-dial: {other:?} after {seen:?}"),
    }
    h.wait_for_state(T, |s| matches!(s, HostState::Error { .. }))
        .expect("a refused host with no route did not stop");
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        dial.calls.load(Ordering::SeqCst),
        2,
        "a refused relay was dialled again"
    );
    assert!(h.shutdown_and_join(T));
}

/// **Stop during a re-dial's backoff stops it.** The operator's Stop is final:
/// nothing dials after it.
#[test]
fn stop_ends_a_redial_that_is_waiting_out_its_backoff() {
    let connects = Arc::new(AtomicUsize::new(0));
    let mut h = host_controller::spawn_with_dial_out(
        Probe::default,
        CountingDeadDialOut {
            relay: sa("203.0.113.9:9443"),
            connects: connects.clone(),
        },
    );
    h.send(HostCommand::StartViaRelay).unwrap();
    // Wait until a re-dial is sitting in a real (non-zero) backoff.
    let (waiting, seen) = await_event(
        &mut h,
        T,
        |e| matches!(e, HostEvent::RelayRetrying { in_seconds, .. } if *in_seconds >= 1),
    );
    assert!(waiting.is_some(), "no backoff was ever announced: {seen:?}");
    h.send(HostCommand::Stop).unwrap();
    h.wait_for_state(T, |s| *s == HostState::Stopped)
        .expect("Stop did not stop a host that was re-dialling");
    let at_stop = connects.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(
        connects.load(Ordering::SeqCst),
        at_stop,
        "the relay was dialled after Stop"
    );
    assert!(h.shutdown_and_join(T));
}

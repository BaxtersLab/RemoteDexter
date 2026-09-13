//! The seam between the lifecycle and the machine.
//!
//! `HostController` decides *when* capture and input may exist. It has no idea
//! *how* — that is portal/PipeWire on Linux and DXGI on Windows for capture,
//! uinput on Linux and SendInput on Windows for control. Those live behind this
//! trait so the lifecycle is testable without a compositor, a GPU or a seat.
//!
//! This is a seam, not a stub (Article VII): there is one real shipped
//! implementation in `host_app`, and the trait exists so the state machine can
//! be driven by tests that must never touch the operator's live session
//! (Article XIV).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

/// A backend failure, already reduced to something safe to show and log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendFault(pub String);

impl BackendFault {
    /// Build a fault from a display-safe message.
    pub fn new(msg: impl Into<String>) -> Self {
        BackendFault(msg.into())
    }
}

/// A future that serves one accepted connection to completion.
pub type ServeFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Builds one [`ServeFuture`] per accepted socket, without borrowing the
/// backend.
pub type ServeDispatch =
    std::sync::Arc<dyn Fn(tokio::net::TcpStream, SocketAddr, String) -> ServeFuture + Send + Sync>;

/// The backend's one-shot way of telling the controller "this peer proved who
/// it is".
///
/// **This is the whole reason `PeerConnected` is trustworthy.** Before the
/// Block 4 repair the controller emitted `PeerConnected` the instant `accept()`
/// returned — that is, for any TCP connection at all, from anyone, before a
/// single byte was authenticated. The console said "1 device connected" for
/// `nc host 8082`.
///
/// The backend now signals only after the pinned Noise handshake completes AND
/// the pairing token is redeemed inside that encrypted channel. A connection
/// that never authenticates is served, closed, and never counted.
#[derive(Clone)]
pub struct AuthNotifier {
    tx: tokio::sync::mpsc::UnboundedSender<String>,
    peer: String,
}

impl AuthNotifier {
    /// Construct one. The controller does this; backends only call
    /// [`AuthNotifier::authenticated`].
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<String>, peer: String) -> Self {
        AuthNotifier { tx, peer }
    }

    /// Report that this peer completed authentication. Idempotent from the
    /// controller's point of view: a second call for the same peer is ignored
    /// there rather than double-counting.
    pub fn authenticated(&self) {
        let _ = self.tx.send(self.peer.clone());
    }
}

impl std::fmt::Debug for AuthNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthNotifier")
            .field("peer", &self.peer)
            .finish()
    }
}

/// The backend's way of telling the controller something the OPERATOR needs to
/// see, from inside a connection that is already running.
///
/// [`BackendFault`] cannot carry this. It is a return type, and it is only
/// returned by `start_capture`, `open_input` and `create_invite` — three calls
/// that happen at Start, before any peer exists. A session that goes wrong
/// halfway through has no way back to the console at all.
///
/// **The case that made this necessary:** on Windows, a higher-integrity
/// foreground window makes the OS discard injected input while `SendInput`
/// still reports success (UIPI). The host detects it and gives the control
/// grant back — the operator's own decision — and until now it said so in a
/// log line and in a JSON denial to the phone. The person actually holding the
/// phone saw control stop working and the host say nothing.
///
/// Shaped exactly like [`AuthNotifier`]: per-connection, cloneable, and it
/// cannot fail. A closed channel means the controller is gone, which is not
/// something a session can do anything about.
#[derive(Clone)]
pub struct NoticeNotifier {
    tx: tokio::sync::mpsc::UnboundedSender<String>,
    peer: String,
}

impl NoticeNotifier {
    /// Construct one. The controller does this; backends only call
    /// [`NoticeNotifier::fault`].
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<String>, peer: String) -> Self {
        NoticeNotifier { tx, peer }
    }

    /// Report something that went wrong inside this connection. The controller
    /// raises it as [`crate::state::HostEvent::Fault`].
    ///
    /// `message` must already be display-safe, on the same terms as
    /// [`BackendFault`]: rule names and typed reasons, never a token, a key, or
    /// a payload the peer supplied.
    pub fn fault(&self, message: impl Into<String>) {
        let _ = self.tx.send(message.into());
    }

    /// The peer label this notifier belongs to. Used for logging on the
    /// backend side; the controller already knows which connection it is.
    pub fn peer(&self) -> &str {
        &self.peer
    }
}

impl std::fmt::Debug for NoticeNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoticeNotifier")
            .field("peer", &self.peer)
            .finish()
    }
}

/// The platform machinery the controller starts and stops.
///
/// Ordering is guaranteed by the controller and depended on by the
/// implementations: capture and input are opened only after a listener exists,
/// and closed before the listener is dropped. Every `open_*` is paired with
/// exactly one `close_*`, including on the error and shutdown paths.
pub trait HostBackend: Send + 'static {
    /// Begin capturing. Called once per `Start`.
    fn start_capture(&mut self) -> Result<(), BackendFault>;

    /// Stop capturing. Called once per `Stop`, and on every failure path after
    /// a successful `start_capture`. Must be idempotent.
    fn stop_capture(&mut self);

    /// Open input devices (uinput on Linux). Called once per `Start`, after
    /// capture.
    fn open_input(&mut self) -> Result<(), BackendFault>;

    /// Release input devices. Must release every held button first — a host
    /// left with a latched mouse button drag-selects everything the pointer
    /// crosses. Must be idempotent.
    fn close_input(&mut self);

    /// Mint a pairing invitation for `reach`, which is how the host is ALREADY
    /// reachable — a bound address, or the relay it dialled and the session it
    /// was issued.
    ///
    /// The controller passes it in rather than letting the backend discover
    /// anything. That is the whole shape of the fix: the previous
    /// implementation guessed its own address by opening a UDP socket to a
    /// public resolver, and then advertised the result.
    ///
    /// Takes a [`crate::state::Reach`] and not a `SocketAddr` because a
    /// dialled-out host has no address to pass. Giving it one — the relay's,
    /// say — would put an endpoint in a signed invite that nothing is listening
    /// on, which is the same defect in a new place.
    fn create_invite(
        &mut self,
        reach: &crate::state::Reach,
        now: u64,
    ) -> Result<crate::state::InviteView, BackendFault>;

    /// Drop any outstanding invitation. Called on Stop.
    fn revoke_invite(&mut self);

    /// Serve one accepted connection.
    ///
    /// The returned future is spawned on the controller's runtime and **dropped
    /// on Stop, Shutdown, or loss of the UI channel** — cancellation is the
    /// controller's, not the backend's.
    ///
    /// The backend owns the socket completely from here: it performs the Noise
    /// handshake, redeems the pairing token inside that encrypted channel, and
    /// runs the session. The controller does **not** read from the socket. It
    /// used to, discarding a byte at a time to detect disconnects, which meant
    /// the product's own protocol bytes were consumed by the lifecycle layer
    /// and `serve` was never called at all.
    ///
    /// Call [`AuthNotifier::authenticated`] once, and only once the peer has
    /// actually proven itself.
    ///
    /// `notices` carries news the operator needs mid-session — see
    /// [`NoticeNotifier`]. It is optional to use and must never be used for
    /// per-event chatter: everything sent here reaches the console.
    fn serve(
        &mut self,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
        authed: AuthNotifier,
        notices: NoticeNotifier,
    ) -> ServeFuture;

    /// Hand out a dispatcher the accept task can call once per connection.
    ///
    /// The controller owns the backend, so the accept task cannot borrow it.
    /// The default implementation is almost certainly what you want; it exists
    /// as a trait method only so a backend that needs to share state across
    /// connections can build the closure itself.
    fn dispatch(
        &mut self,
        auth_tx: tokio::sync::mpsc::UnboundedSender<String>,
        notice_tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> ServeDispatch;
}

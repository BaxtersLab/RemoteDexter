//! The WAN relay: it splices ciphertext between a host and a phone, and does
//! nothing else.
//!
//! # Why this exists
//!
//! RemoteDexter has to work off the local Wi-Fi, and today it cannot. That was
//! a design decision rather than a bug: `host_app` is a LISTENER,
//! `host_controller::bind` accepts one deliberately chosen local interface and
//! refuses every wildcard, and the v4 invite carries the bound socket — a
//! private LAN address. `wan_ip` was removed in v4 on purpose, because v3
//! discovered it by opening a UDP socket to a public resolver, which leaked the
//! timing of every invitation.
//!
//! Behind a VPN nobody here controls, inbound connections cannot be assumed, so
//! **the direction has to invert**: the host dials out and holds the connection
//! rather than being dialled.
//!
//! # The one property that does not bend
//!
//! **THE RELAY SEES CIPHERTEXT AND NOTHING ELSE.**
//!
//! The transport is already Noise XX with the host identity key pinned on the
//! phone, so a relay that only copies encrypted bytes between two sockets never
//! has to be trusted: it cannot read a session, cannot modify one undetected,
//! and cannot impersonate the host. This crate therefore has **no dependency
//! that could decrypt** — no `snow`, no session types. That is structural, and
//! adding one would be a visible dependency change in review.
//!
//! A future reader who wants the relay to terminate plaintext "to make
//! reconnection easier" is throwing away the only reason it needs no trust.
//! Argue with this paragraph first.
//!
//! # How the host reaches the relay
//!
//! **One persistent control connection, and a data connection dialled on
//! demand.** The host dials out once and holds that connection for the life of
//! its invite; when a phone arrives the relay sends `ClientWaiting` down it with
//! a single-use ticket, and the host dials a SECOND connection carrying that
//! ticket. Only the second is spliced.
//!
//! The alternative was one dial per session, with the host redialling after
//! each client. It is simpler, and it was rejected: the session id would change
//! on every reconnection, so the invite naming it would be a moving target, and
//! invite v5's signed bytes are pinned cross-language.
//!
//! What this shape must NOT become is one connection carrying several clients.
//! That would make the relay multiplex, and multiplexing means parsing session
//! framing — the one thing this crate exists not to do. Two connections is the
//! price of never having to look.
//!
//! The control connection is pinged, because a dialled-out connection sits idle
//! between clients and a home NAT reaps idle TCP without telling either end. A
//! host that stops answering has its session released: an unreachable host
//! holding a slot is a session id that is already in someone's hands and can
//! never be attached to.
//!
//! # What is in here
//!
//! The parts that DECIDE anything, kept free of sockets so they can be proven
//! without one: the control-frame grammar, the session table, session-id and
//! ticket generation, and host authentication. The I/O that carries them lives
//! above.

pub mod auth;
pub mod server;
pub mod session;

/// The control-frame grammar, which lives in its own crate because the HOST
/// speaks it too and must not have to link the relay server to do so.
pub use relay_proto as frame;

pub use auth::{HostAuth, HostAuthError, HostIdentity};
pub use frame::{ControlFrame, FrameError, MAX_CONTROL_FRAME};
pub use server::{
    accept_data, accept_data_with, attach_control, confirm_join, heartbeat, join_client,
    join_client_with, mint_attach, notify_host, register_host, register_host_with, release,
    serve_connection, splice, touch_session, vacate_session, AttachWaiter, DataAttachment, Relay,
    ServeError,
};
pub use session::{AttachTable, SessionId, SessionTable, TableError, Ticket};

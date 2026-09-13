//! # session_core
//!
//! RemoteDexter's **authorization authority**. It is the only thing in the
//! product permitted to say yes to a captured frame or an injected input event.
//!
//! This crate has **zero dependencies** and performs **no I/O, no capture, no
//! networking**. It holds only the rules:
//!
//! - [`surface`] — what can be shared: [`SurfaceId`], [`SurfaceKind`],
//!   [`SurfaceGeometry`], [`SurfaceDescriptor`].
//! - [`scope`]   — which surfaces are permitted (an allow-list that starts empty).
//! - [`consent`] — the per-session control level, view-only by default.
//! - [`session`] — [`ShareSession`], which ties scope, consent and expiry into
//!   one state machine and owns every authorization gate.
//! - [`traits`]  — the seams ([`FrameSource`], [`InputSink`], [`Transport`])
//!   the real capture, input and transport implementations plug into. Those
//!   implementations may *only* be driven through an `Active` [`ShareSession`].
//!
//! ## The core invariant
//!
//! A frame may leave the machine, or an input may be injected, **only if**
//! [`ShareSession::authorize_frame`], [`ShareSession::authorize_input`] or
//! [`ShareSession::authorize_absolute_input`] returns `Ok`. Those return `Ok`
//! only when *all* of the following hold:
//!
//! 1. the pinned Noise handshake has completed — the session is past
//!    [`SessionState::AwaitingHandshake`];
//! 2. the owner has consented and the session is `Active` and unexpired;
//! 3. the target surface is in the permitted [`scope::SurfaceScope`];
//! 4. for input, control was granted **separately from viewing**; and
//! 5. for an absolute pointer move, the surface's geometry is known and
//!    contains the coordinate.
//!
//! Anything else is denied with a typed [`ShareError`]. **Viewing never grants
//! control**, and unknown geometry refuses rather than skips.
//!
//! ## Provenance
//!
//! Absorbed in Block 2 of the RemoteDexter rebuild from the operator-owned
//! `VoDesktop/core` (declared MIT), which scoped a *contractor* to specific
//! *windows* on a client's machine. RemoteDexter scopes a *paired device* to
//! *surfaces* on its owner's machine, so `WindowId` became [`SurfaceId`],
//! `WindowScope` became [`scope::SurfaceScope`], `permit_window` became
//! [`ShareSession::permit_surface`], and `contract_id` became
//! [`ShareSession::peer_id`]. Every authorization invariant survived the move,
//! and one that had been enforced loosely in the host binary — the absolute-move
//! geometry clamp — moved *into* the core where it is tested.
//!
//! Original code, owned by the operator. See `docs/THIRD_PARTY_NOTICES.md`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod consent;
pub mod scope;
pub mod session;
pub mod surface;
pub mod traits;

pub use consent::ControlLevel;
pub use scope::SurfaceScope;
pub use session::{SessionState, ShareError, ShareSession, Timestamp};
pub use surface::{SurfaceDescriptor, SurfaceGeometry, SurfaceId, SurfaceKind};
pub use traits::{CaptureError, Frame, FrameSource, InputError, InputEvent, InputSink, Transport};

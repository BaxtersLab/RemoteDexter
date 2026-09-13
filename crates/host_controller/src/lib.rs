//! # host_controller
//!
//! The host lifecycle: `Stopped -> Starting -> Pairable -> Connected ->
//! Stopping -> Stopped`, plus `Error`.
//!
//! It is the **only** thing permitted to create a listener, start capture, or
//! open input devices, and it owns no UI, no keys and no wire protocol. The UI
//! sends [`HostCommand`] and reads [`HostEvent`]; it never touches a socket.
//!
//! ## What replaced what
//!
//! `modules/module25_windows_ui` reported a placeholder as launched: it printed
//! `[Module25] Windows UI placeholder active`, subscribed to a telemetry
//! channel, and ticked `[UI] Event loop maintenance tick` every five seconds
//! forever. Nothing was ever drawn. A console that reports success for work it
//! did not do is a security defect against the owner, not merely a usability
//! one — it is the difference between "I can see my machine is not sharing" and
//! "I have been told my machine is not sharing".
//!
//! ## The property this crate exists to hold
//!
//! **In `Stopped`, no listener exists.** Not a listener that refuses
//! connections; no socket. `HostState::bound()` returns `None` and the port is
//! closed, which `scripts/vm-host-console-proof.sh` verifies with `ss` in an
//! isolated VM across Stop/Start/Stop.
//!
//! ## Design provenance
//!
//! The *shape* of the console — explicit Ready/Stopped/Connected state, direct
//! start/stop, a visible connected-peer count, fingerprints on screen — is
//! chosen so the operator can tell what the host is doing at a glance, without
//! reading a log or trusting an icon. This crate is original to RemoteDexter.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod bind;
pub mod controller;
pub mod source;
pub mod state;

pub use backend::{
    AuthNotifier, BackendFault, HostBackend, NoticeNotifier, ServeDispatch, ServeFuture,
};
pub use bind::{validate as validate_bind, BindRejection};
pub use controller::{
    spawn, spawn_with, spawn_with_dial_out, HostHandle, PreAuthLimit, SessionLimit,
};
pub use source::{DialOut, ListenSource, Peer, PeerSource};
pub use state::{HostCommand, HostEvent, HostState, Reach};

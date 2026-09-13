//! Input/Control Stream module for RemoteDexter.
//!
//! Provides low-latency bidirectional input events (keyboard, mouse, control).
//!
//! Block 10 removed `RemoteControl` and `stream` from this crate.
//! `RemoteControl` was an UNDECLARED STUB in product code (Article VII): it
//! spawned two tasks whose bodies were a timer and comments saying "in a real
//! implementation, this would listen for input events from the multiplexer".
//! It listened to nothing and injected nothing, while being the only reason
//! this crate linked the multiplexer at all. The live input path is `inject` /
//! `inject_linux`, driven directly by `host_app`.

pub mod message;
pub mod encode;
pub mod decode;
pub mod inject;
pub mod keymap;
#[cfg(all(target_os = "linux", feature = "linux-input"))]
pub mod inject_linux;
pub mod coalesce;
pub mod errors;

pub use message::*;
pub use inject::{cursor_pos, inject};


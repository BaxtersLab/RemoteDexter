//! Module 11: Delta Engine
//! Provides delta-based synchronization for efficient data updates.

pub mod types;
pub mod capture;
pub mod capture_health;
#[cfg(all(target_os = "linux", feature = "linux-capture"))]
pub mod capture_linux;
pub mod display_watch;
/// The stream wire format now lives in the zero-dependency `stream_chunk`
/// crate, so the Android client can reassemble frames without depending on this
/// host-side capture stack. Re-exported under its original path: every existing
/// `module11::chunk::…` and `module11::FrameReassembler` user is unaffected, and
/// there is still exactly one implementation of the format.
pub use stream_chunk as chunk;

pub mod delta_engine;
pub mod encoder;
pub mod stream_pump;
pub mod bitrate;

// Re-export main types
pub use types::*;
pub use capture::*;
pub use chunk::*;
pub use delta_engine::*;
pub use encoder::*;
pub use stream_pump::StreamPump;
pub use bitrate::*;
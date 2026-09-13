//! The seams between the security core and the real machinery.
//!
//! The actual screen capture, video encoding, input injection, and encrypted
//! transport live in the RemoteDexter host layer, behind these
//! traits. They are intentionally abstract here so that:
//!
//! 1. the security core stays dependency-free and testable; and
//! 2. every implementation is forced through the [`crate::session::ShareSession`]
//!    authorization checks — there is no API that captures a surface or injects
//!    an event without a prior `authorize_*` call.
//!
//! The implementations live in the host binary and the platform capture and
//! input crates.

use crate::surface::SurfaceId;

/// A captured frame from a single permitted surface.
///
/// `surface` records which surface it came from so the transport/UI can label it
/// and so a defensive second check is possible before it leaves the machine.
#[derive(Debug, Clone)]
pub struct Frame {
    /// The surface this frame was captured from (must be a permitted surface).
    pub surface: SurfaceId,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Encoded frame bytes (codec negotiated out of band).
    pub data: Vec<u8>,
}

/// A single input event destined for a permitted surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputEvent {
    /// Pointer move/click, in surface-local coordinates.
    Pointer {
        /// X coordinate relative to the target surface's client area.
        x: i32,
        /// Y coordinate relative to the target surface's client area.
        y: i32,
        /// Mouse button bitmask (0 = move only).
        buttons: u8,
    },
    /// Keyboard event (virtual-key code + pressed/released).
    Key {
        /// Platform virtual-key code.
        vk: u32,
        /// True on key-down, false on key-up.
        down: bool,
    },
}

/// Error from a capture attempt.
#[derive(Debug)]
pub enum CaptureError {
    /// The surface vanished (closed/minimised) between authorization and capture.
    SurfaceUnavailable(SurfaceId),
    /// Platform capture API failed.
    Backend(String),
}

/// Error from an input-injection attempt.
#[derive(Debug)]
pub enum InputError {
    /// The surface vanished between authorization and injection.
    SurfaceUnavailable(SurfaceId),
    /// Platform input API failed.
    Backend(String),
}

/// Error from the transport layer.
#[derive(Debug)]
pub enum TransportError {
    /// The secure channel is not established / has dropped.
    NotConnected,
    /// Underlying I/O or crypto failure.
    Backend(String),
}

/// Captures frames from a single permitted surface.
///
/// Implementations MUST NOT capture anything other than the `surface` passed in,
/// and callers MUST gate every call behind
/// [`crate::session::ShareSession::authorize_frame`].
pub trait FrameSource {
    /// Capture one frame from the given (already-authorized) surface.
    fn capture(&mut self, surface: SurfaceId) -> Result<Frame, CaptureError>;
}

/// Injects input into a single permitted surface.
///
/// Implementations MUST clamp the event to the target surface and MUST be gated
/// behind [`crate::session::ShareSession::authorize_input`].
pub trait InputSink {
    /// Inject one input event into the given (already-authorized) surface.
    fn inject(&mut self, surface: SurfaceId, event: &InputEvent) -> Result<(), InputError>;
}

/// The encrypted, authenticated channel to the remote peer.
///
/// In RemoteDexter this is a Noise XX session; the core only needs to know that
/// frames go out and events come in over something already secured.
pub trait Transport {
    /// Send an encoded frame to the peer.
    fn send_frame(&mut self, frame: &Frame) -> Result<(), TransportError>;
    /// Receive the next input event from the peer, if any is ready.
    fn recv_event(&mut self) -> Result<Option<InputEvent>, TransportError>;
}

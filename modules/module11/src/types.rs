//! Types for Module 11: Delta Engine

use thiserror::Error;

#[derive(Clone)]
pub struct RawFrame {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone)]
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub is_keyframe: bool,
    pub rect: Option<DirtyRect>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DirtyRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChromaSubsampling {
    Yuv420,
    Yuv444,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BitratePreset {
    Fast,
    Medium,
    Slow,
    Auto,
    Thermal,
}

#[derive(Clone, Debug)]
pub enum ScreenStreamControl {
    SetBitratePreset(BitratePreset),
    RequestKeyframe,
    Pause,
    Resume,
}

#[derive(Error, Debug)]
pub enum StreamError {
    /// The capture stream ended, or the platform capture returned an error.
    ///
    /// **It says nothing about permission, because nothing that returns it
    /// knows anything about permission.** Until 2026-09-18 its text was
    /// "Platform capture permission denied or failed", and the operator went
    /// looking for a screen-share dialog that did not exist: a portal that
    /// refuses is reported earlier and separately, when the capture is built.
    #[error("screen capture failed: the capture stream stopped or returned an error")]
    CaptureFailed,
    /// The stream is alive and has not sent a picture yet.
    ///
    /// A Wayland screencast is damage-driven: it sends a buffer when something
    /// on screen repaints. A freshly built capture on a still desktop — a host
    /// nobody is sitting at, which is the whole use of remote access — can wait
    /// a long time for its first one. Not a fault.
    #[error("no picture from the screen yet — it sends one when something on it changes")]
    NoFrameYet,
    #[error("CPU Encoding failed")]
    EncodeFailed,
    #[error("Multiplexer backpressure")]
    MuxerCongested,
}
#[cfg(test)]
mod tests {
    use super::*;

    /// **No capture error claims a permission decision**, because nothing that
    /// returns one has made one. "Platform capture permission denied or failed"
    /// sent the operator looking for a screen-share dialog that did not exist
    /// (2026-09-18): the capture had simply had no picture yet.
    #[test]
    fn no_capture_error_claims_a_permission_decision() {
        for e in [
            StreamError::CaptureFailed,
            StreamError::NoFrameYet,
            StreamError::EncodeFailed,
            StreamError::MuxerCongested,
        ] {
            let text = e.to_string().to_lowercase();
            assert!(
                !text.contains("permission") && !text.contains("denied"),
                "{e:?} says {text:?}"
            );
        }
    }

    /// "No picture yet" says what the operator can do about it: nothing is
    /// wrong, the screen sends a picture when something on it changes.
    #[test]
    fn no_picture_yet_says_the_screen_has_not_changed_rather_than_that_it_failed() {
        let text = StreamError::NoFrameYet.to_string();
        assert!(text.contains("changes"), "{text}");
        assert!(!text.contains("fail"), "{text}");
    }
}

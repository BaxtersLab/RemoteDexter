//! A self-contained screen-stream producer for the host's Noise
//! request/response loop.
//!
//! It was described as being "for transports that aren't the multiplexer
//! `FramedStream`" — the alternative to a `ScreenStream` that no longer
//! exists. Block 10 deleted that path, so this is simply how the host
//! streams.
//!
//! Each `next_frame_chunks()` call captures the current screen, decides whether
//! it's a no-change (skip), a delta (dirty sub-rect), or a keyframe (full
//! frame), JPEG-encodes it, and returns wire chunks ready to send. The caller
//! owns the transport and the pacing.

use crate::capture::ScreenCapturer;
use crate::chunk::chunk_frame;
use crate::delta_engine::DeltaEngine;
use crate::encoder::{Encoder, JPEGEncoder};
use crate::types::StreamError;

/// Emit a fresh keyframe at least this often so a client that joined mid-stream
/// (or dropped a delta) resynchronizes.
const KEYFRAME_INTERVAL: u32 = 60;

pub struct StreamPump {
    capturer: ScreenCapturer,
    delta: DeltaEngine,
    encoder: JPEGEncoder,
    width: u32,
    height: u32,
    quality: u8,
    max_chunk_payload: usize,
    seq: u32,
    last_hash: Option<u64>,
    force_keyframe: bool,
}

impl StreamPump {
    /// `quality` 1..=100; `max_chunk_payload` is the frame-data budget per wire
    /// chunk (transport message size minus the chunk header and any AEAD tag).
    pub fn new(quality: u8, max_chunk_payload: usize) -> Self {
        Self::from_capturer(ScreenCapturer::new(1920, 1080), quality, max_chunk_payload)
    }

    /// A pump on the synthetic-fallback capturer. Test-only; see
    /// [`ScreenCapturer::synthetic`] for why the fallback-path tests must not
    /// construct the real backend.
    #[cfg(test)]
    pub(crate) fn synthetic(
        quality: u8,
        max_chunk_payload: usize,
        width: u32,
        height: u32,
    ) -> Self {
        Self::from_capturer(
            ScreenCapturer::synthetic(width, height),
            quality,
            max_chunk_payload,
        )
    }

    fn from_capturer(capturer: ScreenCapturer, quality: u8, max_chunk_payload: usize) -> Self {
        let (width, height) = capturer.dimensions();
        Self {
            capturer,
            delta: DeltaEngine::new(width, height),
            encoder: JPEGEncoder::new(),
            width,
            height,
            quality: quality.clamp(1, 100),
            max_chunk_payload: max_chunk_payload.max(1),
            seq: 0,
            last_hash: None,
            force_keyframe: true,
        }
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub fn is_real(&self) -> bool {
        self.capturer.is_real()
    }

    /// Force the next produced frame to be a full keyframe (e.g. on a client
    /// keyframe request or after a gap).
    pub fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    /// Capture and produce the next frame's wire chunks. Returns an empty vec
    /// when the screen hasn't changed (nothing to send this tick).
    pub fn next_frame_chunks(&mut self) -> Result<Vec<Vec<u8>>, StreamError> {
        let frame = self.capturer.capture()?;

        let hash = fast_hash(&frame.data);
        let unchanged = self.last_hash == Some(hash);
        let keyframe_due = self.force_keyframe || self.seq % KEYFRAME_INTERVAL == 0;

        if unchanged && !keyframe_due {
            return Ok(Vec::new()); // no update
        }
        self.last_hash = Some(hash);

        // Keyframe (full) vs delta (dirty sub-rect). compute_bounding_box
        // returns None both for "no dirt" and "too much dirt (send full)"; on a
        // keyframe-due tick we always send full anyway.
        let rect = if keyframe_due {
            None
        } else {
            self.delta.compute_bounding_box(&frame)
        };

        let encoded = self
            .encoder
            .encode(&frame, self.quality, crate::types::ChromaSubsampling::Yuv420, rect)?;

        self.force_keyframe = false;
        self.seq = self.seq.wrapping_add(1);

        Ok(chunk_frame(
            self.seq,
            self.width.min(u16::MAX as u32) as u16,
            self.height.min(u16::MAX as u32) as u16,
            encoded.is_keyframe,
            &encoded.data,
            self.max_chunk_payload,
        ))
    }
}

fn fast_hash(bytes: &[u8]) -> u64 {
    use ahash::AHasher;
    use std::hash::{Hash, Hasher};
    let mut h = AHasher::default();
    bytes.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::FrameReassembler;

    #[test]
    fn pump_produces_reassemblable_keyframe() {
        // Synthetic backend: the subject here is chunk → reassemble → decode,
        // which does not depend on where the pixels came from, and running it
        // deterministically keeps an ordinary `cargo test` from opening a screen
        // -share portal. The same path against the *real* screen is proven by
        // the RD_USE_HW-gated `tests/live_stream.rs`.
        // Small chunk budget so the frame must span several chunks.
        let mut pump = StreamPump::synthetic(75, 4000, 1920, 1080);
        let (w, h) = pump.dimensions();
        assert!(w > 0 && h > 0);

        let chunks = pump.next_frame_chunks().expect("first frame");
        assert!(!chunks.is_empty(), "first frame must be a keyframe");

        let mut r = FrameReassembler::new();
        let mut frame = None;
        for c in &chunks {
            if let Some(f) = r.push(c) {
                frame = Some(f);
            }
        }
        let f = frame.expect("reassembled");
        assert!(f.keyframe);
        assert_eq!((f.width as u32, f.height as u32), (w, h));
        // Payload is a valid JPEG that decodes to the screen dimensions.
        let img = image::load_from_memory(&f.data).expect("valid jpeg");
        assert_eq!((img.width(), img.height()), (w, h));
    }

    #[test]
    fn static_synthetic_screen_skips_after_keyframe() {
        // The synthetic backend renders the same gradient every tick, so after
        // the initial keyframe a non-keyframe tick has nothing to send.
        //
        // This used to build a real pump and `return` early whenever it was
        // real — so on any machine with a working screen backend it opened a
        // portal and then asserted nothing at all. Requesting the synthetic
        // backend explicitly is what the invariant was always about, and the
        // test now actually runs.
        let mut pump = StreamPump::synthetic(75, 65000, 1920, 1080);
        assert!(
            !pump.is_real(),
            "this invariant is for the synthetic backend"
        );
        let first = pump.next_frame_chunks().unwrap();
        assert!(!first.is_empty());
        // Next tick: unchanged and not keyframe-due -> empty.
        let second = pump.next_frame_chunks().unwrap();
        assert!(second.is_empty());
    }
}

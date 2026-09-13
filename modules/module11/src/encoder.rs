//! Encoder implementations for Module 11.
//!
//! Turns a captured RGBA [`RawFrame`] into a compressed [`EncodedFrame`].
//! `rect = Some(..)` encodes only that dirty sub-rectangle (a delta update);
//! `rect = None` is a full keyframe. Real JPEG (motion-JPEG style, the
//! streaming default) and PNG (lossless) encoders back the `Encoder` trait.

use crate::types::{ChromaSubsampling, DirtyRect, EncodedFrame, RawFrame, StreamError};

pub trait Encoder: Send + Sync {
    fn encode(
        &self,
        frame: &RawFrame,
        quality: u8,
        chroma: ChromaSubsampling,
        rect: Option<DirtyRect>,
    ) -> Result<EncodedFrame, StreamError>;
}

/// Extract the RGB (alpha-dropped) bytes for `rect` (or the whole frame when
/// `None`), returning `(rgb, width, height)`. Out-of-range rects are clamped.
fn rgb_region(frame: &RawFrame, rect: Option<DirtyRect>) -> (Vec<u8>, u32, u32) {
    let (rx, ry, rw, rh) = match rect {
        Some(r) => {
            let x = r.x.min(frame.width);
            let y = r.y.min(frame.height);
            let w = r.w.min(frame.width - x);
            let h = r.h.min(frame.height - y);
            (x, y, w.max(1), h.max(1))
        }
        None => (0, 0, frame.width, frame.height),
    };
    let stride = (frame.width * 4) as usize;
    let mut rgb = Vec::with_capacity((rw * rh * 3) as usize);
    for row in 0..rh {
        let sy = (ry + row) as usize;
        let base = sy * stride + (rx * 4) as usize;
        for col in 0..rw {
            let p = base + (col * 4) as usize;
            rgb.push(frame.data[p]); // R
            rgb.push(frame.data[p + 1]); // G
            rgb.push(frame.data[p + 2]); // B
        }
    }
    (rgb, rw, rh)
}

/// Motion-JPEG-style encoder. `quality` (1..=100) is honored; `chroma` is
/// advisory (JPEG carries its own subsampling — 4:2:0 at lower quality).
pub struct JPEGEncoder;

impl JPEGEncoder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JPEGEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for JPEGEncoder {
    fn encode(
        &self,
        frame: &RawFrame,
        quality: u8,
        _chroma: ChromaSubsampling,
        rect: Option<DirtyRect>,
    ) -> Result<EncodedFrame, StreamError> {
        let (rgb, w, h) = rgb_region(frame, rect);
        let mut out = std::io::Cursor::new(Vec::new());
        let q = quality.clamp(1, 100);
        let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, q);
        enc.encode(&rgb, w, h, image::ExtendedColorType::Rgb8)
            .map_err(|_| StreamError::EncodeFailed)?;
        Ok(EncodedFrame {
            data: out.into_inner(),
            is_keyframe: rect.is_none(),
            rect,
        })
    }
}

/// Lossless PNG encoder (RGB). Larger output; useful for exact keyframes.
pub struct PngEncoder;

impl PngEncoder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PngEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for PngEncoder {
    fn encode(
        &self,
        frame: &RawFrame,
        _quality: u8,
        _chroma: ChromaSubsampling,
        rect: Option<DirtyRect>,
    ) -> Result<EncodedFrame, StreamError> {
        let (rgb, w, h) = rgb_region(frame, rect);
        let mut out = std::io::Cursor::new(Vec::new());
        let enc = image::codecs::png::PngEncoder::new(&mut out);
        use image::ImageEncoder;
        enc.write_image(&rgb, w, h, image::ExtendedColorType::Rgb8)
            .map_err(|_| StreamError::EncodeFailed)?;
        Ok(EncodedFrame {
            data: out.into_inner(),
            is_keyframe: rect.is_none(),
            rect,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::synthetic_frame;

    fn decode_dims(bytes: &[u8]) -> (u32, u32) {
        let img = image::load_from_memory(bytes).expect("decode");
        (img.width(), img.height())
    }

    #[test]
    fn jpeg_full_frame_is_valid_and_smaller() {
        let frame = synthetic_frame(320, 240);
        let enc = JPEGEncoder::new()
            .encode(&frame, 80, ChromaSubsampling::Yuv420, None)
            .unwrap();
        assert!(enc.is_keyframe);
        assert!(!enc.data.is_empty());
        // JPEG magic
        assert_eq!(&enc.data[0..2], &[0xFF, 0xD8]);
        assert_eq!(decode_dims(&enc.data), (320, 240));
        // compressed smaller than raw RGBA
        assert!(enc.data.len() < frame.data.len());
    }

    #[test]
    fn jpeg_dirty_rect_encodes_subregion() {
        let frame = synthetic_frame(320, 240);
        let rect = DirtyRect { x: 32, y: 16, w: 64, h: 48 };
        let enc = JPEGEncoder::new()
            .encode(&frame, 80, ChromaSubsampling::Yuv420, Some(rect))
            .unwrap();
        assert!(!enc.is_keyframe);
        assert_eq!(enc.rect, Some(rect));
        assert_eq!(decode_dims(&enc.data), (64, 48));
    }

    #[test]
    fn png_roundtrips_dimensions() {
        let frame = synthetic_frame(100, 50);
        let enc = PngEncoder::new()
            .encode(&frame, 0, ChromaSubsampling::Yuv444, None)
            .unwrap();
        assert_eq!(&enc.data[1..4], b"PNG");
        assert_eq!(decode_dims(&enc.data), (100, 50));
    }

    #[test]
    fn quality_affects_size() {
        let frame = synthetic_frame(256, 256);
        let lo = JPEGEncoder::new()
            .encode(&frame, 20, ChromaSubsampling::Yuv420, None)
            .unwrap();
        let hi = JPEGEncoder::new()
            .encode(&frame, 95, ChromaSubsampling::Yuv420, None)
            .unwrap();
        assert!(lo.data.len() < hi.data.len(), "lower quality should be smaller");
    }
}

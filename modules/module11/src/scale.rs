//! Downscale a captured RGBA frame before encoding.
//!
//! The adaptive ladder (`host_app::stream_ladder`) trades frame rate and JPEG
//! quality for bitrate, but its floor still sends FULL-RESOLUTION frames — on a
//! ~1.8 Mbit/s uplink that is ~224 KB at 3 fps, so the link drops two frames of
//! three indefinitely (measured on a real phone session, 2026-09-21). The rung
//! below the quality floor is fewer PIXELS: a smaller frame at the same quality
//! is a large, cheap win because JPEG cost scales with pixel count.
//!
//! This is the pixel knob, kept pure — no capture, no encoder, no clock, the
//! same shape as `encoder` and `stream_ladder`. `host_app` downscales the raw
//! frame here when the current rung asks for it, then encodes and chunks the
//! SMALLER dimensions onto the wire. The phone requires the declared header
//! size to equal the decoded JPEG size (`FrameReceiver.kt` drops any frame
//! where they differ) and already treats a mid-stream size change as a
//! first-class event (`FrameGeometryChange`), so a downscaled keyframe needs no
//! protocol change: input is sent normalized 0..65535 and the host maps it to
//! the real screen, so fewer pixels on the wire never move a tap.

use crate::types::RawFrame;

/// Scale `frame` down to `scale_pct` percent of each dimension, so the pixel
/// count falls as the square of the percentage.
///
/// `scale_pct >= 100` returns the frame unchanged (the ladder's full-resolution
/// rungs). The result keeps RGBA (4 bytes per pixel), preserves the aspect
/// ratio to integer rounding, and is never smaller than 1x1 — a zero dimension
/// is an un-encodable, un-decodable frame, and the phone drops any frame whose
/// declared size is implausible.
///
/// A malformed buffer (length not `width*height*4`) cannot happen for a frame
/// from capture; if one ever did, this returns it unchanged rather than
/// panicking the live stream thread.
pub fn downscale_rgba(frame: &RawFrame, scale_pct: u16) -> RawFrame {
    if scale_pct >= 100 || frame.width == 0 || frame.height == 0 {
        return frame.clone();
    }
    let pct = scale_pct.max(1) as u64;
    let nw = ((frame.width as u64 * pct) / 100).max(1) as u32;
    let nh = ((frame.height as u64 * pct) / 100).max(1) as u32;
    // Rounding can land on the original size (e.g. a 1px edge); skip the resize.
    if (nw, nh) == (frame.width, frame.height) {
        return frame.clone();
    }
    // A frame from capture is always width*height*4. If one ever is not, return
    // it unchanged rather than panic the live stream thread.
    let src = match image::RgbaImage::from_raw(frame.width, frame.height, frame.data.clone()) {
        Some(img) => img,
        None => return frame.clone(),
    };
    // Triangle (bilinear): a good quality/CPU trade for downscaling screen
    // content on the host while it is already streaming. Nearest aliases text
    // badly; Lanczos3 is sharper but costs more CPU per frame.
    let dst = image::imageops::resize(&src, nw, nh, image::imageops::FilterType::Triangle);
    RawFrame {
        width: nw,
        height: nh,
        data: dst.into_raw(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::synthetic_frame;
    use crate::encoder::{Encoder, JPEGEncoder};
    use crate::types::ChromaSubsampling;

    #[test]
    fn downscale_halves_dimensions() {
        let f = synthetic_frame(1920, 1080);
        let out = downscale_rgba(&f, 50);
        assert_eq!((out.width, out.height), (960, 540));
    }

    #[test]
    fn output_is_rgba_four_bytes_per_pixel() {
        let out = downscale_rgba(&synthetic_frame(1920, 1080), 40);
        assert_eq!(
            out.data.len(),
            (out.width * out.height * 4) as usize,
            "a downscaled frame must still be width*height*4 RGBA"
        );
    }

    #[test]
    fn downscale_preserves_aspect_ratio() {
        // 16:9 at 40% stays 16:9 exactly (1920*0.4=768, 1080*0.4=432).
        let out = downscale_rgba(&synthetic_frame(1920, 1080), 40);
        assert_eq!((out.width, out.height), (768, 432));
        assert_eq!(out.width * 1080, out.height * 1920, "aspect ratio drifted");
    }

    #[test]
    fn full_scale_is_identity() {
        let f = synthetic_frame(640, 480);
        let out = downscale_rgba(&f, 100);
        assert_eq!((out.width, out.height), (640, 480));
        assert_eq!(out.data, f.data, "100% must not touch the pixels");
    }

    #[test]
    fn over_100_does_not_upscale() {
        let out = downscale_rgba(&synthetic_frame(640, 480), 150);
        assert_eq!((out.width, out.height), (640, 480));
    }

    #[test]
    fn never_produces_a_zero_dimension() {
        // A tiny frame at an aggressive scale must floor at 1, not round to 0.
        let out = downscale_rgba(&synthetic_frame(3, 3), 10);
        assert!(
            out.width >= 1 && out.height >= 1,
            "{}x{}",
            out.width,
            out.height
        );
        assert_eq!(out.data.len(), (out.width * out.height * 4) as usize);
    }

    #[test]
    fn a_downscaled_frame_encodes_to_fewer_bytes() {
        // The whole point: fewer pixels is fewer JPEG bytes at the same quality.
        let f = synthetic_frame(1280, 720);
        let enc = JPEGEncoder::new();
        let full = enc.encode(&f, 50, ChromaSubsampling::Yuv420, None).unwrap();
        let half = enc
            .encode(&downscale_rgba(&f, 50), 50, ChromaSubsampling::Yuv420, None)
            .unwrap();
        assert!(
            half.data.len() < full.data.len(),
            "downscaled {} must be smaller than full {}",
            half.data.len(),
            full.data.len()
        );
    }

    #[test]
    fn a_downscaled_frame_is_self_describing_on_the_wire() {
        // The phone drops any frame whose declared header size differs from the
        // decoded JPEG size (FrameReceiver.kt). So a downscaled frame must carry
        // its DOWNSCALED dimensions on the wire, not the screen's. Prove the
        // whole host path agrees: downscale -> encode -> chunk_frame(scaled
        // dims) -> reassemble, and every size matches what the phone will check.
        use crate::chunk::{chunk_frame, FrameReassembler};
        let screen = synthetic_frame(1920, 1080);
        let scaled = downscale_rgba(&screen, 50);
        assert_eq!((scaled.width, scaled.height), (960, 540));
        let enc = JPEGEncoder::new()
            .encode(&scaled, 50, ChromaSubsampling::Yuv420, None)
            .unwrap();
        assert!(enc.is_keyframe, "a downscaled rung sends full keyframes");
        let chunks = chunk_frame(
            1,
            scaled.width as u16,
            scaled.height as u16,
            enc.is_keyframe,
            &enc.data,
            4000,
        );
        let mut r = FrameReassembler::new();
        let mut frame = None;
        for c in &chunks {
            if let Some(f) = r.push(c) {
                frame = Some(f);
            }
        }
        let f = frame.expect("reassembled");
        // The declared dims on the wire are the downscaled dims...
        assert_eq!((f.width as u32, f.height as u32), (960, 540));
        // ...and the JPEG decodes to exactly those — the equality the phone
        // enforces before it will draw a frame.
        let img = image::load_from_memory(&f.data).expect("valid jpeg");
        assert_eq!((img.width(), img.height()), (960, 540));
    }

    /// Evidence, not a gate assertion: encode a representative desktop frame at
    /// each candidate rung and print bytes + the bitrate it implies at that
    /// rung's frame rate. Run against the in-repo console screenshot:
    ///
    ///   RD_MEASURE_IMAGE=docs/deb-e2e-console-fa26816.png \
    ///     cargo test -p module11 measure_rung_bitrates -- --ignored --nocapture
    #[test]
    #[ignore = "measurement; needs RD_MEASURE_IMAGE and prints a table"]
    fn measure_rung_bitrates() {
        let path = std::env::var("RD_MEASURE_IMAGE")
            .expect("set RD_MEASURE_IMAGE to a representative image (absolute path)");
        let src = image::open(&path).expect("open image").to_rgba8();
        // Tile the sample up to a real screen size so the absolute bitrate is
        // meaningful, keeping sharp text edges (upscaling would blur them and
        // understate JPEG cost). Override with RD_MEASURE_W / RD_MEASURE_H.
        let tw: u32 = std::env::var("RD_MEASURE_W")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1920);
        let th: u32 = std::env::var("RD_MEASURE_H")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1080);
        let (sw, sh) = (src.width(), src.height());
        let mut data = vec![0u8; (tw * th * 4) as usize];
        for y in 0..th {
            for x in 0..tw {
                let p = src.get_pixel(x % sw, y % sh).0;
                let o = ((y * tw + x) * 4) as usize;
                data[o..o + 4].copy_from_slice(&p);
            }
        }
        let (w, h) = (tw, th);
        let frame = RawFrame {
            width: w,
            height: h,
            data,
        };
        let enc = JPEGEncoder::new();
        let mut full_bytes = 0usize;
        // (scale_pct, quality, frame_interval_ms) candidates, richest first.
        let candidates = [
            (100u16, 50u8, 333u64),
            (75, 50, 333),
            (67, 50, 333),
            (50, 50, 333),
            (50, 45, 333),
            (40, 45, 333),
            (33, 40, 333),
        ];
        eprintln!("tiled to {w}x{h} from {sw}x{sh}  ({path})");
        eprintln!("scale%  q   fps    bytes  kbit/s  vs-full   dims");
        for (s, q, ms) in candidates {
            let scaled = downscale_rgba(&frame, s);
            let bytes = enc
                .encode(&scaled, q, ChromaSubsampling::Yuv420, None)
                .unwrap()
                .data
                .len();
            if full_bytes == 0 {
                full_bytes = bytes;
            }
            let fps = 1000.0 / ms as f64;
            let kbits = (bytes as f64 * 8.0 * fps) / 1000.0;
            let ratio = bytes as f64 / full_bytes as f64;
            eprintln!(
                "{s:>5}  {q:>2}  {fps:>4.1}  {bytes:>7}  {kbits:>6.0}  {ratio:>6.2}  {}x{}",
                scaled.width, scaled.height
            );
        }
    }
}

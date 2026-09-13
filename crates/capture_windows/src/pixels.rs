//! Pixel plumbing, with no Windows types in sight.
//!
//! Everything here is ordinary Rust over ordinary slices, on purpose. The DXGI
//! and GDI modules are unsafe FFI that only a Windows machine can execute; this
//! module is where the arithmetic that actually corrupts images lives — stride
//! handling, channel order, rotation — and it is fully testable on any platform,
//! including the Linux box this is written on.
//!
//! That split is the point. "The screen is white" is not usually a DXGI bug. It
//! is usually a stride treated as a width, a BGRA buffer read as RGBA, or a
//! rotation applied to the wrong axis — and every one of those is provable here
//! without a GPU.

/// BGRA and RGBA are both four bytes per pixel. Named because a bare `4`
/// scattered through index arithmetic is how stride bugs hide.
pub const BYTES_PER_PIXEL: usize = 4;

/// What can go wrong turning a mapped surface into a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PixelError {
    /// A zero-width or zero-height frame. Never a valid capture.
    ZeroDimension { width: u32, height: u32 },
    /// The row stride is smaller than one row of pixels. Physically impossible;
    /// means the value came from the wrong field.
    StrideTooSmall { stride: usize, needed: usize },
    /// The source buffer cannot hold the frame it claims to describe.
    SourceTooSmall { have: usize, need: usize },
    /// Dimensions that overflow `usize` when multiplied out.
    Overflow { width: u32, height: u32 },
}

impl std::fmt::Display for PixelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PixelError::ZeroDimension { width, height } => {
                write!(f, "capture reported a {width}x{height} frame")
            }
            PixelError::StrideTooSmall { stride, needed } => {
                write!(
                    f,
                    "row stride {stride} is smaller than one row ({needed} bytes)"
                )
            }
            PixelError::SourceTooSmall { have, need } => {
                write!(f, "mapped surface holds {have} bytes, frame needs {need}")
            }
            PixelError::Overflow { width, height } => {
                write!(
                    f,
                    "{width}x{height} overflows this platform's address space"
                )
            }
        }
    }
}

impl std::error::Error for PixelError {}

/// Bytes in one tightly packed frame, or `Overflow`.
fn packed_len(width: u32, height: u32) -> Result<usize, PixelError> {
    (width as usize)
        .checked_mul(height as usize)
        .and_then(|px| px.checked_mul(BYTES_PER_PIXEL))
        .ok_or(PixelError::Overflow { width, height })
}

/// Convert a **strided** BGRA surface into a **tightly packed** RGBA frame.
///
/// DXGI hands back a mapped rectangle with a `Pitch` that is frequently larger
/// than `width * 4` — the driver pads rows to a hardware alignment. Copying
/// `width * height * 4` bytes straight out of that buffer produces the diagonal
/// smear everyone recognises, and reading it as RGBA produces a blue-orange
/// image. Both are avoided here, once, rather than at each call site.
///
/// The last row is allowed to be short: a mapped surface is only guaranteed to
/// contain padding *between* rows, not after the final one.
pub fn bgra_to_rgba(
    src: &[u8],
    stride: usize,
    width: u32,
    height: u32,
) -> Result<Vec<u8>, PixelError> {
    if width == 0 || height == 0 {
        return Err(PixelError::ZeroDimension { width, height });
    }
    let row_bytes = (width as usize)
        .checked_mul(BYTES_PER_PIXEL)
        .ok_or(PixelError::Overflow { width, height })?;
    if stride < row_bytes {
        return Err(PixelError::StrideTooSmall {
            stride,
            needed: row_bytes,
        });
    }
    // Rows before the last need their full stride; the last needs only pixels.
    let need = stride
        .checked_mul(height as usize - 1)
        .and_then(|n| n.checked_add(row_bytes))
        .ok_or(PixelError::Overflow { width, height })?;
    if src.len() < need {
        return Err(PixelError::SourceTooSmall {
            have: src.len(),
            need,
        });
    }

    let mut out = vec![0u8; packed_len(width, height)?];
    for y in 0..height as usize {
        let s = y * stride;
        let d = y * row_bytes;
        let src_row = &src[s..s + row_bytes];
        let dst_row = &mut out[d..d + row_bytes];
        for (px_in, px_out) in src_row
            .chunks_exact(BYTES_PER_PIXEL)
            .zip(dst_row.chunks_exact_mut(BYTES_PER_PIXEL))
        {
            // B,G,R,A -> R,G,B,A. Alpha is forced opaque: the desktop
            // duplication surface carries per-window alpha that means nothing
            // once composited, and a viewer that honours it renders holes.
            px_out[0] = px_in[2];
            px_out[1] = px_in[1];
            px_out[2] = px_in[0];
            px_out[3] = 0xFF;
        }
    }
    Ok(out)
}

/// How the display is physically turned, as DXGI reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rotation {
    #[default]
    Identity,
    /// Display rotated 90° clockwise.
    Clockwise90,
    Clockwise180,
    Clockwise270,
}

impl Rotation {
    /// Map a `DXGI_MODE_ROTATION` value.
    ///
    /// `UNSPECIFIED` (0) and `IDENTITY` (1) both mean "not rotated"; anything
    /// unknown is treated as not rotated rather than guessed at, because a
    /// wrong guess silently transposes the whole desktop.
    ///
    /// The numbers are **not** sequential in the obvious way, and writing them
    /// from memory gets them wrong: `ROTATE90` is 2, `ROTATE180` is 3,
    /// `ROTATE270` is 4. The first draft of this function used 3/4/5 and its
    /// test asserted 3/4/5 too — the test was written from the same bad
    /// assumption as the code, so it agreed with the bug. `rotation_constants`
    /// below is compiled on Windows against the real `windows` crate constants
    /// so the mapping cannot drift again on anybody's memory.
    pub const fn from_dxgi(raw: i32) -> Rotation {
        match raw {
            2 => Rotation::Clockwise90,
            3 => Rotation::Clockwise180,
            4 => Rotation::Clockwise270,
            _ => Rotation::Identity,
        }
    }

    /// Output dimensions after applying this rotation to a `w x h` frame.
    pub fn apply_to_dimensions(self, width: u32, height: u32) -> (u32, u32) {
        match self {
            Rotation::Identity | Rotation::Clockwise180 => (width, height),
            Rotation::Clockwise90 | Rotation::Clockwise270 => (height, width),
        }
    }
}

/// The anchor for [`Rotation::from_dxgi`].
///
/// This is a **compile-time** assertion, not a test, and that is the point: it
/// is evaluated whenever the crate is type-checked for Windows, including by
/// `cargo check --target x86_64-pc-windows-gnu` on the Linux build box. So the
/// mapping is proven against the `windows` crate's own constants without a
/// Windows machine, and a wrong number is a build failure rather than a
/// silently transposed desktop.
///
/// The first draft of `from_dxgi` used 3/4/5 instead of 2/3/4, and the unit
/// test asserted the same wrong values because it was written from the same
/// memory. Nothing that reads like documentation can catch that; only the real
/// constants can.
#[cfg(windows)]
const _: () = {
    use windows::Win32::Graphics::Dxgi::Common::{
        DXGI_MODE_ROTATION_IDENTITY, DXGI_MODE_ROTATION_ROTATE180, DXGI_MODE_ROTATION_ROTATE270,
        DXGI_MODE_ROTATION_ROTATE90, DXGI_MODE_ROTATION_UNSPECIFIED,
    };
    assert!(matches!(
        Rotation::from_dxgi(DXGI_MODE_ROTATION_UNSPECIFIED.0),
        Rotation::Identity
    ));
    assert!(matches!(
        Rotation::from_dxgi(DXGI_MODE_ROTATION_IDENTITY.0),
        Rotation::Identity
    ));
    assert!(matches!(
        Rotation::from_dxgi(DXGI_MODE_ROTATION_ROTATE90.0),
        Rotation::Clockwise90
    ));
    assert!(matches!(
        Rotation::from_dxgi(DXGI_MODE_ROTATION_ROTATE180.0),
        Rotation::Clockwise180
    ));
    assert!(matches!(
        Rotation::from_dxgi(DXGI_MODE_ROTATION_ROTATE270.0),
        Rotation::Clockwise270
    ));
};

/// The turn that puts a **duplicated DXGI surface** the right way up.
///
/// Desktop Duplication hands back the surface in the unrotated orientation of
/// the physical panel and reports how the desktop is turned on top of it. The
/// correction is therefore the turn that *undoes* the display's rotation, not
/// the display's rotation itself: applying the rotation directly turns the
/// frame the wrong way, which on a portrait display looks like a picture
/// rotated 180 degrees away from where it belongs.
///
/// Observed on the Windows box on 2026-08-25 with a real 90-degree rotation:
/// the streamed image turned the opposite way to the desktop.
pub fn correction_for(display_rotation: Rotation) -> Rotation {
    match display_rotation {
        Rotation::Identity => Rotation::Identity,
        Rotation::Clockwise90 => Rotation::Clockwise270,
        Rotation::Clockwise180 => Rotation::Clockwise180,
        Rotation::Clockwise270 => Rotation::Clockwise90,
    }
}

/// The turn a **GDI desktop BitBlt** needs, which is none.
///
/// `CreateDCW("DISPLAY")` hands back the desktop exactly as the user sees it —
/// a rotated display is already upright in that DC, at its logical width and
/// height. Unlike a duplicated DXGI surface there is nothing to undo, so the
/// only correct turn is the identity one. Applying the display's rotation here
/// takes an upright capture and lays it on its side.
///
/// Observed on the Windows box on 2026-08-26: with the desktop rotated 90
/// degrees and the GDI fallback engaged, the captured frame came back turned,
/// with the taskbar down the left edge and text reading bottom-to-top. At
/// `Identity` the same bug is invisible, because turning by identity is a
/// no-op — which is why the first Windows trip could not see it.
pub fn gdi_correction_for(display_rotation: Rotation) -> Rotation {
    let _ = display_rotation;
    Rotation::Identity
}

/// Rotate a tightly packed RGBA frame, returning the frame and its new size.
///
/// `Identity` returns the input untouched rather than copying it — the common
/// case must not pay for the rare one.
pub fn rotate(
    frame: Vec<u8>,
    width: u32,
    height: u32,
    rotation: Rotation,
) -> Result<(Vec<u8>, u32, u32), PixelError> {
    if rotation == Rotation::Identity {
        return Ok((frame, width, height));
    }
    let need = packed_len(width, height)?;
    if frame.len() < need {
        return Err(PixelError::SourceTooSmall {
            have: frame.len(),
            need,
        });
    }
    let (w, h) = (width as usize, height as usize);
    let (out_w, out_h) = rotation.apply_to_dimensions(width, height);
    let mut out = vec![0u8; need];
    let ow = out_w as usize;
    for y in 0..h {
        for x in 0..w {
            let (nx, ny) = match rotation {
                // Source (x, y) lands at (h-1-y, x) when the image is turned
                // a quarter turn clockwise.
                Rotation::Clockwise90 => (h - 1 - y, x),
                Rotation::Clockwise180 => (w - 1 - x, h - 1 - y),
                Rotation::Clockwise270 => (y, w - 1 - x),
                Rotation::Identity => unreachable!("handled above"),
            };
            let si = (y * w + x) * BYTES_PER_PIXEL;
            let di = (ny * ow + nx) * BYTES_PER_PIXEL;
            out[di..di + BYTES_PER_PIXEL].copy_from_slice(&frame[si..si + BYTES_PER_PIXEL]);
        }
    }
    Ok((out, out_w, out_h))
}

/// Is every pixel in this frame the same colour?
///
/// This is the white-screen detector, and it is deliberately a question about
/// the frame rather than about the API that produced it. A capture backend that
/// returns success while handing back a uniform buffer has failed, whatever its
/// return code said — and that is precisely the failure Block 8 exists to
/// diagnose.
///
/// An empty or partial frame is not uniform; it is malformed, and callers get
/// `false` so they do not report a fault with the wrong name.
/// Alpha-blend a small RGBA sprite over a frame, in place.
///
/// This exists to draw the mouse pointer into Windows captures. **Neither
/// Windows backend includes it:** Desktop Duplication delivers the pointer as
/// separate metadata and never draws it, and a GDI `BitBlt` of the screen DC
/// does not pick it up either. Linux composites the cursor by default and calls
/// that a requirement — *"a remote-desktop viewer needs to see the pointer"* —
/// so until this existed the two platforms disagreed about it, and the operator
/// could not aim a click they could not see.
///
/// Source-over compositing: `dst = src*a + dst*(1-a)`.
///
/// **The clipping is the whole difficulty and the reason this is here rather
/// than next to the Win32 calls.** A cursor is drawn from its hotspot, so
/// `at_x`/`at_y` are routinely NEGATIVE — the pointer at the top-left corner of
/// the screen has most of its bitmap off-screen — and it is just as routinely
/// hanging off the right and bottom edges. Getting that wrong reads or writes
/// outside the frame, or wraps the sprite onto the far side of the image. All
/// of it is arithmetic, none of it needs a display, so it is tested on every
/// platform.
///
/// A sprite entirely off-frame is not an error; it draws nothing.
pub fn blend_over(
    frame: &mut [u8],
    frame_w: u32,
    frame_h: u32,
    sprite: &[u8],
    sprite_w: u32,
    sprite_h: u32,
    at_x: i32,
    at_y: i32,
) -> Result<(), PixelError> {
    if frame_w == 0 || frame_h == 0 {
        return Err(PixelError::ZeroDimension {
            width: frame_w,
            height: frame_h,
        });
    }
    let need = (frame_w as usize)
        .checked_mul(frame_h as usize)
        .and_then(|n| n.checked_mul(BYTES_PER_PIXEL))
        .ok_or(PixelError::Overflow {
            width: frame_w,
            height: frame_h,
        })?;
    if frame.len() < need {
        return Err(PixelError::SourceTooSmall {
            have: frame.len(),
            need,
        });
    }
    // A zero-sized sprite is nothing to draw, not a malformed one.
    if sprite_w == 0 || sprite_h == 0 {
        return Ok(());
    }
    let sprite_need = (sprite_w as usize)
        .checked_mul(sprite_h as usize)
        .and_then(|n| n.checked_mul(BYTES_PER_PIXEL))
        .ok_or(PixelError::Overflow {
            width: sprite_w,
            height: sprite_h,
        })?;
    if sprite.len() < sprite_need {
        return Err(PixelError::SourceTooSmall {
            have: sprite.len(),
            need: sprite_need,
        });
    }

    for sy in 0..sprite_h {
        let dy = at_y + sy as i32;
        if dy < 0 || dy >= frame_h as i32 {
            continue;
        }
        for sx in 0..sprite_w {
            let dx = at_x + sx as i32;
            if dx < 0 || dx >= frame_w as i32 {
                continue;
            }
            let si = (sy as usize * sprite_w as usize + sx as usize) * BYTES_PER_PIXEL;
            let alpha = sprite[si + 3] as u32;
            if alpha == 0 {
                continue;
            }
            let di = (dy as usize * frame_w as usize + dx as usize) * BYTES_PER_PIXEL;
            if alpha == 255 {
                frame[di..di + 3].copy_from_slice(&sprite[si..si + 3]);
                continue;
            }
            let inv = 255 - alpha;
            for c in 0..3 {
                // +127 rounds to nearest rather than truncating, so a run of
                // blends over the same pixel does not drift toward black.
                let v = sprite[si + c] as u32 * alpha + frame[di + c] as u32 * inv;
                frame[di + c] = ((v + 127) / 255) as u8;
            }
        }
    }
    Ok(())
}

pub fn is_uniform(frame: &[u8]) -> bool {
    if frame.len() < BYTES_PER_PIXEL || frame.len() % BYTES_PER_PIXEL != 0 {
        return false;
    }
    let first = &frame[..BYTES_PER_PIXEL];
    frame.chunks_exact(BYTES_PER_PIXEL).all(|px| px == first)
}

/// How many distinct pixel values a frame contains, counting no further than
/// `cap`. Used by `windows-frame-probe` to say something more useful than
/// "uniform: false" — a desktop has thousands of distinct values, a broken
/// capture has one or two.
pub fn distinct_pixels(frame: &[u8], cap: usize) -> usize {
    let mut seen: Vec<[u8; BYTES_PER_PIXEL]> = Vec::new();
    for px in frame.chunks_exact(BYTES_PER_PIXEL) {
        let key: [u8; BYTES_PER_PIXEL] = [px[0], px[1], px[2], px[3]];
        if !seen.contains(&key) {
            seen.push(key);
            if seen.len() >= cap {
                break;
            }
        }
    }
    seen.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One pixel, so the channel order is unmistakable: B=1, G=2, R=3.
    #[test]
    fn bgra_becomes_rgba_and_alpha_is_forced_opaque() {
        let src = [1u8, 2, 3, 0x00];
        let out = bgra_to_rgba(&src, 4, 1, 1).unwrap();
        assert_eq!(out, vec![3, 2, 1, 0xFF], "R,G,B,A with alpha forced opaque");
    }

    /// The bug this module exists for. A 2x2 frame in a buffer whose rows are
    /// padded to 12 bytes: reading it as 16 contiguous bytes walks the padding
    /// into the image.
    #[test]
    fn padded_rows_are_not_copied_into_the_image() {
        let stride = 12;
        let mut src = vec![0xEEu8; stride * 2];
        // row 0: two pixels, then padding
        src[0..4].copy_from_slice(&[10, 20, 30, 0]);
        src[4..8].copy_from_slice(&[11, 21, 31, 0]);
        // row 1
        src[stride..stride + 4].copy_from_slice(&[12, 22, 32, 0]);
        src[stride + 4..stride + 8].copy_from_slice(&[13, 23, 33, 0]);

        let out = bgra_to_rgba(&src, stride, 2, 2).unwrap();
        assert_eq!(out.len(), 16, "output must be tightly packed");
        assert_eq!(&out[0..4], &[30, 20, 10, 255]);
        assert_eq!(&out[4..8], &[31, 21, 11, 255]);
        assert_eq!(&out[8..12], &[32, 22, 12, 255]);
        assert_eq!(&out[12..16], &[33, 23, 13, 255]);
        assert!(
            !out.contains(&0xEE),
            "padding bytes leaked into the image: {out:?}"
        );
    }

    /// A mapped surface is only guaranteed to pad BETWEEN rows. Requiring
    /// `stride * height` bytes rejects perfectly good final rows.
    #[test]
    fn a_short_final_row_is_accepted() {
        let stride = 12;
        let mut src = vec![0u8; stride + 8]; // one full row + 2 pixels
        src[stride..stride + 4].copy_from_slice(&[1, 2, 3, 0]);
        assert!(bgra_to_rgba(&src, stride, 2, 2).is_ok());
    }

    #[test]
    fn a_stride_smaller_than_a_row_is_refused() {
        let src = vec![0u8; 64];
        assert_eq!(
            bgra_to_rgba(&src, 4, 2, 2),
            Err(PixelError::StrideTooSmall {
                stride: 4,
                needed: 8
            })
        );
    }

    #[test]
    fn a_truncated_surface_is_refused_rather_than_read_past() {
        let src = vec![0u8; 8];
        assert!(matches!(
            bgra_to_rgba(&src, 8, 2, 2),
            Err(PixelError::SourceTooSmall { .. })
        ));
    }

    #[test]
    fn zero_dimensions_are_refused() {
        let src = vec![0u8; 16];
        assert!(matches!(
            bgra_to_rgba(&src, 8, 0, 2),
            Err(PixelError::ZeroDimension { .. })
        ));
        assert!(matches!(
            bgra_to_rgba(&src, 8, 2, 0),
            Err(PixelError::ZeroDimension { .. })
        ));
    }

    /// The literals here are transcribed from
    /// `windows-0.58.0/.../Graphics/Dxgi/Common/mod.rs`:
    /// UNSPECIFIED 0, IDENTITY 1, ROTATE90 **2**, ROTATE180 **3**, ROTATE270 **4**.
    /// On Windows the same mapping is checked against the crate's own constants
    /// by `rotation_constants_match_the_windows_crate`, so this test documents
    /// the values and that one proves them.
    #[test]
    fn dxgi_rotation_values_map_to_the_documented_quarter_turns() {
        assert_eq!(Rotation::from_dxgi(0), Rotation::Identity, "UNSPECIFIED");
        assert_eq!(Rotation::from_dxgi(1), Rotation::Identity, "IDENTITY");
        assert_eq!(Rotation::from_dxgi(2), Rotation::Clockwise90, "ROTATE90");
        assert_eq!(Rotation::from_dxgi(3), Rotation::Clockwise180, "ROTATE180");
        assert_eq!(Rotation::from_dxgi(4), Rotation::Clockwise270, "ROTATE270");
        // An unknown value must not be guessed at.
        assert_eq!(Rotation::from_dxgi(99), Rotation::Identity);
        assert_eq!(Rotation::from_dxgi(-1), Rotation::Identity);
        assert_eq!(Rotation::from_dxgi(5), Rotation::Identity);
    }

    #[test]
    fn a_quarter_turn_swaps_the_dimensions_and_a_half_turn_does_not() {
        assert_eq!(
            Rotation::Identity.apply_to_dimensions(1920, 1080),
            (1920, 1080)
        );
        assert_eq!(
            Rotation::Clockwise180.apply_to_dimensions(1920, 1080),
            (1920, 1080)
        );
        assert_eq!(
            Rotation::Clockwise90.apply_to_dimensions(1920, 1080),
            (1080, 1920)
        );
        assert_eq!(
            Rotation::Clockwise270.apply_to_dimensions(1920, 1080),
            (1080, 1920)
        );
    }

    /// A 2x1 frame: pixel A at (0,0), pixel B at (1,0). Turned a quarter turn
    /// clockwise it becomes 1x2 with A on top.
    #[test]
    fn a_clockwise_quarter_turn_moves_pixels_where_the_eye_expects() {
        let a = [1u8, 1, 1, 255];
        let b = [2u8, 2, 2, 255];
        let frame: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
        let (out, w, h) = rotate(frame, 2, 1, Rotation::Clockwise90).unwrap();
        assert_eq!((w, h), (1, 2));
        assert_eq!(&out[0..4], &a, "the left pixel ends up on top");
        assert_eq!(&out[4..8], &b);
    }

    #[test]
    fn four_quarter_turns_return_the_original_image() {
        let w = 3u32;
        let h = 5u32;
        let original: Vec<u8> = (0..(w * h * 4) as u8).collect();
        let (mut f, mut cw, mut ch) = (original.clone(), w, h);
        for _ in 0..4 {
            let r = rotate(f, cw, ch, Rotation::Clockwise90).unwrap();
            f = r.0;
            cw = r.1;
            ch = r.2;
        }
        assert_eq!((cw, ch), (w, h));
        assert_eq!(f, original, "four quarter turns must be the identity");
    }

    #[test]
    fn identity_rotation_does_not_copy_or_alter_the_frame() {
        let frame = vec![7u8; 4 * 4];
        let (out, w, h) = rotate(frame.clone(), 2, 2, Rotation::Identity).unwrap();
        assert_eq!(out, frame);
        assert_eq!((w, h), (2, 2));
    }

    /// Helpers for the blend tests: a solid frame and a solid sprite.
    fn solid(w: u32, h: u32, px: [u8; 4]) -> Vec<u8> {
        px.iter()
            .copied()
            .cycle()
            .take((w * h) as usize * BYTES_PER_PIXEL)
            .collect()
    }

    #[test]
    fn an_opaque_sprite_replaces_the_pixels_it_covers() {
        let mut frame = solid(4, 4, [0, 0, 0, 255]);
        let sprite = solid(2, 2, [255, 0, 0, 255]);
        blend_over(&mut frame, 4, 4, &sprite, 2, 2, 1, 1).unwrap();
        let at = |x: usize, y: usize| {
            let i = (y * 4 + x) * BYTES_PER_PIXEL;
            [frame[i], frame[i + 1], frame[i + 2]]
        };
        assert_eq!(at(1, 1), [255, 0, 0]);
        assert_eq!(at(2, 2), [255, 0, 0]);
        assert_eq!(at(0, 0), [0, 0, 0], "outside the sprite is untouched");
        assert_eq!(at(3, 3), [0, 0, 0]);
    }

    #[test]
    fn a_fully_transparent_sprite_changes_nothing() {
        let mut frame = solid(3, 3, [10, 20, 30, 255]);
        let before = frame.clone();
        let sprite = solid(3, 3, [255, 255, 255, 0]);
        blend_over(&mut frame, 3, 3, &sprite, 3, 3, 0, 0).unwrap();
        assert_eq!(frame, before);
    }

    #[test]
    fn a_half_transparent_sprite_blends_toward_it() {
        let mut frame = solid(1, 1, [0, 0, 0, 255]);
        let sprite = solid(1, 1, [255, 255, 255, 128]);
        blend_over(&mut frame, 1, 1, &sprite, 1, 1, 0, 0).unwrap();
        // 255*128/255 = 128, rounded.
        assert_eq!(&frame[..3], &[128, 128, 128]);
    }

    /// **The case a cursor hits constantly.** A pointer at the top-left of the
    /// screen is drawn from its hotspot, so most of its bitmap is at negative
    /// coordinates. It must clip, not wrap and not panic.
    #[test]
    fn a_sprite_at_negative_coordinates_is_clipped_not_wrapped() {
        let mut frame = solid(4, 4, [0, 0, 0, 255]);
        let sprite = solid(3, 3, [255, 0, 0, 255]);
        blend_over(&mut frame, 4, 4, &sprite, 3, 3, -2, -2).unwrap();
        let at = |x: usize, y: usize| frame[(y * 4 + x) * BYTES_PER_PIXEL];
        assert_eq!(at(0, 0), 255, "the one visible pixel is drawn");
        assert_eq!(at(1, 0), 0, "and nothing beyond it");
        assert_eq!(at(0, 1), 0);
        assert_eq!(at(3, 3), 0, "it must NOT have wrapped to the far corner");
    }

    /// The same at the other two edges, which is where an off-by-one writes
    /// into the next row instead of nowhere.
    #[test]
    fn a_sprite_hanging_off_the_right_and_bottom_is_clipped() {
        let mut frame = solid(4, 4, [0, 0, 0, 255]);
        let sprite = solid(3, 3, [255, 0, 0, 255]);
        blend_over(&mut frame, 4, 4, &sprite, 3, 3, 3, 3).unwrap();
        let at = |x: usize, y: usize| frame[(y * 4 + x) * BYTES_PER_PIXEL];
        assert_eq!(at(3, 3), 255, "the corner pixel is drawn");
        assert_eq!(at(0, 3), 0, "no wrap onto the start of the row");
        assert_eq!(at(3, 0), 0);
    }

    #[test]
    fn a_sprite_entirely_off_frame_draws_nothing_and_is_not_an_error() {
        let mut frame = solid(4, 4, [7, 7, 7, 255]);
        let before = frame.clone();
        let sprite = solid(2, 2, [255, 0, 0, 255]);
        blend_over(&mut frame, 4, 4, &sprite, 2, 2, 100, 100).unwrap();
        blend_over(&mut frame, 4, 4, &sprite, 2, 2, -100, -100).unwrap();
        assert_eq!(frame, before);
    }

    #[test]
    fn a_zero_sized_sprite_is_nothing_to_draw_rather_than_a_fault() {
        let mut frame = solid(2, 2, [1, 2, 3, 255]);
        let before = frame.clone();
        assert!(blend_over(&mut frame, 2, 2, &[], 0, 0, 0, 0).is_ok());
        assert_eq!(frame, before);
    }

    #[test]
    fn a_frame_smaller_than_it_claims_is_refused_rather_than_written_past() {
        let mut frame = solid(2, 2, [0, 0, 0, 255]);
        let sprite = solid(1, 1, [255, 255, 255, 255]);
        assert!(matches!(
            blend_over(&mut frame, 8, 8, &sprite, 1, 1, 0, 0),
            Err(PixelError::SourceTooSmall { .. })
        ));
        assert!(matches!(
            blend_over(&mut frame, 0, 2, &sprite, 1, 1, 0, 0),
            Err(PixelError::ZeroDimension { .. })
        ));
    }

    /// A truncated sprite must be refused too — it is built from a Win32 call
    /// whose output size we do not control.
    #[test]
    fn a_sprite_smaller_than_it_claims_is_refused() {
        let mut frame = solid(4, 4, [0, 0, 0, 255]);
        assert!(matches!(
            blend_over(&mut frame, 4, 4, &[0, 0, 0, 255], 2, 2, 0, 0),
            Err(PixelError::SourceTooSmall { .. })
        ));
    }

    #[test]
    fn a_white_frame_and_a_black_frame_are_both_uniform() {
        assert!(is_uniform(&[0xFF; 64]), "all white");
        assert!(is_uniform(&[0x00; 64]), "all black");
        let mut mixed = vec![0u8; 64];
        mixed[60] = 1;
        assert!(!is_uniform(&mixed), "one different pixel is not uniform");
    }

    /// Malformed input must not be reported as a uniform frame — that would
    /// raise a capture fault naming the wrong cause.
    #[test]
    fn a_malformed_buffer_is_not_called_uniform() {
        assert!(!is_uniform(&[]), "empty");
        assert!(!is_uniform(&[1, 2, 3]), "not a whole pixel");
        assert!(!is_uniform(&[1, 2, 3, 4, 5]), "trailing partial pixel");
    }

    #[test]
    fn distinct_pixels_counts_colours_and_stops_at_the_cap() {
        let uniform = vec![0xFFu8; 400];
        assert_eq!(distinct_pixels(&uniform, 16), 1);
        let mut two = vec![0xFFu8; 400];
        two[0..4].copy_from_slice(&[0, 0, 0, 255]);
        assert_eq!(distinct_pixels(&two, 16), 2);
        // 100 distinct pixels, capped at 16.
        let many: Vec<u8> = (0..100u8).flat_map(|i| [i, i, i, 255]).collect();
        assert_eq!(distinct_pixels(&many, 16), 16);
    }

    /// A duplicated surface must be turned by the turn that UNDOES the
    /// display's rotation. Applying the display's own rotation turns the frame
    /// the wrong way — observed live on 2026-08-25: with the desktop rotated
    /// 90 degrees, the phone showed the image turned the opposite way.
    #[test]
    fn a_duplicated_surface_is_corrected_by_the_opposite_turn() {
        assert_eq!(
            correction_for(Rotation::Clockwise90),
            Rotation::Clockwise270,
            "a display turned 90 clockwise needs the frame turned back 90, not forward"
        );
        assert_eq!(
            correction_for(Rotation::Clockwise270),
            Rotation::Clockwise90,
        );
    }

    /// The symmetric cases: no turn needs no correction, and a half turn is its
    /// own inverse, so those two must pass through unchanged.
    #[test]
    fn identity_and_half_turns_are_their_own_correction() {
        assert_eq!(correction_for(Rotation::Identity), Rotation::Identity);
        assert_eq!(
            correction_for(Rotation::Clockwise180),
            Rotation::Clockwise180
        );
    }

    /// End to end on real pixels: turning a frame by the display's rotation and
    /// then by the correction must return the original image, which is what
    /// "the right way up" means.
    #[test]
    fn correcting_a_turned_frame_restores_the_original() {
        let w = 4u32;
        let h = 3u32;
        let mut frame = Vec::new();
        for i in 0..(w * h) {
            frame.extend_from_slice(&[i as u8, (i * 2) as u8, (i * 3) as u8, 255]);
        }
        for r in [
            Rotation::Clockwise90,
            Rotation::Clockwise180,
            Rotation::Clockwise270,
        ] {
            // The panel hands back a surface turned by `r`...
            let (turned, tw, th) = rotate(frame.clone(), w, h, r).expect("turn");
            // ...and the correction must put it back.
            let (back, bw, bh) = rotate(turned, tw, th, correction_for(r)).expect("correct");
            assert_eq!((bw, bh), (w, h), "correction must restore the dimensions");
            assert_eq!(back, frame, "correction must restore the pixels for {r:?}");
        }
    }

    /// The GDI fallback must not turn its frame. `BitBlt` on a display DC
    /// already yields the desktop upright at its logical size, so any turn
    /// applied here lays an upright capture on its side.
    ///
    /// Observed on Windows on 2026-08-26: desktop rotated 90 degrees, GDI
    /// fallback engaged, and the captured frame came back sideways — taskbar
    /// down the left edge, text reading bottom-to-top.
    #[test]
    fn the_gdi_fallback_never_turns_its_frame() {
        for r in [
            Rotation::Identity,
            Rotation::Clockwise90,
            Rotation::Clockwise180,
            Rotation::Clockwise270,
        ] {
            assert_eq!(
                gdi_correction_for(r),
                Rotation::Identity,
                "GDI already captures the desktop upright; turning it by {r:?} \
                 puts the picture on its side"
            );
        }
    }

    /// The two backends do NOT share a correction, and that difference is the
    /// point: a duplicated DXGI surface arrives in the panel's orientation and
    /// must be turned back, while a GDI BitBlt arrives already upright.
    #[test]
    fn dxgi_and_gdi_corrections_differ_where_it_matters() {
        assert_eq!(
            correction_for(Rotation::Clockwise90),
            Rotation::Clockwise270
        );
        assert_eq!(
            gdi_correction_for(Rotation::Clockwise90),
            Rotation::Identity
        );
        // With no rotation in play the two agree, which is why a landscape-only
        // test cannot tell them apart.
        assert_eq!(
            correction_for(Rotation::Identity),
            gdi_correction_for(Rotation::Identity)
        );
    }

    /// A GDI frame of a portrait desktop must keep its portrait dimensions.
    /// Turning it would swap them, which is exactly what was seen: a 720x1280
    /// desktop arriving as a 1280x720 sideways frame.
    #[test]
    fn a_gdi_portrait_frame_keeps_its_portrait_dimensions() {
        let (w, h) = (4u32, 6u32);
        let mut frame = Vec::new();
        for i in 0..(w * h) {
            frame.extend_from_slice(&[i as u8, 0, 0, 255]);
        }
        let (out, ow, oh) = rotate(
            frame.clone(),
            w,
            h,
            gdi_correction_for(Rotation::Clockwise90),
        )
        .expect("gdi correction");
        assert_eq!((ow, oh), (w, h), "a GDI frame must not swap its dimensions");
        assert_eq!(out, frame, "a GDI frame must not be reordered at all");
    }
}

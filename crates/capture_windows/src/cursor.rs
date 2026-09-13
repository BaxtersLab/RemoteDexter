//! The mouse pointer, rasterised so it can be drawn into a captured frame.
//! Windows only.
//!
//! SPDX-License-Identifier: AGPL-3.0-only
//!
//! **Why this exists.** Neither Windows capture backend includes the pointer.
//! Desktop Duplication reports it as *separate metadata* — shape and position on
//! `AcquireNextFrame` — and never draws it into the surface; a GDI `BitBlt` of
//! the screen DC does not pick it up either. Linux composites the cursor into
//! the stream by default and `capture_linux` calls that a requirement: *"a
//! remote-desktop viewer needs to see the pointer"*.
//!
//! So the two platforms disagreed about something one of them treats as
//! mandatory, and the practical cost was found by the operator on 2026-09-01
//! while driving this host from a phone: **you cannot aim a click you cannot
//! see.** This module is the Windows equivalent.
//!
//! ## Shape
//!
//! Everything here is the unsafe FFI needed to turn the current `HCURSOR` into a
//! plain top-down RGBA sprite plus a screen position. The compositing itself —
//! the alpha blend and, far more importantly, the clipping — is
//! [`crate::pixels::blend_over`], which contains no Windows types and is tested
//! on every platform. That split is deliberate: the arithmetic is where the bugs
//! are, and it should not need a display to test.
//!
//! ## Why the icon is drawn twice
//!
//! `DrawIconEx` composites onto whatever is already in the destination bitmap.
//! A monochrome cursor (the I-beam, the resize arrows) carries no alpha at all:
//! it is a pair of masks that INVERT what is underneath. Drawn once onto a
//! zeroed bitmap it can come out solid black, invisible over a dark window.
//!
//! So it is drawn twice, over black and over white, and the two results are
//! compared per pixel. Where they agree, the cursor is opaque and that colour is
//! real. Where they differ, the destination showed through — that pixel is
//! transparent. This recovers a usable alpha channel for cursors that have none,
//! and is the standard way to do it; the alternative is reading `hbmMask`
//! directly and reimplementing the AND/XOR rules by hand.

use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, PatBlt, ReleaseDC,
    SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, BLACKNESS, DIB_RGB_COLORS, HBITMAP, HDC,
    HGDIOBJ, WHITENESS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DrawIconEx, GetCursorInfo, GetIconInfo, CURSORINFO, CURSOR_SHOWING, DI_NORMAL, HICON, ICONINFO,
};

use crate::pixels::BYTES_PER_PIXEL;

/// A pointer ready to be drawn: top-down RGBA, and where its top-left corner
/// belongs in virtual-desktop coordinates.
///
/// The position already has the hotspot subtracted, so it is the corner of the
/// bitmap rather than the point of the arrow — and it is therefore routinely
/// negative near the top-left of the screen. [`crate::pixels::blend_over`]
/// expects exactly that and clips.
pub struct CursorSprite {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub x: i32,
    pub y: i32,
}

/// Owns a DC and its bitmap, and releases both exactly once.
struct Canvas {
    dc: HDC,
    bitmap: HBITMAP,
    previous: HGDIOBJ,
    bits: *mut std::ffi::c_void,
}

impl Drop for Canvas {
    fn drop(&mut self) {
        unsafe {
            if !self.previous.is_invalid() {
                SelectObject(self.dc, self.previous);
            }
            if !self.bitmap.is_invalid() {
                let _ = DeleteObject(HGDIOBJ(self.bitmap.0));
            }
            if !self.dc.is_invalid() {
                let _ = DeleteDC(self.dc);
            }
        }
    }
}

impl Canvas {
    /// A `w` x `h` 32-bit top-down DIB with its own memory DC.
    unsafe fn new(screen: HDC, w: i32, h: i32) -> Option<Self> {
        let dc = unsafe { CreateCompatibleDC(screen) };
        if dc.is_invalid() {
            return None;
        }
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                // Negative: top-down, the order everything downstream wants.
                biHeight: -h,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits = std::ptr::null_mut();
        let bitmap =
            match unsafe { CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut bits, None, 0) } {
                Ok(b) if !b.is_invalid() && !bits.is_null() => b,
                _ => {
                    unsafe {
                        let _ = DeleteDC(dc);
                    };
                    return None;
                }
            };
        let previous = unsafe { SelectObject(dc, HGDIOBJ(bitmap.0)) };
        Some(Canvas {
            dc,
            bitmap,
            previous,
            bits,
        })
    }

    /// The DIB's pixels. BGRA, tightly packed at 32bpp.
    unsafe fn pixels(&self, len: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.bits as *const u8, len) }
    }
}

/// Rasterise the cursor as it is right now, or `None` if there is nothing to
/// draw.
///
/// `None` — not an error — when the cursor is hidden, when there is no cursor
/// (a full-screen app can hide it), or when any of the Win32 calls decline.
/// A missing pointer must never fail a frame: a capture with no cursor drawn is
/// still a correct capture of the desktop.
pub fn current() -> Option<CursorSprite> {
    unsafe {
        let mut info = CURSORINFO {
            cbSize: std::mem::size_of::<CURSORINFO>() as u32,
            ..Default::default()
        };
        GetCursorInfo(&mut info).ok()?;
        if info.flags != CURSOR_SHOWING || info.hCursor.is_invalid() {
            return None;
        }

        let mut icon = ICONINFO::default();
        GetIconInfo(HICON(info.hCursor.0), &mut icon).ok()?;
        // GetIconInfo hands over two bitmaps and they are ours to free.
        let _masks = MaskBitmaps {
            color: icon.hbmColor,
            mask: icon.hbmMask,
        };

        let (w, h) = cursor_extent(&icon)?;
        if w <= 0 || h <= 0 || w > MAX_CURSOR_EDGE || h > MAX_CURSOR_EDGE {
            return None;
        }

        let screen = GetDC(HWND(std::ptr::null_mut()));
        if screen.is_invalid() {
            return None;
        }
        let release = ScreenDc(screen);

        // Twice, over opposite backgrounds. See the module note.
        let on_black = Canvas::new(screen, w, h)?;
        let on_white = Canvas::new(screen, w, h)?;
        // PatBlt returns BOOL; a failure here means the canvas is not the
        // known background these two draws are compared against, so there is
        // no alpha to recover and the honest answer is no sprite.
        if !PatBlt(on_black.dc, 0, 0, w, h, BLACKNESS).as_bool()
            || !PatBlt(on_white.dc, 0, 0, w, h, WHITENESS).as_bool()
        {
            return None;
        }
        DrawIconEx(
            on_black.dc,
            0,
            0,
            HICON(info.hCursor.0),
            w,
            h,
            0,
            None,
            DI_NORMAL,
        )
        .ok()?;
        DrawIconEx(
            on_white.dc,
            0,
            0,
            HICON(info.hCursor.0),
            w,
            h,
            0,
            None,
            DI_NORMAL,
        )
        .ok()?;
        drop(release);

        let len = (w as usize) * (h as usize) * BYTES_PER_PIXEL;
        let black = on_black.pixels(len);
        let white = on_white.pixels(len);
        let rgba = recover_alpha(black, white);

        Some(CursorSprite {
            rgba,
            width: w as u32,
            height: h as u32,
            // From the hotspot to the bitmap's corner. Frequently negative.
            x: info.ptScreenPos.x - icon.xHotspot as i32,
            y: info.ptScreenPos.y - icon.yHotspot as i32,
        })
    }
}

/// A sanity bound on cursor size. Windows cursors are 32x32 or 64x64; a
/// high-DPI or accessibility cursor can be larger, but a four-figure edge means
/// the `ICONINFO` was not what we think it is.
const MAX_CURSOR_EDGE: i32 = 512;

/// Frees the two bitmaps `GetIconInfo` allocates. Leaking these leaks GDI
/// objects once per captured frame, which is a slow death rather than an
/// obvious one.
struct MaskBitmaps {
    color: HBITMAP,
    mask: HBITMAP,
}

impl Drop for MaskBitmaps {
    fn drop(&mut self) {
        unsafe {
            if !self.color.is_invalid() {
                let _ = DeleteObject(HGDIOBJ(self.color.0));
            }
            if !self.mask.is_invalid() {
                let _ = DeleteObject(HGDIOBJ(self.mask.0));
            }
        }
    }
}

struct ScreenDc(HDC);

impl Drop for ScreenDc {
    fn drop(&mut self) {
        unsafe {
            ReleaseDC(HWND(std::ptr::null_mut()), self.0);
        }
    }
}

/// The cursor's pixel size, from whichever bitmap it actually has.
///
/// A colour cursor's `hbmColor` is its true size. A **monochrome** cursor has no
/// colour bitmap at all: `hbmMask` holds the AND mask stacked on top of the XOR
/// mask, so it is twice as tall as the cursor and the height must be halved.
/// Missing that draws the pointer at double height with its own mask smeared
/// underneath it.
unsafe fn cursor_extent(icon: &ICONINFO) -> Option<(i32, i32)> {
    use windows::Win32::Graphics::Gdi::{GetObjectW, BITMAP};
    let mut bm = BITMAP::default();
    let size = std::mem::size_of::<BITMAP>() as i32;
    if !icon.hbmColor.is_invalid() {
        let got = unsafe {
            GetObjectW(
                HGDIOBJ(icon.hbmColor.0),
                size,
                Some(&mut bm as *mut _ as *mut std::ffi::c_void),
            )
        };
        if got == 0 {
            return None;
        }
        return Some((bm.bmWidth, bm.bmHeight));
    }
    let got = unsafe {
        GetObjectW(
            HGDIOBJ(icon.hbmMask.0),
            size,
            Some(&mut bm as *mut _ as *mut std::ffi::c_void),
        )
    };
    if got == 0 {
        return None;
    }
    Some((bm.bmWidth, bm.bmHeight / 2))
}

/// Recover RGBA from the same cursor drawn over black and over white.
///
/// Where the two agree the cursor is opaque and that colour is its own. Where
/// they differ the background showed through: `white - black` is the amount of
/// background that survived, so `255 - (white - black)` is the alpha. Colour is
/// taken from the black-background draw, which is already premultiplied against
/// zero and therefore the straight contribution of the cursor itself.
///
/// Pure, and given its own tests: this is the half that decides whether an
/// I-beam is visible or a black smear.
fn recover_alpha(black: &[u8], white: &[u8]) -> Vec<u8> {
    let n = black.len().min(white.len());
    let mut out = Vec::with_capacity(n);
    let mut i = 0;
    while i + BYTES_PER_PIXEL <= n {
        // Source DIBs are BGRA; the frame is RGBA.
        let (bb, bg, br) = (black[i] as i32, black[i + 1] as i32, black[i + 2] as i32);
        let (wb, wg, wr) = (white[i] as i32, white[i + 1] as i32, white[i + 2] as i32);
        // How much white survived, averaged over the channels for robustness
        // against a cursor that tints one of them.
        let leaked = (((wb - bb) + (wg - bg) + (wr - br)) / 3).clamp(0, 255);
        let alpha = (255 - leaked) as u8;
        out.push(br as u8);
        out.push(bg as u8);
        out.push(bb as u8);
        out.push(alpha);
        i += BYTES_PER_PIXEL;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bgra(b: u8, g: u8, r: u8) -> [u8; 4] {
        [b, g, r, 0]
    }

    /// An opaque pixel looks identical over both backgrounds.
    #[test]
    fn a_pixel_that_ignores_its_background_is_opaque() {
        let black = bgra(0, 0, 255);
        let white = bgra(0, 0, 255);
        let out = recover_alpha(&black, &white);
        assert_eq!(out[3], 255, "alpha");
        assert_eq!(&out[..3], &[255, 0, 0], "and it came back as RGB");
    }

    /// A pixel the background shows straight through is fully transparent —
    /// this is most of a cursor's bounding box.
    #[test]
    fn a_pixel_the_background_passes_through_is_transparent() {
        let black = bgra(0, 0, 0);
        let white = bgra(255, 255, 255);
        let out = recover_alpha(&black, &white);
        assert_eq!(out[3], 0);
    }

    /// Half-covered edges, which is what makes a cursor look anti-aliased
    /// rather than jagged.
    #[test]
    fn a_partly_covered_pixel_gets_a_partial_alpha() {
        let black = bgra(0, 0, 0);
        let white = bgra(128, 128, 128);
        let out = recover_alpha(&black, &white);
        assert_eq!(out[3], 127);
    }

    #[test]
    fn the_channel_order_is_swapped_from_bgra_to_rgba() {
        let out = recover_alpha(&bgra(1, 2, 3), &bgra(1, 2, 3));
        assert_eq!(&out[..3], &[3, 2, 1]);
    }

    /// Ragged input must not panic or read past the end — the buffers come
    /// from two separate Win32 allocations.
    #[test]
    fn mismatched_buffers_are_truncated_rather_than_read_past() {
        let out = recover_alpha(&[0, 0, 0, 0, 0, 0, 0, 0], &[255, 255, 255, 0]);
        assert_eq!(
            out.len(),
            BYTES_PER_PIXEL,
            "one pixel, the shorter of the two"
        );
        let out = recover_alpha(&[0, 0, 0], &[255, 255, 255]);
        assert!(out.is_empty(), "a partial pixel is not a pixel");
    }
}

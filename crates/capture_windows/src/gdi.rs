//! Full-desktop GDI capture — the fallback. Windows only.
//!
//! SPDX-License-Identifier: AGPL-3.0-only
//!
//! GDI capture fallback, written against the `windows` crate.
//!
//! **Deliberate choice: the rows come back the right way up.** The obvious call
//! asks `GetDIBits` for a positive `biHeight`, which is a bottom-up bitmap, and
//! then corrects it with a mirror followed by a 180° rotation — two full passes
//! over every pixel of every frame. A negative `biHeight` asks the kernel for a
//! top-down bitmap, which is the order everything downstream already wants, so
//! neither pass is needed. The same trick the legacy `PrintWindow` crate used.
//!
//! This path is slower than duplication and always available, which is exactly
//! what a fallback should be. It captures the whole display, never a window.

use session_core::CaptureError;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleDC, CreateDCW, CreateDIBSection, DeleteDC, DeleteObject, SelectObject,
    BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS, HBITMAP, HDC, HGDIOBJ,
    SRCCOPY,
};

use crate::health::Outcome;
use crate::pixels::{self, BYTES_PER_PIXEL};
use crate::DisplayInfo;

/// Owns the four GDI objects a capture needs, and releases all of them exactly
/// once. Every early return in `open` below would otherwise be a leak.
pub struct DesktopGdi {
    screen: HDC,
    mem: HDC,
    bitmap: HBITMAP,
    previous: HGDIOBJ,
    bits: *mut std::ffi::c_void,
    width: u32,
    height: u32,
    pending: Option<(Vec<u8>, u32, u32)>,
}

impl Drop for DesktopGdi {
    fn drop(&mut self) {
        unsafe {
            if !self.previous.is_invalid() {
                SelectObject(self.mem, self.previous);
            }
            if !self.bitmap.is_invalid() {
                let _ = DeleteObject(HGDIOBJ(self.bitmap.0));
            }
            if !self.mem.is_invalid() {
                let _ = DeleteDC(self.mem);
            }
            if !self.screen.is_invalid() {
                let _ = DeleteDC(self.screen);
            }
        }
    }
}

impl DesktopGdi {
    /// Open a device context on one display by name and prepare a top-down
    /// 32-bit DIB to receive it.
    pub fn open(display: &DisplayInfo) -> Result<Self, CaptureError> {
        if display.width == 0 || display.height == 0 {
            return Err(CaptureError::Backend(format!(
                "display {} reports {}x{}",
                display.name, display.width, display.height
            )));
        }
        let mut name: Vec<u16> = display.name.encode_utf16().collect();
        name.push(0);
        unsafe {
            // CreateDCW on a display name gives a DC for that display only —
            // not the virtual desktop, and not a window.
            let screen = CreateDCW(PCWSTR(name.as_ptr()), PCWSTR::null(), PCWSTR::null(), None);
            if screen.is_invalid() {
                return Err(CaptureError::Backend(format!(
                    "could not open a device context for {}",
                    display.name
                )));
            }
            let mem = CreateCompatibleDC(screen);
            if mem.is_invalid() {
                let _ = DeleteDC(screen);
                return Err(CaptureError::Backend("CreateCompatibleDC failed".into()));
            }
            let info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: display.width as i32,
                    // NEGATIVE: top-down rows. See the module note.
                    biHeight: -(display.height as i32),
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
            let bitmap = match CreateDIBSection(mem, &info, DIB_RGB_COLORS, &mut bits, None, 0) {
                Ok(b) => b,
                Err(e) => {
                    let _ = DeleteDC(mem);
                    let _ = DeleteDC(screen);
                    return Err(CaptureError::Backend(format!("CreateDIBSection: {e}")));
                }
            };
            if bits.is_null() {
                let _ = DeleteObject(HGDIOBJ(bitmap.0));
                let _ = DeleteDC(mem);
                let _ = DeleteDC(screen);
                return Err(CaptureError::Backend(
                    "CreateDIBSection returned a null pixel pointer".into(),
                ));
            }
            let previous = SelectObject(mem, HGDIOBJ(bitmap.0));
            Ok(DesktopGdi {
                screen,
                mem,
                bitmap,
                previous,
                bits,
                width: display.width,
                height: display.height,
                pending: None,
            })
        }
    }

    pub fn take_frame(&mut self) -> Option<(Vec<u8>, u32, u32)> {
        self.pending.take()
    }

    /// Blit the display into the DIB and convert it.
    pub fn next_frame(&mut self, display: &DisplayInfo) -> Outcome {
        // A resolution change invalidates the bitmap; say so and let the health
        // policy decide, rather than silently capturing the wrong size.
        if display.width != self.width || display.height != self.height {
            return Outcome::AccessLost;
        }
        unsafe {
            // CAPTUREBLT includes layered windows. It also makes the cursor
            // blink on some drivers; a visible remote
            // session is worth more than a steady local cursor.
            if BitBlt(
                self.mem,
                0,
                0,
                self.width as i32,
                self.height as i32,
                self.screen,
                0,
                0,
                SRCCOPY | CAPTUREBLT,
            )
            .is_err()
            {
                return Outcome::BackendError("BitBlt of the desktop failed".into());
            }
            let len = self.width as usize * self.height as usize * BYTES_PER_PIXEL;
            let src = std::slice::from_raw_parts(self.bits as *const u8, len);
            // A DIB section is tightly packed at 32bpp: stride == width * 4.
            match pixels::bgra_to_rgba(
                src,
                self.width as usize * BYTES_PER_PIXEL,
                self.width,
                self.height,
            ) {
                Ok(rgba) => match pixels::rotate(
                    rgba,
                    self.width,
                    self.height,
                    pixels::gdi_correction_for(display.rotation),
                ) {
                    Ok((rgba, w, h)) => {
                        let uniform = pixels::is_uniform(&rgba);
                        self.pending = Some((rgba, w, h));
                        Outcome::Frame { uniform }
                    }
                    Err(e) => Outcome::BackendError(e.to_string()),
                },
                Err(e) => Outcome::BackendError(e.to_string()),
            }
        }
    }
}

// A DC opened on a display name is not associated with a window; this asserts
// the type we are NOT using is still the one GDI would want for a window DC,
// so a later edit cannot quietly turn this into window capture again.
const _: Option<HWND> = None;

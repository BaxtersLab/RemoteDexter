//! Display enumeration. Windows only.
//!
//! SPDX-License-Identifier: AGPL-3.0-only
//!
//! Two paths, because either can be the one that works: DXGI knows about
//! adapters and outputs, and GDI knows about whatever the desktop is actually
//! composed of. The thorough approach reconciles the two lists by name and reorders one to
//! match the other; Block 8 captures the primary display only, so the simpler
//! rule applies — try DXGI, and if it yields nothing usable, ask GDI.

use session_core::CaptureError;
use windows::core::Interface;
use windows::Win32::Foundation::BOOL;
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, DXGI_ERROR_NOT_FOUND,
};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayDevicesW, EnumDisplaySettingsExW, DEVMODEW, DISPLAY_DEVICEW,
    DISPLAY_DEVICE_ATTACHED_TO_DESKTOP, DISPLAY_DEVICE_MIRRORING_DRIVER, DMDO_180, DMDO_270,
    DMDO_90, ENUM_CURRENT_SETTINGS, ENUM_DISPLAY_SETTINGS_FLAGS,
};

use crate::pixels::Rotation;
use crate::DisplayInfo;

fn backend(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Backend(e.to_string())
}

/// Trim a fixed-size UTF-16 device-name field at its NUL.
fn device_name(raw: &[u16]) -> String {
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    String::from_utf16_lossy(&raw[..end])
}

/// Enumerate through DXGI: every output of every adapter.
fn from_dxgi() -> Result<Vec<DisplayInfo>, CaptureError> {
    let mut out = Vec::new();
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1().map_err(backend)?;
        let mut ai = 0u32;
        loop {
            let adapter: IDXGIAdapter1 = match factory.EnumAdapters1(ai) {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(backend(e)),
            };
            ai += 1;
            let mut oi = 0u32;
            loop {
                let output = match adapter.EnumOutputs(oi) {
                    Ok(o) => o,
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                    Err(e) => return Err(backend(e)),
                };
                oi += 1;
                // IDXGIOutput1 is the interface DuplicateOutput lives on. An
                // output that cannot provide it cannot be duplicated, so it is
                // no use to us even for enumeration.
                let Ok(output1) = output.cast::<IDXGIOutput1>() else {
                    continue;
                };
                let desc = match output1.GetDesc() {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                if desc.AttachedToDesktop == BOOL(0) {
                    continue;
                }
                let r = desc.DesktopCoordinates;
                out.push(DisplayInfo {
                    name: device_name(&desc.DeviceName),
                    origin: (r.left, r.top),
                    width: (r.right - r.left).max(0) as u32,
                    height: (r.bottom - r.top).max(0) as u32,
                    is_primary: r.left == 0 && r.top == 0,
                    rotation: Rotation::from_dxgi(desc.Rotation.0),
                });
            }
        }
    }
    Ok(out)
}

/// Enumerate through GDI. Used when DXGI reports nothing — a basic display
/// adapter, a remote session, or a machine where the duplication API is not
/// available at all still has displays, and refusing to list them would turn a
/// degraded capture into no capture.
fn from_gdi() -> Vec<DisplayInfo> {
    let mut out = Vec::new();
    unsafe {
        let mut i = 0u32;
        loop {
            let mut dev = DISPLAY_DEVICEW {
                cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
                ..Default::default()
            };
            if !EnumDisplayDevicesW(None, i, &mut dev, 0).as_bool() {
                break;
            }
            i += 1;
            let flags = dev.StateFlags;
            if flags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP == 0
                || flags & DISPLAY_DEVICE_MIRRORING_DRIVER != 0
            {
                continue;
            }
            let name = device_name(&dev.DeviceName);
            let mut mode = DEVMODEW {
                dmSize: std::mem::size_of::<DEVMODEW>() as u16,
                ..Default::default()
            };
            let name_w: Vec<u16> = dev.DeviceName.to_vec();
            if !EnumDisplaySettingsExW(
                windows::core::PCWSTR(name_w.as_ptr()),
                ENUM_CURRENT_SETTINGS,
                &mut mode,
                ENUM_DISPLAY_SETTINGS_FLAGS(0),
            )
            .as_bool()
            {
                continue;
            }
            let pos = mode.Anonymous1.Anonymous2.dmPosition;
            out.push(DisplayInfo {
                name,
                origin: (pos.x, pos.y),
                width: mode.dmPelsWidth,
                height: mode.dmPelsHeight,
                is_primary: pos.x == 0 && pos.y == 0,
                // GDI reports orientation in dmDisplayOrientation, using the
                // SAME 0/1/2/3 quarter-turn numbering as DMDO_*, which is NOT
                // the DXGI numbering. Converted explicitly rather than passed
                // through a function that expects DXGI values.
                rotation: match mode.Anonymous1.Anonymous2.dmDisplayOrientation {
                    DMDO_90 => Rotation::Clockwise90,
                    DMDO_180 => Rotation::Clockwise180,
                    DMDO_270 => Rotation::Clockwise270,
                    _ => Rotation::Identity,
                },
            });
        }
    }
    out
}

/// Every display attached to the desktop.
pub fn enumerate() -> Result<Vec<DisplayInfo>, CaptureError> {
    let dxgi = from_dxgi().unwrap_or_default();
    if !dxgi.is_empty() {
        return Ok(dxgi);
    }
    let gdi = from_gdi();
    if gdi.is_empty() {
        return Err(CaptureError::Backend(
            "neither DXGI nor GDI reported a display attached to the desktop".into(),
        ));
    }
    Ok(gdi)
}

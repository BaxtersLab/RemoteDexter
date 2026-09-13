//! DXGI Desktop Duplication. Windows only.
//!
//! SPDX-License-Identifier: AGPL-3.0-only
//!
//! Desktop Duplication capture, written against the `windows` crate.
//!
//! **One deliberate simplification.** There is a "fastlane" that calls
//! `MapDesktopSurface` when `DesktopImageInSystemMemory` is set, avoiding a GPU
//! copy on hardware that keeps the desktop image in system memory. This module
//! always copies into a staging texture instead. That costs one copy on the
//! minority of adapters where the fastlane would apply, and removes an entire
//! second acquisition path that no machine in this project's reach can execute.
//! An untestable optimisation is a liability in a block whose whole purpose is
//! to find out why a capture path produces white.

use std::mem::size_of;

use session_core::CaptureError;
use windows::core::Interface;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_FLAG, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_NOT_FOUND, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO,
};

use crate::health::Outcome;
use crate::pixels;
use crate::DisplayInfo;

/// How long to wait for the desktop to publish a new frame.
///
/// Desktop Duplication only publishes on change, so a timeout here is a normal
/// event on an idle desktop, not an error — it becomes `WouldBlock` and the
/// health policy decides what a run of them means. Short enough that the caller
/// stays responsive, long enough not to spin.
const ACQUIRE_TIMEOUT_MS: u32 = 100;

/// An open duplication of one output, plus the device that owns it.
pub struct Duplication {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    /// Reused between frames — allocating a staging texture per frame is the
    /// single most expensive mistake available in this loop.
    staging: Option<ID3D11Texture2D>,
    staging_size: (u32, u32),
    /// Set by `next_frame`, taken by `take_frame`.
    pending: Option<(Vec<u8>, u32, u32)>,
}

fn backend(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Backend(e.to_string())
}

impl Duplication {
    /// Create a D3D11 device on the adapter owning `display`, and duplicate it.
    pub fn open(display: &DisplayInfo) -> Result<Self, CaptureError> {
        unsafe {
            let (adapter, output) = find_output(display)?;
            let mut device: Option<ID3D11Device> = None;
            let mut context: Option<ID3D11DeviceContext> = None;
            let mut level = D3D_FEATURE_LEVEL::default();
            D3D11CreateDevice(
                &adapter,
                // UNKNOWN is required when an adapter is supplied; passing
                // HARDWARE with an explicit adapter is an invalid-arg error.
                D3D_DRIVER_TYPE_UNKNOWN,
                None,
                D3D11_CREATE_DEVICE_FLAG(0),
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                Some(&mut level),
                Some(&mut context),
            )
            .map_err(backend)?;
            let device = device
                .ok_or_else(|| CaptureError::Backend("D3D11 device was not created".into()))?;
            let context = context
                .ok_or_else(|| CaptureError::Backend("D3D11 context was not created".into()))?;
            let duplication = output.DuplicateOutput(&device).map_err(backend)?;
            Ok(Duplication {
                device,
                context,
                duplication,
                staging: None,
                staging_size: (0, 0),
                pending: None,
            })
        }
    }

    /// Take the frame produced by the last successful [`Self::next_frame`].
    pub fn take_frame(&mut self) -> Option<(Vec<u8>, u32, u32)> {
        self.pending.take()
    }

    /// Attempt one frame. Never returns an error type: the health policy needs
    /// to distinguish "nothing published" from "the object died" from "broken",
    /// and an `Err` collapses all three.
    pub fn next_frame(&mut self, display: &DisplayInfo) -> Outcome {
        match self.acquire(display) {
            Ok(Some((data, w, h))) => {
                let uniform = pixels::is_uniform(&data);
                self.pending = Some((data, w, h));
                Outcome::Frame { uniform }
            }
            Ok(None) => Outcome::WouldBlock,
            Err(e) => e,
        }
    }

    fn acquire(&mut self, display: &DisplayInfo) -> Result<Option<(Vec<u8>, u32, u32)>, Outcome> {
        unsafe {
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource: Option<IDXGIResource> = None;
            match self
                .duplication
                .AcquireNextFrame(ACQUIRE_TIMEOUT_MS, &mut info, &mut resource)
            {
                Ok(()) => {}
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
                Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => return Err(Outcome::AccessLost),
                Err(e) => return Err(Outcome::BackendError(e.to_string())),
            }

            // Everything below must release the frame, including on the error
            // paths — a duplication with an un-released frame stops publishing.
            let result = self.copy_out(resource, &info, display);
            let _ = self.duplication.ReleaseFrame();
            result
        }
    }

    unsafe fn copy_out(
        &mut self,
        resource: Option<IDXGIResource>,
        info: &DXGI_OUTDUPL_FRAME_INFO,
        display: &DisplayInfo,
    ) -> Result<Option<(Vec<u8>, u32, u32)>, Outcome> {
        // A frame with no presentation time carries only mouse movement. There
        // are no new desktop pixels in it, so treat it as "nothing published"
        // rather than re-sending the previous image as if it were new.
        if info.LastPresentTime == 0 {
            return Ok(None);
        }
        let Some(resource) = resource else {
            return Ok(None);
        };
        let texture: ID3D11Texture2D = resource
            .cast()
            .map_err(|e| Outcome::BackendError(format!("acquired frame is not a texture: {e}")))?;

        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { texture.GetDesc(&mut desc) };
        let (w, h) = (desc.Width, desc.Height);
        if w == 0 || h == 0 {
            return Err(Outcome::BackendError(format!(
                "duplication produced a {w}x{h} texture"
            )));
        }

        // Rebuild the staging texture only when the geometry changes.
        if self.staging.is_none() || self.staging_size != (w, h) {
            let mut staging_desc = desc;
            staging_desc.Usage = D3D11_USAGE_STAGING;
            staging_desc.BindFlags = 0;
            staging_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
            staging_desc.MiscFlags = 0;
            let mut made: Option<ID3D11Texture2D> = None;
            unsafe {
                self.device
                    .CreateTexture2D(&staging_desc, None, Some(&mut made))
            }
            .map_err(|e| Outcome::BackendError(format!("staging texture: {e}")))?;
            self.staging = made;
            self.staging_size = (w, h);
        }
        let staging = self
            .staging
            .as_ref()
            .ok_or_else(|| Outcome::BackendError("staging texture missing".into()))?;

        unsafe { self.context.CopyResource(staging, &texture) };

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe {
            self.context
                .Map(staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        }
        .map_err(|e| Outcome::BackendError(format!("map staging texture: {e}")))?;

        // From here until Unmap, `mapped.pData` is borrowed from the driver.
        let converted = {
            let len = mapped.RowPitch as usize * h as usize;
            let src = unsafe { std::slice::from_raw_parts(mapped.pData as *const u8, len) };
            pixels::bgra_to_rgba(src, mapped.RowPitch as usize, w, h)
        };
        unsafe { self.context.Unmap(staging, 0) };

        let rgba = converted.map_err(|e| Outcome::BackendError(e.to_string()))?;
        let (rgba, w, h) = pixels::rotate(rgba, w, h, pixels::correction_for(display.rotation))
            .map_err(|e| Outcome::BackendError(e.to_string()))?;
        Ok(Some((rgba, w, h)))
    }
}

/// Find the adapter and output that own `display`, by device name.
unsafe fn find_output(
    display: &DisplayInfo,
) -> Result<(IDXGIAdapter1, IDXGIOutput1), CaptureError> {
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
                let Ok(output1) = output.cast::<IDXGIOutput1>() else {
                    continue;
                };
                let Ok(desc) = output1.GetDesc() else {
                    continue;
                };
                let end = desc
                    .DeviceName
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(desc.DeviceName.len());
                if String::from_utf16_lossy(&desc.DeviceName[..end]) == display.name {
                    return Ok((adapter, output1));
                }
            }
        }
    }
    Err(CaptureError::Backend(format!(
        "display {} is no longer attached",
        display.name
    )))
}

// Keeps `size_of` honest if the struct layout assumption ever changes.
const _: () = assert!(size_of::<DXGI_OUTDUPL_FRAME_INFO>() > 0);

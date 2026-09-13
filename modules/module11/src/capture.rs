//! Real screen capture for Module 11.
//!
//! Windows: DXGI Desktop Duplication (Direct3D 11) — the same proven API
//! sequence used by the sibling `Baxters Screen Record` / VirtualOffice
//! `vo-windows-capture` backends, adapted here into a **persistent
//! streaming** capturer (the duplication handle is held across frames and
//! `AcquireNextFrame` is polled per tick), not the one-shot form.
//!
//! Linux: xdg-desktop-portal ScreenCast -> PipeWire -> GStreamer, which is the
//! only mechanism that can see a Wayland desktop at all (an X11 grab under a
//! Wayland session returns solid black, silently). See `capture_linux`. Built
//! by default; `--no-default-features` drops it for a machine without the
//! GStreamer development headers.
//!
//! Everywhere else (and whenever the real backend is unavailable — headless CI,
//! no GPU, no portal): a synthetic gradient frame, so the pipeline still runs
//! and the module still builds cross-platform. `is_real()` distinguishes the
//! two so callers/tests can assert a genuine capture.

use crate::types::{RawFrame, StreamError};

#[cfg(all(target_os = "linux", feature = "linux-capture"))]
use crate::capture_linux::PortalCapturer;

/// Produces RGBA frames from the real screen (Windows) or a synthetic
/// gradient (fallback). RGBA byte order matches the module's original
/// synthetic frame (`data[i] = R`).
pub struct ScreenCapturer {
    backend: Backend,
    last: Option<RawFrame>,
    width: u32,
    height: u32,
}

enum Backend {
    #[cfg(windows)]
    Dxgi(dxgi::DxgiCapturer),
    #[cfg(all(target_os = "linux", feature = "linux-capture"))]
    Portal(PortalCapturer),
    Synthetic { frame: u64 },
}

impl ScreenCapturer {
    /// Try the real backend; fall back to a synthetic capturer of
    /// `fallback_w × fallback_h` when the real one is unavailable.
    pub fn new(fallback_w: u32, fallback_h: u32) -> Self {
        #[cfg(windows)]
        {
            match dxgi::DxgiCapturer::new(0) {
                Ok(cap) => {
                    let (w, h) = cap.dimensions();
                    return Self {
                        backend: Backend::Dxgi(cap),
                        last: None,
                        width: w,
                        height: h,
                    };
                }
                Err(e) => {
                    eprintln!("[module11] DXGI capture unavailable ({e}); using synthetic frames");
                }
            }
        }
        #[cfg(all(target_os = "linux", feature = "linux-capture"))]
        {
            match PortalCapturer::new() {
                Ok(cap) => {
                    let (w, h) = cap.dimensions();
                    return Self {
                        backend: Backend::Portal(cap),
                        last: None,
                        width: w,
                        height: h,
                    };
                }
                Err(e) => {
                    eprintln!("[module11] portal capture unavailable ({e}); using synthetic frames");
                }
            }
        }
        Self {
            backend: Backend::Synthetic { frame: 0 },
            last: None,
            width: fallback_w,
            height: fallback_h,
        }
    }

    /// Select the synthetic-fallback backend directly, without probing — and
    /// therefore without *opening* — the real one.
    ///
    /// Test-only, and not a mock: this is the same synthetic backend that ships
    /// in the binary, chosen deliberately rather than reached by failure. It
    /// exists because on Linux `new()` reaches xdg-desktop-portal, which raises
    /// a GNOME screen-share dialog and then holds a live capture session for the
    /// life of the process. A unit test whose subject is the *fallback* path
    /// must not do that: it prompts the operator on an ordinary `cargo test`,
    /// and on a box where the portal succeeds it silently exercises the real
    /// backend instead of the one it names. Real-backend coverage lives in the
    /// `RD_USE_HW`-gated integration tests (`tests/live_capture.rs`,
    /// `tests/live_stream.rs`).
    #[cfg(test)]
    pub(crate) fn synthetic(width: u32, height: u32) -> Self {
        Self {
            backend: Backend::Synthetic { frame: 0 },
            last: None,
            width,
            height,
        }
    }

    /// Screen dimensions this capturer produces.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// True when this is a real screen capture (not the synthetic fallback).
    pub fn is_real(&self) -> bool {
        #[cfg(windows)]
        {
            matches!(self.backend, Backend::Dxgi(_))
        }
        #[cfg(all(target_os = "linux", feature = "linux-capture"))]
        {
            matches!(self.backend, Backend::Portal(_))
        }
        #[cfg(not(any(windows, all(target_os = "linux", feature = "linux-capture"))))]
        {
            false
        }
    }

    /// Capture the current frame as RGBA. On the real backend a tick with no
    /// screen change re-emits the last captured frame (DXGI reports "no new
    /// frame" via a wait-timeout); the first-ever frame always forces a real
    /// grab.
    pub fn capture(&mut self) -> Result<RawFrame, StreamError> {
        match &mut self.backend {
            #[cfg(windows)]
            Backend::Dxgi(cap) => {
                let force = self.last.is_none();
                match cap.capture_rgba(force) {
                    Ok(Some(frame)) => {
                        self.last = Some(frame.clone());
                        Ok(frame)
                    }
                    // No change since last tick — re-emit the previous frame.
                    Ok(None) => self.last.clone().ok_or(StreamError::CaptureFailed),
                    Err(_) => self.last.clone().ok_or(StreamError::CaptureFailed),
                }
            }
            #[cfg(all(target_os = "linux", feature = "linux-capture"))]
            Backend::Portal(cap) => {
                use crate::capture_health::{action, Action, Observation};
                let force = self.last.is_none();
                let fetched = cap.capture_rgba(force);
                // Ask whether the stream is alive BEFORE deciding what a
                // missing buffer means. Re-emitting the last frame past the end
                // of the stream is what froze the phone with no error.
                let observed = if let Some(reason) = cap.stream_ended() {
                    eprintln!("[module11] portal capture stream ended: {reason}");
                    Observation::Ended
                } else if matches!(fetched, Ok(Some(_))) {
                    Observation::Fresh
                } else {
                    if let Err(e) = &fetched {
                        eprintln!("[module11] portal capture error: {e}");
                    }
                    Observation::Quiet
                };
                match (action(observed, self.last.is_some()), fetched) {
                    (Action::Serve, Ok(Some(frame))) => {
                        self.width = frame.width;
                        self.height = frame.height;
                        self.last = Some(frame.clone());
                        Ok(frame)
                    }
                    // Serve without a frame cannot arise; fail closed anyway.
                    (Action::Serve, _) => Err(StreamError::CaptureFailed),
                    (Action::ReuseLast, _) => self.last.clone().ok_or(StreamError::CaptureFailed),
                    (Action::Fault, _) => Err(StreamError::CaptureFailed),
                }
            }
            Backend::Synthetic { frame } => {
                *frame = frame.wrapping_add(1);
                Ok(synthetic_frame(self.width, self.height))
            }
        }
    }
}

/// Result of a one-shot capture: the frame plus whether it came from the real
/// screen backend (vs the synthetic fallback).
pub struct OneShot {
    pub width: u32,
    pub height: u32,
    pub real: bool,
    pub frame: RawFrame,
}

/// Capture a single frame from the primary screen. Real pixels on Windows with
/// a GPU; synthetic gradient otherwise. Intended for one-off screenshot
/// requests (a fresh capturer is created and dropped each call) — the
/// continuous stream uses a long-lived `ScreenCapturer` via `ScreenStream`.
pub fn capture_one() -> Result<OneShot, StreamError> {
    let mut cap = ScreenCapturer::new(1920, 1080);
    let real = cap.is_real();
    let frame = cap.capture()?;
    Ok(OneShot {
        width: frame.width,
        height: frame.height,
        real,
        frame,
    })
}

/// The original 640×360-style RGBA gradient, sized to the requested
/// dimensions. Kept as the deterministic fallback the pipeline was built on.
pub fn synthetic_frame(width: u32, height: u32) -> RawFrame {
    let mut data = vec![0u8; (width * height * 4) as usize];
    for y in 0..height {
        for x in 0..width {
            let i = ((y * width + x) * 4) as usize;
            data[i] = (x & 0xFF) as u8; // R
            data[i + 1] = (y & 0xFF) as u8; // G
            data[i + 2] = 128; // B
            data[i + 3] = 255; // A
        }
    }
    RawFrame { data, width, height }
}

#[cfg(windows)]
mod dxgi {
    use crate::types::RawFrame;
    use windows::core::Interface;
    use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
        D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
        D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    };
    use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
        DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTPUT_DESC,
    };

    /// How long `AcquireNextFrame` waits for a fresh frame before reporting
    /// "no change" (per streaming tick).
    const ACQUIRE_TIMEOUT_MS: u32 = 16;

    /// Persistent DXGI Desktop Duplication capturer for one monitor output.
    pub struct DxgiCapturer {
        monitor_index: u32,
        device: ID3D11Device,
        context: ID3D11DeviceContext,
        duplication: IDXGIOutputDuplication,
        staging: ID3D11Texture2D,
        width: u32,
        height: u32,
    }

    impl DxgiCapturer {
        pub fn new(monitor_index: u32) -> Result<Self, String> {
            unsafe {
                let (device, context) = create_device()?;
                let (duplication, width, height) =
                    create_duplication(&device, monitor_index)?;
                let staging = create_staging(&device, width, height)?;
                Ok(Self {
                    monitor_index,
                    device,
                    context,
                    duplication,
                    staging,
                    width,
                    height,
                })
            }
        }

        pub fn dimensions(&self) -> (u32, u32) {
            (self.width, self.height)
        }

        /// Grab one frame. Returns `Ok(None)` when the desktop hasn't changed
        /// since the last acquire (unless `force`). Recreates the duplication
        /// on ACCESS_LOST (mode change, secure-desktop transition, etc.).
        ///
        /// DXGI gotcha handled here: the first `AcquireNextFrame` after
        /// `DuplicateOutput` (and any acquire with `LastPresentTime == 0`)
        /// hands back a *resurfaced* frame whose desktop image can be blank —
        /// only frames with a non-zero present time are guaranteed to carry
        /// real pixels. In `force` mode we poll until such a frame arrives
        /// (a blinking caret / clock / cursor on any live desktop presents
        /// within a second), keeping the last frame as a fallback.
        pub fn capture_rgba(&mut self, force: bool) -> Result<Option<RawFrame>, String> {
            unsafe {
                let (attempts, timeout) = if force {
                    (30u32, 100u32) // up to ~3s waiting for a real present
                } else {
                    (1, ACQUIRE_TIMEOUT_MS)
                };
                let mut fallback: Option<RawFrame> = None;
                for _ in 0..attempts {
                    let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
                    let mut resource: Option<IDXGIResource> = None;
                    match self
                        .duplication
                        .AcquireNextFrame(timeout, &mut frame_info, &mut resource)
                    {
                        Ok(()) => {
                            let has_image = frame_info.LastPresentTime != 0;
                            let out = self.copy_frame(resource);
                            let _ = self.duplication.ReleaseFrame();
                            let frame = out?;
                            if has_image || !force {
                                return Ok(Some(frame));
                            }
                            // resurfaced/empty frame — remember it, keep polling
                            fallback = Some(frame);
                        }
                        Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {
                            if force {
                                continue;
                            }
                            return Ok(None);
                        }
                        Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                            self.recreate()?;
                            continue;
                        }
                        Err(e) => return Err(format!("AcquireNextFrame: {e}")),
                    }
                }
                Ok(fallback)
            }
        }

        unsafe fn copy_frame(
            &self,
            resource: Option<IDXGIResource>,
        ) -> Result<RawFrame, String> {
            let resource = resource.ok_or_else(|| "no desktop resource".to_string())?;
            let texture: ID3D11Texture2D = resource
                .cast()
                .map_err(|e| format!("cast ID3D11Texture2D: {e}"))?;

            self.context.CopyResource(&self.staging, &texture);

            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.context
                .Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|e| format!("Map: {e}"))?;

            let row_pitch = mapped.RowPitch as usize;
            let w = self.width as usize;
            let h = self.height as usize;
            let mut data = vec![0u8; w * h * 4];
            let src = std::slice::from_raw_parts(mapped.pData as *const u8, row_pitch * h);
            // BGRA (DXGI) -> RGBA (module convention: data[i] = R).
            for y in 0..h {
                let src_row = &src[y * row_pitch..y * row_pitch + w * 4];
                let dst_row = &mut data[y * w * 4..(y + 1) * w * 4];
                for x in 0..w {
                    let s = x * 4;
                    dst_row[s] = src_row[s + 2]; // R <- B
                    dst_row[s + 1] = src_row[s + 1]; // G
                    dst_row[s + 2] = src_row[s]; // B <- R
                    dst_row[s + 3] = 255; // opaque
                }
            }

            self.context.Unmap(&self.staging, 0);
            Ok(RawFrame {
                data,
                width: self.width,
                height: self.height,
            })
        }

        unsafe fn recreate(&mut self) -> Result<(), String> {
            let (duplication, width, height) =
                create_duplication(&self.device, self.monitor_index)?;
            if width != self.width || height != self.height {
                self.staging = create_staging(&self.device, width, height)?;
                self.width = width;
                self.height = height;
            }
            self.duplication = duplication;
            Ok(())
        }
    }

    unsafe fn create_device() -> Result<(ID3D11Device, ID3D11DeviceContext), String> {
        let mut device = None;
        let mut context = None;
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .map_err(|e| format!("D3D11CreateDevice: {e}"))?;
        let device = device.ok_or_else(|| "D3D11 device is None".to_string())?;
        let context = context.ok_or_else(|| "D3D11 context is None".to_string())?;
        Ok((device, context))
    }

    unsafe fn create_duplication(
        device: &ID3D11Device,
        monitor_index: u32,
    ) -> Result<(IDXGIOutputDuplication, u32, u32), String> {
        let factory: IDXGIFactory1 =
            CreateDXGIFactory1().map_err(|e| format!("CreateDXGIFactory1: {e}"))?;
        let adapter = factory
            .EnumAdapters1(0)
            .map_err(|e| format!("EnumAdapters1: {e}"))?;
        let output = adapter
            .EnumOutputs(monitor_index)
            .map_err(|e| format!("EnumOutputs({monitor_index}): {e}"))?;
        let desc: DXGI_OUTPUT_DESC = output.GetDesc().map_err(|e| format!("GetDesc: {e}"))?;
        let width = (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) as u32;
        let height = (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) as u32;
        let output1: IDXGIOutput1 = output.cast().map_err(|e| format!("cast IDXGIOutput1: {e}"))?;
        let duplication = output1
            .DuplicateOutput(device)
            .map_err(|e| format!("DuplicateOutput: {e}"))?;
        Ok((duplication, width, height))
    }

    unsafe fn create_staging(
        device: &ID3D11Device,
        width: u32,
        height: u32,
    ) -> Result<ID3D11Texture2D, String> {
        let staging_desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut staging: Option<ID3D11Texture2D> = None;
        device
            .CreateTexture2D(&staging_desc, None, Some(&mut staging))
            .map_err(|e| format!("CreateTexture2D: {e}"))?;
        staging.ok_or_else(|| "staging texture is None".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_frame_has_expected_shape() {
        let f = synthetic_frame(8, 4);
        assert_eq!(f.width, 8);
        assert_eq!(f.height, 4);
        assert_eq!(f.data.len(), 8 * 4 * 4);
        // top-left pixel: R=0, G=0, B=128, A=255
        assert_eq!(&f.data[0..4], &[0, 0, 128, 255]);
    }

    #[test]
    fn fallback_capturer_produces_frames() {
        // Deliberately the synthetic backend, on every platform. This test is
        // named for the fallback and only ever meant to cover it; going through
        // `new()` meant it tested whichever backend the host happened to have —
        // and opened a screen-share portal on Linux to find out.
        let mut cap = ScreenCapturer::synthetic(320, 240);
        assert!(
            !cap.is_real(),
            "this test must exercise the synthetic backend"
        );
        let (w, h) = cap.dimensions();
        assert!(w > 0 && h > 0);
        let frame = cap.capture().expect("capture");
        assert_eq!(frame.data.len(), (w * h * 4) as usize);
    }
}

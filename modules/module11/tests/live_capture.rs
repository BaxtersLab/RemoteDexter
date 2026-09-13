//! Hardware-gated live screen-capture proof.
//!
//! Runs only when `RD_USE_HW=1` (real GPU + interactive desktop). Captures a
//! real frame from the platform backend and proves it is genuine — real
//! monitor dimensions, not the synthetic gradient, not blank — then writes a
//! BMP to the temp dir for visual confirmation.
//!
//! Windows takes that frame from DXGI Desktop Duplication, Linux from
//! xdg-desktop-portal ScreenCast over PipeWire. The assertions are shared,
//! because the bar is the same either way: a real picture of the real desktop.

use module11::capture::ScreenCapturer;

/// Detected primary-monitor size mismatch is fine (multi-mon/DPI); we only
/// assert the capture is real and non-degenerate.
#[cfg(windows)]
#[test]
fn live_dxgi_capture_is_real() {
    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping live_dxgi_capture_is_real (set RD_USE_HW=1)");
        return;
    }
    let mut cap = ScreenCapturer::new(1920, 1080);
    assert!(cap.is_real(), "DXGI backend not active — no real screen capture");
    assert_real_desktop_frame(&mut cap, "rd_live_capture.bmp");
}

/// The Wayland twin. The first run raises GNOME's screen-share dialog and needs
/// one click; the portal then returns a restore token and every later run is
/// silent. If no grant is in force this fails rather than quietly streaming the
/// synthetic gradient — a host that serves a fake desktop while reporting
/// success is precisely the failure worth failing loudly on.
#[cfg(all(target_os = "linux", feature = "linux-capture"))]
#[test]
fn live_portal_capture_is_real() {
    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping live_portal_capture_is_real (set RD_USE_HW=1)");
        return;
    }
    let mut cap = ScreenCapturer::new(1920, 1080);
    assert!(
        cap.is_real(),
        "portal backend not active — capture fell back to synthetic frames"
    );
    assert_real_desktop_frame(&mut cap, "rd_live_capture_linux.bmp");
}

#[allow(dead_code)]
fn assert_real_desktop_frame(cap: &mut ScreenCapturer, out_name: &str) {
    let (w, h) = cap.dimensions();
    eprintln!("captured monitor: {w}x{h}");
    assert!(w >= 640 && h >= 480, "implausible screen size {w}x{h}");
    // A real monitor is not the 640x360 the old synthetic stub hardcoded.
    assert!(!(w == 640 && h == 360), "got the old synthetic 640x360 size");

    let frame = cap.capture().expect("capture");
    assert_eq!(frame.data.len(), (w * h * 4) as usize);

    // Prove it is not the synthetic gradient: that frame's pixel (x,y) is
    // exactly (x&0xFF, y&0xFF, 128, 255). Count matches over a sample grid.
    let mut gradient_matches = 0usize;
    let mut samples = 0usize;
    let mut nonzero = 0usize;
    for y in (0..h).step_by((h / 20).max(1) as usize) {
        for x in (0..w).step_by((w / 20).max(1) as usize) {
            let i = ((y * w + x) * 4) as usize;
            let (r, g, b) = (frame.data[i], frame.data[i + 1], frame.data[i + 2]);
            if r == (x & 0xFF) as u8 && g == (y & 0xFF) as u8 && b == 128 {
                gradient_matches += 1;
            }
            if r != 0 || g != 0 || b != 0 {
                nonzero += 1;
            }
            samples += 1;
        }
    }
    eprintln!("samples={samples} gradient_matches={gradient_matches} nonzero={nonzero}");
    assert!(nonzero > 0, "captured frame is entirely black");
    assert!(
        gradient_matches * 2 < samples,
        "frame looks like the synthetic gradient ({gradient_matches}/{samples})"
    );

    // Visual proof.
    let out = std::env::temp_dir().join(out_name);
    write_bmp(&out, &frame.data, w, h).expect("write bmp");
    eprintln!("wrote proof screenshot: {}", out.display());
    assert!(out.exists());
}

/// Minimal 24-bit BMP writer (bottom-up, BGR) — no dependencies. Input is
/// RGBA top-down.
#[allow(dead_code)]
fn write_bmp(path: &std::path::Path, rgba: &[u8], w: u32, h: u32) -> std::io::Result<()> {
    use std::io::Write;
    let row_bytes = (w * 3 + 3) & !3; // padded to 4
    let pixel_data = row_bytes * h;
    let file_size = 54 + pixel_data;
    let mut f = std::fs::File::create(path)?;

    // BITMAPFILEHEADER (14) + BITMAPINFOHEADER (40)
    f.write_all(b"BM")?;
    f.write_all(&file_size.to_le_bytes())?;
    f.write_all(&0u32.to_le_bytes())?; // reserved
    f.write_all(&54u32.to_le_bytes())?; // pixel offset
    f.write_all(&40u32.to_le_bytes())?; // header size
    f.write_all(&(w as i32).to_le_bytes())?;
    f.write_all(&(h as i32).to_le_bytes())?; // positive = bottom-up
    f.write_all(&1u16.to_le_bytes())?; // planes
    f.write_all(&24u16.to_le_bytes())?; // bpp
    f.write_all(&0u32.to_le_bytes())?; // compression = BI_RGB
    f.write_all(&pixel_data.to_le_bytes())?;
    f.write_all(&2835i32.to_le_bytes())?; // x ppm
    f.write_all(&2835i32.to_le_bytes())?; // y ppm
    f.write_all(&0u32.to_le_bytes())?; // colors used
    f.write_all(&0u32.to_le_bytes())?; // important colors

    let pad = vec![0u8; (row_bytes - w * 3) as usize];
    for y in (0..h).rev() {
        let mut row = Vec::with_capacity((w * 3) as usize);
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            row.push(rgba[i + 2]); // B
            row.push(rgba[i + 1]); // G
            row.push(rgba[i]); // R
        }
        f.write_all(&row)?;
        f.write_all(&pad)?;
    }
    Ok(())
}

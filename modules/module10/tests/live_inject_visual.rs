//! Hardware-gated proof that the **compositor** acts on injected input, not
//! just the kernel.
//!
//! `live_inject.rs` proves the events reach the kernel with the right codes by
//! reading them back off our own evdev nodes. That is necessary but not
//! sufficient: a device can publish perfect events that libinput or the
//! compositor ignores, which is exactly how the X11-under-Wayland failure looks
//! (events accepted, nothing happens).
//!
//! So this test closes the loop with the other half of the host — it moves the
//! pointer to a known coordinate, photographs the desktop through the portal
//! capture backend with the cursor composited in, and checks the picture
//! changed *at that coordinate*. Two positions are used and each is checked in
//! both directions (cursor arrived here, cursor left there), so a busy desktop
//! repainting on its own cannot pass it.
//!
//! Requires `RD_USE_HW=1` and an approved screen-share grant. It moves the real
//! pointer and never clicks.

#![cfg(all(target_os = "linux", feature = "linux-input"))]

use module10::inject_linux::{set_virtual_screen, UinputInjector};
use module10::message::{InputControlMessage, MouseMoveMode};
use module11::capture::ScreenCapturer;
use module11::types::RawFrame;

/// Half-width of the box examined around each pointer position. A GNOME cursor
/// is roughly 24 px; 40 gives it room without swallowing half the screen.
const BOX_HALF: i64 = 40;

/// Per-channel difference that counts as a changed pixel. Above the noise of
/// JPEG-free capture (there is none — these are raw RGBA) but below a real
/// cursor edge.
const CHANNEL_DELTA: i32 = 24;

#[test]
fn injected_pointer_move_is_visible_on_the_captured_desktop() {
    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping injected_pointer_move_is_visible_on_the_captured_desktop (RD_USE_HW=1)");
        return;
    }

    let mut cap = ScreenCapturer::new(1920, 1080);
    assert!(
        cap.is_real(),
        "portal capture is not live — cannot photograph anything"
    );
    let (w, h) = cap.dimensions();
    eprintln!("desktop {w}x{h}");

    // The injector must normalize against the size the capture actually
    // reports, or the cursor lands somewhere other than where we look for it.
    set_virtual_screen(w, h);
    let mut inj = UinputInjector::new().expect("create uinput devices");

    // Two positions far apart, both inset from the edges so the whole
    // inspection box stays on screen.
    let a = (w as i64 / 5, h as i64 / 4);
    let b = (w as i64 * 4 / 5, h as i64 * 3 / 4);

    let frame_a = park_and_capture(&mut inj, &mut cap, a);
    let frame_b = park_and_capture(&mut inj, &mut cap, b);

    let at_a = changed_in_box(&frame_a, &frame_b, a);
    let at_b = changed_in_box(&frame_a, &frame_b, b);
    // A control region the pointer never visited. Whatever this reports is the
    // desktop's own churn — clocks, carets, notifications — and the pointer
    // boxes have to beat it to mean anything.
    let control = (w as i64 / 2, h as i64 / 10);
    let at_control = changed_in_box(&frame_a, &frame_b, control);

    eprintln!(
        "changed px — left {a:?}: {at_a}, arrived {b:?}: {at_b}, control {control:?}: {at_control}"
    );

    write_bmp(
        &std::env::temp_dir().join("rd_inject_visual_a.bmp"),
        &frame_a.data,
        frame_a.width,
        frame_a.height,
    )
    .expect("write frame a");
    write_bmp(
        &std::env::temp_dir().join("rd_inject_visual_b.bmp"),
        &frame_b.data,
        frame_b.width,
        frame_b.height,
    )
    .expect("write frame b");
    eprintln!(
        "wrote {} and {}",
        std::env::temp_dir().join("rd_inject_visual_a.bmp").display(),
        std::env::temp_dir().join("rd_inject_visual_b.bmp").display()
    );

    // A cursor is a couple of hundred opaque pixels; require a decent fraction
    // of that at both ends of the move.
    assert!(
        at_b > 60,
        "no visible change where the pointer arrived ({b:?}): {at_b} px — \
         the compositor did not act on the injected move"
    );
    assert!(
        at_a > 60,
        "no visible change where the pointer left ({a:?}): {at_a} px"
    );
    assert!(
        at_b > at_control * 2 && at_a > at_control * 2,
        "pointer boxes ({at_a}, {at_b}) are not clearly above desktop churn ({at_control})"
    );
}

/// Move the pointer to `(x, y)`, let the compositor redraw, and take a frame.
fn park_and_capture(
    inj: &mut UinputInjector,
    cap: &mut ScreenCapturer,
    (x, y): (i64, i64),
) -> RawFrame {
    inj.inject(&InputControlMessage::MouseMove {
        mode: MouseMoveMode::Absolute,
        dx: 0,
        dy: 0,
        abs_x: x as u32,
        abs_y: y as u32,
    })
    .expect("inject absolute move");
    // The stream is damage-driven: give the compositor time to repaint the
    // cursor and PipeWire time to deliver the buffer that contains it.
    std::thread::sleep(std::time::Duration::from_millis(600));
    // Two grabs — the first may still be the pre-move frame that was already
    // queued when the move landed.
    let _ = cap.capture();
    std::thread::sleep(std::time::Duration::from_millis(250));
    cap.capture().expect("capture")
}

/// Count pixels differing by more than `CHANNEL_DELTA` on any channel inside
/// the box centred on `(cx, cy)`.
fn changed_in_box(a: &RawFrame, b: &RawFrame, (cx, cy): (i64, i64)) -> usize {
    assert_eq!(a.width, b.width);
    assert_eq!(a.height, b.height);
    let w = a.width as i64;
    let h = a.height as i64;
    let mut count = 0usize;
    for y in (cy - BOX_HALF).max(0)..(cy + BOX_HALF).min(h) {
        for x in (cx - BOX_HALF).max(0)..(cx + BOX_HALF).min(w) {
            let i = ((y * w + x) * 4) as usize;
            let d = |k: usize| (a.data[i + k] as i32 - b.data[i + k] as i32).abs();
            if d(0) > CHANNEL_DELTA || d(1) > CHANNEL_DELTA || d(2) > CHANNEL_DELTA {
                count += 1;
            }
        }
    }
    count
}

/// Minimal 24-bit BMP writer (bottom-up, BGR) — no dependencies. Input is
/// RGBA top-down. Same shape as module11's live capture proof.
fn write_bmp(path: &std::path::Path, rgba: &[u8], w: u32, h: u32) -> std::io::Result<()> {
    use std::io::Write;
    let row_bytes = (w * 3 + 3) & !3;
    let pixel_data = row_bytes * h;
    let file_size = 54 + pixel_data;
    let mut f = std::fs::File::create(path)?;
    f.write_all(b"BM")?;
    f.write_all(&file_size.to_le_bytes())?;
    f.write_all(&0u32.to_le_bytes())?;
    f.write_all(&54u32.to_le_bytes())?;
    f.write_all(&40u32.to_le_bytes())?;
    f.write_all(&(w as i32).to_le_bytes())?;
    f.write_all(&(h as i32).to_le_bytes())?;
    f.write_all(&1u16.to_le_bytes())?;
    f.write_all(&24u16.to_le_bytes())?;
    f.write_all(&0u32.to_le_bytes())?;
    f.write_all(&pixel_data.to_le_bytes())?;
    f.write_all(&2835i32.to_le_bytes())?;
    f.write_all(&2835i32.to_le_bytes())?;
    f.write_all(&0u32.to_le_bytes())?;
    f.write_all(&0u32.to_le_bytes())?;
    let pad = vec![0u8; (row_bytes - w * 3) as usize];
    for y in (0..h).rev() {
        let mut row = Vec::with_capacity((w * 3) as usize);
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            row.push(rgba[i + 2]);
            row.push(rgba[i + 1]);
            row.push(rgba[i]);
        }
        f.write_all(&row)?;
        f.write_all(&pad)?;
    }
    Ok(())
}

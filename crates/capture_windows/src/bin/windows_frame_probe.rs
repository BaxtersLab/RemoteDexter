//! `windows-frame-probe` — answers "is the raw capture white?" before anyone
//! argues about encoders.
//!
//! SPDX-License-Identifier: AGPL-3.0-only
//!
//! The reported Windows symptom is a white screen on the phone. That symptom is
//! consistent with a fault in any of five layers — capture, encode, transport,
//! decode, render — and the cheapest way to cut the search in half is to look
//! at the very first buffer, before it has been encoded or sent anywhere. This
//! binary does that and nothing else.
//!
//! It runs on the Windows-owned box, at an ordinary user's privilege, in the
//! interactive session. It opens no socket, starts no service, and sends
//! nothing anywhere: the frame stays on that machine, and what leaves is a
//! summary and (optionally) a bitmap the operator chooses to copy.
//!
//! ```text
//! windows-frame-probe.exe                 # summarise one frame
//! windows-frame-probe.exe --save shot.bmp # and write it out to look at
//! windows-frame-probe.exe --frames 30     # sample a run of frames
//! windows-frame-probe.exe --seconds 30    # sample for a wall-clock duration
//! windows-frame-probe.exe --backend gdi   # force one backend and pin it
//! ```
//!
//! `--backend` and `--seconds` exist for a second question the probe turned out
//! to be the right tool for: **the operator's display flickers white while
//! capture is live.** Answering it needs a run long enough for a person to
//! watch, and it needs to name a backend -- and the default policy switches
//! backend on its own, silently, after four idle frames. Without pinning, "I
//! ran the capture and it flickered" is not evidence about DXGI or about GDI.
//!
//! Exit codes are the point — this is evidence, so it has to be able to fail:
//!   0  a frame was captured and it contains more than one colour
//!   1  a frame was captured and every pixel is identical  ← the white screen
//!   2  no frame could be captured at all
//!
//! Exit 1 localises the fault to capture. Exit 0 exonerates capture and moves
//! the search to encode/transport/decode/render.

use capture_windows::pixels::{self, BYTES_PER_PIXEL};
use capture_windows::{primary_display, WindowsDesktopCapture};
use session_core::{FrameSource, SurfaceId};
use sha2::{Digest, Sha256};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut save: Option<String> = None;
    let mut frames: u32 = 1;
    let mut seconds: Option<u64> = None;
    let mut forced: Option<String> = None;
    let mut quiet = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--save" => {
                i += 1;
                match args.get(i) {
                    Some(p) => save = Some(p.clone()),
                    None => {
                        eprintln!("--save needs a file path");
                        return std::process::ExitCode::from(2);
                    }
                }
            }
            "--frames" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u32>().ok()) {
                    Some(n) if n > 0 => frames = n,
                    _ => {
                        eprintln!("--frames needs a positive number");
                        return std::process::ExitCode::from(2);
                    }
                }
            }
            "--seconds" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                    Some(n) if n > 0 => seconds = Some(n),
                    _ => {
                        eprintln!("--seconds needs a positive number");
                        return std::process::ExitCode::from(2);
                    }
                }
            }
            "--backend" => {
                i += 1;
                match args.get(i) {
                    Some(v) => forced = Some(v.clone()),
                    None => {
                        eprintln!("--backend needs dxgi, gdi or auto");
                        return std::process::ExitCode::from(2);
                    }
                }
            }
            // A run long enough to watch produces thousands of frames, and
            // per-frame lines would then be the slowest thing in the loop.
            "--quiet" => quiet = true,
            "-h" | "--help" => {
                println!("{}", HELP);
                return std::process::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}\n\n{HELP}");
                return std::process::ExitCode::from(2);
            }
        }
        i += 1;
    }

    println!("windows-frame-probe — raw capture evidence, before any encoding");
    println!();

    match primary_display() {
        Ok(d) => {
            println!("display        {}", d.name);
            println!("geometry       {}x{} at {:?}", d.width, d.height, d.origin);
            println!("primary        {}", d.is_primary);
            println!("rotation       {:?}", d.rotation);
        }
        Err(e) => {
            println!("display        COULD NOT ENUMERATE: {e:?}");
            return std::process::ExitCode::from(2);
        }
    }
    if let Ok(all) = capture_windows::displays() {
        println!("displays       {} attached", all.len());
        for d in &all {
            println!(
                "               {} {}x{} at {:?}",
                d.name, d.width, d.height, d.origin
            );
        }
    }
    println!();

    // `--backend` beats the environment variable, so a run can be scripted
    // without disturbing whatever the shell already has set.
    let preference = match forced.as_deref() {
        Some(v) => capture_windows::backend_preference_from(Some(v)),
        None => capture_windows::backend_preference(),
    };
    let preference = match preference {
        Ok(p) => p,
        Err(e) => {
            println!("RESULT         BAD BACKEND REQUEST: {e:?}");
            return std::process::ExitCode::from(2);
        }
    };
    println!("backend req    {preference:?}");
    if let Some(secs) = seconds {
        println!("duration       {secs}s (--frames ignored)");
    }
    println!();

    let mut cap = match WindowsDesktopCapture::with_preference(preference) {
        Ok(c) => c,
        Err(e) => {
            println!("RESULT         NO CAPTURE — {e:?}");
            return std::process::ExitCode::from(2);
        }
    };

    let mut any_non_uniform = false;
    let mut last: Option<Vec<u8>> = None;
    let mut captured_any = false;
    // A silent backend change is the thing that makes an unpinned run
    // uninterpretable, so it is called out the moment it happens.
    let mut backend_at_start = cap.backend();
    let mut backend_changes: Vec<(u32, String)> = Vec::new();
    let mut failures: u32 = 0;
    let started = std::time::Instant::now();
    let deadline = seconds.map(|s| started + std::time::Duration::from_secs(s));
    let total = if deadline.is_some() { u32::MAX } else { frames };

    for n in 1..=total {
        if let Some(end) = deadline {
            if std::time::Instant::now() >= end {
                println!(
                    "stopped        after {n} frames, {:?} elapsed",
                    started.elapsed()
                );
                break;
            }
        }
        match cap.capture(SurfaceId::DESKTOP) {
            Ok(frame) => {
                captured_any = true;
                let uniform = pixels::is_uniform(&frame.data);
                any_non_uniform |= !uniform;
                let distinct = pixels::distinct_pixels(&frame.data, 256);
                let digest = Sha256::digest(&frame.data);
                let changed = match &last {
                    Some(prev) => {
                        if prev == &frame.data {
                            "identical to previous"
                        } else {
                            "differs from previous"
                        }
                    }
                    None => "first",
                };
                if cap.backend() != backend_at_start {
                    let note = format!("{backend_at_start:?} -> {:?}", cap.backend());
                    println!("!! frame {n}: BACKEND CHANGED {note}");
                    backend_changes.push((n, note));
                    backend_at_start = cap.backend();
                }
                if quiet {
                    last = Some(frame.data);
                    continue;
                }
                println!(
                    "frame {n:<3}    {}x{}  {} bytes  backend={:?}",
                    frame.width,
                    frame.height,
                    frame.data.len(),
                    cap.backend()
                );
                println!(
                    "               uniform={uniform}  distinct_colours={}{}  {changed}",
                    distinct,
                    if distinct >= 256 { "+" } else { "" }
                );
                println!("               sha256={:x}", digest);
                if uniform && frame.data.len() >= BYTES_PER_PIXEL {
                    let px = &frame.data[..BYTES_PER_PIXEL];
                    println!(
                        "               THE WHOLE FRAME IS ONE COLOUR: R={} G={} B={} A={}",
                        px[0], px[1], px[2], px[3]
                    );
                }
                let expected = frame.width as usize * frame.height as usize * BYTES_PER_PIXEL;
                if frame.data.len() != expected {
                    println!(
                        "               LENGTH MISMATCH: {} bytes for {}x{} (expected {expected})",
                        frame.data.len(),
                        frame.width,
                        frame.height
                    );
                }
                if n == frames {
                    if let Some(path) = &save {
                        match write_bmp(path, &frame.data, frame.width, frame.height) {
                            Ok(()) => println!("               wrote {path}"),
                            Err(e) => println!("               could not write {path}: {e}"),
                        }
                    }
                }
                last = Some(frame.data);
            }
            Err(e) => {
                failures += 1;
                if quiet && failures > 20 {
                    continue;
                }
                println!("frame {n:<3}    CAPTURE FAILED — {e:?}");
            }
        }
    }

    println!();
    println!(
        "backend        started {:?}, ended {:?}, {} change(s){}",
        cap.backend(),
        cap.backend(),
        backend_changes.len(),
        if backend_changes.is_empty() {
            String::new()
        } else {
            format!(" at frames {:?}", backend_changes)
        }
    );
    println!("failures       {failures}");
    println!("elapsed        {:?}", started.elapsed());
    println!();
    if !captured_any {
        println!("RESULT         NO FRAME CAPTURED. The fault is at or below capture.");
        return std::process::ExitCode::from(2);
    }
    if any_non_uniform {
        println!("RESULT         CAPTURE IS PRODUCING REAL PIXELS.");
        println!("               A white screen on the phone is NOT a capture fault —");
        println!("               look at encode, transport, decode and render.");
        std::process::ExitCode::SUCCESS
    } else {
        println!("RESULT         EVERY FRAME IS A SINGLE COLOUR.");
        println!("               The fault is IN CAPTURE. Nothing downstream is implicated:");
        println!("               the encoder is faithfully encoding a blank screen.");
        std::process::ExitCode::from(1)
    }
}

const HELP: &str = "\
windows-frame-probe — capture one desktop frame and describe it

  --save <path.bmp>   write the last captured frame out as a bitmap
  --frames <n>        capture n frames (default 1) to see whether they change
  --seconds <n>       capture for n seconds instead of a frame count
  --backend <b>       dxgi | gdi | auto -- force one and pin it there
  --quiet             suppress the per-frame lines, keep the summary
  -h, --help          this

RD_CAPTURE_BACKEND does the same thing as --backend, for callers that cannot
pass arguments. --backend wins when both are set.

exit 0  captured, more than one colour   (capture is fine)
exit 1  captured, single colour          (the fault is in capture)
exit 2  nothing captured
";

/// Write a 32-bit BMP. No dependency, and Windows opens it by double-click,
/// which matters when the person running this is standing at the machine.
///
/// BMP rows are bottom-up, and the file wants BGRA; the frame is top-down RGBA.
fn write_bmp(path: &str, rgba: &[u8], width: u32, height: u32) -> std::io::Result<()> {
    use std::io::Write;
    let (w, h) = (width as usize, height as usize);
    let row = w * BYTES_PER_PIXEL;
    if rgba.len() < row * h {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame is smaller than its stated dimensions",
        ));
    }
    let pixel_bytes = row * h;
    let file_size = 54 + pixel_bytes;
    let mut out = Vec::with_capacity(file_size);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(file_size as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&54u32.to_le_bytes()); // pixel data offset
    out.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER size
    out.extend_from_slice(&(width as i32).to_le_bytes());
    out.extend_from_slice(&(height as i32).to_le_bytes()); // positive: bottom-up
    out.extend_from_slice(&1u16.to_le_bytes()); // planes
    out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    out.extend_from_slice(&(pixel_bytes as u32).to_le_bytes());
    out.extend_from_slice(&2835i32.to_le_bytes()); // ~72 dpi
    out.extend_from_slice(&2835i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // palette colours
    out.extend_from_slice(&0u32.to_le_bytes()); // important colours
    for y in (0..h).rev() {
        for x in 0..w {
            let i = y * row + x * BYTES_PER_PIXEL;
            let px = &rgba[i..i + BYTES_PER_PIXEL];
            out.extend_from_slice(&[px[2], px[1], px[0], px[3]]); // RGBA -> BGRA
        }
    }
    std::fs::File::create(path)?.write_all(&out)
}

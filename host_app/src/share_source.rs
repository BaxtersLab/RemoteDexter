//! What this host can share, and how it captures it — the one place the two
//! platforms differ.
//!
//! **Both platforms now share the desktop, and only the desktop.** Linux always
//! did — Wayland refuses to enumerate windows or capture one by id on
//! principle, so there was never a second option. Windows shared individual
//! windows until Block 8, via `PrintWindow`, because that code was absorbed
//! from VoDesktop, where an outside contractor is given one window on somebody
//! else's machine. That is not what RemoteDexter is: it is one person reaching
//! their own workstation, and a remote desktop that can only show one window is
//! not the product.
//!
//! So Block 8 replaced the Windows path with `capture_windows` — DXGI Desktop
//! Duplication with a GDI fallback — and deleted the per-window crate outright.
//! There is no window picker on either platform, one `SurfaceKind::Desktop`
//! surface on both, and one reserved id (`SurfaceId::DESKTOP`) that both agree
//! on because it is defined once, in `session_core`.
//!
//! What does *not* change: every `ShareSession` gate still applies. The desktop
//! is a surface that must be permitted, capture must be granted, input must be
//! granted separately, and either can be revoked mid-session. The boundary moves
//! from "which window" to "is this paired session allowed at all" — which is the
//! boundary that actually matters when both ends belong to the same person.

use session_core::{SurfaceDescriptor, SurfaceGeometry, SurfaceId, SurfaceKind};

/// The reserved id for "this workstation's desktop".
///
/// Defined once, in `session_core`, and re-exported here so existing callers
/// keep working. It used to be declared in this file, which was fine while only
/// Linux used it; from Block 8 both platforms do, and a sentinel with two
/// definitions is a sentinel waiting to disagree with itself. The reasoning for
/// the value — why `i64::MAX` and not `u64::MAX` — lives with the constant.
pub const DESKTOP_ID: u64 = SurfaceId::DESKTOP.raw();

/// Surfaces this host offers, as `session_core`'s own descriptor type.
///
/// The local `Shareable` struct this replaced carried an `is_desktop: bool`.
/// [`SurfaceKind`] says the same thing without a boolean that can be read
/// backwards, and it is the vocabulary the authorization core already speaks —
/// so a surface cannot be described one way here and another way at the gate.
///
/// Never captures anything.
pub fn enumerate() -> Vec<SurfaceDescriptor> {
    #[cfg(target_os = "linux")]
    {
        let (w, h) = module10::inject_linux::virtual_screen();
        // Linux offers exactly one surface: the desktop. Wayland refuses to
        // enumerate windows or capture one by id on principle, so there is no
        // second entry to offer and no picker to build.
        vec![SurfaceDescriptor {
            id: SurfaceId::new(DESKTOP_ID),
            kind: SurfaceKind::Desktop,
            title: format!("Desktop ({w}x{h})"),
            geometry: Some(SurfaceGeometry::new(0, 0, w as i32, h as i32)),
        }]
    }
    #[cfg(not(target_os = "linux"))]
    {
        // One entry, like Linux. If no display can be enumerated the list is
        // empty rather than fabricated: the host then has nothing to offer and
        // says so, which is the truthful outcome for a machine with no attached
        // desktop.
        match capture_windows::primary_display() {
            Ok(d) => {
                let (l, t, r, b) = d.bounds();
                vec![SurfaceDescriptor {
                    id: SurfaceId::DESKTOP,
                    kind: SurfaceKind::Desktop,
                    title: format!("Desktop ({}x{})", d.width, d.height),
                    geometry: Some(SurfaceGeometry::new(l, t, r, b)),
                }]
            }
            Err(e) => {
                eprintln!("[host] no desktop to share: {e:?}");
                Vec::new()
            }
        }
    }
}

/// On-screen rect `(left, top, right, bottom)` of a shareable surface, or
/// `None` when it cannot be established.
///
/// The input gate clamps absolute pointer moves against this and **refuses the
/// move when it is `None`** — so returning `None` is a real decision, not a
/// convenience. On Linux the desktop's bounds are read from the DRM connectors
/// rather than by opening a capture session, because an input event must never
/// have the side effect of raising a screen-share dialog.
pub fn rect(surface: SurfaceId) -> Option<(i32, i32, i32, i32)> {
    #[cfg(target_os = "linux")]
    {
        if surface.raw() == DESKTOP_ID {
            let (w, h) = module10::inject_linux::virtual_screen();
            return Some((0, 0, w as i32, h as i32));
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        if !surface.is_desktop() {
            return None;
        }
        capture_windows::primary_display().ok().map(|d| d.bounds())
    }
}

/// Capture one surface as module11's RGBA `RawFrame` (`data[i] == R`).
///
/// Windows captures the whole desktop through DXGI Desktop Duplication (GDI
/// fallback); Linux pulls a frame off the persistent portal session. Both hand
/// back RGBA — the Windows crate converts once, inside the capture, rather than
/// returning BGRA for this function to swap in place. A frame's byte order
/// should not depend on how far it has travelled.
pub fn capture_rgba(surface: SurfaceId) -> Result<module11::RawFrame, String> {
    #[cfg(target_os = "linux")]
    {
        linux::capture(surface)
    }
    #[cfg(not(target_os = "linux"))]
    {
        windows_desktop::capture(surface)
    }
}

/// Release the platform capture session after all client producers have
/// stopped. The controller owns the ordering; this owns the platform resource.
pub fn shutdown_capture() {
    #[cfg(target_os = "linux")]
    linux::shutdown();
    #[cfg(not(target_os = "linux"))]
    windows_desktop::shutdown();
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    /// The portal session is expensive to establish (~100 ms) and shows the
    /// GNOME picker the first time, so it is opened once and held. A
    /// per-capture session would re-handshake on every frame.
    ///
    /// It is **not** held for the life of the process, which it used to be. A
    /// failed or dead session was cached permanently: `OnceLock` never
    /// re-initialises, so a refused screen-share grant, or a stream GNOME tore
    /// down on a display change, could not be recovered by reconnecting or by
    /// restarting the stream — only by restarting the host. Now the lock holds
    /// a slot that can be refilled, rate-limited so a persistent fault cannot
    /// hammer the portal ~30 times a second.
    struct Slot {
        cap: Option<module11::capture::ScreenCapturer>,
        last_attempt: Option<Instant>,
        /// Defect E: a PipeWire node is negotiated once and keeps producing its
        /// original geometry after the desktop changes size, so the stream
        /// stays apparently healthy while showing a desktop that no longer
        /// exists — and every absolute pointer coordinate is normalised against
        /// the wrong dimensions, putting taps in the wrong place.
        watch: module11::display_watch::DisplayWatch,
        last_probe: Option<Instant>,
    }

    static CAPTURER: OnceLock<Mutex<Slot>> = OnceLock::new();

    fn slot() -> &'static Mutex<Slot> {
        CAPTURER.get_or_init(|| {
            Mutex::new(Slot {
                cap: None,
                last_attempt: None,
                watch: module11::display_watch::DisplayWatch::new(),
                last_probe: None,
            })
        })
    }

    pub fn capture(surface: SurfaceId) -> Result<module11::RawFrame, String> {
        if surface.raw() != DESKTOP_ID {
            return Err(format!(
                "this host shares the desktop (id {DESKTOP_ID}); there is no window {} to capture \
                 — Wayland does not permit capturing a window by id",
                surface.raw()
            ));
        }
        let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());

        // ── defect E: has the desktop changed size under us? ──────────
        //
        // The capture cannot answer this on its own — it would be comparing its
        // frames against its own caps, which agree by construction. The DRM
        // connectors are the independent opinion, and reading them needs no
        // display-server connection (Article XIV: nothing here touches the live
        // compositor).
        //
        // Every uncertain case answers "no". A spurious rebuild tears down a
        // working stream and re-enters the portal path, which can cost the
        // operator their grant; a missed change costs a stale picture that the
        // next real change or reconnect corrects. Not symmetric.
        if guard.cap.is_some() {
            let since = guard.last_probe.map(|t| t.elapsed().as_millis() as u64);
            if module11::display_watch::DisplayWatch::due(since) {
                guard.last_probe = Some(Instant::now());
                let capture_size = guard.cap.as_ref().map(|c| c.dimensions()).unwrap_or((0, 0));
                let probed = module10::inject_linux::probe_screen_size();
                if guard.watch.observe(capture_size, probed) {
                    let (pw, ph) = probed.unwrap_or((0, 0));
                    eprintln!(
                        "[host] display changed: capture is {}x{} but the connectors report \
                         {pw}x{ph} — rebuilding the capture",
                        capture_size.0, capture_size.1
                    );
                    // Drop it and fall THROUGH to the rebuild below, in this
                    // same call, so the caller gets a frame at the new size and
                    // never sees an error.
                    //
                    // Returning Err here was the first attempt and was wrong:
                    // the stream thread treats a capture error as fatal, so a
                    // resolution change would have ENDED the session — trading
                    // a stale picture for a dropped one.
                    //
                    // Clearing last_attempt is deliberate: this is a planned
                    // replacement, not a fault, so it must not wait out the
                    // fault backoff.
                    guard.cap = None;
                    guard.last_attempt = None;
                }
            }
        }

        if guard.cap.is_none() {
            let since = guard.last_attempt.map(|t| t.elapsed().as_millis() as u64);
            if !module11::capture_health::may_rebuild(since) {
                return Err("desktop capture is unavailable".to_string());
            }
            guard.last_attempt = Some(Instant::now());
            let (w, h) = module10::inject_linux::virtual_screen();
            // Announced unconditionally: this opens a PORTAL SESSION, which is
            // the one call here that can wait on something outside this
            // process. If the log ends on this line, that is where it stopped.
            eprintln!("[capture] rebuilding the capture source at {w}x{h} — opening a portal");
            let cap = module11::capture::ScreenCapturer::new(w, h);
            eprintln!("[capture] rebuild returned (real: {})", cap.is_real());
            if cap.is_real() {
                // Absolute pointer coordinates must normalize against the size
                // the capture actually produces, or a click lands somewhere
                // other than where the viewer tapped. Re-read on every rebuild,
                // so a host that changed resolution is aimed at correctly.
                let (cw, ch) = cap.dimensions();
                module10::inject_linux::set_virtual_screen(cw, ch);
                guard.cap = Some(cap);
            } else {
                // Refuse rather than serve the synthetic gradient. A host that
                // streams a fake desktop while reporting success is worse than
                // one that plainly does not work.
                eprintln!(
                    "[host] desktop capture unavailable — the screen-share grant was refused or \
                     the portal is not running. Not falling back to synthetic frames."
                );
                return Err("desktop capture is unavailable".to_string());
            }
        }

        let result = match guard.cap.as_mut() {
            Some(cap) => cap.capture().map_err(|e| format!("{e}")),
            None => Err("desktop capture is unavailable".to_string()),
        };
        if result.is_err() {
            // Drop the dead session rather than handing back the same corpse on
            // every later call. The next attempt rebuilds it, after the backoff.
            //
            // Said out loud: dropping the capture means the NEXT stream pays a
            // fresh portal handshake, and that is exactly the expensive,
            // failure-prone step. When a black screen turns up later, the
            // question is always "who threw the capture away", and silence here
            // made that unanswerable.
            eprintln!("[capture] releasing the capture source after an error");
            guard.cap = None;
        }
        result
    }

    pub fn shutdown() {
        if let Some(cell) = CAPTURER.get() {
            let mut guard = cell.lock().unwrap_or_else(|p| p.into_inner());
            if guard.cap.is_some() {
                // The other way the capture is thrown away, and the one the
                // operator triggers by pressing Stop. The next Start pays a
                // fresh portal handshake for it.
                eprintln!("[capture] releasing the capture source on host stop");
            }
            guard.cap = None;
            // A deliberate stop is not a fault, so the next Start must not be
            // made to wait out the rebuild backoff.
            guard.last_attempt = None;
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod windows_desktop {
    use super::*;
    use session_core::FrameSource;
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
    use std::sync::{Mutex, OnceLock};

    /// **The capturer never crosses a thread boundary, and that is deliberate.**
    ///
    /// The obvious shape — a `static Mutex<Option<WindowsDesktopCapture>>`, like
    /// the Linux portal session — does not compile, and the compiler is right to
    /// refuse it. A `CreateDIBSection` pixel pointer is a raw `*mut c_void`, and
    /// GDI device contexts and bitmaps have thread affinity: a DC is destroyed
    /// when the thread that made it exits, and the D3D11 immediate context is
    /// documented as requiring external synchronisation. Slapping `unsafe impl
    /// Send` on it to get past the error would be asserting something about
    /// somebody else's driver that this project cannot check.
    ///
    /// So the capturer is owned by one dedicated thread until controller Stop,
    /// and callers ask it for frames over a channel. Only the channel
    /// ends move between threads, and those are `Send` for real reasons.
    /// Bounded at one outstanding request: a caller that falls behind should
    /// wait for the current frame, not queue stale ones.
    struct Job {
        surface: SurfaceId,
        reply: SyncSender<Result<module11::RawFrame, String>>,
    }

    struct Service {
        tx: SyncSender<Job>,
        thread: std::thread::JoinHandle<()>,
    }

    static SERVICE: OnceLock<Mutex<Option<Service>>> = OnceLock::new();

    fn service() -> Option<SyncSender<Job>> {
        let slot = SERVICE.get_or_init(|| Mutex::new(None));
        let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(service) = guard.as_ref() {
            return Some(service.tx.clone());
        }

        let (tx, rx) = sync_channel::<Job>(1);
        // The thread reports whether the capturer opened before any caller
        // waits on a frame, so "capture is unavailable" is answered
        // immediately instead of after a timeout.
        let (ready_tx, ready_rx) = sync_channel::<Result<(u32, u32), String>>(1);
        let thread = match std::thread::Builder::new()
            .name("rd-desktop-capture".into())
            .spawn(move || run(rx, ready_tx))
        {
            Ok(thread) => thread,
            Err(_) => {
                eprintln!("[host] could not start the desktop capture thread");
                return None;
            }
        };
        match ready_rx.recv() {
            Ok(Ok((w, h))) => {
                eprintln!("[host] desktop capture ready: {w}x{h}");
                *guard = Some(Service {
                    tx: tx.clone(),
                    thread,
                });
                Some(tx)
            }
            Ok(Err(e)) => {
                // Refuse rather than serve something synthetic. A host that
                // streams a fake desktop while reporting success is worse than
                // one that plainly does not work.
                eprintln!("[host] desktop capture unavailable: {e}");
                drop(tx);
                let _ = thread.join();
                None
            }
            Err(_) => {
                eprintln!("[host] the desktop capture thread stopped before reporting");
                drop(tx);
                let _ = thread.join();
                None
            }
        }
    }

    /// The capture thread. Owns the capturer; never sends it anywhere.
    fn run(rx: Receiver<Job>, ready: SyncSender<Result<(u32, u32), String>>) {
        let mut cap = match capture_windows::WindowsDesktopCapture::new() {
            Ok(c) => {
                let d = c.display();
                // Which backend, said out loud. The host used to report only
                // "capture ready", and the backend is not a detail: DXGI and
                // GDI are different code, different cost and different
                // interaction with the compositor. Three Windows rounds
                // reported "the display flickers with capture live" and none
                // of them could say which backend was live at the time,
                // because nothing ever wrote it down.
                eprintln!("[host] desktop capture backend: {:?}", c.backend());
                let _ = ready.send(Ok((d.width, d.height)));
                c
            }
            Err(e) => {
                let _ = ready.send(Err(format!("{e:?}")));
                return;
            }
        };
        // The backend can change under a running stream without anything
        // failing: four idle frames are enough for the health policy to
        // abandon DXGI for GDI, permanently and silently. A session that
        // started on one backend and finished on the other looked identical
        // in the log to one that never moved.
        let mut backend = cap.backend();
        while let Ok(job) = rx.recv() {
            let out = cap
                .capture(job.surface)
                .map(|f| module11::RawFrame {
                    data: f.data,
                    width: f.width,
                    height: f.height,
                })
                .map_err(|e| format!("{e:?}"));
            if cap.backend() != backend {
                eprintln!(
                    "[host] desktop capture backend changed: {backend:?} -> {:?}",
                    cap.backend()
                );
                backend = cap.backend();
            }
            // A caller that gave up is not an error worth logging every frame.
            let _ = job.reply.send(out);
        }
    }

    pub fn capture(surface: SurfaceId) -> Result<module11::RawFrame, String> {
        if !surface.is_desktop() {
            return Err(format!(
                "this host shares the desktop (id {DESKTOP_ID}); there is no surface {} to capture",
                surface.raw()
            ));
        }
        let tx = service().ok_or_else(|| "desktop capture is unavailable".to_string())?;
        let (rtx, rrx) = sync_channel(1);
        tx.send(Job {
            surface,
            reply: rtx,
        })
        .map_err(|_| "the desktop capture thread has stopped".to_string())?;
        rrx.recv()
            .map_err(|_| "the desktop capture thread stopped before answering".to_string())?
    }

    pub fn shutdown() {
        let Some(slot) = SERVICE.get() else {
            return;
        };
        let service = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(Service { tx, thread }) = service {
            // `run` owns the capturer. Closing its last request sender lets the
            // receive loop end, so DXGI/GDI are dropped on the creating thread.
            drop(tx);
            let _ = thread.join();
        }
    }
}

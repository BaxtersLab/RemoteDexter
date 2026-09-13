//! Full-desktop Windows capture: DXGI Desktop Duplication, with a GDI fallback.
//!
//! Replaces `crates/capture_windows_printwindow/`, which captured a single
//! window with `PrintWindow`. That was VoDesktop's policy — hand an outside
//! contractor one window on somebody else's machine — and it is not
//! RemoteDexter's. RemoteDexter is one person reaching their own workstation,
//! and a remote desktop that can only show one window is not the product. From
//! this block on, both platforms share exactly one surface: the desktop.
//!
//! ## Provenance
//!
//! SPDX-License-Identifier: AGPL-3.0-only
//!
//! This crate is original to RemoteDexter. It is written against the `windows`
//! crate and every call, type and error path is its own.
//!
//! The lifecycle it implements — acquire/`WouldBlock`/release, the
//! staging-texture copy when the surface is not in system memory, access-lost
//! rebuild, rotation handling, and the decision to fall back to GDI — is what
//! the Desktop Duplication API requires of any correct consumer.
//!
//! Choices that differ from the obvious implementation, each for a reason:
//!
//! * **Top-down DIB in the GDI path.** The obvious call requests a bottom-up bitmap and
//!   then mirrors and rotates 180° to correct it. Asking for a negative
//!   `biHeight` gets the rows in the right order from the kernel and skips both
//!   passes over every pixel.
//! * **A constant frame is a fault.** See
//!   [`health`]: the reported Windows symptom was a white screen, and a backend
//!   that returns `Ok` with one repeated colour has failed regardless of its
//!   return code.
//! * **No privacy mode, no service elevation, no magnifier backend.** Out of
//!   scope for Block 8 and deliberately not imported.
//!
//! ## Shape
//!
//! [`pixels`] and [`health`] contain no Windows types and are tested on every
//! platform — that is where stride arithmetic, channel order, rotation and the
//! capture policy live, because those are what actually break. The `#[cfg(windows)]`
//! modules below are the unsafe FFI, kept as thin as they can be made.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod health;
pub mod pixels;

use session_core::{CaptureError, Frame, FrameSource, SurfaceId};

#[cfg(windows)]
mod cursor;
#[cfg(windows)]
mod display;
#[cfg(windows)]
mod dxgi;
#[cfg(windows)]
mod gdi;

/// One attached display, as the host needs to describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayInfo {
    /// The device name, e.g. `\\.\DISPLAY1`.
    pub name: String,
    /// Top-left corner in virtual-desktop coordinates.
    pub origin: (i32, i32),
    pub width: u32,
    pub height: u32,
    /// True for the display whose origin is (0, 0).
    pub is_primary: bool,
    pub rotation: pixels::Rotation,
}

impl DisplayInfo {
    /// `(left, top, right, bottom)` in virtual-desktop coordinates, right and
    /// bottom exclusive — the convention `session_core::SurfaceGeometry` uses.
    pub fn bounds(&self) -> (i32, i32, i32, i32) {
        (
            self.origin.0,
            self.origin.1,
            self.origin.0 + self.width as i32,
            self.origin.1 + self.height as i32,
        )
    }
}

/// Enumerate attached displays.
#[cfg(windows)]
pub fn displays() -> Result<Vec<DisplayInfo>, CaptureError> {
    display::enumerate()
}

#[cfg(not(windows))]
pub fn displays() -> Result<Vec<DisplayInfo>, CaptureError> {
    Err(CaptureError::Backend(
        "DXGI desktop capture is implemented on Windows only".into(),
    ))
}

/// The primary display — origin (0, 0) — or the first attached one if no
/// display claims the origin.
///
/// Multi-monitor selection is explicitly out of scope for Block 8, so this is
/// the whole policy: capture the primary display, full-desktop, no picker.
pub fn primary_display() -> Result<DisplayInfo, CaptureError> {
    let all = displays()?;
    all.iter()
        .find(|d| d.is_primary)
        .or_else(|| all.first())
        .cloned()
        .ok_or_else(|| CaptureError::Backend("no display is attached to the desktop".into()))
}

/// The environment variable that forces a capture backend.
pub const BACKEND_ENV: &str = "RD_CAPTURE_BACKEND";

/// Which backend to open, when somebody has insisted on one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendPreference {
    /// DXGI, with GDI as the fallback it was designed to be. The product path.
    #[default]
    Auto,
    /// Desktop Duplication only. A DXGI stream that stops working stops.
    ForceDxgi,
    /// GDI `BitBlt` only. Duplication is never opened.
    ForceGdi,
}

/// Read `RD_CAPTURE_BACKEND`.
///
/// This exists for one question that could not otherwise be asked: **does a
/// symptom on the operator's screen follow DXGI or GDI?** The automatic policy
/// makes that unanswerable, because it switches backend on its own after four
/// idle frames and does not announce it -- so "I ran the capture and the display
/// flickered" names no backend at all.
///
/// Unset is [`BackendPreference::Auto`] and nothing about the product changes.
/// An unrecognised value is an **error**, not a fall-through to `Auto`: a
/// diagnostic that silently ignores a typo tells you the flicker survived DXGI
/// when what actually ran was the default.
pub fn backend_preference_from(value: Option<&str>) -> Result<BackendPreference, CaptureError> {
    match value.map(str::trim) {
        None | Some("") => Ok(BackendPreference::Auto),
        Some(v) if v.eq_ignore_ascii_case("auto") => Ok(BackendPreference::Auto),
        Some(v) if v.eq_ignore_ascii_case("dxgi") => Ok(BackendPreference::ForceDxgi),
        Some(v) if v.eq_ignore_ascii_case("gdi") => Ok(BackendPreference::ForceGdi),
        Some(other) => Err(CaptureError::Backend(format!(
            "{BACKEND_ENV}={other:?} is not a backend; use \"dxgi\", \"gdi\" or \"auto\""
        ))),
    }
}

/// [`backend_preference_from`] applied to the process environment.
pub fn backend_preference() -> Result<BackendPreference, CaptureError> {
    backend_preference_from(std::env::var(BACKEND_ENV).ok().as_deref())
}

/// The environment variable that controls the mouse pointer.
///
/// Same name and same default as Linux, deliberately: `capture_linux` reads
/// `RD_CAPTURE_CURSOR` and embeds the cursor unless told otherwise, and a
/// remote desktop whose pointer behaviour depends on which host you dialled is
/// worse than either choice.
pub const CURSOR_ENV: &str = "RD_CAPTURE_CURSOR";

/// Whether to draw the mouse pointer into captured frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CursorMode {
    /// Composite the pointer into the frame. **The default**, because a remote
    /// desktop viewer needs to see where it is pointing.
    #[default]
    Embedded,
    /// Do not draw it.
    Hidden,
}

/// Read `RD_CAPTURE_CURSOR`, matching `capture_linux::cursor_mode`.
///
/// * `hidden` — do not draw the pointer.
/// * `metadata` — **also does not draw it here.** On Linux this asks the portal
///   to deliver the pointer as separate metadata for a consumer to render.
///   Windows has no such channel in this product: nothing on the wire carries a
///   pointer and the client does not draw one. Treating it as "not embedded" is
///   the honest reading — the alternative is drawing a pointer for a mode whose
///   whole meaning is "do not draw it".
/// * anything else, including unset — embedded.
///
/// Unrecognised values fall through to the default rather than erroring,
/// because that is what the Linux side does with the same variable and the two
/// must not disagree about a shared name. `RD_CAPTURE_BACKEND` is strict for
/// the opposite reason: it exists to answer a diagnostic question, and a typo
/// there silently answers it wrongly.
pub fn cursor_mode_from(value: Option<&str>) -> CursorMode {
    match value.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("hidden") => CursorMode::Hidden,
        Some(v) if v.eq_ignore_ascii_case("metadata") => CursorMode::Hidden,
        _ => CursorMode::Embedded,
    }
}

/// [`cursor_mode_from`] applied to the process environment.
pub fn cursor_mode() -> CursorMode {
    cursor_mode_from(std::env::var(CURSOR_ENV).ok().as_deref())
}

/// Full-desktop capturer.
///
/// Holds the DXGI device, duplication object and staging texture for the life
/// of the session — recreating them per frame costs more than the capture. Drop
/// releases every COM object it owns.
/// How often to ask the OS whether the display moved under a running capture.
///
/// A rotation raises no error, so the only way to notice is to look. Twice a
/// second is far below any frame rate this serves and costs one enumeration.
#[cfg(windows)]
const DISPLAY_POLL: std::time::Duration = std::time::Duration::from_millis(500);

/// How long to wait between retries of a backend that just errored.
///
/// Paired with [`health::MAX_BACKEND_ERRORS`] this is the tolerance window for a
/// transient failure — 50 x 100ms, about five seconds. See that constant for
/// why it exists (a UAC prompt used to end a session permanently).
#[cfg(windows)]
const BACKEND_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

pub struct WindowsDesktopCapture {
    health: health::Health,
    cursor: CursorMode,
    #[cfg(windows)]
    inner: Option<dxgi::Duplication>,
    #[cfg(windows)]
    fallback: Option<gdi::DesktopGdi>,
    display: DisplayInfo,
    #[cfg(windows)]
    last_display_check: std::time::Instant,
}

#[cfg(any(windows, test))]
enum InitialCapture<D, G> {
    Dxgi(D),
    Gdi(G),
}

#[cfg(any(windows, test))]
fn select_initial_backend<D, G, E>(
    dxgi: Result<D, E>,
    open_gdi: impl FnOnce() -> Result<G, E>,
) -> Result<InitialCapture<D, G>, (E, Option<E>)> {
    match dxgi {
        Ok(capture) => Ok(InitialCapture::Dxgi(capture)),
        Err(dxgi_error) => match open_gdi() {
            Ok(capture) => Ok(InitialCapture::Gdi(capture)),
            Err(gdi_error) => Err((dxgi_error, Some(gdi_error))),
        },
    }
}

/// The display geometry to rebuild a lost capture against.
///
/// A rotation or a resolution change is the usual reason a duplication object
/// is lost, so the geometry that was current when the capturer opened is
/// exactly the geometry that must not be reused: rebuilding against it
/// restores the capture at the old size and the old rotation, and
/// `dxgi::copy_out` then rotates every later frame by a `Rotation` that
/// stopped being true the moment the display turned.
///
/// If the re-query fails, the previous geometry is kept — a display that
/// cannot be enumerated is the backend's error to report when the reopen
/// fails, not a reason to lose the only geometry we have.
#[cfg(any(windows, test))]
fn display_for_rebuild(
    opened_with: &DisplayInfo,
    requery: impl FnOnce() -> Result<DisplayInfo, CaptureError>,
) -> DisplayInfo {
    requery().unwrap_or_else(|_| opened_with.clone())
}

/// Has the display moved out from under a capture that is already running?
///
/// **A rotation is invisible to Desktop Duplication.** Turning the desktop
/// leaves the physical panel surface exactly as it was, so the duplication
/// object stays valid and goes on delivering frames of the old orientation;
/// only the desktop's metadata changed. Nothing raises `AccessLost`, so nothing
/// ever triggers the rebuild that would re-read `DisplayInfo` — and the
/// rotation correction keeps using the `Rotation` captured at startup.
///
/// A *resolution* change does alter the surface, which is why that one is
/// noticed without any help. This predicate exists for the case that is not.
///
/// Measured on Windows 10 / RTX 3060, driver 32.0.15.9636, on 2026-08-26: a
/// held landscape -> portrait -> landscape cycle produced no geometry change,
/// no fault and no rebuild, while the stream ran continuously.
pub fn display_changed(opened_with: &DisplayInfo, current: &DisplayInfo) -> bool {
    opened_with != current
}

impl WindowsDesktopCapture {
    /// Open capture on the primary display.
    #[cfg(windows)]
    pub fn new() -> Result<Self, CaptureError> {
        Self::with_preference(backend_preference()?)
    }

    /// Open capture on the primary display with the backend policy given.
    ///
    /// [`BackendPreference::Auto`] is what the product uses and what
    /// [`WindowsDesktopCapture::new`] passes when `RD_CAPTURE_BACKEND` is
    /// unset. The forcing variants pin the stream -- see [`health::Health::pinned`]
    /// -- so a forced run is evidence about one backend rather than a stream
    /// that quietly became the other one.
    #[cfg(windows)]
    pub fn with_preference(preference: BackendPreference) -> Result<Self, CaptureError> {
        let display = primary_display()?;
        let (health, inner, fallback) = match preference {
            BackendPreference::ForceDxgi => (
                health::Health::pinned(health::Backend::Dxgi),
                Some(dxgi::Duplication::open(&display)?),
                None,
            ),
            BackendPreference::ForceGdi => (
                health::Health::pinned(health::Backend::Gdi),
                None,
                Some(gdi::DesktopGdi::open(&display)?),
            ),
            BackendPreference::Auto => {
                let initial = select_initial_backend(dxgi::Duplication::open(&display), || {
                    gdi::DesktopGdi::open(&display)
                })
                .map_err(|(dxgi, gdi)| {
                    CaptureError::Backend(format!(
                        "DXGI could not open ({dxgi:?}); GDI fallback {}",
                        gdi.map_or_else(
                            || "was not attempted".into(),
                            |e| format!("failed ({e:?})")
                        )
                    ))
                })?;
                match initial {
                    InitialCapture::Dxgi(capture) => (
                        health::Health::new(health::Backend::Dxgi),
                        Some(capture),
                        None,
                    ),
                    InitialCapture::Gdi(capture) => (
                        health::Health::new(health::Backend::Gdi),
                        None,
                        Some(capture),
                    ),
                }
            }
        };
        Ok(WindowsDesktopCapture {
            health,
            cursor: cursor_mode(),
            inner,
            fallback,
            display,
            last_display_check: std::time::Instant::now(),
        })
    }

    #[cfg(not(windows))]
    pub fn new() -> Result<Self, CaptureError> {
        Err(CaptureError::Backend(
            "DXGI desktop capture is implemented on Windows only".into(),
        ))
    }

    /// The non-Windows twin of [`Self::with_preference`], for the same reason
    /// `new` has one: `windows-frame-probe` calls it unconditionally, so
    /// without this the whole crate stops compiling on Linux.
    ///
    /// Round 5 added `with_preference` on Windows and not here, which is
    /// invisible on the machine it was written on -- the crate builds, the
    /// probe builds, everything passes. It failed on the Linux box the moment
    /// the patch landed. This is the shape of cross-platform work: each side
    /// can only see its own half, and the guard has to be added by whoever
    /// notices first.
    #[cfg(not(windows))]
    pub fn with_preference(preference: BackendPreference) -> Result<Self, CaptureError> {
        let _ = preference;
        Err(CaptureError::Backend(
            "DXGI desktop capture is implemented on Windows only".into(),
        ))
    }

    /// The display being captured.
    pub fn display(&self) -> &DisplayInfo {
        &self.display
    }

    /// Which backend is currently producing frames.
    pub fn backend(&self) -> health::Backend {
        self.health.backend()
    }

    /// Whether the pointer is being drawn into frames.
    pub fn cursor_mode(&self) -> CursorMode {
        self.cursor
    }

    /// Override the pointer policy for this capturer.
    ///
    /// The environment decides it at construction; this exists so a caller with
    /// its own opinion — a test, or a future per-session setting — does not have
    /// to mutate the process environment to express it.
    pub fn set_cursor_mode(&mut self, mode: CursorMode) {
        self.cursor = mode;
    }
}

impl WindowsDesktopCapture {
    /// Draw the pointer into a finished frame.
    ///
    /// **Never fails a capture.** A frame with no pointer drawn is still a
    /// correct picture of the desktop, whereas refusing the frame because the
    /// cursor could not be rasterised would trade a cosmetic gap for a dead
    /// stream. Every failure path here is a silent skip, and they are all
    /// reachable in normal use: a full-screen application can hide the cursor,
    /// and `GetCursorInfo` reports nothing during a desktop switch.
    ///
    /// Screen coordinates are converted to frame coordinates by subtracting the
    /// display origin, because a secondary monitor's frame starts at its own
    /// corner while the cursor is reported on the virtual desktop.
    #[cfg(windows)]
    fn draw_cursor(&self, data: &mut [u8], width: u32, height: u32) {
        let Some(sprite) = cursor::current() else {
            return;
        };
        let (ox, oy) = self.display.origin;
        let _ = pixels::blend_over(
            data,
            width,
            height,
            &sprite.rgba,
            sprite.width,
            sprite.height,
            sprite.x - ox,
            sprite.y - oy,
        );
    }
}

impl FrameSource for WindowsDesktopCapture {
    /// Capture one frame of the whole desktop as tightly packed **RGBA**.
    ///
    /// RGBA, not the BGRA the platform hands over: the encoder and the Android
    /// renderer both want RGBA, and converting once here is one conversion
    /// instead of one per consumer. The legacy crate returned BGRA and made
    /// `share_source` swap channels in place, which meant the byte order of a
    /// frame depended on how far it had travelled.
    #[cfg(windows)]
    fn capture(&mut self, surface: SurfaceId) -> Result<Frame, CaptureError> {
        use health::{Action, Backend, Outcome};

        if !surface.is_desktop() {
            return Err(CaptureError::SurfaceUnavailable(surface));
        }
        // A rotation never invalidates the duplication: the panel surface is
        // unchanged, so DXGI keeps serving frames of the old orientation and
        // no error is ever raised. Nothing would rebuild, and the correction
        // would go on using the `Rotation` read at startup. So look, on a
        // cadence, rather than waiting to be told.
        if self.last_display_check.elapsed() >= DISPLAY_POLL {
            self.last_display_check = std::time::Instant::now();
            if let Ok(current) = primary_display() {
                if display_changed(&self.display, &current) {
                    self.display = current;
                    match self.health.backend() {
                        Backend::Dxgi => {
                            self.inner = Some(dxgi::Duplication::open(&self.display)?);
                        }
                        Backend::Gdi => {
                            self.fallback = Some(gdi::DesktopGdi::open(&self.display)?);
                        }
                    }
                }
            }
        }
        // Bounded: every arm either returns or changes state, and the only
        // repeating arms (Retry, Reinitialize, FallBackToGdi) are themselves
        // bounded by `Health`'s counters.
        //
        // The budget includes `MAX_BACKEND_ERRORS` because a backend error is
        // now retried rather than fatal. Without that room the retries would
        // run out of loop before they ran out of budget, and `capture` would
        // return "no progress" — which the stream thread treats as fatal, so
        // the session would still die on a UAC prompt with the fix in place.
        let budget = health::WOULD_BLOCK_BEFORE_GDI
            + health::MAX_REINIT_ATTEMPTS
            + health::MAX_BACKEND_ERRORS
            + 4;
        for _ in 0..budget {
            let outcome = match self.health.backend() {
                Backend::Dxgi => match self.inner.as_mut() {
                    Some(capture) => capture.next_frame(&self.display),
                    None => Outcome::BackendError("DXGI capture was never created".into()),
                },
                Backend::Gdi => match self.fallback.as_mut() {
                    Some(g) => g.next_frame(&self.display),
                    None => Outcome::BackendError("GDI fallback was never created".into()),
                },
            };
            let captured = match &outcome {
                Outcome::Frame { .. } => match self.health.backend() {
                    Backend::Dxgi => self.inner.as_mut().and_then(|capture| capture.take_frame()),
                    Backend::Gdi => self.fallback.as_mut().and_then(|g| g.take_frame()),
                },
                _ => None,
            };
            match self.health.observe(outcome) {
                Action::Deliver => {
                    let (mut data, width, height) = captured.ok_or_else(|| {
                        CaptureError::Backend("backend reported a frame but produced none".into())
                    })?;
                    // The pointer, if anyone is meant to see it. Neither backend
                    // includes it, so it is drawn here, once, at the last moment
                    // before the frame leaves — after any rotation, so the
                    // sprite is not turned with the desktop.
                    if self.cursor == CursorMode::Embedded {
                        self.draw_cursor(&mut data, width, height);
                    }
                    return Ok(Frame {
                        surface,
                        width,
                        height,
                        data,
                    });
                }
                Action::Retry => {
                    // Backing off matters only for the backend-error case: a
                    // `WouldBlock` already cost `ACQUIRE_TIMEOUT_MS` inside the
                    // backend, but a failed `BitBlt` returns immediately, so
                    // spinning would burn the whole budget in microseconds and
                    // outlast nothing. With this, `MAX_BACKEND_ERRORS` retries
                    // span about five seconds — long enough for a secure
                    // desktop to come and go.
                    if self.health.backend_error_streak() > 0 {
                        std::thread::sleep(BACKEND_ERROR_BACKOFF);
                    }
                    continue;
                }
                Action::Reinitialize => {
                    self.display = display_for_rebuild(&self.display, primary_display);
                    self.inner = Some(dxgi::Duplication::open(&self.display)?);
                }
                Action::FallBackToGdi => {
                    self.display = display_for_rebuild(&self.display, primary_display);
                    self.fallback = Some(gdi::DesktopGdi::open(&self.display)?);
                }
                Action::Fail(fault) => {
                    return Err(CaptureError::Backend(fault.to_string()));
                }
            }
        }
        Err(CaptureError::Backend(
            "capture made no progress within its retry budget".into(),
        ))
    }

    #[cfg(not(windows))]
    fn capture(&mut self, surface: SurfaceId) -> Result<Frame, CaptureError> {
        let _ = surface;
        Err(CaptureError::Backend(
            "DXGI desktop capture is implemented on Windows only".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Geometry must be half-open and match what `session_core` expects, or
    /// injected pointer coordinates clamp against the wrong rectangle.
    /// The default has to match Linux's, or the pointer appears or vanishes
    /// depending on which host you dialled.
    #[test]
    fn the_pointer_is_drawn_unless_something_says_otherwise() {
        assert_eq!(cursor_mode_from(None), CursorMode::Embedded);
        assert_eq!(cursor_mode_from(Some("")), CursorMode::Embedded);
        assert_eq!(CursorMode::default(), CursorMode::Embedded);
    }

    #[test]
    fn hidden_and_metadata_both_mean_do_not_draw_it() {
        for v in ["hidden", "HIDDEN", " Hidden "] {
            assert_eq!(cursor_mode_from(Some(v)), CursorMode::Hidden, "{v:?}");
        }
        // Windows has no metadata channel for a pointer, so the only honest
        // reading of "send it as metadata" here is "do not draw it".
        for v in ["metadata", "Metadata"] {
            assert_eq!(cursor_mode_from(Some(v)), CursorMode::Hidden, "{v:?}");
        }
    }

    /// Unlike `RD_CAPTURE_BACKEND`, a typo here is NOT an error: this variable
    /// is shared with the Linux implementation, which falls through to its
    /// default, and two platforms disagreeing about one name is worse than
    /// either rule.
    #[test]
    fn an_unrecognised_cursor_value_falls_through_like_it_does_on_linux() {
        assert_eq!(cursor_mode_from(Some("hiden")), CursorMode::Embedded);
        assert_eq!(cursor_mode_from(Some("yes")), CursorMode::Embedded);
    }

    #[test]
    fn an_unset_backend_variable_leaves_the_product_policy_alone() {
        assert_eq!(
            backend_preference_from(None).unwrap(),
            BackendPreference::Auto
        );
        assert_eq!(
            backend_preference_from(Some("")).unwrap(),
            BackendPreference::Auto
        );
        assert_eq!(BackendPreference::default(), BackendPreference::Auto);
    }

    #[test]
    fn each_backend_can_be_named_in_any_case_and_with_stray_spaces() {
        for v in ["dxgi", "DXGI", "  Dxgi "] {
            assert_eq!(
                backend_preference_from(Some(v)).unwrap(),
                BackendPreference::ForceDxgi,
                "{v:?}"
            );
        }
        for v in ["gdi", "GDI", " gdi\t"] {
            assert_eq!(
                backend_preference_from(Some(v)).unwrap(),
                BackendPreference::ForceGdi,
                "{v:?}"
            );
        }
        assert_eq!(
            backend_preference_from(Some("AUTO")).unwrap(),
            BackendPreference::Auto
        );
    }

    /// A typo must not read as "the default". The whole value of a forced run
    /// is knowing which backend produced the symptom.
    #[test]
    fn a_misspelled_backend_is_refused_rather_than_ignored() {
        let e = backend_preference_from(Some("dxig")).unwrap_err();
        let message = format!("{e:?}");
        assert!(
            message.contains("dxig"),
            "the bad value must be quoted back: {message}"
        );
        assert!(
            backend_preference_from(Some("none")).is_err(),
            "there is no way to ask for no capture"
        );
    }

    #[test]
    fn display_bounds_are_half_open_and_offset_by_the_origin() {
        let d = DisplayInfo {
            name: r"\\.\DISPLAY2".into(),
            origin: (1920, -120),
            width: 2560,
            height: 1440,
            is_primary: false,
            rotation: pixels::Rotation::Identity,
        };
        assert_eq!(d.bounds(), (1920, -120, 4480, 1320));
    }

    #[test]
    fn a_display_at_the_origin_is_the_primary_one() {
        let d = DisplayInfo {
            name: r"\\.\DISPLAY1".into(),
            origin: (0, 0),
            width: 1920,
            height: 1080,
            is_primary: true,
            rotation: pixels::Rotation::Identity,
        };
        assert_eq!(d.bounds(), (0, 0, 1920, 1080));
        assert!(d.is_primary);
    }

    #[test]
    fn initial_dxgi_failure_opens_the_gdi_fallback() {
        let gdi_called = std::cell::Cell::new(false);
        let selected = select_initial_backend::<(), _, &str>(Err("dxgi failed"), || {
            gdi_called.set(true);
            Ok("gdi")
        });

        assert!(gdi_called.get(), "initial DXGI failure must try GDI");
        assert!(matches!(selected, Ok(InitialCapture::Gdi("gdi"))));
    }

    #[test]
    fn initial_dxgi_success_does_not_open_gdi() {
        let gdi_called = std::cell::Cell::new(false);
        let selected = select_initial_backend::<_, (), &str>(Ok("dxgi"), || {
            gdi_called.set(true);
            Ok(())
        });

        assert!(
            !gdi_called.get(),
            "GDI is a fallback, not a second capturer"
        );
        assert!(matches!(selected, Ok(InitialCapture::Dxgi("dxgi"))));
    }

    #[test]
    fn initial_failure_reports_both_backends() {
        let selected = select_initial_backend::<(), (), _>(Err("dxgi"), || Err("gdi"));
        assert!(matches!(selected, Err(("dxgi", Some("gdi")))));
    }

    /// On a machine that is not Windows, every entry point must say so plainly
    /// rather than returning an empty list that reads like "no displays".
    #[cfg(not(windows))]
    #[test]
    fn the_non_windows_build_refuses_instead_of_pretending() {
        assert!(displays().is_err());
        assert!(primary_display().is_err());
        assert!(WindowsDesktopCapture::new().is_err());
        let msg = format!("{:?}", displays().unwrap_err());
        assert!(
            msg.contains("Windows"),
            "the error must name the reason: {msg}"
        );
    }

    /// A live 90-degree rotation is exactly the event that invalidates the
    /// duplication object, so the rebuild must re-read the display. Rebuilding
    /// against the geometry captured at startup restores the capture at the old
    /// size and, worse, keeps feeding `pixels::rotate` a `Rotation` that is no
    /// longer true — the frame stops being turned at all and the phone shows an
    /// unrotated desktop while the monitor is in portrait.
    ///
    /// Observed on the Windows box on 2026-08-25: the display was rotated to
    /// portrait mid-session and the streamed image did not rotate.
    #[test]
    fn a_rebuild_re_reads_the_display_after_a_rotation() {
        let opened_with = DisplayInfo {
            name: r"\.\DISPLAY1".into(),
            origin: (0, 0),
            width: 1440,
            height: 900,
            is_primary: true,
            rotation: pixels::Rotation::Identity,
        };
        // What the display actually looks like by the time the rebuild happens.
        let now_rotated = DisplayInfo {
            name: r"\.\DISPLAY1".into(),
            origin: (0, 0),
            width: 900,
            height: 1440,
            is_primary: true,
            rotation: pixels::Rotation::Clockwise90,
        };
        let chosen = display_for_rebuild(&opened_with, || Ok(now_rotated.clone()));
        assert_eq!(
            chosen.rotation,
            pixels::Rotation::Clockwise90,
            "the rebuild reused the rotation from startup; every later frame \
             would be turned by a rotation that is no longer true"
        );
        assert_eq!((chosen.width, chosen.height), (900, 1440));
    }

    /// The same seam covers a resolution change: the duplication is lost, and
    /// the rebuild must not restore the old mode.
    #[test]
    fn a_rebuild_re_reads_the_display_after_a_resolution_change() {
        let opened_with = DisplayInfo {
            name: r"\.\DISPLAY1".into(),
            origin: (0, 0),
            width: 1440,
            height: 900,
            is_primary: true,
            rotation: pixels::Rotation::Identity,
        };
        let now_smaller = DisplayInfo {
            width: 1280,
            height: 720,
            ..opened_with.clone()
        };
        let chosen = display_for_rebuild(&opened_with, || Ok(now_smaller.clone()));
        assert_eq!((chosen.width, chosen.height), (1280, 720));
    }

    /// A display that cannot be enumerated must not destroy the only geometry
    /// the capturer has; the reopen reports that failure itself.
    #[test]
    fn a_failed_re_query_keeps_the_geometry_it_already_had() {
        let opened_with = DisplayInfo {
            name: r"\.\DISPLAY1".into(),
            origin: (0, 0),
            width: 1440,
            height: 900,
            is_primary: true,
            rotation: pixels::Rotation::Identity,
        };
        let chosen = display_for_rebuild(&opened_with, || {
            Err(CaptureError::Backend("no display is attached".into()))
        });
        assert_eq!(chosen, opened_with);
    }

    /// The case Desktop Duplication cannot report: the desktop turned, the
    /// panel surface did not, and the duplication stayed valid. Without this
    /// the capturer keeps its startup `Rotation` for the life of the session.
    #[test]
    fn a_rotation_is_a_display_change_even_though_dxgi_stays_happy() {
        let opened = DisplayInfo {
            name: r"\.\DISPLAY1".into(),
            origin: (0, 0),
            width: 1440,
            height: 900,
            is_primary: true,
            rotation: pixels::Rotation::Identity,
        };
        let turned = DisplayInfo {
            width: 900,
            height: 1440,
            rotation: pixels::Rotation::Clockwise90,
            ..opened.clone()
        };
        assert!(
            display_changed(&opened, &turned),
            "a rotation must force a rebuild; the duplication will never say so"
        );
    }

    /// A resolution change must also count, so the one predicate covers both
    /// and the caller needs no second rule.
    #[test]
    fn a_resolution_change_is_a_display_change() {
        let opened = DisplayInfo {
            name: r"\.\DISPLAY1".into(),
            origin: (0, 0),
            width: 1440,
            height: 900,
            is_primary: true,
            rotation: pixels::Rotation::Identity,
        };
        let smaller = DisplayInfo {
            width: 1280,
            height: 720,
            ..opened.clone()
        };
        assert!(display_changed(&opened, &smaller));
    }

    /// And an unchanged display must NOT force a rebuild, or the capturer would
    /// tear its own duplication down on every poll.
    #[test]
    fn an_unchanged_display_is_not_a_change() {
        let d = DisplayInfo {
            name: r"\.\DISPLAY1".into(),
            origin: (0, 0),
            width: 1440,
            height: 900,
            is_primary: true,
            rotation: pixels::Rotation::Identity,
        };
        assert!(!display_changed(&d, &d.clone()));
    }
}

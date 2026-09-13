//! The capture loop's policy, with no capture in it.
//!
//! Deciding *what to do* when a capture attempt goes wrong is the part of a
//! screen-capture backend most likely to be wrong, and the part least likely to
//! be tested — because testing it normally means owning the hardware that
//! misbehaves. So the decisions live here, as a state machine over reported
//! outcomes, and the DXGI module's only job is to report honestly what
//! happened. Every rule below is exercised on the build machine, whatever OS it
//! is running.
//!
//! ## The rules, and where they came from
//!
//! * **Repeated `WouldBlock` means fall back to GDI.** Desktop Duplication
//!   returns "no new frame" legitimately — it only publishes on change — but a
//!   run of them means the duplication is not going to produce anything.
//!   Three consecutive is the threshold: enough to distinguish a genuinely idle
//!   desktop from a duplication that has stopped producing.
//! * **Access lost means rebuild, not die.** A resolution change, a UAC secure
//!   desktop, a driver reset or a session switch all invalidate the duplication
//!   object. Recreating it is the correct response; doing so forever is not.
//! * **A constant frame is a failure, not a frame.** This is RemoteDexter's
//!   rule, and it is the whole reason Block 8 exists: the
//!   reported symptom was a white screen, and every layer downstream of capture
//!   faithfully encoded, transported, decoded and rendered that white. A
//!   backend returning `Ok` while handing back one repeated colour has failed,
//!   and after a short run of them the session is told so and stops rather than
//!   streaming a lie.

/// Which backend is currently producing frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// DXGI Desktop Duplication — the fast path.
    Dxgi,
    /// GDI `BitBlt` of the whole desktop — slower, always available.
    Gdi,
}

/// What one capture attempt reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A frame arrived. `uniform` is the answer to "is every pixel identical".
    Frame { uniform: bool },
    /// No new frame was published within the timeout. Normal in isolation.
    WouldBlock,
    /// The duplication object was invalidated (resolution change, secure
    /// desktop, driver reset, session switch).
    AccessLost,
    /// The backend failed in some other way.
    BackendError(String),
}

/// Why capture stopped for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// The backend kept returning success with a single-colour image.
    ConstantFrame { frames: u32 },
    /// Even the fallback could not produce frames.
    BackendUnavailable { detail: String },
    /// The duplication object could not be rebuilt and there is nothing left
    /// to fall back to.
    AccessLostUnrecoverable,
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::ConstantFrame { frames } => write!(
                f,
                "capture returned {frames} consecutive single-colour frames; \
                 the desktop is not being captured"
            ),
            Fault::BackendUnavailable { detail } => {
                write!(f, "no capture backend is available: {detail}")
            }
            Fault::AccessLostUnrecoverable => {
                write!(f, "desktop duplication was lost and could not be rebuilt")
            }
        }
    }
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this frame.
    Deliver,
    /// Nothing arrived; try again.
    Retry,
    /// Abandon DXGI and capture through GDI from now on.
    FallBackToGdi,
    /// Rebuild the duplication object and try again.
    Reinitialize,
    /// Stop. The session must be told.
    Fail(Fault),
}

/// Consecutive `WouldBlock`s tolerated before giving up on DXGI.
///
/// Three. Desktop Duplication publishes only
/// on change, so a static desktop legitimately produces these — the number has
/// to be big enough to survive an idle screen and small enough that a genuinely
/// dead duplication is noticed in well under a second at any frame rate.
pub const WOULD_BLOCK_BEFORE_GDI: u32 = 3;

/// Consecutive single-colour frames tolerated before declaring a fault.
///
/// Thirty. A real desktop is essentially never uniform — there is a wallpaper,
/// a taskbar, a cursor — but it CAN be, briefly and legitimately: a blanking
/// monitor, a fullscreen video cutting to black, a lock screen mid-fade. One
/// such frame must not kill a session. Thirty consecutive ones cannot be any of
/// those; at 15-30 fps that is one to two seconds of a screen that is not
/// changing and not showing anything.
pub const UNIFORM_FRAMES_BEFORE_FAULT: u32 = 30;

/// How many times the duplication object may be rebuilt before falling back.
pub const MAX_REINIT_ATTEMPTS: u32 = 3;

/// Consecutive backend errors tolerated before the stream is declared dead.
///
/// **A UAC prompt used to end a session permanently.** Elevating switches
/// Windows to the secure desktop, where a `BitBlt` of the screen DC fails; a
/// GDI `BackendError` was terminal on the first occurrence, so the stream
/// stopped and could not come back. Measured on Windows 10 / RTX 3060,
/// 2026-09-01: one prompt, one dead session.
///
/// That was not a pinned-mode curiosity. [`WOULD_BLOCK_BEFORE_GDI`] is 3 at a
/// 100ms acquire timeout, so an idle desktop lands on GDI in under half a
/// second and an ordinary session is often already there — where any prompt
/// ended it.
///
/// **Five seconds was measured and was not enough.** The first attempt at this
/// used fifty, and a real UAC prompt outlived it: the budget was spent while
/// the prompt sat on screen waiting to be read, and the session died anyway.
/// A prompt is up for as long as a person takes to look at it, so the window
/// has to be human-scale rather than transition-scale.
///
/// Three hundred, paired with the 100ms backoff the caller applies between
/// attempts, is **about thirty seconds** of continuous failure. Long enough for
/// somebody to notice a prompt, read it and click; short enough that a
/// genuinely dead backend is still reported rather than hanging forever.
///
/// Exhausting it is no longer fatal to the *state machine* either — see
/// [`Health::observe`]. A backend error stops this capture call without
/// condemning every later one, because "the desktop was unreachable for thirty
/// seconds" is not "the desktop will never be reachable again".
///
/// The count is CONSECUTIVE: any delivered frame clears it, so a display that
/// glitches once an hour never accumulates its way to a fault.
pub const MAX_BACKEND_ERRORS: u32 = 300;

/// Tracks a capture stream's health across attempts.
#[derive(Debug, Clone)]
pub struct Health {
    backend: Backend,
    would_block_streak: u32,
    uniform_streak: u32,
    reinit_attempts: u32,
    backend_error_streak: u32,
    /// The fault this stream died of, if it died. Was a bare `bool`, which
    /// meant the guard below had to invent a `Fault` to return and always
    /// invented the same one — a stream killed by a failed `BitBlt` reported
    /// "capture returned 0 consecutive single-colour frames", naming the wrong
    /// cause and a count that was zero because it had never been counting.
    fault: Option<Fault>,
    /// True when the operator named a backend and every automatic switch away
    /// from it is suppressed. See [`Health::pinned`].
    pinned: bool,
}

impl Default for Health {
    fn default() -> Self {
        Health::new(Backend::Dxgi)
    }
}

impl Health {
    pub fn new(backend: Backend) -> Self {
        Health {
            backend,
            would_block_streak: 0,
            uniform_streak: 0,
            reinit_attempts: 0,
            backend_error_streak: 0,
            fault: None,
            pinned: false,
        }
    }

    /// A stream that must stay on the backend it was opened with.
    ///
    /// The automatic policy exists so a session survives a backend that stops
    /// working, and it is right for a session. It is wrong for a *diagnosis*:
    /// the question "does this symptom follow DXGI or GDI?" cannot be answered
    /// by a capturer that silently changes backend after four idle frames, and
    /// that is exactly what the default does — `ACQUIRE_TIMEOUT_MS` is 100ms
    /// and [`WOULD_BLOCK_BEFORE_GDI`] is 3, so a still desktop lands on GDI in
    /// under half a second while the caller goes on believing it asked for
    /// duplication.
    ///
    /// Pinned, a backend that cannot do the job says so instead of being
    /// replaced: `WouldBlock` retries forever, and the errors that would have
    /// demoted DXGI become faults. That makes a forced run either evidence or
    /// a clear failure, never a quiet substitution.
    pub fn pinned(backend: Backend) -> Self {
        Health {
            pinned: true,
            ..Health::new(backend)
        }
    }

    /// True when this stream may not change backend.
    pub fn is_pinned(&self) -> bool {
        self.pinned
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn uniform_streak(&self) -> u32 {
        self.uniform_streak
    }

    pub fn would_block_streak(&self) -> u32 {
        self.would_block_streak
    }

    /// Consecutive backend errors seen since the last delivered frame.
    pub fn backend_error_streak(&self) -> u32 {
        self.backend_error_streak
    }

    /// True once an unrecoverable [`Fault`] has been raised. Such a stream
    /// stays faulted.
    pub fn has_failed(&self) -> bool {
        self.fault.is_some()
    }

    /// What this stream died of, if it did.
    pub fn fault(&self) -> Option<&Fault> {
        self.fault.as_ref()
    }

    /// Feed in one attempt's outcome, get back what to do.
    pub fn observe(&mut self, outcome: Outcome) -> Action {
        // A faulted stream does not get a second opinion. Without this, a
        // caller that ignores `Fail` and keeps polling would see `Deliver` the
        // moment one non-uniform frame arrived, and quietly resume streaming
        // something already reported as broken.
        if let Some(fault) = &self.fault {
            return Action::Fail(fault.clone());
        }
        match outcome {
            Outcome::Frame { uniform: false } => {
                self.would_block_streak = 0;
                self.uniform_streak = 0;
                self.reinit_attempts = 0;
                self.backend_error_streak = 0;
                Action::Deliver
            }
            Outcome::Frame { uniform: true } => {
                self.would_block_streak = 0;
                self.uniform_streak += 1;
                if self.uniform_streak >= UNIFORM_FRAMES_BEFORE_FAULT {
                    let fault = Fault::ConstantFrame {
                        frames: self.uniform_streak,
                    };
                    self.fault = Some(fault.clone());
                    Action::Fail(fault)
                } else {
                    // Below the threshold this really might be a black screen.
                    Action::Deliver
                }
            }
            Outcome::WouldBlock => {
                self.would_block_streak += 1;
                if !self.pinned
                    && self.backend == Backend::Dxgi
                    && self.would_block_streak > WOULD_BLOCK_BEFORE_GDI
                {
                    self.backend = Backend::Gdi;
                    self.would_block_streak = 0;
                    Action::FallBackToGdi
                } else {
                    Action::Retry
                }
            }
            Outcome::AccessLost => {
                if self.backend == Backend::Gdi {
                    // GDI has no duplication object to lose; if it says this,
                    // the desktop itself is gone.
                    self.fault = Some(Fault::AccessLostUnrecoverable);
                    return Action::Fail(Fault::AccessLostUnrecoverable);
                }
                if self.reinit_attempts < MAX_REINIT_ATTEMPTS {
                    self.reinit_attempts += 1;
                    Action::Reinitialize
                } else if self.pinned {
                    // Pinned to DXGI: out of rebuilds and forbidden to swap, so
                    // this is the end of the stream rather than the start of a
                    // GDI one the caller never asked for.
                    self.fault = Some(Fault::AccessLostUnrecoverable);
                    Action::Fail(Fault::AccessLostUnrecoverable)
                } else {
                    self.backend = Backend::Gdi;
                    self.reinit_attempts = 0;
                    Action::FallBackToGdi
                }
            }
            Outcome::BackendError(detail) => {
                // An unpinned DXGI error still falls straight to GDI: that is
                // the fallback this backend was designed around, and it is a
                // working capture rather than a wait.
                if self.backend == Backend::Dxgi && !self.pinned {
                    self.backend = Backend::Gdi;
                    self.backend_error_streak = 0;
                    return Action::FallBackToGdi;
                }
                // Everywhere else there is nothing to fall back TO, so the only
                // choices are "wait" and "die". A backend error is not proof of
                // a dead backend — a secure desktop makes `BitBlt` fail for as
                // long as the prompt is up and not one moment longer. Waiting
                // is bounded so a genuinely dead backend is still reported.
                self.backend_error_streak += 1;
                if self.backend_error_streak >= MAX_BACKEND_ERRORS {
                    // Deliberately NOT latched. Thirty seconds of a backend
                    // refusing to produce is worth reporting, and it is worth
                    // ending this capture call — but it is not proof the
                    // desktop is gone for good, and latching it here is what
                    // made a UAC prompt permanent. The streak resets so the
                    // next call starts with a full budget rather than
                    // inheriting a verdict from a prompt that has since been
                    // dismissed.
                    self.backend_error_streak = 0;
                    Action::Fail(Fault::BackendUnavailable { detail })
                } else {
                    Action::Retry
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Outcome {
        Outcome::Frame { uniform: false }
    }
    fn blank() -> Outcome {
        Outcome::Frame { uniform: true }
    }

    /// **The half that a bounded budget alone did not fix.**
    ///
    /// Measured on hardware 2026-09-01: with a 5s budget, a real UAC prompt
    /// outlived it, the budget was spent, `failed` latched, and every frame
    /// afterwards failed — including all the ones after the desktop came back.
    /// Exhausting the budget must end the CALL, not the STREAM.
    #[test]
    fn a_backend_error_does_not_condemn_the_stream_forever() {
        let mut h = Health::new(Backend::Gdi);
        for _ in 0..MAX_BACKEND_ERRORS {
            h.observe(Outcome::BackendError("BitBlt of the desktop failed".into()));
        }
        assert!(
            !h.has_failed(),
            "thirty seconds of an unreachable desktop is not proof it will never \
             be reachable again; latching here is what made a UAC prompt permanent"
        );
        // The prompt is dismissed; the very next frame must be delivered.
        assert_eq!(h.observe(good()), Action::Deliver);
        assert_eq!(h.backend_error_streak(), 0);
    }

    /// The two faults that ARE unrecoverable still latch, and still report
    /// themselves rather than the first fault anyone thought of.
    #[test]
    fn an_unrecoverable_fault_latches_and_names_itself() {
        let mut h = Health::new(Backend::Gdi);
        assert_eq!(
            h.observe(Outcome::AccessLost),
            Action::Fail(Fault::AccessLostUnrecoverable)
        );
        assert!(h.has_failed());
        // The guard used to answer every later call with ConstantFrame { 0 } —
        // the wrong cause and a count that had never been counting. Hardware
        // printed exactly that: "capture returned 0 consecutive single-colour
        // frames" from a stream killed by a failed BitBlt.
        assert_eq!(
            h.observe(good()),
            Action::Fail(Fault::AccessLostUnrecoverable),
            "a faulted stream must keep reporting the fault it actually had"
        );
        assert_eq!(h.fault(), Some(&Fault::AccessLostUnrecoverable));
    }

    /// The same, for the blank-screen fault, so the guard is not just echoing
    /// a hard-coded value that happens to match.
    #[test]
    fn a_constant_frame_fault_keeps_reporting_its_own_count() {
        let mut h = Health::default();
        for _ in 0..UNIFORM_FRAMES_BEFORE_FAULT {
            h.observe(blank());
        }
        let expected = Fault::ConstantFrame {
            frames: UNIFORM_FRAMES_BEFORE_FAULT,
        };
        assert_eq!(h.fault(), Some(&expected));
        assert_eq!(h.observe(good()), Action::Fail(expected));
    }

    /// The UAC defect, as a test.
    ///
    /// A single `BitBlt` failure used to end the session permanently. It is a
    /// transient — the secure desktop goes away when the prompt is dismissed —
    /// so one error must be a retry, and the stream must still be alive.
    #[test]
    fn one_backend_error_on_gdi_is_a_transient_not_a_dead_session() {
        let mut h = Health::new(Backend::Gdi);
        assert_eq!(
            h.observe(Outcome::BackendError("BitBlt of the desktop failed".into())),
            Action::Retry
        );
        assert!(!h.has_failed(), "one failed blit is not a dead backend");
        assert_eq!(h.backend(), Backend::Gdi);
        // And it recovers completely once the desktop comes back.
        assert_eq!(h.observe(good()), Action::Deliver);
        assert_eq!(h.backend_error_streak(), 0);
    }

    /// Bounded, though: a backend that never comes back is still reported.
    #[test]
    fn a_backend_that_keeps_failing_is_eventually_declared_dead() {
        let mut h = Health::new(Backend::Gdi);
        for i in 1..MAX_BACKEND_ERRORS {
            assert_eq!(
                h.observe(Outcome::BackendError("gone".into())),
                Action::Retry,
                "error {i} of {MAX_BACKEND_ERRORS} is still within the budget"
            );
        }
        assert_eq!(
            h.observe(Outcome::BackendError("gone".into())),
            Action::Fail(Fault::BackendUnavailable {
                detail: "gone".into()
            }),
            "the budget must not be infinite; a dead backend has to be reported"
        );
        assert!(
            !h.has_failed(),
            "reported, but not condemned — see              a_backend_error_does_not_condemn_the_stream_forever"
        );
    }

    /// The streak is CONSECUTIVE. A display that glitches once in a while must
    /// never accumulate its way to a fault over a long session.
    #[test]
    fn a_delivered_frame_restores_the_whole_backend_error_budget() {
        let mut h = Health::new(Backend::Gdi);
        for _ in 0..(MAX_BACKEND_ERRORS - 1) {
            h.observe(Outcome::BackendError("blip".into()));
        }
        assert_eq!(h.backend_error_streak(), MAX_BACKEND_ERRORS - 1);
        assert_eq!(h.observe(good()), Action::Deliver);
        assert_eq!(h.backend_error_streak(), 0, "one good frame clears it");
        // The full budget is available again.
        for _ in 0..(MAX_BACKEND_ERRORS - 1) {
            assert_eq!(
                h.observe(Outcome::BackendError("blip".into())),
                Action::Retry
            );
        }
        assert!(!h.has_failed());
    }

    /// The fallback that already worked must not have become a wait: an
    /// unpinned DXGI error still goes straight to GDI, which is a working
    /// capture rather than fifty retries of a broken one.
    #[test]
    fn an_unpinned_dxgi_backend_error_still_falls_back_immediately() {
        let mut h = Health::new(Backend::Dxgi);
        assert_eq!(
            h.observe(Outcome::BackendError("dxgi died".into())),
            Action::FallBackToGdi
        );
        assert_eq!(h.backend(), Backend::Gdi);
        assert!(!h.has_failed());
        assert_eq!(
            h.backend_error_streak(),
            0,
            "the budget belongs to the new backend"
        );
    }

    /// The default policy, stated so the pinned tests below have something to
    /// be different from: an idle DXGI stream becomes a GDI stream on its own.
    #[test]
    fn an_unpinned_dxgi_stream_falls_back_to_gdi_when_nothing_is_published() {
        let mut h = Health::new(Backend::Dxgi);
        for _ in 0..WOULD_BLOCK_BEFORE_GDI {
            assert_eq!(h.observe(Outcome::WouldBlock), Action::Retry);
        }
        assert_eq!(h.observe(Outcome::WouldBlock), Action::FallBackToGdi);
        assert_eq!(h.backend(), Backend::Gdi);
    }

    /// The reason `pinned` exists. A still desktop publishes nothing, so an
    /// unpinned run answers "is this symptom DXGI's?" with a GDI stream.
    #[test]
    fn a_pinned_dxgi_stream_never_becomes_a_gdi_one_however_long_it_waits() {
        let mut h = Health::pinned(Backend::Dxgi);
        assert!(h.is_pinned());
        for _ in 0..(WOULD_BLOCK_BEFORE_GDI * 100 + 1) {
            assert_eq!(h.observe(Outcome::WouldBlock), Action::Retry);
            assert_eq!(h.backend(), Backend::Dxgi);
        }
        assert!(!h.has_failed(), "waiting is not failing");
        assert_eq!(h.observe(good()), Action::Deliver);
    }

    /// Pinned, an exhausted rebuild budget ends the stream instead of quietly
    /// producing frames from the backend the caller ruled out.
    #[test]
    fn a_pinned_dxgi_stream_that_cannot_rebuild_fails_rather_than_switching() {
        let mut h = Health::pinned(Backend::Dxgi);
        for _ in 0..MAX_REINIT_ATTEMPTS {
            assert_eq!(h.observe(Outcome::AccessLost), Action::Reinitialize);
        }
        assert_eq!(
            h.observe(Outcome::AccessLost),
            Action::Fail(Fault::AccessLostUnrecoverable)
        );
        assert_eq!(h.backend(), Backend::Dxgi, "it must not have switched");
        assert!(h.has_failed());
    }

    /// Same rule for a backend error: report it, do not paper over it — but
    /// report it after the retry budget, not on the first occurrence. Round 6
    /// changed this: a single error is a transient until proven otherwise.
    #[test]
    fn a_pinned_dxgi_backend_error_is_retried_then_faults_without_switching() {
        let mut h = Health::pinned(Backend::Dxgi);
        for i in 1..MAX_BACKEND_ERRORS {
            assert_eq!(
                h.observe(Outcome::BackendError("device removed".into())),
                Action::Retry,
                "error {i} must be retried, not treated as a dead backend"
            );
            assert_eq!(h.backend(), Backend::Dxgi, "pinned must never switch");
        }
        assert_eq!(
            h.observe(Outcome::BackendError("device removed".into())),
            Action::Fail(Fault::BackendUnavailable {
                detail: "device removed".into()
            })
        );
        assert_eq!(h.backend(), Backend::Dxgi);
        assert!(
            !h.has_failed(),
            "the budget ends the call, not the stream — a device that comes back              must be usable again without a new capturer"
        );
    }

    /// Pinning must not change what a healthy stream does, or a forced run
    /// would be measuring the pin instead of the backend.
    #[test]
    fn pinning_does_not_change_how_ordinary_frames_are_handled() {
        let mut pinned = Health::pinned(Backend::Gdi);
        let mut loose = Health::new(Backend::Gdi);
        for outcome in [good(), blank(), good(), blank(), blank()] {
            assert_eq!(pinned.observe(outcome.clone()), loose.observe(outcome));
        }
        for _ in 0..UNIFORM_FRAMES_BEFORE_FAULT {
            pinned.observe(blank());
            loose.observe(blank());
        }
        assert!(pinned.has_failed() && loose.has_failed());
    }

    #[test]
    fn a_normal_frame_is_delivered_and_clears_every_streak() {
        let mut h = Health::default();
        h.observe(Outcome::WouldBlock);
        h.observe(blank());
        assert_eq!(h.observe(good()), Action::Deliver);
        assert_eq!(h.would_block_streak(), 0);
        assert_eq!(h.uniform_streak(), 0);
    }

    /// The Block 8 rule. A white screen is delivered while it might still be a
    /// real black frame, and becomes a fault once it plainly is not.
    #[test]
    fn a_run_of_single_colour_frames_becomes_a_fault_not_a_stream() {
        let mut h = Health::default();
        for i in 1..UNIFORM_FRAMES_BEFORE_FAULT {
            assert_eq!(
                h.observe(blank()),
                Action::Deliver,
                "frame {i} is still plausibly a real black screen"
            );
        }
        assert_eq!(
            h.observe(blank()),
            Action::Fail(Fault::ConstantFrame {
                frames: UNIFORM_FRAMES_BEFORE_FAULT
            }),
            "frame {UNIFORM_FRAMES_BEFORE_FAULT} is not a screen, it is a broken capture"
        );
        assert!(h.has_failed());
    }

    /// A brief legitimate blank must not kill a session.
    #[test]
    fn a_short_blank_followed_by_real_content_is_not_a_fault() {
        let mut h = Health::default();
        for _ in 0..UNIFORM_FRAMES_BEFORE_FAULT - 1 {
            assert_eq!(h.observe(blank()), Action::Deliver);
        }
        assert_eq!(h.observe(good()), Action::Deliver);
        assert_eq!(h.uniform_streak(), 0, "the streak must reset");
        // And the full budget is available again.
        for _ in 0..UNIFORM_FRAMES_BEFORE_FAULT - 1 {
            assert_eq!(h.observe(blank()), Action::Deliver);
        }
        assert!(!h.has_failed());
    }

    /// The defect this guard exists for: a caller that ignores `Fail` must not
    /// be able to resume a stream that has already been declared broken.
    #[test]
    fn a_faulted_stream_never_reports_deliver_again() {
        let mut h = Health::default();
        for _ in 0..UNIFORM_FRAMES_BEFORE_FAULT {
            h.observe(blank());
        }
        assert!(h.has_failed());
        for _ in 0..5 {
            assert!(
                matches!(h.observe(good()), Action::Fail(_)),
                "a faulted stream must stay faulted"
            );
        }
    }

    #[test]
    fn one_would_block_is_retried_rather_than_treated_as_a_problem() {
        let mut h = Health::default();
        assert_eq!(h.observe(Outcome::WouldBlock), Action::Retry);
        assert_eq!(h.backend(), Backend::Dxgi);
    }

    #[test]
    fn a_run_of_would_blocks_falls_back_to_gdi_exactly_once() {
        let mut h = Health::default();
        for _ in 0..WOULD_BLOCK_BEFORE_GDI {
            assert_eq!(h.observe(Outcome::WouldBlock), Action::Retry);
        }
        assert_eq!(h.observe(Outcome::WouldBlock), Action::FallBackToGdi);
        assert_eq!(h.backend(), Backend::Gdi);
        // Already on GDI: no second fallback, just keep trying.
        for _ in 0..10 {
            assert_eq!(h.observe(Outcome::WouldBlock), Action::Retry);
        }
    }

    #[test]
    fn access_lost_rebuilds_before_it_gives_up() {
        let mut h = Health::default();
        for i in 1..=MAX_REINIT_ATTEMPTS {
            assert_eq!(
                h.observe(Outcome::AccessLost),
                Action::Reinitialize,
                "rebuild attempt {i}"
            );
        }
        assert_eq!(h.observe(Outcome::AccessLost), Action::FallBackToGdi);
        assert_eq!(h.backend(), Backend::Gdi);
    }

    /// A successful frame means the rebuild worked, so the next unrelated
    /// access-loss gets the full budget again rather than inheriting a used-up
    /// counter from an incident that is over.
    #[test]
    fn a_good_frame_restores_the_rebuild_budget() {
        let mut h = Health::default();
        for _ in 0..MAX_REINIT_ATTEMPTS {
            h.observe(Outcome::AccessLost);
        }
        h.observe(good());
        for i in 1..=MAX_REINIT_ATTEMPTS {
            assert_eq!(
                h.observe(Outcome::AccessLost),
                Action::Reinitialize,
                "budget restored, attempt {i}"
            );
        }
    }

    #[test]
    fn access_lost_on_gdi_is_terminal_because_there_is_nothing_below_it() {
        let mut h = Health::new(Backend::Gdi);
        assert_eq!(
            h.observe(Outcome::AccessLost),
            Action::Fail(Fault::AccessLostUnrecoverable)
        );
        assert!(h.has_failed());
    }

    /// The fallback is used ONCE, and there is nothing below GDI.
    ///
    /// Round 6 changed *when* the second half arrives, not whether it does: a
    /// GDI backend error is now retried up to [`MAX_BACKEND_ERRORS`] before the
    /// stream is declared dead, because a secure desktop makes `BitBlt` fail
    /// for exactly as long as a UAC prompt is up. The property this test has
    /// always guarded — that GDI does not get a fallback of its own, and that a
    /// backend which never recovers is eventually reported — is unchanged.
    #[test]
    fn a_dxgi_error_falls_back_once_and_gdi_has_nothing_below_it() {
        let mut h = Health::default();
        assert_eq!(
            h.observe(Outcome::BackendError("E_ACCESSDENIED".into())),
            Action::FallBackToGdi
        );
        assert_eq!(h.backend(), Backend::Gdi);

        // Now on GDI: retried, never switched again, and finally fatal.
        for _ in 1..MAX_BACKEND_ERRORS {
            assert_eq!(
                h.observe(Outcome::BackendError("BitBlt failed".into())),
                Action::Retry
            );
            assert_eq!(h.backend(), Backend::Gdi, "there is nothing below GDI");
        }
        assert_eq!(
            h.observe(Outcome::BackendError("BitBlt failed".into())),
            Action::Fail(Fault::BackendUnavailable {
                detail: "BitBlt failed".into()
            })
        );
    }

    /// Falling back must not also reset the blank-frame counter: a DXGI path
    /// that produced white and a GDI path that produces white are the same
    /// problem, and the fault must still arrive.
    #[test]
    fn falling_back_to_gdi_does_not_forgive_a_blank_screen() {
        let mut h = Health::default();
        for _ in 0..UNIFORM_FRAMES_BEFORE_FAULT - 1 {
            h.observe(blank());
        }
        assert_eq!(
            h.observe(Outcome::BackendError("dxgi died".into())),
            Action::FallBackToGdi
        );
        assert_eq!(
            h.uniform_streak(),
            UNIFORM_FRAMES_BEFORE_FAULT - 1,
            "the blank-frame evidence survives a backend change"
        );
        assert!(matches!(
            h.observe(blank()),
            Action::Fail(Fault::ConstantFrame { .. })
        ));
    }

    #[test]
    fn every_fault_renders_a_sentence_that_names_the_problem() {
        let faults = [
            Fault::ConstantFrame { frames: 30 },
            Fault::BackendUnavailable {
                detail: "no adapter".into(),
            },
            Fault::AccessLostUnrecoverable,
        ];
        for f in faults {
            let text = f.to_string();
            assert!(text.len() > 20, "{f:?} renders as {text:?}");
            assert!(!text.contains("Fault"), "{text:?} leaks the type name");
        }
    }
}

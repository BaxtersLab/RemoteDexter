//! Notice when the desktop changed size under a live capture.
//!
//! # The defect this exists for (defect E)
//!
//! A PipeWire screencast node is negotiated once. When the host's resolution
//! changes, the node goes on producing its original geometry, and nothing in
//! the capture path notices: `capture_rgba` faithfully reports the size of the
//! frames it is given, and those frames are still the old size. So the stream
//! continues, apparently healthy, showing a desktop that no longer matches the
//! one the operator is looking at — and every absolute pointer coordinate is
//! normalised against the wrong dimensions, so taps land in the wrong place.
//!
//! It is the mirror image of the Windows defect fixed in Block 8, where a
//! *rotation* was invisible to Desktop Duplication because the panel surface
//! never changed. Same shape: the capture source has no obligation to tell you
//! the world moved.
//!
//! # Why an independent opinion is required
//!
//! The capture cannot detect this by itself — it would be comparing its frames
//! against its own caps, which agree with each other by construction. Something
//! outside the capture has to say how big the display actually is.
//!
//! `module10::inject_linux::probe_screen_size` reads the DRM connectors from
//! sysfs. That needs no display-server connection, which matters twice: there
//! is no portable way to ask a Wayland compositor, and Article XIV forbids
//! experimenting against this box's live session.
//!
//! # Failing closed
//!
//! Every uncertain case here answers "do not rebuild". A spurious rebuild tears
//! down a working stream and re-enters the portal path, which on a bad day
//! costs the operator their grant. The cost of a missed change is a stale
//! picture that the next real change or reconnect will fix; the cost of a false
//! positive is a session that keeps killing itself. They are not symmetric.

/// Consecutive disagreements required before acting.
///
/// A resolution change is not atomic from sysfs's point of view: connectors can
/// be read mid-switch, and a single sample taken at the wrong moment can
/// disagree with a capture that is about to be correct. Three consecutive
/// readings, at the poll interval below, is a second of steady disagreement —
/// far longer than any mode switch, and far shorter than a person's patience.
pub const MISMATCHES_BEFORE_REBUILD: u32 = 3;

/// Minimum gap between probes, in milliseconds.
///
/// The capture path runs up to 20 times a second and reading sysfs on every
/// frame would be pure waste. A resolution change is a human action; noticing
/// it within about a second is immediate to the person who caused it.
pub const PROBE_INTERVAL_MS: u64 = 300;

/// Tracks whether the capture's geometry still matches the display's.
#[derive(Debug, Default)]
pub struct DisplayWatch {
    mismatches: u32,
}

impl DisplayWatch {
    pub const fn new() -> Self {
        DisplayWatch { mismatches: 0 }
    }

    /// Whether enough time has passed to be worth probing sysfs again.
    ///
    /// `None` means "never probed", which is always due.
    pub const fn due(ms_since_last_probe: Option<u64>) -> bool {
        match ms_since_last_probe {
            None => true,
            Some(ms) => ms >= PROBE_INTERVAL_MS,
        }
    }

    /// Feed one observation. `true` means: rebuild the capture now.
    ///
    /// Returns `true` **once** per change — the counter resets on firing, so a
    /// caller that keeps observing while the rebuild is in flight does not get
    /// told again on the next frame.
    pub fn observe(&mut self, capture: (u32, u32), probed: Option<(u32, u32)>) -> bool {
        let agree = match probed {
            // The probe failed. Says nothing about the display, so it must not
            // be read as a change.
            None => true,
            // A zero dimension is not a display, it is a failed parse that got
            // this far.
            Some((0, _)) | Some((_, 0)) => true,
            Some(p) => p == capture,
        };
        // A capture that has not produced a frame yet has no geometry to
        // disagree with.
        let capture_known = capture.0 != 0 && capture.1 != 0;

        if agree || !capture_known {
            self.mismatches = 0;
            return false;
        }
        self.mismatches += 1;
        if self.mismatches >= MISMATCHES_BEFORE_REBUILD {
            self.mismatches = 0;
            return true;
        }
        false
    }

    /// Disagreements seen so far. For diagnostics and tests.
    pub const fn mismatches(&self) -> u32 {
        self.mismatches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_display_never_rebuilds() {
        let mut w = DisplayWatch::new();
        for _ in 0..50 {
            assert!(!w.observe((1920, 1080), Some((1920, 1080))));
        }
    }

    /// The defect, stated as a test.
    #[test]
    fn a_changed_resolution_eventually_rebuilds() {
        let mut w = DisplayWatch::new();
        let mut fired = false;
        for _ in 0..MISMATCHES_BEFORE_REBUILD {
            fired = w.observe((1920, 1080), Some((2560, 1440)));
        }
        assert!(
            fired,
            "a sustained resolution change must trigger a rebuild"
        );
    }

    /// One sample is not evidence: sysfs can be read mid-switch.
    #[test]
    fn a_single_disagreement_does_not_rebuild() {
        let mut w = DisplayWatch::new();
        assert!(!w.observe((1920, 1080), Some((2560, 1440))));
    }

    /// A blip must not accumulate towards a rebuild across unrelated moments.
    #[test]
    fn a_transient_disagreement_resets() {
        let mut w = DisplayWatch::new();
        assert!(!w.observe((1920, 1080), Some((2560, 1440))));
        assert!(!w.observe((1920, 1080), Some((1920, 1080))));
        assert_eq!(w.mismatches(), 0, "agreement must clear the count");
        assert!(!w.observe((1920, 1080), Some((2560, 1440))));
        assert!(!w.observe((1920, 1080), Some((2560, 1440))));
    }

    /// **The dangerous case.** A host whose sysfs read breaks must not rebuild
    /// its capture forever.
    #[test]
    fn a_failed_probe_never_rebuilds() {
        let mut w = DisplayWatch::new();
        for _ in 0..100 {
            assert!(!w.observe((1920, 1080), None));
        }
    }

    /// A zero dimension is a failed parse that got this far, not a display.
    #[test]
    fn a_zero_probe_never_rebuilds() {
        let mut w = DisplayWatch::new();
        for _ in 0..100 {
            assert!(!w.observe((1920, 1080), Some((0, 1080))));
            assert!(!w.observe((1920, 1080), Some((1920, 0))));
        }
    }

    /// Before the first frame the capture has no geometry, so it cannot
    /// disagree with anything.
    #[test]
    fn a_capture_with_no_frames_yet_never_rebuilds() {
        let mut w = DisplayWatch::new();
        for _ in 0..100 {
            assert!(!w.observe((0, 0), Some((1920, 1080))));
        }
    }

    /// Fires once, not on every subsequent frame while the rebuild runs.
    #[test]
    fn firing_resets_so_a_rebuild_is_requested_once() {
        let mut w = DisplayWatch::new();
        for _ in 0..MISMATCHES_BEFORE_REBUILD {
            w.observe((1920, 1080), Some((2560, 1440)));
        }
        assert!(
            !w.observe((1920, 1080), Some((2560, 1440))),
            "a second rebuild must not be requested immediately after the first"
        );
    }

    /// A rotation on Linux presents as a swapped pair, and must be caught.
    #[test]
    fn a_rotation_counts_as_a_change() {
        let mut w = DisplayWatch::new();
        let mut fired = false;
        for _ in 0..MISMATCHES_BEFORE_REBUILD {
            fired = w.observe((1920, 1080), Some((1080, 1920)));
        }
        assert!(fired, "a rotated display is a different geometry");
    }

    #[test]
    fn probing_is_rate_limited_but_always_due_at_first() {
        assert!(DisplayWatch::due(None));
        assert!(!DisplayWatch::due(Some(0)));
        assert!(!DisplayWatch::due(Some(PROBE_INTERVAL_MS - 1)));
        assert!(DisplayWatch::due(Some(PROBE_INTERVAL_MS)));
    }
}

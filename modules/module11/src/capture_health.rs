//! Pure policy for a portal capture session's liveness and recovery.
//!
//! The Linux counterpart of `capture_windows::health`, and it exists for a
//! defect found on 2026-08-25: rotating the host display destroyed the portal's
//! PipeWire node (`pw-cli info 69` -> "unknown global"), and the host did not
//! notice. Its capture layer treats "no buffer this tick" as a quiet desktop —
//! correct for a damage-driven stream — and re-emitted the last frame forever.
//! The phone therefore received a valid, frozen picture with no error at all,
//! and the session stayed honestly Connected because the transport really was
//! fine. Only capture had died.
//!
//! The rule this module encodes is the one that was missing: **a stream that has
//! ended is not a desktop that has stopped changing.** Silence is ambiguous;
//! end-of-stream is not, so the decision is driven by an explicit observation
//! rather than by a timeout that would false-positive on an idle desktop.
//!
//! Pure on purpose — no GStreamer, no portal, no clock. The wiring needs
//! hardware; this does not, so the rule is provable on any machine.

/// How long to wait before rebuilding a portal session that has died.
///
/// A rebuild re-runs the portal handshake, so retrying every frame would hammer
/// xdg-desktop-portal ~30 times a second for as long as the fault lasts.
pub const REBUILD_BACKOFF_MS: u64 = 2_000;

/// What one capture attempt saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// A new buffer arrived.
    Fresh,
    /// No buffer, and the stream is still alive — a desktop that has not
    /// repainted genuinely produces nothing.
    Quiet,
    /// The stream signalled end-of-stream or posted an error. Fatal.
    Ended,
}

/// What the capture layer should do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Serve the frame that just arrived.
    Serve,
    /// Serve the previous frame again; nothing has changed.
    ReuseLast,
    /// Report a fault. Never dress a stale frame as a live one.
    Fault,
}

/// Decide what to do, given what was seen and whether a previous frame exists.
pub const fn action(observed: Observation, has_last_frame: bool) -> Action {
    match observed {
        // The whole point of this module. A dead stream must never be served
        // as a static desktop, however many frames were captured before it.
        Observation::Ended => Action::Fault,
        Observation::Fresh => Action::Serve,
        Observation::Quiet => {
            if has_last_frame {
                Action::ReuseLast
            } else {
                // Nothing new and nothing to fall back on: there is no honest
                // frame to serve.
                Action::Fault
            }
        }
    }
}

/// May a dead session be rebuilt yet?
///
/// `None` means nothing has been attempted, so the first try is always allowed.
pub const fn may_rebuild(ms_since_last_attempt: Option<u64>) -> bool {
    match ms_since_last_attempt {
        None => true,
        Some(ms) => ms >= REBUILD_BACKOFF_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect, stated as a test: a stream that ended must fault even though
    /// a perfectly good previous frame is sitting right there. Serving it is
    /// what produced a frozen phone and no error.
    #[test]
    fn an_ended_stream_faults_even_with_a_frame_in_hand() {
        assert_eq!(action(Observation::Ended, true), Action::Fault);
        assert_eq!(action(Observation::Ended, false), Action::Fault);
    }

    /// The behaviour that must NOT regress while fixing the above: a
    /// damage-driven stream legitimately goes quiet over a still desktop, and
    /// that is not a fault.
    #[test]
    fn a_quiet_stream_reuses_the_last_frame() {
        assert_eq!(action(Observation::Quiet, true), Action::ReuseLast);
    }

    #[test]
    fn a_quiet_stream_with_nothing_to_reuse_faults() {
        assert_eq!(action(Observation::Quiet, false), Action::Fault);
    }

    #[test]
    fn a_fresh_frame_is_served() {
        assert_eq!(action(Observation::Fresh, false), Action::Serve);
        assert_eq!(action(Observation::Fresh, true), Action::Serve);
    }

    #[test]
    fn the_first_rebuild_attempt_is_always_allowed() {
        assert!(may_rebuild(None));
    }

    #[test]
    fn rebuilds_are_rate_limited_but_not_forbidden() {
        assert!(!may_rebuild(Some(0)), "an immediate retry would hammer the portal");
        assert!(!may_rebuild(Some(REBUILD_BACKOFF_MS - 1)));
        assert!(may_rebuild(Some(REBUILD_BACKOFF_MS)));
        assert!(
            may_rebuild(Some(60_000)),
            "recovery must stay possible however long the fault lasted"
        );
    }
}

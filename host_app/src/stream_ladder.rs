//! Pure policy: how hard should the encoder push right now?
//!
//! The other half of defect D. `stream_backpressure` stops stale frames from
//! queueing, which caps latency — but on its own it means the encoder still
//! produces 20 fps at quality 75 and throws most of it away, and still
//! overdrives the link hard enough to cause the loss that collapsed `cwnd` to 1
//! on a real session. Dropping is damage control; sending less is the fix.
//!
//! **The signal is the drop count**, which `stream_backpressure` already
//! produces. Dropping a frame IS the observation that production exceeds drain,
//! so no new instrumentation is needed.
//!
//! **Known limit, stated rather than hidden:** this reads *our* queue. The
//! kernel socket buffer sits underneath it and can hold megabytes while our
//! queue looks healthy, so the signal under-reads congestion. The accurate
//! reading is the socket's own `notsent`/`cwnd` via `TCP_INFO`, which is
//! Linux-specific and was deliberately left out of this change. This ladder is
//! a floor under a link that is already collapsing, not a congestion
//! controller.
//!
//! ## Why a ladder and not a dial
//!
//! Continuous adjustment oscillates, and oscillation between two nearly-equal
//! settings is visible as pulsing. Discrete rungs make the behaviour damped,
//! bounded, and enumerable in a test.
//!
//! ## Why the asymmetry
//!
//! Classic AIMD: back off fast, recover slowly. Backing off one rung too far
//! costs a little sharpness; recovering one rung too eagerly re-enters the
//! collapse that takes seconds of retransmits to climb out of. The costs are
//! not symmetric, so the response is not either.
//!
//! Pure — no clock, no channel, no socket. Same shape as
//! `module11::capture_health` and `stream_backpressure`.

/// One operating point. Ordered by bytes per second, richest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rung {
    /// Milliseconds between frames. Larger = fewer frames = fewer bytes, and
    /// less encode CPU — which is why it is the first knob, not quality.
    pub frame_interval_ms: u64,
    /// JPEG quality ceiling for this rung.
    pub quality: u8,
}

/// The ladder. Roughly geometric in bitrate: about 9x from top to bottom.
pub const RUNGS: [Rung; 6] = [
    Rung {
        frame_interval_ms: 50,
        quality: 75,
    }, // 20 fps — the old fixed point
    Rung {
        frame_interval_ms: 66,
        quality: 70,
    }, // ~15 fps
    Rung {
        frame_interval_ms: 100,
        quality: 65,
    }, // 10 fps
    Rung {
        frame_interval_ms: 125,
        quality: 60,
    }, // 8 fps
    Rung {
        frame_interval_ms: 200,
        quality: 55,
    }, // 5 fps
    Rung {
        frame_interval_ms: 333,
        quality: 50,
    }, // ~3 fps — the floor
];

/// Decisions per evaluation window.
pub const WINDOW_FRAMES: u32 = 16;

/// Clean windows required before climbing one rung.
pub const PROMOTE_AFTER_CLEAN_WINDOWS: u32 = 3;

/// Where the ladder currently sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State {
    /// Index into [`RUNGS`]. 0 is richest.
    pub rung: usize,
    /// Consecutive windows with no drops.
    pub clean_windows: u32,
}

impl State {
    /// Start at the top: a healthy link must behave exactly as before.
    pub const fn top() -> Self {
        State {
            rung: 0,
            clean_windows: 0,
        }
    }

    /// The operating point to encode at.
    pub fn rung(&self) -> Rung {
        RUNGS[self.rung.min(RUNGS.len() - 1)]
    }
}

/// Fold one window's outcome into the ladder position.
pub fn on_window(state: State, dropped: u32, sent: u32) -> State {
    let last = RUNGS.len() - 1;
    if dropped == 0 {
        let clean = state.clean_windows + 1;
        if clean >= PROMOTE_AFTER_CLEAN_WINDOWS && state.rung > 0 {
            State {
                rung: state.rung - 1,
                clean_windows: 0,
            }
        } else {
            State {
                rung: state.rung,
                clean_windows: clean,
            }
        }
    } else {
        // Heavy loss means the link is far from where we are, not one rung
        // away, so take two. Dropping at least half the window counts as heavy.
        let offered = dropped + sent;
        let step = if dropped * 2 >= offered { 2 } else { 1 };
        State {
            rung: (state.rung + step).min(last),
            clean_windows: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A structural invariant: the ladder must actually descend in bitrate.
    /// Guards against a future edit that reorders a rung and silently makes
    /// "backing off" cost more bandwidth than it saves.
    #[test]
    fn every_rung_is_cheaper_than_the_one_above_it() {
        for pair in RUNGS.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            assert!(
                b.frame_interval_ms >= a.frame_interval_ms,
                "interval must not shrink going down the ladder: {a:?} -> {b:?}"
            );
            assert!(
                b.quality <= a.quality,
                "quality must not rise going down the ladder: {a:?} -> {b:?}"
            );
            assert!(
                b.frame_interval_ms > a.frame_interval_ms || b.quality < a.quality,
                "a rung that costs the same as the one above it is not a rung: {a:?} -> {b:?}"
            );
        }
    }

    #[test]
    fn a_healthy_link_stays_at_the_top() {
        let mut s = State::top();
        for _ in 0..50 {
            s = on_window(s, 0, WINDOW_FRAMES);
        }
        assert_eq!(s.rung, 0, "no drops must never cost quality");
    }

    #[test]
    fn sustained_drops_walk_down_and_stop_at_the_floor() {
        let mut s = State::top();
        for _ in 0..50 {
            s = on_window(s, WINDOW_FRAMES, 0);
        }
        assert_eq!(s.rung, RUNGS.len() - 1, "must reach the floor");
        // And stay there — no index past the end.
        s = on_window(s, WINDOW_FRAMES, 0);
        assert_eq!(s.rung, RUNGS.len() - 1);
    }

    #[test]
    fn a_recovered_link_climbs_back_to_the_top_and_stops() {
        let mut s = State {
            rung: RUNGS.len() - 1,
            clean_windows: 0,
        };
        for _ in 0..200 {
            s = on_window(s, 0, WINDOW_FRAMES);
        }
        assert_eq!(s.rung, 0, "a link that recovered must get its quality back");
    }

    /// The asymmetry that keeps it from oscillating: falling is fast, climbing
    /// is slow. Stated as a measured comparison rather than a comment.
    #[test]
    fn backing_off_is_faster_than_recovering() {
        let mut down = State::top();
        let mut fall = 0;
        while down.rung != RUNGS.len() - 1 {
            down = on_window(down, 1, WINDOW_FRAMES - 1);
            fall += 1;
        }

        let mut up = State {
            rung: RUNGS.len() - 1,
            clean_windows: 0,
        };
        let mut climb = 0;
        while up.rung != 0 {
            up = on_window(up, 0, WINDOW_FRAMES);
            climb += 1;
        }

        assert!(
            climb > fall,
            "recovery ({climb} windows) must be slower than back-off ({fall})"
        );
    }

    #[test]
    fn heavy_loss_backs_off_further_than_light_loss() {
        let light = on_window(State::top(), 1, WINDOW_FRAMES - 1);
        let heavy = on_window(State::top(), WINDOW_FRAMES, 0);
        assert_eq!(light.rung, 1);
        assert_eq!(
            heavy.rung, 2,
            "losing the whole window is not a one-rung problem"
        );
    }

    #[test]
    fn a_single_drop_is_enough_to_back_off() {
        let s = on_window(State::top(), 1, WINDOW_FRAMES - 1);
        assert_eq!(
            s.rung, 1,
            "waiting for a threshold means waiting for collapse"
        );
        assert_eq!(
            s.clean_windows, 0,
            "a drop resets progress toward promotion"
        );
    }

    /// A drop midway through recovery must reset the clean streak, or the
    /// ladder would creep upward on a link that is still failing.
    #[test]
    fn one_drop_resets_the_climb() {
        let mut s = State {
            rung: 3,
            clean_windows: 0,
        };
        s = on_window(s, 0, WINDOW_FRAMES);
        s = on_window(s, 0, WINDOW_FRAMES);
        assert_eq!(s.clean_windows, 2, "two clean windows banked");
        s = on_window(s, 1, WINDOW_FRAMES - 1);
        assert_eq!(s.clean_windows, 0);
        assert_eq!(s.rung, 4, "and it costs a rung too");
    }
}

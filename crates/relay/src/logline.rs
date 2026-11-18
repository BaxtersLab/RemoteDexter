//! Every line relayd writes about a peer, in one place.
//!
//! **These formats are a contract.** fail2ban bans on two of them
//! (`deploy/fail2ban/filter.d/remotedexter-relay.conf`), and an external watcher
//! classifies the rest. `tests/fail2ban_contract.rs` pins the filter to the
//! strings this crate actually produces, and `docs/RUNNING_YOUR_OWN_RELAY.md`
//! lists every line a watcher may rely on. Change a format here and both must
//! change with it, which is the point of keeping them in one file.
//!
//! ```text
//! [relayd] <peer>: <reason>
//! [relayd] refused <peer>: <cap> connections already unauthenticated
//! [relayd] refused <n> more in the last <ms> ms: <cap> connections already unauthenticated
//! ```
//!
//! `<peer>` is Rust's `SocketAddr` display: `203.0.113.7:4242`, or
//! `[2001:db8::7]:4242` for IPv6.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Every relayd line starts with this.
pub const TAG: &str = "[relayd]";

/// The fixed tail of both refusal lines.
pub const PENDING_REFUSAL_TAIL: &str = "connections already unauthenticated";

/// At most one refusal line per this interval.
pub const REFUSAL_LINE_INTERVAL: Duration = Duration::from_secs(1);

/// `[relayd] <peer>: <reason>` — what relayd logs when serving a connection
/// ends in an error. `<reason>` is `ServeError::public_reason()`.
pub fn peer_line(peer: &SocketAddr, reason: &str) -> String {
    format!("{TAG} {peer}: {reason}")
}

/// The load at which the relay starts saying how full it is.
///
/// Reported before the ceiling is reached, not at it. With hosts dialling in on
/// start the relay fills without anyone doing anything, and "relay at capacity"
/// arriving with no warning means the first person refused is how the operator
/// finds out there was a limit.
pub const CAPACITY_NOTICE_PERCENT: usize = 50;

/// `[relayd] capacity: <live> of <max> sessions live (<pct>%)`
///
/// **Deliberately shaped so the ban filter cannot match it.** That filter wants
/// `<ADDR>:<port>: <reason>`, and this line has a word where the address would
/// be — pinned by `tests/fail2ban_contract.rs`, which fails if this line ever
/// starts looking like a refusal. It carries no address at all: how full the
/// relay is says nothing about who is on it.
pub fn capacity_line(live: usize, capacity: usize, percent: usize) -> String {
    format!("{TAG} capacity: {live} of {capacity} sessions live ({percent}%)")
}

/// The shortest gap between two capacity lines.
pub const CAPACITY_LINE_INTERVAL: Duration = Duration::from_secs(60);

/// The width of a capacity band. A line is printed when the load moves into a
/// different band, not at every session that comes or goes.
pub const CAPACITY_BAND_PERCENT: usize = 10;

/// Decides when a capacity line is worth printing.
///
/// # Why it is throttled
///
/// It printed whenever the percentage changed at or above 50%. With 64 sessions
/// that is a new percentage for every host that connects or leaves, and the
/// deploy agent found Server Guard counts unrecognised lines toward a
/// "degraded" alarm at ten a minute. A busy relay would have raised a false
/// alarm by being busy. Now: only when the load moves into a different 10% band,
/// and never more than once a minute — including a load oscillating across the
/// 50% line, which would otherwise print on every crossing.
///
/// The line's FORMAT is unchanged.
#[derive(Debug, Default)]
pub struct CapacityLog {
    /// The band last printed, or `None` below the notice threshold.
    band: Option<usize>,
    /// When a line was last printed. Kept across dips below the threshold, so
    /// crossing and re-crossing 50% cannot print faster than the interval.
    last_line: Option<Instant>,
}

impl CapacityLog {
    /// Take the current load; return the line to print, if one is due.
    pub fn observe(
        &mut self,
        live: usize,
        capacity: usize,
        percent: usize,
        now: Instant,
    ) -> Option<String> {
        let band = (percent >= CAPACITY_NOTICE_PERCENT)
            .then_some(percent / CAPACITY_BAND_PERCENT * CAPACITY_BAND_PERCENT);
        if band == self.band {
            return None;
        }
        let Some(band) = band else {
            // Fell below the threshold. Nothing to say, but remember it, so
            // coming back above is news.
            self.band = None;
            return None;
        };
        if let Some(at) = self.last_line {
            if now.saturating_duration_since(at) < CAPACITY_LINE_INTERVAL {
                // Too soon. `band` is left as it was, so the change is still
                // pending and is reported once the interval has passed.
                return None;
            }
        }
        self.band = Some(band);
        self.last_line = Some(now);
        Some(capacity_line(live, capacity, percent))
    }
}

/// `[relayd] refused <peer>: <cap> connections already unauthenticated` — one
/// connection refused at the door, logged with its address.
pub fn refused_line(peer: &SocketAddr, cap: usize) -> String {
    format!("{TAG} refused {peer}: {cap} {PENDING_REFUSAL_TAIL}")
}

/// `[relayd] refused <n> more in the last <ms> ms: <cap> connections already
/// unauthenticated` — refusals that were not logged one by one, counted.
pub fn refused_summary_line(count: u64, over: Duration, cap: usize) -> String {
    format!(
        "{TAG} refused {count} more in the last {} ms: {cap} {PENDING_REFUSAL_TAIL}",
        over.as_millis()
    )
}

/// Rate-limits the pending-cap refusal line without losing the count.
///
/// Past the cap relayd used to log one line per refused connection. journald's
/// default per-service limit is 10,000 lines in 30 s, so a flood could make
/// journald drop lines — including the ones a watcher needs to see the flood at
/// all. Now: the first refusal after a quiet second is logged with its peer;
/// the rest are counted and reported in one summary line, and no two lines are
/// ever less than [`REFUSAL_LINE_INTERVAL`] apart. Every refusal is in exactly
/// one line: a per-peer line counts one, a summary counts `<n>`.
///
/// Pure — the caller passes the clock — so the guarantee is provable without
/// a flood.
#[derive(Debug)]
pub struct RefusalLog {
    cap: usize,
    last_line: Option<Instant>,
    suppressed: u64,
}

impl RefusalLog {
    pub fn new(cap: usize) -> Self {
        RefusalLog {
            cap,
            last_line: None,
            suppressed: 0,
        }
    }

    /// A connection was refused. Returns the line to log now, if any.
    pub fn refused(&mut self, peer: &SocketAddr, now: Instant) -> Option<String> {
        match self.last_line {
            Some(t) if now.saturating_duration_since(t) < REFUSAL_LINE_INTERVAL => {
                self.suppressed += 1;
                None
            }
            Some(t) if self.suppressed > 0 => {
                let line = refused_summary_line(
                    self.suppressed + 1,
                    now.saturating_duration_since(t),
                    self.cap,
                );
                self.suppressed = 0;
                self.last_line = Some(now);
                Some(line)
            }
            _ => {
                self.last_line = Some(now);
                Some(refused_line(peer, self.cap))
            }
        }
    }

    /// Call on a timer. Reports refusals still uncounted once the interval has
    /// passed, so a flood that stops is still reported.
    pub fn flush(&mut self, now: Instant) -> Option<String> {
        let t = self.last_line?;
        let since = now.saturating_duration_since(t);
        if self.suppressed == 0 || since < REFUSAL_LINE_INTERVAL {
            return None;
        }
        let line = refused_summary_line(self.suppressed, since, self.cap);
        self.suppressed = 0;
        self.last_line = Some(now);
        Some(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "203.0.113.7:4242".parse().unwrap()
    }

    #[test]
    fn the_peer_line_is_tag_address_reason() {
        assert_eq!(
            peer_line(&peer(), "frame too large"),
            "[relayd] 203.0.113.7:4242: frame too large"
        );
        let v6: SocketAddr = "[2001:db8::7]:4242".parse().unwrap();
        assert_eq!(
            peer_line(&v6, "malformed frame"),
            "[relayd] [2001:db8::7]:4242: malformed frame"
        );
    }

    #[test]
    fn a_quiet_relays_first_refusal_is_logged_at_once_with_its_peer() {
        let mut log = RefusalLog::new(256);
        let t0 = Instant::now();
        assert_eq!(
            log.refused(&peer(), t0).as_deref(),
            Some("[relayd] refused 203.0.113.7:4242: 256 connections already unauthenticated")
        );
        assert_eq!(
            log.flush(t0 + Duration::from_secs(5)),
            None,
            "nothing was suppressed"
        );
    }

    #[test]
    fn a_flood_in_one_second_is_one_line_and_one_count() {
        let mut log = RefusalLog::new(256);
        let t0 = Instant::now();
        let mut lines = Vec::new();
        for i in 0..100_000u64 {
            let now = t0 + Duration::from_micros(i * 9); // all within 0.9 s
            lines.extend(log.refused(&peer(), now));
        }
        assert_eq!(lines.len(), 1, "a flood must not become a flood of lines");
        let summary = log
            .flush(t0 + Duration::from_secs(1))
            .expect("the suppressed count must be reported");
        assert_eq!(
            summary,
            "[relayd] refused 99999 more in the last 1000 ms: 256 connections already unauthenticated"
        );
    }

    #[test]
    fn lines_are_a_second_apart_and_every_refusal_is_counted_once() {
        let mut log = RefusalLog::new(256);
        let t0 = Instant::now();
        let mut emitted: Vec<(Duration, u64)> = Vec::new();
        let count_of = |line: &str| -> u64 {
            match line
                .strip_prefix("[relayd] refused ")
                .and_then(|r| r.split_once(" more"))
            {
                Some((n, _)) => n.parse().unwrap(),
                None => 1,
            }
        };
        let mut refusals = 0u64;
        // A refusal every 3 ms for 10 s, with the timer flushing every 250 ms,
        // then quiet long enough for the last flush.
        for ms in (0..12_000u64).step_by(1) {
            let now = t0 + Duration::from_millis(ms);
            if ms < 10_000 && ms % 3 == 0 {
                refusals += 1;
                if let Some(l) = log.refused(&peer(), now) {
                    emitted.push((now - t0, count_of(&l)));
                }
            }
            if ms % 250 == 0 {
                if let Some(l) = log.flush(now) {
                    emitted.push((now - t0, count_of(&l)));
                }
            }
        }
        for pair in emitted.windows(2) {
            assert!(
                pair[1].0 - pair[0].0 >= REFUSAL_LINE_INTERVAL,
                "two lines {:?} apart",
                pair[1].0 - pair[0].0
            );
        }
        assert_eq!(emitted.iter().map(|e| e.1).sum::<u64>(), refusals);
        assert!(
            emitted.len() <= 12,
            "{} lines for 10 s of refusals",
            emitted.len()
        );
    }

    /// The capacity line must carry no address, and must not be shaped like the
    /// refusal lines a ban filter reads. A relay that banned an address because
    /// it was busy would ban whoever happened to be logged beside the number.
    #[test]
    fn the_capacity_line_names_no_address() {
        let line = capacity_line(33, 64, 51);
        assert!(line.starts_with(&format!("{TAG} capacity:")), "{line}");
        assert!(line.contains("33 of 64"), "{line}");
        assert!(line.contains("(51%)"), "{line}");
        assert!(
            !line.contains(PENDING_REFUSAL_TAIL),
            "the capacity line borrowed the refusal wording: {line}"
        );
        // No dotted quad, and nothing that reads as <addr>:<port>.
        assert!(
            !line.chars().any(|c| c == '.'),
            "the capacity line contains something address-shaped: {line}"
        );
    }

    /// Silent below half full; says so on reaching it.
    #[test]
    fn the_capacity_line_is_silent_below_half_and_speaks_on_reaching_it() {
        let mut log = CapacityLog::default();
        let now = Instant::now();
        for percent in [0, 1, 25, 49] {
            assert_eq!(
                log.observe(percent * 64 / 100, 64, percent, now),
                None,
                "{percent}%"
            );
        }
        let line = log
            .observe(32, 64, 50, now)
            .expect("reaching 50% said nothing");
        assert_eq!(
            line,
            capacity_line(32, 64, 50),
            "the capacity line's format changed"
        );
        // Holding steady is not news.
        assert_eq!(
            log.observe(32, 64, 50, now + Duration::from_secs(120)),
            None
        );
    }

    /// **A load that climbs is reported by band, at most once a minute.**
    ///
    /// With 64 sessions every host that comes or goes moves the percentage, and
    /// Server Guard counts unrecognised lines toward a "degraded" alarm at ten a
    /// minute. A line per change would have let a busy relay raise a false
    /// alarm by being busy.
    #[test]
    fn a_climbing_load_is_reported_by_band_and_no_more_than_once_a_minute() {
        let mut log = CapacityLog::default();
        let t0 = Instant::now();
        assert!(log.observe(32, 64, 50, t0).is_some());
        // Same band: nothing, however many sessions arrive.
        assert_eq!(log.observe(35, 64, 54, t0 + Duration::from_secs(5)), None);
        // A new band, but too soon.
        assert_eq!(log.observe(40, 64, 62, t0 + Duration::from_secs(30)), None);
        // The minute has passed and the change is still true: now it is said,
        // with the current figure.
        assert_eq!(
            log.observe(41, 64, 64, t0 + CAPACITY_LINE_INTERVAL),
            Some(capacity_line(41, 64, 64))
        );
        // Long after the floor, a move WITHIN the band is still not news. Without
        // this, the minute's floor would hide a log that printed every change.
        assert_eq!(
            log.observe(42, 64, 65, t0 + CAPACITY_LINE_INTERVAL * 5),
            None,
            "a change inside the same 10% band printed a line"
        );
    }

    /// **A load hovering on the 50% line cannot print faster than once a minute.**
    ///
    /// Dipping below and coming back is a new "reached 50%" each time. Without a
    /// floor that holds ACROSS the dip, a relay sitting at 31-32 sessions would
    /// print every few seconds.
    #[test]
    fn a_load_hovering_on_half_prints_at_most_once_a_minute() {
        let mut log = CapacityLog::default();
        let t0 = Instant::now();
        let mut lines = 0;
        for s in 0..300u64 {
            let (live, percent) = if s % 2 == 0 { (32, 50) } else { (31, 48) };
            if log
                .observe(live, 64, percent, t0 + Duration::from_secs(s))
                .is_some()
            {
                lines += 1;
            }
        }
        assert!(
            (1..=5).contains(&lines),
            "five minutes hovering on 50% printed {lines} capacity lines"
        );
    }
}

//! The fail2ban filter and jail, held to the strings relayd actually writes.
//!
//! fail2ban bans on log text, and only this crate controls that text. A reason
//! renamed here would silently disarm the ban on the server; a must-not-ban
//! reason slipping into the filter would ban phones on bad networks. Both are
//! failures nobody would see until they mattered, so the filter is loaded with
//! `include_str!` — cargo rebuilds when it changes — and checked against the
//! code, not against a copy of the strings.
//!
//! Proven against fail2ban itself as well: `fail2ban-regex` 1.0.2 on
//! `sample.log` gives 6 matched / 13 missed, in both the file and the journal
//! line form (see the deploy drop's DEPLOY.txt). This test keeps that sample and
//! the filter in step with the code.

use relay::auth::HostAuthError;
use relay::frame::FrameError;
use relay::logline;
use relay::{ServeError, TableError};
use std::net::SocketAddr;
use std::time::Duration;

const FILTER: &str = include_str!("../deploy/fail2ban/filter.d/remotedexter-relay.conf");
const JAIL: &str = include_str!("../deploy/fail2ban/jail.d/remotedexter-relay.local");
const SAMPLE: &str = include_str!("../deploy/fail2ban/sample.log");

/// The relay's pending cap, as relayd logs it.
const PENDING_CAP: usize = 256;

/// `key = value` lines of a fail2ban ini file, comments and sections skipped.
/// A continuation line (indented) is refused rather than silently ignored.
fn settings(ini: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for line in ini.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') || line.starts_with('[') {
            continue;
        }
        assert!(
            !line.starts_with(char::is_whitespace),
            "continuation line in a fail2ban file this test cannot read: {line:?}"
        );
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("not key = value: {line:?}"));
        out.push((k.trim(), v.trim()));
    }
    out
}

fn failregex() -> &'static str {
    let found: Vec<_> = settings(FILTER)
        .into_iter()
        .filter(|(k, _)| *k == "failregex")
        .collect();
    assert_eq!(found.len(), 1, "exactly one failregex line");
    found[0].1
}

/// The alternatives inside `(?:...)$`, which is where the trigger words live.
fn triggers() -> Vec<&'static str> {
    let re = failregex();
    let start = re.rfind("(?:").expect("trigger group") + 3;
    let end = re.rfind(")$").expect("anchored trigger group");
    re[start..end].split('|').collect()
}

/// Every reason relayd can log that must NEVER ban, taken from the code.
fn must_not_ban() -> Vec<(&'static str, String)> {
    let peer: SocketAddr = "203.0.113.7:4242".parse().unwrap();
    vec![
        (
            "auth refusal",
            HostAuthError::NotAuthorised.public_reason().to_string(),
        ),
        (
            "protocol version",
            ServeError::Version(0).public_reason().to_string(),
        ),
        (
            "unexpected frame",
            ServeError::Unexpected.public_reason().to_string(),
        ),
        (
            "relay at capacity",
            TableError::AtCapacity.public_reason().to_string(),
        ),
        ("ordinary close", ServeError::Io.public_reason().to_string()),
        (
            "stalled session",
            ServeError::Stalled.public_reason().to_string(),
        ),
        (
            "silent socket",
            ServeError::Silent.public_reason().to_string(),
        ),
        (
            "stale invite",
            TableError::UnknownSession.public_reason().to_string(),
        ),
        ("empty frame", FrameError::Empty.public_reason().to_string()),
        ("pending refusal", logline::refused_line(&peer, PENDING_CAP)),
        (
            "pending refusal summary",
            logline::refused_summary_line(41, Duration::from_millis(1000), PENDING_CAP),
        ),
        // New in P4. How full the relay is is not an accusation against
        // anybody, and it carries no address for a filter to lift.
        ("capacity notice", logline::capacity_line(33, 64, 51)),
        // A join refused for arriving too fast is told exactly what an unknown
        // session is told, so this is the same string as "stale invite" — kept
        // as its own row so a change to either is caught here rather than in
        // whichever one happens to be read first.
        (
            "join rate limit",
            TableError::TooManyJoins.public_reason().to_string(),
        ),
    ]
}

#[test]
fn the_trigger_strings_are_the_codes_own_frame_refusals() {
    let mut got = triggers();
    got.sort_unstable();
    let mut want = vec![
        FrameError::TooLarge(usize::MAX).public_reason(),
        FrameError::Malformed.public_reason(),
    ];
    want.sort_unstable();
    assert_eq!(
        got, want,
        "the filter bans on words the relay does not write"
    );
}

#[test]
fn no_must_not_ban_reason_appears_in_the_filter() {
    let re = failregex();
    for (what, reason) in must_not_ban() {
        assert!(
            !triggers().contains(&reason.as_str()),
            "{what} ({reason:?}) is a ban trigger"
        );
        // For a refusal line, its fixed wording; for a reason, the whole reason.
        let tail = if reason.starts_with("[relayd] refused") {
            logline::PENDING_REFUSAL_TAIL
        } else {
            reason.as_str()
        };
        assert!(
            !re.contains(tail),
            "{what} ({tail:?}) appears in the failregex"
        );
    }
}

#[test]
fn the_filter_expects_the_line_format_relayd_writes() {
    let peer: SocketAddr = "192.0.2.10:2412".parse().unwrap();
    assert_eq!(
        logline::peer_line(&peer, FrameError::TooLarge(0).public_reason()),
        "[relayd] 192.0.2.10:2412: frame too large"
    );
    assert_eq!(logline::TAG, "[relayd]");
    assert!(
        failregex().contains(r"\[relayd\] <ADDR>:\d+: (?:"),
        "the filter no longer expects `[relayd] <peer>: <reason>`"
    );
    assert!(
        failregex().starts_with("^%(__prefix_line)s"),
        "journal prefix handling changed"
    );
    assert!(settings(FILTER).contains(&("_daemon", "relayd")));
}

#[test]
fn the_sample_log_is_the_codes_own_lines_in_the_expected_numbers() {
    #[derive(PartialEq)]
    enum Part {
        Header,
        Positive,
        Negative,
        LookAlike,
    }
    let mut part = Part::Header;
    let (mut positives, mut negatives, mut lookalikes) = (Vec::new(), Vec::new(), Vec::new());
    for line in SAMPLE.lines() {
        if line.starts_with("# --- positives") {
            part = Part::Positive;
        } else if line.starts_with("# --- negatives") {
            part = Part::Negative;
        } else if line.starts_with("# --- look-alikes") {
            part = Part::LookAlike;
        } else if !line.starts_with('#') && !line.is_empty() {
            let message = line.split_once("]: ").map(|(_, m)| m).unwrap_or(line);
            match part {
                Part::Header => panic!("log line before any section: {line:?}"),
                Part::Positive => positives.push((line, message)),
                Part::Negative => negatives.push(message),
                Part::LookAlike => lookalikes.push(line),
            }
        }
    }

    // Every positive is relayd's own line for a trigger, from a relayd process.
    for (line, message) in &positives {
        assert!(
            line.contains(" relayd["),
            "positive not from relayd: {line:?}"
        );
        let (peer, reason) = message
            .strip_prefix("[relayd] ")
            .and_then(|m| m.split_once(": "))
            .unwrap_or_else(|| panic!("not a peer line: {message:?}"));
        let peer: SocketAddr = peer.parse().unwrap();
        assert!(
            triggers().contains(&reason),
            "positive that is not a trigger: {message:?}"
        );
        assert_eq!(logline::peer_line(&peer, reason), *message);
    }
    // One negative for every must-not-ban reason, each byte-for-byte a line the
    // code can write.
    for (what, reason) in must_not_ban() {
        let found = negatives.iter().any(|m| {
            *m == reason
                || m.strip_prefix("[relayd] ")
                    .and_then(|r| r.split_once(": "))
                    .is_some_and(|(peer, r)| peer.parse::<SocketAddr>().is_ok() && r == reason)
                || (reason.starts_with("[relayd] refused")
                    && m.starts_with("[relayd] refused")
                    && m.ends_with(logline::PENDING_REFUSAL_TAIL)
                    && reason.contains(" more ") == m.contains(" more "))
        });
        assert!(found, "sample.log has no negative for {what}");
    }

    let frame_too_large = positives
        .iter()
        .filter(|(_, m)| m.ends_with(": frame too large"))
        .count();
    let malformed = positives
        .iter()
        .filter(|(_, m)| m.ends_with(": malformed frame"))
        .count();
    assert!(
        frame_too_large >= 3 && malformed >= 1,
        "the brief's minimum positives"
    );
    let missed = negatives.len() + lookalikes.len();
    assert!(
        SAMPLE.contains(&format!("matched: {}   ", positives.len())),
        "header matched count is not {}",
        positives.len()
    );
    assert!(
        SAMPLE.contains(&format!("missed:  {missed}  ")),
        "header missed count is not {missed}"
    );
}

#[test]
fn the_jail_bans_port_9443_for_escalating_hours_and_runs_nothing_else() {
    let s = settings(JAIL);
    let get = |key: &str| -> &str {
        let v: Vec<_> = s.iter().filter(|(k, _)| *k == key).collect();
        assert_eq!(v.len(), 1, "exactly one {key}");
        v[0].1
    };
    assert_eq!(get("enabled"), "true");
    assert_eq!(get("backend"), "systemd");
    assert_eq!(
        get("journalmatch"),
        "_SYSTEMD_UNIT=remotedexter-relay.service"
    );
    assert_eq!(get("filter"), "remotedexter-relay");
    assert_eq!(get("port"), "9443");
    assert_eq!(get("protocol"), "tcp");
    assert_eq!(get("maxretry"), "3");
    assert_eq!(get("findtime"), "10m");
    assert_eq!(get("bantime"), "1h");
    assert_eq!(get("bantime.increment"), "true");
    // fail2ban 1.0.2: bantime * multipliers[earlier bans], capped at maxtime —
    // 1 h, 24 h, 168 h, then 168 h.
    assert_eq!(get("bantime.multipliers"), "1 24 168");
    assert_eq!(get("bantime.maxtime"), "7d");
    assert_eq!(get("usedns"), "no");
    for forbidden in [
        "action",
        "banaction",
        "banaction_allports",
        "ignoreip",
        "ignorecommand",
    ] {
        assert!(
            !s.iter().any(|(k, _)| *k == forbidden),
            "the jail sets {forbidden}: no notification action, no all-ports ban, no allow-list"
        );
    }
    assert!(JAIL.contains("[remotedexter-relay]"));
}

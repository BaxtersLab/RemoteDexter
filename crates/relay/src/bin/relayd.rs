//! `relayd` — the WAN relay, as a server.
//!
//! It listens on one port, splices ciphertext between a host and a phone, and
//! does nothing else. Everything it is allowed to know is in `crates/relay`'s
//! module docs; what is here is the part that owns a listener, a clock and a
//! signal handler.
//!
//! # Fails closed
//!
//! There are no defaults. No bind address, no authentication method, no
//! credentials: every one must be named, and `relayd` refuses to start without
//! them. A relay that started with a default would be a relay that accepted any
//! host that asked, on an address nobody chose.
//!
//! # What it never logs
//!
//! Bearer tokens, in any form. Session ids and tickets, which are what a phone
//! and a host present to be spliced. And not one byte of a session: there is no
//! code here that could read one.
//!
//! **It is silent on success, and that is deliberate rather than unfinished.**
//! A registration and a splice produce no line at all; only refusals do. An
//! earlier draft carried a `fingerprint()` helper to log session ids as short
//! hashes, and it was removed because nothing called it — the relay never needs
//! to name a session, and a helper kept for a use that has not arrived is how
//! dead code enters a release.
//!
//! If operational logging is wanted later — "a host registered", "a session
//! ended" — it needs `serve_connection` to report what kind of connection it
//! served, which it does not today. That is a deliberate design change, not a
//! call to an existing helper.

use relay::auth::{BearerToken, EnrolThenProve, HostAuth, HostIdentity};
use relay::logline::{self, RefusalLog};
use relay::{serve_connection_admitted, Relay};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// The most connections being authenticated at once.
///
/// A connection that has not yet said who it is costs a task and a buffer. The
/// bound is what stops a stranger accumulating them; refusing costs one accept
/// and one close, which is cheaper than holding what it asked for.
///
/// It counts ONLY connections that have not identified themselves: the permit
/// goes into `serve_connection_admitted` and is released at a successful
/// register, join or attach. Until 2026-09-14 it was held for the connection's
/// whole life, so registered hosts and live sessions counted against it.
const MAX_PENDING: usize = 256;

/// How `relayd` was told to run.
#[derive(Debug, PartialEq, Eq)]
struct Config {
    bind: SocketAddr,
    auth: AuthChoice,
}

#[derive(Debug, PartialEq, Eq)]
enum AuthChoice {
    /// One or more per-host shared secrets. The relay stores only their hashes.
    Bearer(Vec<String>),
    /// One or more enrolled Ed25519 host identities, challenged on every
    /// registration.
    Signing(Vec<[u8; 32]>),
}

impl Config {
    /// Parse from a lookup rather than from the process environment.
    ///
    /// Taking the lookup as a parameter is what makes every branch testable
    /// without setting a real variable — and this project has already paid for
    /// env-var tests once, in a poisoned lock that turned one failure into
    /// nine.
    fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let bind = get("RD_RELAY_BIND").ok_or_else(|| {
            "RD_RELAY_BIND is not set. There is no default: a relay that binds an address nobody \
             chose is a relay listening somewhere nobody meant."
                .to_string()
        })?;
        let bind: SocketAddr = bind
            .parse()
            .map_err(|_| format!("RD_RELAY_BIND is not an address and port: {bind}"))?;

        let method = get("RD_RELAY_AUTH").ok_or_else(|| {
            "RD_RELAY_AUTH is not set. Choose `bearer` or `signing`; there is no default, because \
             the default would be whichever one this file happened to list first."
                .to_string()
        })?;

        let auth = match method.as_str() {
            "bearer" => {
                let raw = get("RD_RELAY_TOKENS")
                    .ok_or_else(|| "RD_RELAY_AUTH=bearer needs RD_RELAY_TOKENS".to_string())?;
                let tokens: Vec<String> = raw
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                if tokens.is_empty() {
                    // Never quote the value back: the error would carry it.
                    return Err("RD_RELAY_TOKENS contained no tokens".to_string());
                }
                AuthChoice::Bearer(tokens)
            }
            "signing" => {
                let raw = get("RD_RELAY_HOSTS")
                    .ok_or_else(|| "RD_RELAY_AUTH=signing needs RD_RELAY_HOSTS".to_string())?;
                let mut keys = Vec::new();
                for (i, entry) in raw
                    .split(',')
                    .map(str::trim)
                    .filter(|e| !e.is_empty())
                    .enumerate()
                {
                    use base64::Engine;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(entry)
                        .map_err(|_| format!("RD_RELAY_HOSTS entry {} is not base64", i + 1))?;
                    let key: [u8; 32] = bytes.try_into().map_err(|_| {
                        format!("RD_RELAY_HOSTS entry {} is not a 32-byte key", i + 1)
                    })?;
                    keys.push(key);
                }
                if keys.is_empty() {
                    return Err("RD_RELAY_HOSTS contained no keys".to_string());
                }
                AuthChoice::Signing(keys)
            }
            other => {
                return Err(format!(
                    "RD_RELAY_AUTH must be `bearer` or `signing`, not `{other}`"
                ))
            }
        };

        Ok(Config { bind, auth })
    }

    fn into_auth(self) -> Box<dyn HostAuth> {
        match self.auth {
            AuthChoice::Bearer(tokens) => Box::new(BearerToken::new(&tokens)),
            AuthChoice::Signing(keys) => {
                let ids: Vec<HostIdentity> = keys.into_iter().map(HostIdentity).collect();
                Box::new(EnrolThenProve::new(&ids))
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let config = match Config::parse(|k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(why) => {
            eprintln!("[relayd] refusing to start: {why}");
            std::process::exit(2);
        }
    };

    let bind = config.bind;
    let described = match &config.auth {
        // The COUNT, never the tokens.
        AuthChoice::Bearer(t) => format!("bearer, {} credential(s) enrolled", t.len()),
        AuthChoice::Signing(k) => format!("enrol-then-prove, {} host identity(ies)", k.len()),
    };

    let listener = match TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[relayd] could not bind {bind}: {}", e.kind());
            std::process::exit(2);
        }
    };
    let bound = listener.local_addr().unwrap_or(bind);

    eprintln!("[relayd] listening on {bound}");
    eprintln!("[relayd] host authentication: {described}");
    if bound.ip().is_unspecified() {
        // Said out loud, not refused: unlike the host, a relay is MEANT to be
        // publicly reachable. What must not happen is it becoming so by
        // accident.
        eprintln!(
            "[relayd] NOTE: {bound} is a wildcard — every interface on this machine is reachable"
        );
    }
    eprintln!(
        "[relayd] the relay sees ciphertext only; it has no code that could decrypt a session"
    );

    let relay = Relay::new(config.into_auth());
    let pending = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING));
    // One refusal line per second at most, with the rest counted: a line per
    // refused connection let a flood exceed journald's rate limit and blind
    // whatever watches the log. See `relay::logline`.
    let mut refusals = RefusalLog::new(MAX_PENDING);
    let mut refusal_tick = tokio::time::interval(logline::REFUSAL_LINE_INTERVAL);
    refusal_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // How full the relay is, said on a tick rather than per registration — a
    // host reconnecting is not news — and throttled: see `CapacityLog`.
    let mut capacity_log = logline::CapacityLog::default();

    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = refusal_tick.tick() => {
                if let Some(line) = refusals.flush(std::time::Instant::now()) {
                    eprintln!("{line}");
                }
                // Say how full the relay is once it is half full, when it moves
                // into a different 10% band, and never more than once a minute.
                let (live, capacity, percent) = relay.load();
                if let Some(line) =
                    capacity_log.observe(live, capacity, percent, std::time::Instant::now())
                {
                    eprintln!("{line}");
                }
                continue;
            }
            _ = shutdown_signal() => {
                eprintln!("[relayd] signal received — no longer accepting");
                break;
            }
        };
        let Ok((sock, peer)) = accepted else { continue };

        // Refuse rather than queue. A queued connection costs a task and a
        // buffer for as long as the peer cares to hold it.
        let Ok(permit) = pending.clone().try_acquire_owned() else {
            if let Some(line) = refusals.refused(&peer, std::time::Instant::now()) {
                eprintln!("{line}");
            }
            drop(sock);
            continue;
        };

        let r = relay.clone();
        tokio::spawn(async move {
            // The permit is released inside, the moment the connection has
            // identified itself: the cap counts only connections that have not.
            let outcome = serve_connection_admitted(&r, sock, permit).await;
            if let Err(e) = outcome {
                // The coarse public reason, which is all the peer was told.
                eprintln!("{}", logline::peer_line(&peer, e.public_reason()));
            }
        });
    }

    eprintln!("[relayd] stopped");
}

/// Wait for the operator, or the service manager, to ask it to stop.
///
/// SIGTERM is what systemd sends, so the relay must not need a SIGKILL to go
/// away. The non-Unix arm is not aspiration — leaving the Unix signal API
/// unguarded would make this file fail to compile for any other target, which
/// is a portability defect whether or not anything compiles it today.
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v.to_string())
        }
    }

    /// **Fails closed.** Every one of these is a relay that would otherwise
    /// start and accept hosts nobody enrolled, on an address nobody chose.
    #[test]
    fn every_missing_setting_refuses_to_start() {
        for (missing, pairs) in [
            (
                "bind",
                vec![("RD_RELAY_AUTH", "bearer"), ("RD_RELAY_TOKENS", "t")],
            ),
            ("auth", vec![("RD_RELAY_BIND", "127.0.0.1:9443")]),
            (
                "tokens",
                vec![
                    ("RD_RELAY_BIND", "127.0.0.1:9443"),
                    ("RD_RELAY_AUTH", "bearer"),
                ],
            ),
            (
                "hosts",
                vec![
                    ("RD_RELAY_BIND", "127.0.0.1:9443"),
                    ("RD_RELAY_AUTH", "signing"),
                ],
            ),
        ] {
            assert!(
                Config::parse(env(&pairs)).is_err(),
                "a relay started with no {missing}"
            );
        }
    }

    #[test]
    fn an_empty_token_list_is_refused() {
        let pairs = [
            ("RD_RELAY_BIND", "127.0.0.1:9443"),
            ("RD_RELAY_AUTH", "bearer"),
            ("RD_RELAY_TOKENS", " , , "),
        ];
        assert!(
            Config::parse(env(&pairs)).is_err(),
            "a relay enrolled nobody and started anyway"
        );
    }

    #[test]
    fn an_unknown_auth_method_is_refused_by_name() {
        let pairs = [
            ("RD_RELAY_BIND", "127.0.0.1:9443"),
            ("RD_RELAY_AUTH", "none"),
        ];
        let why = Config::parse(env(&pairs)).unwrap_err();
        assert!(
            why.contains("bearer"),
            "the refusal should say what is valid: {why}"
        );
    }

    #[test]
    fn bearer_tokens_are_split_and_trimmed() {
        let pairs = [
            ("RD_RELAY_BIND", "127.0.0.1:9443"),
            ("RD_RELAY_AUTH", "bearer"),
            ("RD_RELAY_TOKENS", "one, two ,three"),
        ];
        match Config::parse(env(&pairs)).unwrap().auth {
            AuthChoice::Bearer(t) => assert_eq!(t.len(), 3),
            other => panic!("expected bearer, got {other:?}"),
        }
    }

    /// A malformed key is refused rather than truncated, padded, or skipped.
    #[test]
    fn a_host_key_that_is_not_32_bytes_is_refused() {
        use base64::Engine;
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let pairs = [
            ("RD_RELAY_BIND", "127.0.0.1:9443"),
            ("RD_RELAY_AUTH", "signing"),
            ("RD_RELAY_HOSTS", short.as_str()),
        ];
        let why = Config::parse(env(&pairs)).unwrap_err();
        assert!(why.contains("32-byte"), "should name the problem: {why}");
    }

    #[test]
    fn a_valid_signing_configuration_parses() {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let pairs = [
            ("RD_RELAY_BIND", "127.0.0.1:9443"),
            ("RD_RELAY_AUTH", "signing"),
            ("RD_RELAY_HOSTS", key.as_str()),
        ];
        match Config::parse(env(&pairs)).unwrap().auth {
            AuthChoice::Signing(k) => assert_eq!(k, vec![[7u8; 32]]),
            other => panic!("expected signing, got {other:?}"),
        }
    }

    /// **No error may quote a credential back.** An operator pasting a bad
    /// token into a terminal must not have it land in scrollback, a log, or a
    /// support paste.
    #[test]
    fn a_refusal_never_quotes_the_credential() {
        let fixture = "inert-fixture-value";
        let pairs = [
            ("RD_RELAY_BIND", "not-an-address"),
            ("RD_RELAY_AUTH", "bearer"),
            ("RD_RELAY_TOKENS", fixture),
        ];
        let why = Config::parse(env(&pairs)).unwrap_err();
        assert!(
            !why.contains(fixture),
            "the refusal carried the credential: {why}"
        );
    }
}

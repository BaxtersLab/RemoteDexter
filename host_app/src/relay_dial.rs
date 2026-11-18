//! Dialling out to the relay, and serving clients it hands back.
//!
//! # Why this lives here and not in `host_controller`
//!
//! `host_controller` owns no wire protocol — it is the lifecycle machine, and
//! the only thing permitted to create a listener. The relay control grammar IS
//! a wire protocol, so it is spoken here and injected through
//! [`host_controller::DialOut`]. The controller learns only that something
//! produces sockets and reports how the host is reachable.
//!
//! # The shape
//!
//! One persistent CONTROL connection, dialled out and held. When a phone
//! arrives the relay sends `ClientWaiting` down it with a single-use ticket, and
//! this host dials a SECOND connection presenting that ticket. Only the second
//! carries session bytes, and the relay splices it without looking.
//!
//! The host never binds. That is the point of the exercise — `bind`'s wildcard
//! refusal is not routed around here, it is simply not involved.

use host_controller::source::{DialFailure, DialFuture, DialOut, PeerFuture, PeerSource};
use host_controller::Reach;
use relay_proto::{self as frame, ControlFrame, PROTOCOL_VERSION};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long the control connection may say nothing before the host treats it
/// as gone.
///
/// **Found 2026-09-17 and 2026-09-18, twice the same way.** The host's path to
/// the relay rebound — a NAT or VPN mapping reset — mid-session. The busy
/// session connection failed at once ("Broken pipe"); the idle control
/// connection failed silently: the relay's pings stopped reaching the host, the
/// relay gave up and closed it, and that close never arrived either. The host
/// only ever READS its control connection, so it waited on a socket that would
/// never speak again, and the re-dial that would have fixed it never ran. Ten
/// hours, then three.
///
/// The relay pings every `CONTROL_KEEPALIVE` (20 s) and gives `KEEPALIVE_GRACE`
/// (10 s) for the answer, so a live control connection is never quiet for much
/// more than 20 s. 45 s is past two ping intervals; a test holds the two
/// crates to it.
pub const CONTROL_SILENCE_LIMIT: Duration = Duration::from_secs(45);

/// How long one dial-back may take, from connect to `Attached`.
///
/// It runs inside the same future that answers the relay's pings, so while it
/// waits the host is not listening to its relay — and on a path that has gone
/// dead, an unbounded wait never ends. The relay answers an `Attach` at once
/// and gives a host 10 s to answer a ping, so 8 s is generous for a live path
/// and still inside that grace.
pub const DIAL_BACK_LIMIT: Duration = Duration::from_secs(8);

/// How this host proves itself to the relay.
///
/// Both methods the relay implements are represented, because which one is used
/// is the operator's decision and it is still open. Neither is a default: a
/// `RelayDialOut` cannot be built without one being named.
pub enum RelayCredential {
    /// A per-host shared secret, sent as the registration itself. The relay
    /// stores only its SHA-256, so relay state that leaks yields no working
    /// credential — but the secret does cross the wire, and a replayed
    /// registration frame is a registration.
    Bearer(String),
    /// The host's Ed25519 identity. The relay issues a nonce and this signs it,
    /// so nothing replayable crosses the wire.
    Signing(ed25519_dalek::SigningKey),
}

impl std::fmt::Debug for RelayCredential {
    /// Never renders either credential. A `Debug` that printed the bearer token
    /// would put it in the first log line that formatted a dial-out error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayCredential::Bearer(_) => f.write_str("RelayCredential::Bearer(<redacted>)"),
            RelayCredential::Signing(_) => f.write_str("RelayCredential::Signing(<key>)"),
        }
    }
}

impl RelayCredential {
    /// What goes in `Register.host_pub`.
    fn announce(&self) -> String {
        match self {
            RelayCredential::Bearer(token) => token.clone(),
            RelayCredential::Signing(sk) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
            }
        }
    }

    /// Sign the relay's challenge nonce. `None` when this method has no answer,
    /// which is itself the right answer: a bearer host asked to sign has been
    /// pointed at a relay expecting a different method.
    fn prove(&self, nonce: &[u8]) -> Option<String> {
        match self {
            RelayCredential::Bearer(_) => None,
            RelayCredential::Signing(sk) => {
                use base64::Engine;
                use ed25519_dalek::Signer;
                Some(base64::engine::general_purpose::STANDARD.encode(sk.sign(nonce).to_bytes()))
            }
        }
    }
}

/// Which credential a configured method calls for.
///
/// Split from [`RelayDialOut::configure`] so every branch is testable without
/// setting a real environment variable — this estate has paid for env-var tests
/// once already, in a poisoned lock that turned one failure into nine.
pub(crate) fn credential_from(
    method: &str,
    token: Option<String>,
    signing: Option<ed25519_dalek::SigningKey>,
) -> Result<RelayCredential, String> {
    match method {
        "bearer" => match token {
            Some(t) if !t.is_empty() => Ok(RelayCredential::Bearer(t)),
            // Never quote the value back, even when it is empty: the message
            // ends up in a terminal the operator may paste somewhere.
            _ => Err("RD_RELAY_AUTH=bearer needs RD_RELAY_TOKEN".to_string()),
        },
        "signing" => signing.map(RelayCredential::Signing).ok_or_else(|| {
            "RD_RELAY_AUTH=signing needs this host's invite-signing identity, \
             which has not been loaded"
                .to_string()
        }),
        "" => Err("RD_RELAY_AUTH is not set — choose `bearer` or `signing`".to_string()),
        other => Err(format!(
            "RD_RELAY_AUTH must be `bearer` or `signing`, not `{other}`"
        )),
    }
}

/// Where this run's relay address came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `RD_RELAY`, for this run only. Never written to the settings file.
    Environment,
    /// `settings.json`, chosen by the owner and remembered.
    Stored,
}

impl Origin {
    /// How the console names it.
    pub fn label(self) -> &'static str {
        match self {
            Origin::Environment => "set by RD_RELAY for this run",
            Origin::Stored => "remembered",
        }
    }
}

/// The relay this host would dial, or why it would not.
///
/// Computed from the stored settings and the environment together, so the
/// console can show ONE answer about the relay rather than two half-answers
/// that disagree. A configuration that is present and unusable is its own
/// state: it must never look the same as having no relay at all, which is the
/// difference between "you have not set this up" and "what you set up is wrong".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPlan {
    /// No relay anywhere.
    Unset,
    /// A relay this host can dial.
    Dial {
        /// The address, already parsed.
        relay: SocketAddr,
        /// Where it came from.
        origin: Origin,
    },
    /// A relay is configured and cannot be used.
    Unusable {
        /// Where the unusable value came from.
        origin: Origin,
        /// Safe to show. Never quotes a credential.
        why: String,
    },
}

impl RelayPlan {
    /// The address to dial, if there is one.
    pub fn address(&self) -> Option<SocketAddr> {
        match self {
            RelayPlan::Dial { relay, .. } => Some(*relay),
            _ => None,
        }
    }

    /// One line for the console.
    pub fn summary(&self) -> String {
        match self {
            RelayPlan::Unset => {
                "No relay: this host can only be reached on the local network.".to_string()
            }
            RelayPlan::Dial { relay, origin } => format!("Relay {relay} ({})", origin.label()),
            RelayPlan::Unusable { origin, why } => {
                format!("Relay unusable ({}): {why}", origin.label())
            }
        }
    }
}

/// Work out which relay this host would dial.
///
/// **The environment wins, and the file is never written from it.** `RD_RELAY`
/// is how development and the tests point a host at a throwaway relay, and a
/// stored address silently overriding it would make those runs reach the real
/// one. Pure, so every branch is provable without setting a process-global
/// variable — this estate has paid for env-var tests once already.
pub fn plan(
    stored: &crate::settings::RelaySettings,
    var: impl Fn(&str) -> Option<String>,
) -> RelayPlan {
    let (raw, origin) = match (var("RD_RELAY"), stored.address.as_deref()) {
        (Some(from_env), _) => (from_env, Origin::Environment),
        (None, Some(from_file)) => (from_file.to_string(), Origin::Stored),
        (None, None) => return RelayPlan::Unset,
    };
    match raw.trim().parse::<SocketAddr>() {
        Ok(relay) => RelayPlan::Dial { relay, origin },
        // The value is echoed because the owner typed it and needs to see which
        // of the two it is. It is an address, not a credential.
        Err(_) => RelayPlan::Unusable {
            origin,
            why: format!("`{}` is not an address and port", raw.trim()),
        },
    }
}

/// Dials the relay and registers, producing a live [`RelaySource`].
pub struct RelayDialOut {
    relay: SocketAddr,
    credential: RelayCredential,
    silence_limit: Duration,
    dial_back_limit: Duration,
}

impl RelayDialOut {
    pub fn new(relay: SocketAddr, credential: RelayCredential) -> Self {
        RelayDialOut {
            relay,
            credential,
            silence_limit: CONTROL_SILENCE_LIMIT,
            dial_back_limit: DIAL_BACK_LIMIT,
        }
    }

    /// The same dial-out with shorter limits, so a test can watch a silent
    /// relay be given up on in milliseconds. Test-only: the product always
    /// runs the constants above.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, silence: Duration, dial_back: Duration) -> Self {
        self.silence_limit = silence;
        self.dial_back_limit = dial_back;
        self
    }

    /// Build from the stored settings and the environment together.
    ///
    /// **`RD_RELAY_AUTH` is required when the address came from the
    /// environment, and is not inferred**, exactly as `relayd` requires it.
    /// Deciding the method from whether `RD_RELAY_TOKEN` happens to be set
    /// would hide the thing that matters most to a reader — WHICH CREDENTIAL
    /// this host presents — and would silently downgrade a signing host to a
    /// bearer one the moment a variable went missing.
    ///
    /// A **stored** relay needs no such variable: `settings.json` can only say
    /// `signing`, because the other method needs a token and a token in a
    /// settings file is a credential at rest that the owner never chose to
    /// store.
    ///
    /// ```text
    /// RD_RELAY=host:port        overrides the stored address for this run
    /// RD_RELAY_AUTH=bearer      RD_RELAY_TOKEN is then required
    /// RD_RELAY_AUTH=signing     uses this host's own invite-signing identity
    /// ```
    ///
    /// A token is read and never logged, never echoed into an error, and never
    /// written anywhere. It is the operator's, set in the operator's own shell.
    pub fn configure(
        stored: &crate::settings::RelaySettings,
        var: impl Fn(&str) -> Option<String>,
        signing: Option<ed25519_dalek::SigningKey>,
    ) -> Relay {
        let plan = plan(stored, &var);
        let (relay, origin) = match plan {
            RelayPlan::Dial { relay, origin } => (relay, origin),
            // Nothing to build, and the reason is already in the plan.
            other => {
                return Relay {
                    plan: other,
                    dial_out: None,
                }
            }
        };
        // A stored relay says `signing` by its own type. The environment may
        // still name a method, and when it does it is the one used, because a
        // developer pointing this host at a throwaway bearer relay must not
        // have the stored choice silently applied to it.
        let method = match (var("RD_RELAY_AUTH"), origin) {
            (Some(named), _) => named,
            (None, Origin::Stored) => match stored.auth {
                crate::settings::RelayAuth::Signing => "signing".to_string(),
            },
            (None, Origin::Environment) => String::new(),
        };
        match credential_from(&method, var("RD_RELAY_TOKEN"), signing) {
            Ok(credential) => Relay {
                plan: RelayPlan::Dial { relay, origin },
                dial_out: Some(RelayDialOut::new(relay, credential)),
            },
            // A relay that is configured wrongly must not look identical to one
            // that was never configured: the console would simply have no
            // button and no reason for its absence.
            Err(why) => Relay {
                plan: RelayPlan::Unusable { origin, why },
                dial_out: None,
            },
        }
    }
}

/// What this host knows about its relay: what to show, and what to dial with.
///
/// One value, computed once at start, so the console and the controller cannot
/// disagree about whether there is a relay.
pub struct Relay {
    /// What the console shows.
    pub plan: RelayPlan,
    /// The dialler, present exactly when [`RelayPlan::Dial`] is.
    pub dial_out: Option<RelayDialOut>,
}

impl DialOut for RelayDialOut {
    /// Dial and register.
    ///
    /// Every failure says whether it is worth trying again, and the split is
    /// not cosmetic: a relay that could not be REACHED is an ordinary event on
    /// a laptop and is retried quietly, while a relay that answered and said no
    /// is shown to the operator and dialled no further. Retrying a rejected
    /// credential would hammer the relay and overwrite the reason before anyone
    /// could read it.
    fn connect(&mut self) -> DialFuture<'_> {
        Box::pin(async move {
            let mut control = TcpStream::connect(self.relay).await.map_err(|e| {
                DialFailure::unreachable(format!("could not reach the relay: {}", e.kind()))
            })?;

            write_frame(
                &mut control,
                &ControlFrame::Register {
                    v: PROTOCOL_VERSION,
                    host_pub: self.credential.announce(),
                },
            )
            .await
            .map_err(|_| DialFailure::unreachable("the relay closed while registering"))?;

            let session = loop {
                let f = read_frame(&mut control)
                    .await
                    .map_err(|_| DialFailure::unreachable("the relay closed while registering"))?;
                match f {
                    ControlFrame::Challenge { nonce } => {
                        use base64::Engine;
                        let nonce = base64::engine::general_purpose::STANDARD
                            .decode(nonce)
                            .map_err(|_| {
                                // Not retryable: a relay that cannot phrase a
                                // challenge is not one this host can register
                                // with, and dialling it again produces the same
                                // malformed frame.
                                DialFailure::refused("the relay sent a malformed challenge")
                            })?;
                        let sig = self.credential.prove(&nonce).ok_or_else(|| {
                            DialFailure::refused(
                                "the relay asked this host to sign, and it is configured with a shared secret instead",
                            )
                        })?;
                        write_frame(&mut control, &ControlFrame::Prove { sig })
                            .await
                            .map_err(|_| {
                                DialFailure::unreachable("the relay closed while registering")
                            })?;
                    }
                    ControlFrame::Registered { session } => break session,
                    // The reason is the relay's coarse one by design; it is
                    // shown as given and never embellished into a guess.
                    ControlFrame::Denied { why } => {
                        return Err(DialFailure::refused(format!(
                            "the relay refused this host: {why}"
                        )))
                    }
                    _ => return Err(DialFailure::refused("the relay sent an unexpected frame")),
                }
            };

            Ok(Box::new(RelaySource {
                relay: self.relay,
                control,
                session,
                served: 0,
                silence_limit: self.silence_limit,
                dial_back_limit: self.dial_back_limit,
                last_heard: tokio::time::Instant::now(),
            }) as Box<dyn PeerSource>)
        })
    }
}

/// A registered control connection, handing back one data connection per client.
pub struct RelaySource {
    relay: SocketAddr,
    control: TcpStream,
    session: String,
    /// Labels have to be unique per connection and must not be the ticket: a
    /// ticket is single-use credential-shaped data and belongs in no log line.
    served: u64,
    /// See [`CONTROL_SILENCE_LIMIT`].
    silence_limit: Duration,
    /// See [`DIAL_BACK_LIMIT`].
    dial_back_limit: Duration,
    /// When the relay last said anything on the control connection. Kept here,
    /// not in `next_peer`, because the accept loop drops and recreates that
    /// future: a deadline held inside it would restart every time.
    last_heard: tokio::time::Instant,
}

impl RelaySource {
    /// Open the data connection for one waiting client.
    ///
    /// Bounded by [`DIAL_BACK_LIMIT`]: this runs inside the future that answers
    /// the relay's pings, so while it waits the host is not listening to its
    /// relay.
    async fn dial_back(&mut self, ticket: String) -> Option<(TcpStream, SocketAddr, String)> {
        let relay = self.relay;
        let hand_over = async move {
            let mut data = TcpStream::connect(relay).await.ok()?;
            write_frame(
                &mut data,
                &ControlFrame::Attach {
                    v: PROTOCOL_VERSION,
                    ticket,
                },
            )
            .await
            .ok()?;
            match read_frame(&mut data).await.ok()? {
                ControlFrame::Attached => Some(data),
                _ => None,
            }
        };
        let data = match tokio::time::timeout(self.dial_back_limit, hand_over).await {
            Ok(data) => data?,
            Err(_) => {
                eprintln!(
                    "[host] a hand-over through the relay did not complete within {} s — dropped",
                    self.dial_back_limit.as_secs()
                );
                return None;
            }
        };
        self.served += 1;
        let label = format!("via relay {} #{}", self.relay, self.served);
        Some((data, self.relay, label))
    }
}

impl PeerSource for RelaySource {
    fn next_peer(&mut self) -> PeerFuture<'_> {
        Box::pin(async move {
            loop {
                // Silence is an answer. See CONTROL_SILENCE_LIMIT: a path that
                // rebinds leaves this socket open and mute for ever, and a
                // host that only reads it would never find out.
                let deadline = self.last_heard + self.silence_limit;
                let frame =
                    match tokio::time::timeout_at(deadline, read_frame(&mut self.control)).await {
                        Ok(frame) => frame,
                        Err(_) => {
                            eprintln!(
                            "[host] nothing from the relay for {} s — its connection is gone even \
                             though it never closed",
                            self.silence_limit.as_secs()
                        );
                            return None;
                        }
                    };
                if frame.is_ok() {
                    self.last_heard = tokio::time::Instant::now();
                }
                match frame {
                    // Keepalive. A dialled-out connection sits idle between
                    // clients and a home NAT reaps idle TCP without telling
                    // either end; answering is what keeps the relay from
                    // releasing this host's session.
                    Ok(ControlFrame::Ping) => {
                        if write_frame(&mut self.control, &ControlFrame::Pong)
                            .await
                            .is_err()
                        {
                            return None;
                        }
                    }
                    Ok(ControlFrame::ClientWaiting { ticket }) => {
                        match self.dial_back(ticket).await {
                            Some(peer) => return Some(peer),
                            // ONE failed hand-over is not the end of the control
                            // connection. The relay frees the ticket and the client
                            // gives up; this host waits for the next one rather
                            // than tearing down a session that is still fine.
                            None => continue,
                        }
                    }
                    // Anything else, or a closed socket, is the end of the
                    // route. The controller turns this into a visible fault:
                    // a host that cannot be reached must not keep saying it is
                    // pairable.
                    _ => return None,
                }
            }
        })
    }

    fn reach(&self) -> Reach {
        Reach::ViaRelay {
            relay: self.relay,
            session: self.session.clone(),
        }
    }
}

async fn write_frame(sock: &mut TcpStream, f: &ControlFrame) -> std::io::Result<()> {
    let body = frame::encode(f);
    sock.write_all(&(body.len() as u32).to_be_bytes()).await?;
    sock.write_all(&body).await?;
    sock.flush().await
}

async fn read_frame(sock: &mut TcpStream) -> std::io::Result<ControlFrame> {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await?;
    let declared = u32::from_be_bytes(len) as usize;
    // The cap is applied to the PREFIX, before the body is read. The relay does
    // the same to us; a host that trusted a length a hostile relay announced
    // would allocate whatever it was told to.
    let n = frame::check_len(declared).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "control frame too large")
    })?;
    let mut body = vec![0u8; n];
    sock.read_exact(&mut body).await?;
    frame::decode(&body).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed control frame")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay::auth::{BearerToken, EnrolThenProve, HostIdentity};
    use relay::server::write_frame as relay_write;
    use relay::{accept_data, confirm_join, heartbeat, join_client, mint_attach, register_host};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;

    /// Settings holding one stored relay address.
    fn stored(address: Option<&str>) -> crate::settings::RelaySettings {
        crate::settings::RelaySettings {
            address: address.map(|a| a.to_string()),
            ..Default::default()
        }
    }

    /// An environment made of a fixed list, so no test sets a process-global
    /// variable and no two of them can race.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    /// **The environment wins over the file, for that run.**
    ///
    /// `RD_RELAY` is how a developer points this host at a throwaway relay. A
    /// stored address quietly winning would send those runs to the real one.
    #[test]
    fn the_environment_relay_wins_over_the_remembered_one() {
        let p = plan(
            &stored(Some("203.0.113.9:9443")),
            env(&[("RD_RELAY", "127.0.0.1:19443")]),
        );
        assert_eq!(
            p,
            RelayPlan::Dial {
                relay: "127.0.0.1:19443".parse().unwrap(),
                origin: Origin::Environment
            }
        );
    }

    /// The point of the whole change: a host launched from the application grid,
    /// with no variables set at all, knows its relay.
    #[test]
    fn a_remembered_relay_is_used_when_the_environment_says_nothing() {
        let p = plan(&stored(Some("203.0.113.9:9443")), env(&[]));
        assert_eq!(
            p,
            RelayPlan::Dial {
                relay: "203.0.113.9:9443".parse().unwrap(),
                origin: Origin::Stored
            }
        );
    }

    #[test]
    fn no_relay_anywhere_is_no_relay() {
        assert_eq!(plan(&stored(None), env(&[])), RelayPlan::Unset);
    }

    /// **A relay that is configured wrongly must not look like no relay.**
    ///
    /// Those two produce the same console — no relay button — and the operator
    /// cannot tell "you never set this up" from "what you set up is broken"
    /// without being told which.
    #[test]
    fn a_relay_that_is_not_an_address_is_unusable_rather_than_absent() {
        match plan(&stored(Some("relay.example.com:9443")), env(&[])) {
            RelayPlan::Unusable { origin, why } => {
                assert_eq!(origin, Origin::Stored);
                assert!(why.contains("relay.example.com:9443"), "{why}");
            }
            other => panic!("a broken stored relay produced {other:?}"),
        }
        match plan(&stored(None), env(&[("RD_RELAY", "nonsense")])) {
            RelayPlan::Unusable { origin, .. } => assert_eq!(origin, Origin::Environment),
            other => panic!("a broken RD_RELAY produced {other:?}"),
        }
    }

    /// **A remembered relay needs no environment variable to be dialled.**
    ///
    /// This is the behaviour the whole phase exists for. Before it, dialling
    /// out required `RD_RELAY_AUTH` in the environment, so the packaged icon —
    /// which sets nothing — could never offer the relay at all.
    #[test]
    fn a_remembered_relay_is_dialled_without_any_variables() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::generate(&mut rand_core_compat());
        let relay = RelayDialOut::configure(&stored(Some("203.0.113.9:9443")), env(&[]), Some(sk));
        assert!(
            relay.dial_out.is_some(),
            "a remembered relay produced no dialler, so the icon still could not use it"
        );
        assert!(matches!(
            relay.plan,
            RelayPlan::Dial {
                origin: Origin::Stored,
                ..
            }
        ));
    }

    /// The environment's own contract is unchanged: `RD_RELAY` still requires
    /// `RD_RELAY_AUTH`, because which credential this host presents is the
    /// thing a reader most needs to be able to see, and inferring it from
    /// whichever variables happen to be set hides exactly that.
    #[test]
    fn an_environment_relay_still_names_its_credential_or_is_refused() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::generate(&mut rand_core_compat());
        let relay = RelayDialOut::configure(
            &stored(None),
            env(&[("RD_RELAY", "203.0.113.9:9443")]),
            Some(sk.clone()),
        );
        assert!(relay.dial_out.is_none());
        match relay.plan {
            RelayPlan::Unusable { origin, why } => {
                assert_eq!(origin, Origin::Environment);
                assert!(why.contains("RD_RELAY_AUTH"), "{why}");
            }
            other => panic!("an unauthenticated RD_RELAY produced {other:?}"),
        }

        // And with the method named, it works as it always did.
        let ok = RelayDialOut::configure(
            &stored(None),
            env(&[
                ("RD_RELAY", "203.0.113.9:9443"),
                ("RD_RELAY_AUTH", "signing"),
            ]),
            Some(sk),
        );
        assert!(ok.dial_out.is_some());
    }

    /// A host with no signing identity loaded cannot prove itself, and says so
    /// rather than dialling out to fail at the challenge.
    #[test]
    fn a_remembered_relay_without_an_identity_says_what_is_missing() {
        let relay = RelayDialOut::configure(&stored(Some("203.0.113.9:9443")), env(&[]), None);
        assert!(relay.dial_out.is_none());
        match relay.plan {
            RelayPlan::Unusable { why, .. } => assert!(why.contains("identity"), "{why}"),
            other => panic!("a relay with no identity produced {other:?}"),
        }
    }

    async fn bearer_relay(token: &str) -> (Arc<relay::Relay>, SocketAddr, TcpListener) {
        let r = relay::Relay::new(Box::new(BearerToken::new(&[token.to_string()])));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        (r, addr, l)
    }

    /// The relay's side of one full session: register the host's control
    /// connection, take a client, tell the host to dial back, splice.
    async fn relay_one_session(r: Arc<relay::Relay>, listener: TcpListener) {
        let (mut control, _) = listener.accept().await.unwrap();
        let id = register_host(&r, &mut control).await.unwrap();

        let (mut client, _) = listener.accept().await.unwrap();
        join_client(&r, &mut client).await.unwrap();
        let (ticket, waiter) = mint_attach(&r, &id).unwrap();
        relay_write(
            &mut control,
            &ControlFrame::ClientWaiting {
                ticket: ticket.as_str().to_string(),
            },
        )
        .await
        .unwrap();

        let (mut data, _) = listener.accept().await.unwrap();
        accept_data(&r, &mut data)
            .await
            .unwrap()
            .deliver(data)
            .unwrap();
        let mut host_data = waiter.wait(Duration::from_secs(5)).await.unwrap();
        confirm_join(&mut client).await.unwrap();
        relay::splice(&mut host_data, &mut client).await;
        // Hold the control connection open for the length of the session.
        drop(control);
    }

    /// The host dials out, registers, and reports how it is reachable.
    #[tokio::test]
    async fn the_host_dials_out_and_is_reachable_through_the_relay() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let id = register_host(&r, &mut control).await.unwrap();
            (id, control)
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()));
        let source = dial.connect().await.expect("the host could not register");

        let (id, _control) = server.await.unwrap();
        match source.reach() {
            Reach::ViaRelay { relay, session } => {
                assert_eq!(relay, addr);
                assert_eq!(session, id.as_str(), "the host kept a different session id");
            }
            other => panic!("a dialled-out host reported {other:?}"),
        }
    }

    /// **A dialled-out host binds nothing, and must never report that it did.**
    ///
    /// If this ever returns `Some`, `HostState::is_listening()` becomes true for
    /// a host with no open port, and the console would tell the operator it is
    /// listening when nothing is. That is the one thing the console exists to
    /// get right.
    #[tokio::test]
    async fn a_dialled_out_host_reports_no_bound_address() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let id = register_host(&r, &mut control).await.unwrap();
            (id, control)
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()));
        let source = dial.connect().await.unwrap();
        let _ = server.await.unwrap();

        assert_eq!(
            source.reach().bound(),
            None,
            "a dialled-out host reported a bound address; nothing is listening"
        );
    }

    /// End to end: a phone joins, the host dials back, bytes cross.
    #[tokio::test]
    async fn a_client_reaches_the_host_through_a_dialled_back_connection() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let server = tokio::spawn(relay_one_session(r, listener));

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()));
        let mut source = dial.connect().await.unwrap();
        let session = match source.reach() {
            Reach::ViaRelay { session, .. } => session,
            other => panic!("expected a relay reach, got {other:?}"),
        };

        // The phone.
        let mut client = TcpStream::connect(addr).await.unwrap();
        write_frame(
            &mut client,
            &ControlFrame::Join {
                v: PROTOCOL_VERSION,
                session,
            },
        )
        .await
        .unwrap();

        // The host's source hands back the dialled-back data connection.
        let (mut host_data, peer_addr, label) =
            source.next_peer().await.expect("no peer was handed back");
        assert_eq!(
            peer_addr, addr,
            "the host reported an address it is not connected to"
        );
        assert!(
            label.contains("via relay"),
            "the peer label should say the connection came through a relay: {label}"
        );
        assert!(
            !label.contains(char::is_whitespace) || !label.is_empty(),
            "labels must be non-empty"
        );

        assert!(matches!(
            read_frame(&mut client).await.unwrap(),
            ControlFrame::Joined
        ));

        host_data.write_all(b"host to phone").await.unwrap();
        host_data.flush().await.unwrap();
        let mut got = [0u8; 13];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"host to phone");

        client.write_all(b"phone to host").await.unwrap();
        client.flush().await.unwrap();
        let mut back = [0u8; 13];
        host_data.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"phone to host");

        drop(host_data);
        drop(client);
        let _ = server.await;
    }

    /// The host answers the relay's keepalive, so its session is not released.
    #[tokio::test]
    async fn the_host_answers_the_relays_keepalive() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let r2 = r.clone();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            register_host(&r2, &mut control).await.unwrap();
            let alive = heartbeat(&mut control, Duration::from_secs(2)).await;
            (alive.is_ok(), control)
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()));
        let mut source = dial.connect().await.unwrap();

        // next_peer answers pings while it waits, which is the only place the
        // host is listening to the control connection at all.
        let waited = tokio::time::timeout(Duration::from_millis(500), source.next_peer()).await;
        assert!(
            waited.is_err(),
            "no client arrived, so nothing should return"
        );

        let (answered, _control) = server.await.unwrap();
        assert!(
            answered,
            "the host did not answer the relay's ping; its session would be released and the invite already issued would name nothing"
        );
        assert_eq!(r.session_count(), 1);
    }

    /// A refused credential is reported, and produces no source.
    #[tokio::test]
    async fn a_refused_credential_produces_no_source() {
        let (r, addr, listener) = bearer_relay("the-right-token").await;
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let outcome = register_host(&r, &mut control).await;
            if let Err(e) = &outcome {
                relay::server::deny(&mut control, e.public_reason()).await;
            }
            outcome.is_err()
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("the-wrong-token".into()));
        let outcome = dial.connect().await;

        assert!(server.await.unwrap());
        assert!(
            outcome.is_err(),
            "a host with the wrong credential believed it had registered"
        );
    }

    /// The signing credential answers the relay's challenge.
    #[tokio::test]
    async fn the_signing_credential_answers_a_challenge() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::generate(&mut rand_core_compat());
        let identity = HostIdentity(sk.verifying_key().to_bytes());

        let r = relay::Relay::new(Box::new(EnrolThenProve::new(&[identity])));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let r2 = r.clone();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let outcome = register_host(&r2, &mut control).await;
            (outcome.is_ok(), control)
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Signing(sk));
        let source = dial.connect().await;

        let (registered, _control) = server.await.unwrap();
        assert!(registered, "the relay refused a correctly signed challenge");
        assert!(
            source.is_ok(),
            "the host did not complete the signing exchange"
        );
        assert_eq!(r.session_count(), 1);
    }

    /// A bearer host pointed at a signing relay says so, rather than hanging or
    /// sending something the relay will read as a signature.
    #[tokio::test]
    async fn a_bearer_host_at_a_signing_relay_says_what_is_wrong() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::generate(&mut rand_core_compat());
        let identity = HostIdentity(sk.verifying_key().to_bytes());
        let r = relay::Relay::new(Box::new(EnrolThenProve::new(&[identity])));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let _ = register_host(&r, &mut control).await;
            control
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()));
        let outcome = dial.connect().await;
        let _control = server.await.unwrap();

        let failure = match outcome {
            Err(f) => f,
            Ok(_) => panic!("a bearer host completed a signing registration"),
        };
        assert!(
            failure.message.contains("sign"),
            "the error should name the mismatch, not be generic: {}",
            failure.message
        );
        // **Not retried.** The wrong kind of credential is wrong every time,
        // and a host that kept dialling would bury this message under the next
        // attempt before the operator could read it.
        assert!(
            !failure.worth_retrying(),
            "a credential the relay cannot accept was marked worth retrying"
        );
    }

    /// A control connection that goes away ends the source, which is what makes
    /// the controller report a fault instead of staying Pairable forever.
    #[tokio::test]
    async fn a_lost_control_connection_ends_the_source() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            register_host(&r, &mut control).await.unwrap();
            // The relay closes the connection. (Not what a NAT reaping looks
            // like — a NAT says nothing at all; that case is
            // a_control_connection_that_goes_silent_ends_the_source.)
            drop(control);
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()));
        let mut source = dial.connect().await.unwrap();
        server.await.unwrap();

        // Bounded deliberately: the failure this guards against is a source
        // that spins on a dead socket instead of reporting it, and an unbounded
        // assertion would hang rather than fail.
        let ended = tokio::time::timeout(Duration::from_secs(2), source.next_peer())
            .await
            .expect("the source neither returned nor gave up on a dead control connection");
        assert!(
            ended.is_none(),
            "a host whose control connection died kept waiting for clients that can never arrive"
        );
    }

    // ---------------------------------- a control connection that dies silently
    //
    // 2026-09-17 and 2026-09-18: the host's path to the relay rebound mid-session.
    // The session connection failed at once; the idle control connection failed
    // SILENTLY — no close ever reached the host — and the host, which only reads
    // it, waited forever. `a_lost_control_connection_ends_the_source` above covers
    // a relay that CLOSES; its comment says that is what a NAT reaping looks
    // like, and it is not: a NAT drops a connection without a word.

    /// **A control connection that goes silent ends the source**, even though
    /// the socket never reports a close.
    #[tokio::test]
    async fn a_control_connection_that_goes_silent_ends_the_source() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            register_host(&r, &mut control).await.unwrap();
            // The path rebinds: nothing more reaches the host, and nothing
            // closes. Held open and silent for far longer than the test.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(control);
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()))
            .with_limits(Duration::from_millis(300), DIAL_BACK_LIMIT);
        let mut source = dial.connect().await.unwrap();

        let ended = tokio::time::timeout(Duration::from_secs(3), source.next_peer())
            .await
            .expect(
                "a control connection that went silent kept the host waiting — the host that \
                 was unreachable for ten hours on 2026-09-17",
            );
        assert!(ended.is_none(), "a silent relay handed the host a client");
        server.abort();
    }

    /// **The silence deadline survives the accept loop dropping the future.**
    /// The controller's accept loop selects over `next_peer` beside every
    /// session's events, so each event drops the future and asks again. A
    /// deadline counted from each call would move every time and never arrive.
    #[tokio::test]
    async fn the_silence_deadline_survives_the_future_being_dropped_and_asked_again() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            register_host(&r, &mut control).await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(control);
        });
        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()))
            .with_limits(Duration::from_millis(300), DIAL_BACK_LIMIT);
        let mut source = dial.connect().await.unwrap();

        let started = std::time::Instant::now();
        let ended = loop {
            // Dropped after 100 ms each time, as a busy accept loop would.
            if let Ok(outcome) =
                tokio::time::timeout(Duration::from_millis(100), source.next_peer()).await
            {
                break Some(outcome);
            }
            if started.elapsed() > Duration::from_secs(3) {
                break None;
            }
        };
        assert!(
            matches!(ended, Some(None)),
            "a silent relay was never given up on while the future kept being dropped: {:?}",
            ended.map(|p| p.is_some())
        );
        server.abort();
    }

    /// And a control connection that is QUIET but alive — the relay pinging,
    /// no client — is kept. The limit is on silence, not on idleness.
    #[tokio::test]
    async fn a_quiet_control_connection_that_the_relay_keeps_pinging_is_kept() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            register_host(&r, &mut control).await.unwrap();
            let mut answered = 0;
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if heartbeat(&mut control, Duration::from_secs(2))
                    .await
                    .is_ok()
                {
                    answered += 1;
                }
            }
            answered
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()))
            .with_limits(Duration::from_millis(300), DIAL_BACK_LIMIT);
        let mut source = dial.connect().await.unwrap();
        let waited = tokio::time::timeout(Duration::from_millis(1200), source.next_peer()).await;
        assert!(
            waited.is_err(),
            "a relay that was pinging every 100 ms was given up on: {:?}",
            waited.map(|p| p.is_some())
        );
        drop(source);
        let answered = server.await.unwrap();
        // The host answers only while it is being asked for a peer — here, for
        // the 1.2 s above, at 100 ms spacing plus a round trip each.
        assert!(
            answered >= 5,
            "the host answered only {answered} of the relay's pings"
        );
    }

    /// **A dial-back the relay never completes does not deafen the host.** It
    /// runs inside the future that answers pings; unbounded, a hand-over on a
    /// dead path would stop the host hearing its relay at all.
    #[tokio::test]
    async fn a_dial_back_the_relay_never_completes_does_not_stop_the_host_answering() {
        let (r, addr, listener) = bearer_relay("a-token").await;
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            register_host(&r, &mut control).await.unwrap();
            relay_write(
                &mut control,
                &ControlFrame::ClientWaiting {
                    ticket: "a-ticket-for-a-hand-over-that-never-completes".into(),
                },
            )
            .await
            .unwrap();
            // The host dials back; the relay takes the connection and never
            // answers it.
            let (stuck, _) = listener.accept().await.unwrap();
            let answered = heartbeat(&mut control, Duration::from_secs(2))
                .await
                .is_ok();
            (answered, stuck, control)
        });

        let mut dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()))
            .with_limits(Duration::from_secs(10), Duration::from_millis(300));
        let mut source = dial.connect().await.unwrap();
        let waited = tokio::time::timeout(Duration::from_secs(3), source.next_peer()).await;
        assert!(
            !matches!(waited, Ok(Some(_))),
            "a hand-over the relay never completed produced a peer"
        );
        let (answered, _stuck, _control) = server.await.unwrap();
        assert!(
            answered,
            "the host stopped answering its relay while a dial-back hung — the relay would \
             release this host's session"
        );
    }

    /// The host's limits are tied to the relay's ping schedule. If the relay
    /// pinged less often than the host's patience, a healthy host would hang up
    /// on it; if a dial-back could outlast the relay's grace, the relay would
    /// hang up on the host.
    #[test]
    fn the_hosts_limits_fit_inside_the_relays_ping_schedule() {
        use relay::server::{CONTROL_KEEPALIVE, KEEPALIVE_GRACE};
        assert!(
            CONTROL_KEEPALIVE + KEEPALIVE_GRACE < CONTROL_SILENCE_LIMIT,
            "a live relay can be quiet for {:?}; the host gives up after {:?}",
            CONTROL_KEEPALIVE + KEEPALIVE_GRACE,
            CONTROL_SILENCE_LIMIT
        );
        assert!(
            DIAL_BACK_LIMIT < KEEPALIVE_GRACE,
            "a dial-back may take {DIAL_BACK_LIMIT:?}, longer than the relay waits for a ping answer"
        );
    }

    /// **The phone app gives a relayed connection longer than the relay gives
    /// the host.** 2026-09-19: a relayed reconnect connected at 10.9 s and the
    /// app had given up at 10.0 s, throwing a working session away. The app's
    /// ceiling lives in Kotlin (`ConnectCeiling.RELAY_MS`); it is read from the
    /// source here and held above the relay crate's own `ATTACH_TTL` plus room
    /// for the handshake, so the two cannot drift apart unseen.
    #[test]
    fn the_phone_app_waits_longer_for_a_relayed_connect_than_the_relay_waits_for_the_host() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../apk/app/src/main/java/com/remotedexter/ConnectCeiling.kt"
        );
        let kotlin = std::fs::read_to_string(path).expect("ConnectCeiling.kt");
        let line = kotlin
            .lines()
            .find(|l| l.contains("const val RELAY_MS"))
            .expect("RELAY_MS is declared");
        let digits: String = line
            .split('=')
            .nth(1)
            .expect("RELAY_MS has a value")
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        let app_wait = Duration::from_millis(digits.parse().expect("a number"));
        let needed = relay::session::ATTACH_TTL + Duration::from_secs(10);
        assert!(
            app_wait >= needed,
            "the app gives a relayed connect {app_wait:?}; the relay alone may take {:?} before \
             the host has even dialled back",
            relay::session::ATTACH_TTL
        );
    }

    /// A backend with no capture and no input, whose sessions authenticate at
    /// once and last until their socket ends — enough for the controller to see
    /// a client come and go through the relay, and nothing more.
    #[derive(Clone)]
    struct BareBackend;

    impl host_controller::HostBackend for BareBackend {
        fn start_capture(&mut self) -> Result<(), host_controller::BackendFault> {
            Ok(())
        }
        fn stop_capture(&mut self) {}
        fn open_input(&mut self) -> Result<(), host_controller::BackendFault> {
            Ok(())
        }
        fn close_input(&mut self) {}
        fn create_invite(
            &mut self,
            _reach: &Reach,
            _now: u64,
        ) -> Result<host_controller::state::InviteView, host_controller::BackendFault> {
            Err(host_controller::BackendFault::new(
                "this test mints no invites",
            ))
        }
        fn revoke_invite(&mut self) {}
        fn serve(
            &mut self,
            mut stream: TcpStream,
            _peer: SocketAddr,
            authed: host_controller::AuthNotifier,
            _notices: host_controller::NoticeNotifier,
        ) -> host_controller::ServeFuture {
            Box::pin(async move {
                authed.authenticated();
                let mut buf = [0u8; 64];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            })
        }
        fn dispatch(
            &mut self,
            auth_tx: tokio::sync::mpsc::UnboundedSender<String>,
            notice_tx: tokio::sync::mpsc::UnboundedSender<String>,
        ) -> host_controller::ServeDispatch {
            let me = self.clone();
            Arc::new(move |stream, peer, label| {
                let mut me = me.clone();
                let authed = host_controller::AuthNotifier::new(auth_tx.clone(), label.clone());
                let notices = host_controller::NoticeNotifier::new(notice_tx.clone(), label);
                me.serve(stream, peer, authed, notices)
            })
        }
    }

    /// **THE 2026-09-18 SEQUENCE, through the real controller.** A relay-only
    /// host serves a client; then the host's path rebinds: the client's
    /// connection dies with a reset — the host's "Broken pipe" — and the control
    /// connection goes silent without ever closing. The host must notice and
    /// dial the relay again. Before this was fixed it never did: its last log
    /// line was "Client disconnected", and it stayed unreachable for hours.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_only_host_whose_path_dies_silently_after_a_client_drops_dials_again() {
        use host_controller::{HostCommand, HostEvent, HostState};
        const T: Duration = Duration::from_secs(5);

        let (r, addr, listener) = bearer_relay("a-token").await;
        let (silence_tx, silence_rx) = tokio::sync::oneshot::channel::<()>();
        let relay_side = tokio::spawn(async move {
            // The path that will die.
            let (mut control, _) = listener.accept().await.unwrap();
            let id = register_host(&r, &mut control).await.unwrap();
            // A client arrives and the host is told to dial back.
            let (ticket, waiter) = mint_attach(&r, &id).unwrap();
            relay_write(
                &mut control,
                &ControlFrame::ClientWaiting {
                    ticket: ticket.as_str().to_string(),
                },
            )
            .await
            .unwrap();
            let (mut data, _) = listener.accept().await.unwrap();
            accept_data(&r, &mut data)
                .await
                .unwrap()
                .deliver(data)
                .unwrap();
            let client_side = waiter.wait(T).await.unwrap();
            // A healthy path: the relay pings fast, the host answers.
            let mut silence_rx = silence_rx;
            loop {
                tokio::select! {
                    _ = &mut silence_rx => break,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        heartbeat(&mut control, T)
                            .await
                            .expect("the host stopped answering while its path was healthy");
                    }
                }
            }
            // The path rebinds. The client's connection dies with a reset...
            // Zero linger: dropping sends a reset, not a close.
            socket2::SockRef::from(&client_side)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(client_side);
            // ...and the control connection goes silent, never closed.
            let silent = control;
            // The host has to come back on a fresh connection.
            let (mut again, _) = listener.accept().await.unwrap();
            register_host(&r, &mut again).await.unwrap();
            (silent, again)
        });

        let dial = RelayDialOut::new(addr, RelayCredential::Bearer("a-token".into()))
            .with_limits(Duration::from_millis(500), Duration::from_secs(2));
        let mut h = host_controller::spawn_with_dial_out(|| BareBackend, dial);
        h.send(HostCommand::StartViaRelay).unwrap();
        h.wait_for_state(T, |s| s.peers() == 1)
            .expect("the client never reached the host through the relay");

        silence_tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + T;
        let mut seen = Vec::new();
        let mut client_gone = false;
        let mut reconnecting = false;
        while std::time::Instant::now() < deadline && !(client_gone && reconnecting) {
            match h.wait_for_event(Duration::from_millis(100)) {
                Some(e @ HostEvent::PeerDisconnected { .. }) => {
                    client_gone = true;
                    seen.push(e);
                }
                Some(HostEvent::Fault { message }) if message.contains("reconnecting") => {
                    reconnecting = true;
                }
                Some(e) => seen.push(e),
                None => {}
            }
        }
        assert!(
            client_gone,
            "the client's reset connection did not end its session: {seen:?}"
        );
        assert!(
            reconnecting,
            "the host never noticed its control connection had gone silent, so it never \
             dialled the relay again — the 2026-09-18 outage: {seen:?}"
        );
        h.wait_for_state(T, |s| {
            matches!(
                s,
                HostState::Pairable {
                    reach: Reach::ViaRelay { .. }
                }
            )
        })
        .expect("the host did not come back through the relay");
        let back = tokio::time::timeout(T, relay_side)
            .await
            .expect("the relay never saw the host come back")
            .unwrap();
        drop(back);
        assert!(h.shutdown_and_join(T));
    }

    // ------------------------------------------- which credential is chosen

    fn a_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
    }

    /// **The method is named, never inferred.** Deciding it from whether a
    /// token happens to be set would silently downgrade a signing host to a
    /// bearer one the moment a variable went missing — and the operator would
    /// see a working relay button either way.
    #[test]
    fn the_auth_method_must_be_named() {
        let why = credential_from("", Some("t".repeat(20)), Some(a_key())).unwrap_err();
        assert!(
            why.contains("bearer") && why.contains("signing"),
            "the refusal should say what is valid: {why}"
        );
        let why = credential_from("none", Some("t".repeat(20)), Some(a_key())).unwrap_err();
        assert!(why.contains("not `none`"), "{why}");
    }

    /// **THE GAP THIS CLOSED.** `signing` was implemented, tested against a
    /// real relay, and RECOMMENDED in the operator guide — but nothing on the
    /// host could construct it, so a signing relay could not be used at all.
    #[test]
    fn signing_uses_this_hosts_own_identity() {
        let key = a_key();
        let expect = key.verifying_key().to_bytes();
        match credential_from("signing", None, Some(key)) {
            Ok(RelayCredential::Signing(sk)) => {
                assert_eq!(sk.verifying_key().to_bytes(), expect)
            }
            other => panic!("signing produced {other:?}"),
        }
    }

    /// And it refuses rather than falling back when the identity is missing.
    /// A host that quietly became a bearer host would present a credential the
    /// operator never configured.
    #[test]
    fn signing_without_an_identity_refuses_rather_than_falling_back() {
        let why = credential_from("signing", Some("t".repeat(20)), None).unwrap_err();
        assert!(why.contains("identity"), "{why}");
    }

    #[test]
    fn bearer_needs_a_token_and_refuses_an_empty_one() {
        assert!(matches!(
            credential_from("bearer", Some("a-value-long-enough".into()), None),
            Ok(RelayCredential::Bearer(_))
        ));
        for absent in [None, Some(String::new())] {
            let why = credential_from("bearer", absent, Some(a_key())).unwrap_err();
            assert!(why.contains("RD_RELAY_TOKEN"), "{why}");
        }
    }

    /// No refusal may quote a credential back — it lands in a terminal the
    /// operator may paste somewhere.
    #[test]
    fn a_refusal_never_quotes_the_credential() {
        let fixture = "inert-fixture-value";
        for method in ["", "nonsense", "signing"] {
            if let Err(why) = credential_from(method, Some(fixture.to_string()), None) {
                assert!(!why.contains(fixture), "{method}: {why}");
            }
        }
    }

    /// Neither credential may appear in a debug rendering: the first log line
    /// that formatted a dial-out error would carry it.
    ///
    /// The binding is `fixture`, not `token`, and that is not cosmetic. Written
    /// the obvious way this line reads to a secret scanner as
    /// `token = "<long string>"` — which is exactly the rule, and exactly what
    /// it caught here, for the second time in two days. Naming a fixture after
    /// the thing it stands in for is how a post-mortem becomes the next finding.
    #[test]
    fn a_credential_is_never_in_its_own_debug_output() {
        let fixture = "inert-fixture-value";
        let rendered = format!("{:?}", RelayCredential::Bearer(fixture.to_string()));
        assert!(
            !rendered.contains(fixture),
            "the bearer credential rendered itself: {rendered}"
        );
    }

    /// `ed25519-dalek` 2 wants a `rand_core` 0.6 RNG; `OsRng` from the `rand`
    /// this crate uses is the same type, re-exported.
    fn rand_core_compat() -> rand::rngs::OsRng {
        rand::rngs::OsRng
    }
}

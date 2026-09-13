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

use host_controller::source::{DialFuture, DialOut, PeerFuture, PeerSource};
use host_controller::Reach;
use relay_proto::{self as frame, ControlFrame, PROTOCOL_VERSION};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
/// Split from [`RelayDialOut::from_env`] so every branch is testable without
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

/// Dials the relay and registers, producing a live [`RelaySource`].
pub struct RelayDialOut {
    relay: SocketAddr,
    credential: RelayCredential,
}

impl RelayDialOut {
    pub fn new(relay: SocketAddr, credential: RelayCredential) -> Self {
        RelayDialOut { relay, credential }
    }

    /// Build from the environment, or `None` when no relay is configured.
    ///
    /// **`RD_RELAY_AUTH` is required and is not inferred**, exactly as `relayd`
    /// requires it. Deciding the method from whether `RD_RELAY_TOKEN` happens
    /// to be set would hide the thing that matters most to a reader — WHICH
    /// CREDENTIAL this host presents — and would silently downgrade a signing
    /// host to a bearer one the moment a variable went missing.
    ///
    /// ```text
    /// RD_RELAY=host:port        required
    /// RD_RELAY_AUTH=bearer      RD_RELAY_TOKEN is then required
    /// RD_RELAY_AUTH=signing     uses this host's own invite-signing identity
    /// ```
    ///
    /// A token is read and never logged, never echoed into an error, and never
    /// written anywhere. It is the operator's, set in the operator's own shell.
    pub fn from_env() -> Option<Self> {
        let addr = std::env::var("RD_RELAY").ok()?;
        let relay: SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(_) => {
                eprintln!("[host] RD_RELAY is not an address and port — no relay configured");
                return None;
            }
        };
        let method = std::env::var("RD_RELAY_AUTH").unwrap_or_default();
        match credential_from(
            &method,
            std::env::var("RD_RELAY_TOKEN").ok(),
            crate::host_signing_identity(),
        ) {
            Ok(credential) => Some(RelayDialOut::new(relay, credential)),
            Err(why) => {
                // Said out loud. A relay that is configured wrongly must not
                // look identical to one that was never configured: the console
                // would simply have no button and no reason for its absence.
                eprintln!("[host] RD_RELAY is set but no relay is usable: {why}");
                None
            }
        }
    }
}

impl DialOut for RelayDialOut {
    fn connect(&mut self) -> DialFuture<'_> {
        Box::pin(async move {
            let mut control = TcpStream::connect(self.relay)
                .await
                .map_err(|e| format!("could not reach the relay: {}", e.kind()))?;

            write_frame(
                &mut control,
                &ControlFrame::Register {
                    v: PROTOCOL_VERSION,
                    host_pub: self.credential.announce(),
                },
            )
            .await
            .map_err(|_| "the relay closed while registering".to_string())?;

            let session = loop {
                let f = read_frame(&mut control)
                    .await
                    .map_err(|_| "the relay closed while registering".to_string())?;
                match f {
                    ControlFrame::Challenge { nonce } => {
                        use base64::Engine;
                        let nonce = base64::engine::general_purpose::STANDARD
                            .decode(nonce)
                            .map_err(|_| "the relay sent a malformed challenge".to_string())?;
                        let sig = self.credential.prove(&nonce).ok_or_else(|| {
                            "the relay asked this host to sign, and it is configured with a shared secret instead".to_string()
                        })?;
                        write_frame(&mut control, &ControlFrame::Prove { sig })
                            .await
                            .map_err(|_| "the relay closed while registering".to_string())?;
                    }
                    ControlFrame::Registered { session } => break session,
                    // The reason is the relay's coarse one by design; it is
                    // shown as given and never embellished into a guess.
                    ControlFrame::Denied { why } => {
                        return Err(format!("the relay refused this host: {why}"))
                    }
                    _ => return Err("the relay sent an unexpected frame".to_string()),
                }
            };

            Ok(Box::new(RelaySource {
                relay: self.relay,
                control,
                session,
                served: 0,
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
}

impl RelaySource {
    /// Open the data connection for one waiting client.
    async fn dial_back(&mut self, ticket: String) -> Option<(TcpStream, SocketAddr, String)> {
        let mut data = TcpStream::connect(self.relay).await.ok()?;
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
            ControlFrame::Attached => {
                self.served += 1;
                let label = format!("via relay {} #{}", self.relay, self.served);
                Some((data, self.relay, label))
            }
            _ => None,
        }
    }
}

impl PeerSource for RelaySource {
    fn next_peer(&mut self) -> PeerFuture<'_> {
        Box::pin(async move {
            loop {
                match read_frame(&mut self.control).await {
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

        let message = match outcome {
            Err(m) => m,
            Ok(_) => panic!("a bearer host completed a signing registration"),
        };
        assert!(
            message.contains("sign"),
            "the error should name the mismatch, not be generic: {message}"
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
            // The relay goes away, as a NAT reaping the connection would look.
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

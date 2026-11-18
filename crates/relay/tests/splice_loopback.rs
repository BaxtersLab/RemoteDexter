//! The relay, end to end on loopback, including the property it exists to have.
//!
//! These run a real relay over real sockets. The decisions were already proven
//! without a socket in the unit tests; what is proven here is that the pieces
//! joined together behave, and — the one that matters — that **a relay operator
//! who captured the entire stream would learn nothing**.

use relay::auth::{BearerToken, EnrolThenProve, HostIdentity};
use relay::frame::{self, ControlFrame, PROTOCOL_VERSION};
use relay::{
    accept_data, attach_control, confirm_join, heartbeat, join_client, mint_attach, notify_host,
    register_host, release_if_current, serve_connection, splice, Relay,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn write_frame(sock: &mut TcpStream, f: &ControlFrame) {
    let body = frame::encode(f);
    sock.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .unwrap();
    sock.write_all(&body).await.unwrap();
    sock.flush().await.unwrap();
}

async fn read_frame(sock: &mut TcpStream) -> ControlFrame {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await.unwrap();
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    sock.read_exact(&mut body).await.unwrap();
    frame::decode(&body).unwrap()
}

/// A relay on loopback with the bearer method, plus its address.
async fn bearer_relay(token: &str) -> (Arc<Relay>, std::net::SocketAddr, TcpListener) {
    let relay = Relay::new(Box::new(BearerToken::new(&[token.to_string()])));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (relay, addr, listener)
}

// ---------------------------------------------------------------------------
// The control/data split, from both ends.
//
// The host holds ONE control connection for the life of its invite and is told
// over it when a client is waiting; it then dials a SECOND connection carrying
// that client's ticket, and only that one is spliced. The relay therefore never
// multiplexes, which is what keeps it from having to parse session framing —
// the one thing it must not do.

/// The relay's side: host control, client join, dial-back, ready to splice.
///
/// Returns `(control, client, host_data)`. The control connection is returned
/// rather than dropped because dropping it would close it, which is a different
/// test.
async fn relay_until_spliceable(
    r: &Arc<Relay>,
    listener: &TcpListener,
) -> (TcpStream, TcpStream, TcpStream) {
    let (mut control, _) = listener.accept().await.unwrap();
    let id = register_host(r, &mut control).await.unwrap();

    let (mut client, _) = listener.accept().await.unwrap();
    let claimed = join_client(r, &mut client).await.unwrap();
    assert_eq!(claimed, id);

    let (ticket, waiter) = mint_attach(r, &claimed).unwrap();
    write_frame(
        &mut control,
        &ControlFrame::ClientWaiting {
            ticket: ticket.as_str().to_string(),
        },
    )
    .await;

    let (mut data, _) = listener.accept().await.unwrap();
    let attachment = accept_data(r, &mut data).await.unwrap();
    attachment.deliver(data).unwrap();

    let host_data = waiter.wait(Duration::from_secs(5)).await.unwrap();
    // Only NOW is the client told, because only now is there anything on the
    // other end of its socket.
    confirm_join(&mut client).await.unwrap();
    (control, client, host_data)
}

/// The host's side: register and hold the control connection.
async fn host_control(addr: SocketAddr, token: &str) -> (TcpStream, String) {
    let mut control = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut control,
        &ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub: token.to_string(),
        },
    )
    .await;
    let session = match read_frame(&mut control).await {
        ControlFrame::Registered { session } => session,
        other => panic!("expected Registered, got {other:?}"),
    };
    (control, session)
}

/// The host's side: wait to be told a client is waiting, then dial back.
async fn host_dial_back(addr: SocketAddr, control: &mut TcpStream) -> TcpStream {
    let ticket = ticket_from(control).await;
    host_attach_with(addr, &ticket).await
}

/// The ticket the relay sent on the control connection.
async fn ticket_from(control: &mut TcpStream) -> String {
    match read_frame(control).await {
        ControlFrame::ClientWaiting { ticket } => ticket,
        other => panic!("expected ClientWaiting, got {other:?}"),
    }
}

/// Dial a data connection presenting an arbitrary ticket, and return the socket
/// with whatever the relay answered still unread.
async fn host_attach_raw(addr: SocketAddr, ticket: &str) -> TcpStream {
    let mut data = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut data,
        &ControlFrame::Attach {
            v: PROTOCOL_VERSION,
            ticket: ticket.to_string(),
        },
    )
    .await;
    data
}

/// Dial back and require the relay to accept it.
async fn host_attach_with(addr: SocketAddr, ticket: &str) -> TcpStream {
    let mut data = host_attach_raw(addr, ticket).await;
    match read_frame(&mut data).await {
        ControlFrame::Attached => data,
        other => panic!("expected Attached, got {other:?}"),
    }
}

/// The phone's side: ask for a session. Deliberately does NOT wait for
/// `Joined`, because that does not arrive until the host has dialled back.
async fn client_join(addr: SocketAddr, session: &str) -> TcpStream {
    let mut client = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut client,
        &ControlFrame::Join {
            v: PROTOCOL_VERSION,
            session: session.to_string(),
        },
    )
    .await;
    client
}

/// The happy path: a host registers a control connection, a phone joins, the
/// host is told to dial back, and bytes cross both ways on the data connection.
#[tokio::test]
async fn a_host_and_a_client_are_spliced_and_bytes_cross_both_ways() {
    let (relay, addr, listener) = bearer_relay("a-token").await;

    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (_control, mut client, mut host_data) = relay_until_spliceable(&r, &listener).await;
        splice(&mut host_data, &mut client).await
    });

    let (mut control, session) = host_control(addr, "a-token").await;
    let mut client = client_join(addr, &session).await;
    let mut host = host_dial_back(addr, &mut control).await;
    assert!(
        matches!(read_frame(&mut client).await, ControlFrame::Joined),
        "the client was not confirmed once the data path existed"
    );

    // Host → phone.
    host.write_all(b"from the host").await.unwrap();
    host.flush().await.unwrap();
    let mut got = [0u8; 13];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"from the host");

    // Phone → host.
    client.write_all(b"from the phone").await.unwrap();
    client.flush().await.unwrap();
    let mut back = [0u8; 14];
    host.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"from the phone");

    drop(host);
    drop(client);
    drop(control);
    let _ = server.await;
}

/// THE PROPERTY THE WHOLE DESIGN RESTS ON.
///
/// A genuine Noise XX session is run through the relay, and every byte the
/// relay handled is captured. The plaintext must appear in none of it.
///
/// `snow` is a DEV dependency for exactly this test. If it ever moves to
/// `[dependencies]`, the relay has gained the ability to decrypt and this test
/// is no longer the point.
#[tokio::test]
async fn a_relay_operator_who_captured_everything_would_learn_nothing() {
    const SECRET: &[u8] = b"the operator's password is hunter2 and the meeting is at noon";
    let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();

    let (relay, addr, listener) = bearer_relay("a-token").await;

    // Everything the relay moved, in both directions.
    let seen = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let seen_srv = seen.clone();

    let r = relay.clone();
    let server = tokio::spawn(async move {
        // The same control/data split the product uses: the capture is of the
        // DATA connection, which is the only one session bytes ever touch.
        let (_control, mut client_sock, mut host_sock) =
            relay_until_spliceable(&r, &listener).await;

        // Copy by hand rather than with `splice`, so the test can KEEP a copy
        // of every byte — which is precisely what a hostile relay operator
        // would do, and the strongest form of the question.
        let (mut hr, mut hw) = host_sock.split();
        let (mut cr, mut cw) = client_sock.split();
        let a = async {
            let mut buf = [0u8; 4096];
            loop {
                match hr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        seen_srv.lock().unwrap().extend_from_slice(&buf[..n]);
                        if cw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        };
        let seen_b = seen_srv.clone();
        let b = async {
            let mut buf = [0u8; 4096];
            loop {
                match cr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        seen_b.lock().unwrap().extend_from_slice(&buf[..n]);
                        if hw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        };
        tokio::join!(a, b);
    });

    // The host end: control connection, then dial back on demand.
    let (mut control, session) = host_control(addr, "a-token").await;
    let mut client = client_join(addr, &session).await;
    let mut host = host_dial_back(addr, &mut control).await;
    assert!(matches!(
        read_frame(&mut client).await,
        ControlFrame::Joined
    ));

    // Noise XX, responder on the host side, initiator on the phone side —
    // the same direction the product uses.
    let host_keys = snow::Builder::new(params.clone())
        .generate_keypair()
        .unwrap();
    let client_keys = snow::Builder::new(params.clone())
        .generate_keypair()
        .unwrap();
    let mut responder = snow::Builder::new(params.clone())
        .local_private_key(&host_keys.private)
        .build_responder()
        .unwrap();
    let mut initiator = snow::Builder::new(params)
        .local_private_key(&client_keys.private)
        .build_initiator()
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let mut rx = vec![0u8; 65535];

    // -> e
    let n = initiator.write_message(&[], &mut buf).unwrap();
    client.write_all(&(n as u32).to_be_bytes()).await.unwrap();
    client.write_all(&buf[..n]).await.unwrap();
    client.flush().await.unwrap();
    let mut len = [0u8; 4];
    host.read_exact(&mut len).await.unwrap();
    let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
    host.read_exact(&mut msg).await.unwrap();
    responder.read_message(&msg, &mut rx).unwrap();

    // <- e, ee, s, es
    let n = responder.write_message(&[], &mut buf).unwrap();
    host.write_all(&(n as u32).to_be_bytes()).await.unwrap();
    host.write_all(&buf[..n]).await.unwrap();
    host.flush().await.unwrap();
    client.read_exact(&mut len).await.unwrap();
    let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
    client.read_exact(&mut msg).await.unwrap();
    initiator.read_message(&msg, &mut rx).unwrap();

    // -> s, se
    let n = initiator.write_message(&[], &mut buf).unwrap();
    client.write_all(&(n as u32).to_be_bytes()).await.unwrap();
    client.write_all(&buf[..n]).await.unwrap();
    client.flush().await.unwrap();
    host.read_exact(&mut len).await.unwrap();
    let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
    host.read_exact(&mut msg).await.unwrap();
    responder.read_message(&msg, &mut rx).unwrap();

    let mut initiator = initiator.into_transport_mode().unwrap();
    let mut responder = responder.into_transport_mode().unwrap();

    // The phone sends something worth stealing.
    let n = initiator.write_message(SECRET, &mut buf).unwrap();
    client.write_all(&(n as u32).to_be_bytes()).await.unwrap();
    client.write_all(&buf[..n]).await.unwrap();
    client.flush().await.unwrap();

    host.read_exact(&mut len).await.unwrap();
    let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
    host.read_exact(&mut msg).await.unwrap();
    let plain = responder.read_message(&msg, &mut rx).unwrap();

    // The host really did receive it, so the session genuinely worked.
    assert_eq!(
        &rx[..plain],
        SECRET,
        "the session did not carry the payload"
    );

    drop(host);
    drop(client);
    drop(control);
    let _ = server.await;

    // And now the question: what did the relay hold?
    let captured = seen.lock().unwrap().clone();
    assert!(
        !captured.is_empty(),
        "the relay captured nothing, so this test proves nothing"
    );
    assert!(
        captured.windows(SECRET.len()).all(|w| w != SECRET),
        "THE PLAINTEXT WAS IN THE RELAY'S BYTES. The no-trust property is gone."
    );
    // Not even a recognisable fragment.
    for probe in [&b"hunter2"[..], &b"password"[..], &b"at noon"[..]] {
        assert!(
            captured.windows(probe.len()).all(|w| w != probe),
            "a fragment of the plaintext was visible to the relay: {:?}",
            std::str::from_utf8(probe).unwrap()
        );
    }
}

/// An unauthenticated host gets nothing, and learns nothing from the refusal.
#[tokio::test]
async fn a_host_with_the_wrong_credential_is_refused() {
    let (relay, addr, listener) = bearer_relay("the-right-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        register_host(&r, &mut sock).await
    });

    let mut host = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut host,
        &ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub: "the-wrong-token".into(),
        },
    )
    .await;

    let outcome = server.await.unwrap();
    assert!(outcome.is_err(), "a wrong credential registered a session");
    assert_eq!(relay.session_count(), 0, "a refused host still took a slot");
}

/// A stranger guessing session ids is told the same thing every time.
#[tokio::test]
async fn an_unknown_session_id_is_refused_and_takes_no_slot() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        join_client(&r, &mut sock).await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut client,
        &ControlFrame::Join {
            v: PROTOCOL_VERSION,
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        },
    )
    .await;

    let outcome = server.await.unwrap();
    assert!(outcome.is_err(), "an invented session id was accepted");
    assert_eq!(relay.session_count(), 0);
}

/// The enrol-then-prove method over a real socket, including the challenge.
#[tokio::test]
async fn an_enrolled_host_registers_by_signing_the_relay_challenge() {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let identity = HostIdentity(sk.verifying_key().to_bytes());
    use base64::Engine;
    let host_pub = base64::engine::general_purpose::STANDARD.encode(identity.0);

    let relay = Relay::new(Box::new(EnrolThenProve::new(&[identity])));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        register_host(&r, &mut sock).await
    });

    let mut host = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut host,
        &ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub,
        },
    )
    .await;
    let nonce = match read_frame(&mut host).await {
        ControlFrame::Challenge { nonce } => base64::engine::general_purpose::STANDARD
            .decode(nonce)
            .unwrap(),
        other => panic!("expected Challenge, got {other:?}"),
    };
    let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(&nonce).to_bytes());
    write_frame(&mut host, &ControlFrame::Prove { sig }).await;

    assert!(
        server.await.unwrap().is_ok(),
        "an enrolled host that signed the challenge was refused"
    );
    assert_eq!(relay.session_count(), 1);
}

/// A peer announcing a version this build does not speak is refused at the door.
#[tokio::test]
async fn an_unsupported_protocol_version_is_refused_before_anything_else() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        register_host(&r, &mut sock).await
    });

    let mut host = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut host,
        &ControlFrame::Register {
            v: PROTOCOL_VERSION + 1,
            host_pub: "a-token".into(),
        },
    )
    .await;

    let outcome = server.await.unwrap();
    assert!(outcome.is_err(), "a future protocol version was accepted");
    assert_eq!(relay.session_count(), 0);
}

// ---------------------------------------------------------------------------
// What a stranger can do with the dial-out half.

/// A ticket is spent when it is redeemed. Replaying it opens no second path.
///
/// This is the property that keeps a leaked `ClientWaiting` frame from being
/// worth anything: whoever presents the ticket first gets a socket joined to a
/// client that is about to run a Noise handshake it cannot pass, and whoever
/// presents it second gets nothing at all.
#[tokio::test]
async fn a_ticket_works_once_and_a_replay_opens_no_second_data_path() {
    let (relay, addr, listener) = bearer_relay("a-token").await;

    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        let id = register_host(&r, &mut control).await.unwrap();
        let (mut client, _) = listener.accept().await.unwrap();
        join_client(&r, &mut client).await.unwrap();
        let (ticket, waiter) = mint_attach(&r, &id).unwrap();
        write_frame(
            &mut control,
            &ControlFrame::ClientWaiting {
                ticket: ticket.as_str().to_string(),
            },
        )
        .await;

        let (mut data, _) = listener.accept().await.unwrap();
        accept_data(&r, &mut data)
            .await
            .unwrap()
            .deliver(data)
            .unwrap();
        let _host_data = waiter.wait(Duration::from_secs(5)).await.unwrap();

        let (mut replay, _) = listener.accept().await.unwrap();
        let second = accept_data(&r, &mut replay).await;
        (second.is_err(), r.pending_attach_count())
    });

    let (mut control, session) = host_control(addr, "a-token").await;
    let _client = client_join(addr, &session).await;
    let ticket = ticket_from(&mut control).await;
    let _first = host_attach_with(addr, &ticket).await;
    let _replay = host_attach_raw(addr, &ticket).await;

    let (refused, pending) = server.await.unwrap();
    assert!(refused, "a spent ticket opened a second data connection");
    assert_eq!(pending, 0, "a redeemed ticket was still held");
}

/// An invented ticket is refused, and tells its sender nothing.
#[tokio::test]
async fn an_invented_ticket_is_refused() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut data, _) = listener.accept().await.unwrap();
        accept_data(&r, &mut data).await
    });

    let _data = host_attach_raw(addr, "AAAAAAAAAAAAAAAAAAAAAA").await;
    assert!(
        server.await.unwrap().is_err(),
        "an invented ticket opened a data connection"
    );
    assert_eq!(relay.pending_attach_count(), 0);
}

/// A session id and a ticket are the same SHAPE, so only the table can tell
/// them apart — and presenting one where the other belongs must fail.
#[tokio::test]
async fn a_session_id_presented_as_a_ticket_is_refused() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        let id = register_host(&r, &mut control).await.unwrap();
        let (mut client, _) = listener.accept().await.unwrap();
        join_client(&r, &mut client).await.unwrap();
        // A REAL ticket exists for this session. Without this the attach table
        // is empty and the test passes for the wrong reason — which is exactly
        // what red-proving it revealed.
        let (_ticket, _waiter) = mint_attach(&r, &id).unwrap();

        let (mut data, _) = listener.accept().await.unwrap();
        let outcome = accept_data(&r, &mut data).await;
        (outcome.is_err(), control, client)
    });

    let (_control, session) = host_control(addr, "a-token").await;
    let _client = client_join(addr, &session).await;
    // The session id passes the shape check by construction.
    let _data = host_attach_raw(addr, &session).await;

    let (refused, _held, _held_client) = server.await.unwrap();
    assert!(
        refused,
        "a session id was redeemable as an attach ticket — the two id spaces are not separated"
    );
}

/// The client is not told `Joined` until the host's data connection exists.
///
/// Confirming earlier has the phone start its Noise handshake into a socket
/// joined to nothing, and the failure then surfaces as a handshake timeout
/// rather than as what it is.
#[tokio::test]
async fn the_client_is_not_told_joined_until_the_host_has_dialled_back() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (_control, _client, _host_data) = relay_until_spliceable(&r, &listener).await;
        // Hold everything open so the client's socket cannot report EOF.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let (mut control, session) = host_control(addr, "a-token").await;
    let mut client = client_join(addr, &session).await;

    // Nothing may arrive for the client yet.
    let mut byte = [0u8; 1];
    let early = tokio::time::timeout(Duration::from_millis(300), client.read(&mut byte)).await;
    assert!(
        early.is_err(),
        "the client was told something before the host had dialled back"
    );

    let _host = host_dial_back(addr, &mut control).await;
    assert!(
        matches!(read_frame(&mut client).await, ControlFrame::Joined),
        "the client was never confirmed once the data path existed"
    );
    server.abort();
}

/// A host that is told to dial back and never does frees the ticket at once,
/// rather than leaving it to age out.
#[tokio::test]
async fn a_host_that_never_dials_back_frees_the_ticket() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        let id = register_host(&r, &mut control).await.unwrap();
        let (_ticket, waiter) = mint_attach(&r, &id).unwrap();
        assert_eq!(r.pending_attach_count(), 1);
        let outcome = waiter.wait(Duration::from_millis(200)).await;
        (outcome.is_err(), r.pending_attach_count())
    });

    let (_control, _session) = host_control(addr, "a-token").await;
    let (gave_up, pending) = server.await.unwrap();
    assert!(gave_up, "the wait returned a socket nobody sent");
    assert_eq!(
        pending, 0,
        "a ticket nobody dialled back for was still redeemable"
    );
}

/// A live control connection answers its keepalive.
#[tokio::test]
async fn a_live_control_connection_answers_its_heartbeat() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        register_host(&r, &mut control).await.unwrap();
        heartbeat(&mut control, Duration::from_secs(2)).await
    });

    let (mut control, _session) = host_control(addr, "a-token").await;
    assert!(matches!(read_frame(&mut control).await, ControlFrame::Ping));
    write_frame(&mut control, &ControlFrame::Pong).await;

    assert!(
        server.await.unwrap().is_ok(),
        "a host that answered its ping was treated as dead"
    );
    assert_eq!(relay.session_count(), 1);
}

/// A control connection that stops answering is dead, and its session must not
/// stay in the table.
///
/// This is the failure the persistent control connection introduces: a NAT
/// reaps an idle TCP connection without telling either end, and the relay would
/// otherwise hold a session that no client can ever attach to while the invite
/// carrying that id is already in someone's hands.
#[tokio::test]
async fn a_control_connection_that_stops_answering_has_its_session_released() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        let id = register_host(&r, &mut control).await.unwrap();
        assert_eq!(r.session_count(), 1);
        let outcome = heartbeat(&mut control, Duration::from_millis(200)).await;
        if outcome.is_err() {
            relay::release(&r, &id);
        }
        (outcome.is_err(), r.session_count())
    });

    // The host connects, registers — and then says nothing ever again.
    let (_control, _session) = host_control(addr, "a-token").await;

    let (declared_dead, sessions) = server.await.unwrap();
    assert!(
        declared_dead,
        "a control connection that never answered was treated as live"
    );
    assert_eq!(
        sessions, 0,
        "a dead control connection kept its session slot, and the invite naming it is already out"
    );
}

/// The control connection carries control frames and never session bytes.
///
/// The split exists so the relay never multiplexes, and multiplexing is what
/// would force it to parse session framing — the one thing it must not do. If
/// session bytes ever appeared on the control connection, that parsing is back.
#[tokio::test]
async fn the_control_connection_never_carries_session_bytes() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let _ = &relay;
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let (_control, mut client, mut host_data) = relay_until_spliceable(&r, &listener).await;
        splice(&mut host_data, &mut client).await
    });

    let (mut control, session) = host_control(addr, "a-token").await;
    let mut client = client_join(addr, &session).await;
    let mut host = host_dial_back(addr, &mut control).await;
    assert!(matches!(
        read_frame(&mut client).await,
        ControlFrame::Joined
    ));

    // A full exchange over the data path.
    host.write_all(b"session bytes going one way")
        .await
        .unwrap();
    host.flush().await.unwrap();
    let mut got = [0u8; 27];
    client.read_exact(&mut got).await.unwrap();
    client.write_all(b"and the other").await.unwrap();
    client.flush().await.unwrap();
    let mut back = [0u8; 13];
    host.read_exact(&mut back).await.unwrap();

    // Nothing whatsoever arrived on the control connection.
    let mut byte = [0u8; 1];
    let leaked = tokio::time::timeout(Duration::from_millis(300), control.read(&mut byte)).await;
    assert!(
        leaked.is_err(),
        "bytes appeared on the control connection during a session"
    );

    drop(host);
    drop(client);
    drop(control);
    let _ = server.await;
}

// ---------------------------------------------------------------------------
// The relay AS IT RUNS: one port, driven by serve_connection.
//
// Everything above drives the pieces directly. These drive the same loop
// `relayd` runs, on one port, with the three kinds of connection told apart by
// their first frame and nothing else.

/// A running relay: one port, one accept loop, `serve_connection` per socket.
async fn one_port_relay(token: &str) -> (Arc<Relay>, SocketAddr) {
    let relay = Relay::new(Box::new(BearerToken::new(&[token.to_string()])));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let r = relay.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let r2 = r.clone();
            tokio::spawn(async move {
                let _ = serve_connection(&r2, sock).await;
            });
        }
    });
    (relay, addr)
}

async fn try_read_frame(sock: &mut TcpStream) -> Option<ControlFrame> {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await.ok()?;
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    sock.read_exact(&mut body).await.ok()?;
    frame::decode(&body).ok()
}

/// A host that dials out and behaves: answers pings, dials back per client.
///
/// This is what `host_app`'s `RelaySource` does, written out here because the
/// relay's tests cannot depend on the host.
async fn dial_out_host(
    addr: SocketAddr,
    token: &str,
) -> (String, tokio::sync::mpsc::UnboundedReceiver<TcpStream>) {
    let mut control = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut control,
        &ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub: token.to_string(),
        },
    )
    .await;
    let session = match read_frame(&mut control).await {
        ControlFrame::Registered { session } => session,
        other => panic!("expected Registered, got {other:?}"),
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(f) = try_read_frame(&mut control).await {
            match f {
                ControlFrame::Ping => write_frame(&mut control, &ControlFrame::Pong).await,
                ControlFrame::ClientWaiting { ticket } => {
                    let Ok(mut data) = TcpStream::connect(addr).await else {
                        continue;
                    };
                    write_frame(
                        &mut data,
                        &ControlFrame::Attach {
                            v: PROTOCOL_VERSION,
                            ticket,
                        },
                    )
                    .await;
                    if matches!(
                        try_read_frame(&mut data).await,
                        Some(ControlFrame::Attached)
                    ) {
                        let _ = tx.send(data);
                    }
                }
                _ => break,
            }
        }
    });
    (session, rx)
}

async fn join_and_expect_bytes(addr: SocketAddr, session: &str) -> TcpStream {
    let mut client = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut client,
        &ControlFrame::Join {
            v: PROTOCOL_VERSION,
            session: session.to_string(),
        },
    )
    .await;
    client
}

/// The whole thing, on one port.
#[tokio::test]
async fn a_host_and_a_client_meet_through_one_port() {
    let (_relay, addr) = one_port_relay("a-token").await;
    let (session, mut peers) = dial_out_host(addr, "a-token").await;

    let mut client = join_and_expect_bytes(addr, &session).await;
    let mut host_data = peers.recv().await.expect("the host was never dialled back");
    assert!(matches!(
        read_frame(&mut client).await,
        ControlFrame::Joined
    ));

    host_data.write_all(b"down").await.unwrap();
    host_data.flush().await.unwrap();
    let mut got = [0u8; 4];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"down");

    client.write_all(b"up").await.unwrap();
    client.flush().await.unwrap();
    let mut back = [0u8; 2];
    host_data.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"up");
}

/// **THE DEFECT THIS FOUND.** A session was claimable once, so the second phone
/// to present a perfectly good id — including the SAME phone after ten seconds
/// of lost signal — was refused by its own host, and the operator would have had
/// to mint a fresh code for every reconnection. That is the exact cost the
/// persistent control connection was chosen to avoid, so the design was
/// undercutting its own reason to exist.
#[tokio::test]
async fn the_same_session_serves_a_second_client_after_the_first_leaves() {
    let (_relay, addr) = one_port_relay("a-token").await;
    let (session, mut peers) = dial_out_host(addr, "a-token").await;

    // First client, served and gone.
    let mut first = join_and_expect_bytes(addr, &session).await;
    let mut first_host = peers
        .recv()
        .await
        .expect("no dial-back for the first client");
    assert!(matches!(read_frame(&mut first).await, ControlFrame::Joined));
    first.write_all(b"one").await.unwrap();
    first.flush().await.unwrap();
    let mut got = [0u8; 3];
    first_host.read_exact(&mut got).await.unwrap();
    drop(first);
    drop(first_host);

    // The SAME id, again. This is a phone that reconnected.
    let mut second = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut c = join_and_expect_bytes(addr, &session).await;
            match tokio::time::timeout(Duration::from_millis(400), read_frame(&mut c)).await {
                Ok(ControlFrame::Joined) => return c,
                // The first splice may not have finished unwinding yet; a
                // refusal here is the race, not the defect.
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("a phone that reconnected was refused by its own host's session");

    let mut second_host = peers
        .recv()
        .await
        .expect("no dial-back for the reconnecting client");
    second.write_all(b"two").await.unwrap();
    second.flush().await.unwrap();
    let mut again = [0u8; 3];
    second_host.read_exact(&mut again).await.unwrap();
    assert_eq!(&again, b"two", "the reconnected client was not spliced");
}

/// One session serves one client at a time. The second, while the first is
/// still connected, is refused — and told nothing it could probe with.
#[tokio::test]
async fn a_second_client_at_the_same_time_is_refused() {
    let (_relay, addr) = one_port_relay("a-token").await;
    let (session, mut peers) = dial_out_host(addr, "a-token").await;

    let mut first = join_and_expect_bytes(addr, &session).await;
    let _first_host = peers.recv().await.expect("no dial-back");
    assert!(matches!(read_frame(&mut first).await, ControlFrame::Joined));

    let mut second = join_and_expect_bytes(addr, &session).await;
    match read_frame(&mut second).await {
        ControlFrame::Denied { why } => assert_eq!(
            why, "no such session",
            "a second client learned that the id was real and busy"
        ),
        other => panic!("a second simultaneous client got {other:?}"),
    }
}

/// A peer opening with a frame only the RELAY sends is not speaking this
/// protocol, and is refused at the door.
#[tokio::test]
async fn a_frame_only_the_relay_sends_is_refused_as_an_opening() {
    let (_relay, addr) = one_port_relay("a-token").await;
    let mut stranger = TcpStream::connect(addr).await.unwrap();
    write_frame(&mut stranger, &ControlFrame::Joined).await;
    match read_frame(&mut stranger).await {
        ControlFrame::Denied { why } => assert_eq!(why, "unexpected frame"),
        other => panic!("an impossible opening frame got {other:?}"),
    }
}

/// A socket that connects and never speaks is dropped, not held.
///
/// Takes the real ten seconds deliberately: a shortened clock would prove that
/// something closes eventually, not that the bound the relay actually ships is
/// the one being enforced. This is the cheapest thing a stranger can do to a
/// public port, so it is the one worth waiting for.
#[tokio::test]
async fn a_socket_that_says_nothing_is_dropped() {
    let (_relay, addr) = one_port_relay("a-token").await;
    let mut silent = TcpStream::connect(addr).await.unwrap();

    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(20), silent.read(&mut byte))
        .await
        .expect("the relay held a silent socket open past its control timeout");
    assert!(
        matches!(closed, Ok(0)) || closed.is_err(),
        "a silent socket was neither closed nor errored"
    );
}

// ---------------------------------------------------------------------------
// A splice must end when one side stops taking bytes, and must not buffer
// megabytes on the way.
//
// Measured through the deployed relay, 2026-09-14: a phone that switched off
// Wi-Fi left its session spliced for over three minutes, holding one of the 64
// slots and ~8.5 MB of buffered stream, waiting for TCP to give up. And while
// the phone was merely slow, the relay's autotuned socket buffers soaked up a
// growing backlog (2.6 MB, 8-10 s of delay) so the host's own link to the relay
// always looked healthy and its congestion handling never engaged.

/// Two connected loopback sockets, with the FAR end's buffers kept small so the
/// relay's own buffering is what the tests measure.
async fn loopback_pair(far_buffer: u32) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let far = tokio::net::TcpSocket::new_v4().unwrap();
    far.set_send_buffer_size(far_buffer).unwrap();
    far.set_recv_buffer_size(far_buffer).unwrap();
    let (far, near) = tokio::join!(far.connect(addr), listener.accept());
    (near.unwrap().0, far.unwrap())
}

#[tokio::test]
async fn a_splice_whose_far_side_stops_reading_ends_and_frees_its_slot() {
    let (mut host_near, mut host_far) = loopback_pair(64 * 1024).await;
    let (mut phone_near, _phone_far_never_reads) = loopback_pair(64 * 1024).await;

    let stall = Duration::from_secs(2);
    let splice =
        tokio::spawn(
            async move { relay::splice_within(&mut host_near, &mut phone_near, stall).await },
        );
    let writer = tokio::spawn(async move {
        let chunk = vec![0x5au8; 16 * 1024];
        while host_far.write_all(&chunk).await.is_ok() {}
    });

    let ended = tokio::time::timeout(Duration::from_secs(20), splice).await;
    writer.abort();
    let report = ended
        .expect("a splice to a phone that took nothing for 20 s was still running")
        .unwrap();
    assert_eq!(report.end, relay::SpliceEnd::Stalled);
}

#[tokio::test]
async fn a_splice_holds_a_bounded_backlog_for_a_side_that_stopped_reading() {
    let (mut host_near, mut host_far) = loopback_pair(64 * 1024).await;
    let (mut phone_near, mut phone_far) = loopback_pair(64 * 1024).await;

    let splice = tokio::spawn(async move {
        relay::splice_within(&mut host_near, &mut phone_near, Duration::from_secs(600)).await
    });

    // A good stretch first, flat out with the phone reading, as a real session
    // has before the path slows: this is when autotuned buffers grow, and the
    // 2026-09-14 backlog was buffers grown in good minutes holding bad ones.
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 256 * 1024];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if tokio::time::timeout(Duration::from_millis(100), phone_far.read(&mut buf))
                .await
                .is_ok_and(|r| r.is_err())
            {
                break;
            }
        }
        phone_far // stop reading, keep the connection open
    });
    let chunk = vec![0xa5u8; 16 * 1024];
    while !reader.is_finished() {
        host_far.write_all(&chunk).await.unwrap();
    }
    let _phone_far_now_silent = reader.await.unwrap();

    // Now the phone reads nothing: how much more will the relay take?
    let mut accepted = 0usize;
    while let Ok(Ok(())) =
        tokio::time::timeout(Duration::from_secs(1), host_far.write_all(&chunk)).await
    {
        accepted += chunk.len();
        assert!(accepted < 64 * 1024 * 1024, "no pushback after 64 MB");
    }
    splice.abort();
    eprintln!("after a fast stretch, the host could hand the relay {accepted} more bytes for a phone reading nothing");
    assert!(
        accepted <= relay::SPLICE_BACKLOG_BOUND,
        "{accepted} bytes queued for a phone that read nothing (bound {}); the host is not told \
         the path is slow until the relay's buffers are full",
        relay::SPLICE_BACKLOG_BOUND
    );
}

#[tokio::test]
async fn spliced_sockets_carry_keepalive_so_a_silent_vanished_peer_is_noticed() {
    let (mut a, _a_far) = loopback_pair(64 * 1024).await;
    let (mut b, mut b_far) = loopback_pair(64 * 1024).await;
    let splice = tokio::spawn(async move {
        let a_ref: &mut TcpStream = &mut a;
        // Checked from inside the splice's own setup: bound first, then inspect.
        relay::bound_splice_socket(a_ref);
        let ka = socket2::SockRef::from(&*a_ref).keepalive().unwrap();
        (
            ka,
            relay::splice_within(a_ref, &mut b, Duration::from_secs(600)).await,
        )
    });
    // End the splice from the far side so the task returns.
    b_far.shutdown().await.unwrap();
    drop(b_far);
    let (keepalive, report) = tokio::time::timeout(Duration::from_secs(10), splice)
        .await
        .expect("closing one side must end the splice")
        .unwrap();
    assert!(
        keepalive,
        "a spliced socket without keepalive holds a slot for a phone that vanished silently"
    );
    assert_eq!(report.end, relay::SpliceEnd::Closed);
}

// ---------------------------------------------------------------------------
// A socket that says nothing is logged as silent, not as an ordinary close.
//
// A flood of connect-and-wait sockets used to read, in the relay's log, exactly
// like phones disconnecting — "connection closed". A watcher cannot classify
// what the relay does not distinguish.

#[tokio::test(start_paused = true)]
async fn a_socket_that_sends_nothing_is_reported_as_silent() {
    let (relay, _addr, listener) = bearer_relay("t").await;
    let addr = listener.local_addr().unwrap();
    let (_client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let (sock, _) = accepted.unwrap();
    let outcome = serve_connection(&relay, sock).await;
    let err = outcome.expect_err("a silent socket must not be served");
    assert!(matches!(err, relay::ServeError::Silent), "got {err:?}");
    assert_eq!(err.public_reason(), "no frame within 10 s");
}

#[tokio::test]
async fn a_socket_that_closes_at_once_is_still_an_ordinary_close() {
    let (relay, _addr, listener) = bearer_relay("t").await;
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    drop(client.unwrap());
    let (sock, _) = accepted.unwrap();
    let err = serve_connection(&relay, sock)
        .await
        .expect_err("nothing to serve");
    assert!(matches!(err, relay::ServeError::Io), "got {err:?}");
    assert_eq!(err.public_reason(), "connection closed");
}

/// Register an enrolled host over a real socket and return the session id the
/// relay issued. Used twice by the reconnect test, which is the point: the
/// SECOND call is a host coming back.
async fn signing_host_registers(
    relay: &Arc<Relay>,
    addr: SocketAddr,
    listener: &TcpListener,
    sk: &ed25519_dalek::SigningKey,
) -> String {
    use base64::Engine;
    use ed25519_dalek::Signer;
    let host_pub = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());

    let mut host = TcpStream::connect(addr).await.unwrap();
    let (mut server_side, _) = listener.accept().await.unwrap();
    let r = relay.clone();
    let server = tokio::spawn(async move { register_host(&r, &mut server_side).await });

    write_frame(
        &mut host,
        &ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub,
        },
    )
    .await;
    let nonce = match read_frame(&mut host).await {
        ControlFrame::Challenge { nonce } => base64::engine::general_purpose::STANDARD
            .decode(nonce)
            .unwrap(),
        other => panic!("expected Challenge, got {other:?}"),
    };
    let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(&nonce).to_bytes());
    write_frame(&mut host, &ControlFrame::Prove { sig }).await;

    let id = server.await.unwrap().expect("an enrolled host was refused");
    id.as_str().to_string()
}

/// **A host that reconnects keeps the session id its invite already names.**
///
/// The whole reason the relay could not be a default route: the id was random
/// per registration, so every host restart invalidated the pairing QR and the
/// operator had to walk to the machine and scan a new one. Proven over real
/// sockets through the real registration path, not against the table alone.
#[tokio::test]
async fn an_enrolled_host_that_reconnects_is_given_the_same_session_id() {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let identity = HostIdentity(sk.verifying_key().to_bytes());
    let relay = Relay::new(Box::new(EnrolThenProve::new(&[identity])));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let first = signing_host_registers(&relay, addr, &listener, &sk).await;
    let second = signing_host_registers(&relay, addr, &listener, &sk).await;

    assert_eq!(
        first, second,
        "a host that reconnected was given a new session id, so its pairing code is dead"
    );
    assert_eq!(
        relay.session_count(),
        1,
        "reconnecting took a second session slot for one host"
    );
}

/// **Two hosts are still two sessions.** The derivation must depend on WHICH
/// host registered; one that ignored the identity would hand every host the
/// same id and splice the operator's phone into a stranger's machine.
#[tokio::test]
async fn two_enrolled_hosts_get_different_sessions() {
    use ed25519_dalek::SigningKey;
    let one = SigningKey::generate(&mut rand::rngs::OsRng);
    let two = SigningKey::generate(&mut rand::rngs::OsRng);
    let relay = Relay::new(Box::new(EnrolThenProve::new(&[
        HostIdentity(one.verifying_key().to_bytes()),
        HostIdentity(two.verifying_key().to_bytes()),
    ])));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let a = signing_host_registers(&relay, addr, &listener, &one).await;
    let b = signing_host_registers(&relay, addr, &listener, &two).await;

    assert_ne!(a, b, "two different hosts were given the same session id");
    assert_eq!(relay.session_count(), 2);
}

/// **A superseded control connection must not release the session that replaced
/// it.**
///
/// With stable ids a reconnecting host registers the id its previous connection
/// still holds, so for a moment two control loops exist for one session. The old
/// one is going to exit — its socket is dead, which is why the host reconnected
/// — and if its cleanup removed the session, the host would have restarted
/// itself into an id that nothing answers. The failure is invisible until a
/// phone tries to connect, which is the worst possible moment to find it.
#[tokio::test]
async fn a_superseded_control_connection_does_not_release_the_new_session() {
    let relay = Relay::new(Box::new(BearerToken::new(&["a-token".to_string()])));
    let id = relay::SessionId::parse("AAAAAAAAAAAAAAAAAAAAAA").unwrap();

    let (mut old_rx, old_gen) = attach_control(&relay, &id);
    let (_new_rx, new_gen) = attach_control(&relay, &id);
    assert_ne!(old_gen, new_gen, "two connections shared one generation");

    // Replacing the sender is how the old loop learns it is finished.
    assert!(
        old_rx.recv().await.is_none(),
        "a superseded control loop was never told: it would sit there pinging a dead socket"
    );

    assert!(
        !release_if_current(&relay, &id, old_gen),
        "the superseded connection released a session it no longer owned"
    );
    assert!(
        notify_host(
            &relay,
            &id,
            relay::Ticket::parse("BBBBBBBBBBBBBBBBBBBBBB").unwrap()
        )
        .is_ok(),
        "the new control connection was unreachable after the old one cleaned up"
    );

    // The connection that DOES own it still releases it, or a host that really
    // went away would leave an id a client can present for ever.
    assert!(release_if_current(&relay, &id, new_gen));
    assert!(notify_host(
        &relay,
        &id,
        relay::Ticket::parse("BBBBBBBBBBBBBBBBBBBBBB").unwrap()
    )
    .is_err());
}

/// Register a bearer host directly and return its session id.
async fn register_bearer_host(
    relay: &Arc<Relay>,
    listener: &TcpListener,
    addr: SocketAddr,
    token: &str,
) -> (relay::SessionId, TcpStream) {
    let mut host = TcpStream::connect(addr).await.unwrap();
    let (mut server_side, _) = listener.accept().await.unwrap();
    let r = relay.clone();
    let server = tokio::spawn(async move {
        let id = register_host(&r, &mut server_side).await.unwrap();
        (id, server_side)
    });
    write_frame(
        &mut host,
        &ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub: token.to_string(),
        },
    )
    .await;
    let _registered = read_frame(&mut host).await;
    let (id, _server_side) = server.await.unwrap();
    (id, host)
}

fn join_frame(session: &str) -> ControlFrame {
    ControlFrame::Join {
        v: PROTOCOL_VERSION,
        session: session.to_string(),
    }
}

/// **A stranger inventing session ids leaves nothing in the join limiter.**
///
/// The first P4 build rate-limited BEFORE asking the table, so every well-formed
/// id a stranger made up became a limiter entry, and every join — including a
/// real phone's — paid to sweep them all. Found by the deploy agent's review. An
/// id the table does not hold is now refused before the limiter is consulted.
#[tokio::test]
async fn a_stranger_inventing_session_ids_leaves_nothing_in_the_join_limiter() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let _host = register_bearer_host(&relay, &listener, addr, "a-token").await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    let _accepted = listener.accept().await.unwrap();

    for n in 0..2_000u32 {
        let invented = format!("{:0>22}", n);
        let outcome = relay::join_client_with(&relay, &mut sock, join_frame(&invented)).await;
        assert_eq!(
            outcome.as_ref().err().map(|e| e.public_reason()),
            Some("no such session"),
            "an invented id was not refused as unknown"
        );
    }
    assert_eq!(
        relay.tracked_joins(),
        0,
        "invented session ids were recorded by the join limiter"
    );
}

/// **Churning a KNOWN session is refused before it claims the host's slot.**
///
/// The limiter exists for this: a stranger who has learned a real id and joins
/// it over and over. Refusing AFTER claiming would still take the host's slot on
/// every attempt — the phone's slot, while the stranger is refused. So the
/// refused join must leave the session unoccupied.
#[tokio::test]
async fn churning_a_known_session_is_refused_before_it_claims_the_hosts_slot() {
    let (relay, addr, listener) = bearer_relay("a-token").await;
    let (id, _host) = register_bearer_host(&relay, &listener, addr, "a-token").await;
    let mut sock = TcpStream::connect(addr).await.unwrap();
    let _accepted = listener.accept().await.unwrap();

    for attempt in 1..=relay::session::MAX_JOINS_PER_WINDOW {
        let joined = relay::join_client_with(&relay, &mut sock, join_frame(id.as_str())).await;
        assert!(
            joined.is_ok(),
            "join {attempt} of a real session was refused"
        );
        relay::vacate_session(&relay, &id);
    }
    let refused = relay::join_client_with(&relay, &mut sock, join_frame(id.as_str())).await;
    assert_eq!(
        refused.as_ref().err().map(|e| e.public_reason()),
        Some("no such session"),
        "a churned session was not refused"
    );
    assert!(
        !relay.is_occupied(&id),
        "the refused join had already claimed the host's slot"
    );
    assert!(
        relay.tracked_joins() <= 1,
        "one known session is tracked as {}",
        relay.tracked_joins()
    );
}

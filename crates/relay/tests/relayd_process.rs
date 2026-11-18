//! `relayd`, run as the real binary, for what only its accept loop decides.
//!
//! The pending-connection cap and the refusal log line live in `relayd.rs`, not
//! in the library, so the only honest test is to start the process, push past
//! the cap, and read what it wrote.
//!
//! History: the pending permit used to be held until a connection ENDED, so the
//! "256 connections already unauthenticated" cap counted registered hosts and
//! spliced sessions too (these tests' predecessor pinned it: 6 hosts registered,
//! 6 of 256 silent sockets refused). The operator approved the fix on 2026-09-14:
//! the permit is released the moment a connection identifies itself.

use relay::frame::{self, ControlFrame, PROTOCOL_VERSION};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TOKEN: &str = "relayd-process-test-token";
/// relayd's MAX_PENDING.
const MAX_PENDING: usize = 256;
/// Sockets opened past the cap, which must be refused.
const OVER: usize = 4;

struct Relayd {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Drop for Relayd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_relayd(env: &[(&str, &str)]) -> (Relayd, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_relayd"));
    cmd.env_clear().env("RD_RELAY_BIND", "127.0.0.1:0");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("start relayd");
    let stderr = child.stderr.take().unwrap();
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let relayd = Relayd { child, lines };
    let deadline = Instant::now() + Duration::from_secs(10);
    let addr = loop {
        let line = relayd
            .lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("relayd never said where it is listening");
        if let Some(a) = line.strip_prefix("[relayd] listening on ") {
            break a.to_string();
        }
    };
    (relayd, addr)
}

fn bearer_relayd() -> (Relayd, String) {
    start_relayd(&[("RD_RELAY_AUTH", "bearer"), ("RD_RELAY_TOKENS", TOKEN)])
}

async fn write_frame(sock: &mut TcpStream, f: &ControlFrame) {
    let body = frame::encode(f);
    sock.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .unwrap();
    sock.write_all(&body).await.unwrap();
}

async fn read_frame(sock: &mut TcpStream) -> ControlFrame {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await.unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    sock.read_exact(&mut body).await.unwrap();
    frame::decode(&body).unwrap()
}

async fn register(addr: &str) -> (TcpStream, String) {
    let mut c = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut c,
        &ControlFrame::Register {
            v: PROTOCOL_VERSION,
            host_pub: TOKEN.to_string(),
        },
    )
    .await;
    match read_frame(&mut c).await {
        ControlFrame::Registered { session } => (c, session),
        other => panic!("registration failed: {other:?}"),
    }
}

/// A client joined to `session` and spliced to a host data connection.
async fn splice(addr: &str, control: &mut TcpStream, session: &str) -> (TcpStream, TcpStream) {
    let mut client = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut client,
        &ControlFrame::Join {
            v: PROTOCOL_VERSION,
            session: session.to_string(),
        },
    )
    .await;
    let ticket = loop {
        match read_frame(control).await {
            ControlFrame::ClientWaiting { ticket } => break ticket,
            ControlFrame::Ping => write_frame(control, &ControlFrame::Pong).await,
            other => panic!("expected ClientWaiting, got {other:?}"),
        }
    };
    let mut data = TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut data,
        &ControlFrame::Attach {
            v: PROTOCOL_VERSION,
            ticket,
        },
    )
    .await;
    assert_eq!(read_frame(&mut data).await, ControlFrame::Attached);
    assert_eq!(read_frame(&mut client).await, ControlFrame::Joined);
    // Bytes cross, so this really is a live session.
    client.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    data.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    (client, data)
}

/// Open `n` sockets that say nothing, then report how many relayd refused.
/// A refused socket is closed at once; an accepted one waits for a frame.
async fn refused_of(addr: &str, n: usize) -> (usize, Vec<TcpStream>) {
    let opened = Instant::now();
    let mut socks = Vec::new();
    for _ in 0..n {
        socks.push(TcpStream::connect(addr).await.unwrap());
    }
    assert!(
        opened.elapsed() < Duration::from_secs(5),
        "too slow to test inside the 10 s timeout"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut checks = Vec::new();
    for mut s in socks {
        checks.push(tokio::spawn(async move {
            let mut b = [0u8; 1];
            let closed = !matches!(
                tokio::time::timeout(Duration::from_millis(500), s.read(&mut b)).await,
                Err(_)
            );
            (closed, s)
        }));
    }
    let (mut refused, mut open) = (0, Vec::new());
    for c in checks {
        let (closed, s) = c.await.unwrap();
        if closed {
            refused += 1;
        } else {
            open.push(s);
        }
    }
    (refused, open)
}

/// Count refusals in relayd's log until `want` are accounted for, and return the lines.
fn refusal_lines(relayd: &Relayd, want: usize) -> (usize, Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let (mut counted, mut lines) = (0usize, Vec::new());
    while counted < want && Instant::now() < deadline {
        if let Ok(line) = relayd.lines.recv_timeout(Duration::from_millis(100)) {
            if let Some(rest) = line.strip_prefix("[relayd] refused ") {
                counted += match rest.split_once(" more in the last ") {
                    Some((n, _)) => n.parse::<usize>().unwrap(),
                    None => 1,
                };
                assert!(
                    line.ends_with("256 connections already unauthenticated"),
                    "{line}"
                );
                lines.push(line);
            }
        }
    }
    (counted, lines)
}

#[tokio::test(flavor = "multi_thread")]
async fn registered_hosts_and_live_sessions_leave_every_pending_slot_free() {
    const HOSTS: usize = 6;
    const SESSIONS: usize = 3;
    let (relayd, addr) = bearer_relayd();

    let mut hosts = Vec::new();
    for _ in 0..HOSTS {
        hosts.push(register(&addr).await);
    }
    let mut live = Vec::new();
    for (control, session) in hosts.iter_mut().take(SESSIONS) {
        live.push(splice(&addr, control, session).await);
    }
    // HOSTS control + SESSIONS clients + SESSIONS data connections, all identified.

    let (refused, silent) = refused_of(&addr, MAX_PENDING).await;
    assert_eq!(
        refused, 0,
        "with {HOSTS} hosts registered and {SESSIONS} sessions spliced, {refused} of \
         {MAX_PENDING} silent sockets were refused: identified connections are holding \
         pending permits"
    );

    // The cap still binds what it is for: past it, silent sockets are refused.
    let (over, _more) = refused_of(&addr, OVER).await;
    assert_eq!(
        over, OVER,
        "the pending cap no longer refuses unidentified connections"
    );

    // And those refusals are counted, not repeated, in relayd's log.
    let (counted, lines) = refusal_lines(&relayd, OVER);
    assert_eq!(counted, OVER, "refusals logged: {lines:#?}");
    assert!(
        lines.len() <= 2,
        "{} refusal lines for {OVER} refusals: {lines:#?}",
        lines.len()
    );
    drop((silent, live, hosts));
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_that_fail_to_identify_release_their_permits() {
    let (_relayd, addr) = bearer_relayd();

    // Every way identification fails before anything long-lived, MAX_PENDING
    // times over, so a single leaked permit per failure would show.
    let mut failing = Vec::new();
    for i in 0..MAX_PENDING {
        let addr = addr.clone();
        failing.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(&addr).await.unwrap();
            match i % 5 {
                // wrong credential
                0 => {
                    write_frame(
                        &mut s,
                        &ControlFrame::Register {
                            v: PROTOCOL_VERSION,
                            host_pub: "wrong".into(),
                        },
                    )
                    .await
                }
                // a session that does not exist
                1 => {
                    write_frame(
                        &mut s,
                        &ControlFrame::Join {
                            v: PROTOCOL_VERSION,
                            session: "no-such-session".into(),
                        },
                    )
                    .await
                }
                // a ticket that was never issued
                2 => {
                    write_frame(
                        &mut s,
                        &ControlFrame::Attach {
                            v: PROTOCOL_VERSION,
                            ticket: "no-such-ticket".into(),
                        },
                    )
                    .await
                }
                // a length prefix past the cap
                3 => s.write_all(&u32::MAX.to_be_bytes()).await.unwrap(),
                // a body that is not a frame
                _ => {
                    s.write_all(&5u32.to_be_bytes()).await.unwrap();
                    s.write_all(b"junk!").await.unwrap();
                }
            }
            // relayd refuses and closes; wait for it.
            let mut buf = vec![0u8; 1024];
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(_)) => {}
                    Err(_) => assert!(
                        Instant::now() < deadline,
                        "relayd kept a failed connection open"
                    ),
                }
            }
        }));
    }
    for f in failing {
        f.await.unwrap();
    }
    // Give relayd's tasks a moment to finish and drop what they held.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (refused, _silent) = refused_of(&addr, MAX_PENDING).await;
    assert_eq!(
        refused, 0,
        "after {MAX_PENDING} failed identifications, {refused} slots were still taken: a permit leaked"
    );
    let (over, _more) = refused_of(&addr, OVER).await;
    assert_eq!(over, OVER);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_registers_and_never_proves_is_released_after_the_timeout() {
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let (_relayd, addr) = start_relayd(&[("RD_RELAY_AUTH", "signing"), ("RD_RELAY_HOSTS", &key)]);

    // Take every pending slot with registrations that get their challenge and
    // then go silent: unidentified, so they rightly count against the cap.
    let mut stalled = Vec::new();
    for _ in 0..MAX_PENDING {
        let mut s = TcpStream::connect(&addr).await.unwrap();
        write_frame(
            &mut s,
            &ControlFrame::Register {
                v: PROTOCOL_VERSION,
                host_pub: key.clone(),
            },
        )
        .await;
        assert!(matches!(
            read_frame(&mut s).await,
            ControlFrame::Challenge { .. }
        ));
        stalled.push(s);
    }
    let started = Instant::now();
    let (over, _more) = refused_of(&addr, OVER).await;
    assert_eq!(
        over, OVER,
        "stalled registrations must count while they are unidentified"
    );

    // Past CONTROL_TIMEOUT they must be let go, not held for ever.
    let wait = Duration::from_secs(11).saturating_sub(started.elapsed());
    tokio::time::sleep(wait).await;
    let (refused, _silent) = refused_of(&addr, MAX_PENDING).await;
    assert_eq!(
        refused, 0,
        "{refused} slots still held by registrations that never proved, after the timeout"
    );
    drop(stalled);
}

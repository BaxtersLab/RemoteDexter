//! The socket layer: read a few control frames, then copy bytes and stop
//! looking.
//!
//! Everything that DECIDES anything lives in [`crate::frame`],
//! [`crate::session`] and [`crate::auth`], and is tested without a socket. What
//! is here is the part that genuinely needs one — and it is deliberately dull,
//! because the interesting properties were settled before this file ran.
//!
//! # The splice is the whole point
//!
//! Once two peers are joined, [`splice`] copies bytes in both directions and
//! never inspects one. It cannot: this crate has no dependency that could
//! decrypt. The Noise XX handshake then runs end to end between phone and host
//! straight through it, and the relay is a wire.

use crate::auth::{HostAuth, HostAuthError, HostIdentity};
use crate::frame::{self, ControlFrame, FrameError};
use crate::session::{AttachTable, SessionId, SessionTable, TableError, Ticket, ATTACH_TTL};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// How long a peer has to finish the control exchange before it is dropped.
///
/// A socket that connects and then says nothing costs the relay a task and, for
/// a host, a session slot. Bounded so a stranger cannot accumulate them.
pub const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The challenge nonce length. 32 bytes from the OS random source.
const NONCE_BYTES: usize = 32;

/// How often the relay pings an idle control connection.
///
/// A dialled-out control connection sits idle between clients, and a home NAT
/// reaps idle TCP without telling either end. Below the common 30-60s idle
/// timeouts on purpose.
pub const CONTROL_KEEPALIVE: Duration = Duration::from_secs(20);

/// How long the host has to answer a ping before its control connection is
/// treated as dead and its session released.
pub const KEEPALIVE_GRACE: Duration = Duration::from_secs(10);

/// Shared relay state.
pub struct Relay {
    sessions: Mutex<SessionTable>,
    attaches: Mutex<AttachTable>,
    /// Where a waiting client parks the channel that will hand it the host's
    /// data connection.
    ///
    /// This is PLUMBING, not policy: every rule about which ticket is valid,
    /// for how long, and that it works once lives in [`AttachTable`], where it
    /// is provable without a socket.
    waiting: Mutex<HashMap<Ticket, oneshot::Sender<TcpStream>>>,
    /// How a client's task reaches the host's control connection.
    ///
    /// One entry per registered host, added when its control loop starts and
    /// removed by [`release`]. A client mints its ticket and then sends it here;
    /// the control task is the only thing that writes to that socket, so there
    /// is no second writer to interleave with.
    controls: Mutex<HashMap<SessionId, mpsc::UnboundedSender<Ticket>>>,
    auth: Box<dyn HostAuth>,
}

impl Relay {
    /// There is deliberately no `Default`: a relay cannot be started without
    /// someone choosing how hosts authenticate.
    pub fn new(auth: Box<dyn HostAuth>) -> Arc<Self> {
        Arc::new(Relay {
            sessions: Mutex::new(SessionTable::default()),
            attaches: Mutex::new(AttachTable::default()),
            waiting: Mutex::new(HashMap::new()),
            controls: Mutex::new(HashMap::new()),
            auth,
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Tickets minted and not yet redeemed.
    pub fn pending_attach_count(&self) -> usize {
        self.attaches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

/// Why a peer was turned away.
#[derive(Debug, PartialEq, Eq)]
pub enum ServeError {
    Frame(FrameError),
    Auth(HostAuthError),
    Table(TableError),
    /// The peer sent a frame that is legal but not the one expected here.
    Unexpected,
    /// The peer announced a protocol version this build does not speak.
    Version(u8),
    /// The peer stopped talking, or the socket failed.
    Io,
}

impl ServeError {
    /// What the peer is told — always coarse. A stranger learns that it was
    /// refused and roughly which contract it broke, never the relay's state.
    pub fn public_reason(&self) -> &'static str {
        match self {
            ServeError::Frame(e) => e.public_reason(),
            ServeError::Auth(e) => e.public_reason(),
            ServeError::Table(e) => e.public_reason(),
            ServeError::Unexpected => "unexpected frame",
            ServeError::Version(_) => "unsupported protocol version",
            ServeError::Io => "connection closed",
        }
    }
}

/// Read one length-prefixed control frame.
///
/// The length prefix is checked against the cap BEFORE the body is read, which
/// is the ordering that stops a peer making the relay allocate.
pub async fn read_frame(sock: &mut TcpStream) -> Result<ControlFrame, ServeError> {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len)
        .await
        .map_err(|_| ServeError::Io)?;
    let declared = u32::from_be_bytes(len) as usize;
    let n = frame::check_len(declared).map_err(ServeError::Frame)?;
    let mut body = vec![0u8; n];
    sock.read_exact(&mut body)
        .await
        .map_err(|_| ServeError::Io)?;
    frame::decode(&body).map_err(ServeError::Frame)
}

/// Write one length-prefixed control frame.
pub async fn write_frame(sock: &mut TcpStream, f: &ControlFrame) -> Result<(), ServeError> {
    let body = frame::encode(f);
    let len = (body.len() as u32).to_be_bytes();
    sock.write_all(&len).await.map_err(|_| ServeError::Io)?;
    sock.write_all(&body).await.map_err(|_| ServeError::Io)?;
    sock.flush().await.map_err(|_| ServeError::Io)
}

/// Tell a peer it was refused, then let the caller drop the socket.
///
/// Best effort on purpose: a peer that has already gone is not an error worth
/// propagating over a refusal that has already been decided.
pub async fn deny(sock: &mut TcpStream, why: &str) {
    let _ = write_frame(
        sock,
        &ControlFrame::Denied {
            why: why.to_string(),
        },
    )
    .await;
}

/// Run the host side of the control exchange and return the session it owns.
pub async fn register_host(
    relay: &Arc<Relay>,
    sock: &mut TcpStream,
) -> Result<SessionId, ServeError> {
    let first = read_frame(sock).await?;
    register_host_with(relay, sock, first).await
}

/// As [`register_host`], for a caller that has ALREADY read the first frame.
///
/// One port carries hosts, clients and data connections, so something has to
/// read the first frame to know which this is. Splitting the read from the rest
/// is what lets that happen once rather than each path hopefully reading the
/// same bytes.
pub async fn register_host_with(
    relay: &Arc<Relay>,
    sock: &mut TcpStream,
    first: ControlFrame,
) -> Result<SessionId, ServeError> {
    let (v, host_pub) = match first {
        ControlFrame::Register { v, host_pub } => (v, host_pub),
        _ => return Err(ServeError::Unexpected),
    };
    if !frame::version_accepted(v) {
        return Err(ServeError::Version(v));
    }

    let identity = HostIdentity::parse_base64(&host_pub);

    // A challenge is issued only when the configured method wants one, so the
    // bearer path is one round trip and the signing path is two.
    let (nonce, proof) = if relay.auth.needs_challenge() {
        let mut nonce = [0u8; NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(nonce);
        write_frame(sock, &ControlFrame::Challenge { nonce: encoded }).await?;
        match read_frame(sock).await? {
            ControlFrame::Prove { sig } => (nonce.to_vec(), sig),
            _ => return Err(ServeError::Unexpected),
        }
    } else {
        // The bearer method carries its secret in `host_pub`'s place: the
        // registration frame is the credential. No nonce is involved, which is
        // exactly the weakness the enrol-then-prove method removes.
        (Vec::new(), host_pub.clone())
    };

    relay
        .auth
        .verify(identity.as_ref(), &nonce, &proof)
        .map_err(ServeError::Auth)?;

    let id = {
        let mut table = relay.sessions.lock().unwrap_or_else(|p| p.into_inner());
        table.register(Instant::now()).map_err(ServeError::Table)?
    };
    write_frame(
        sock,
        &ControlFrame::Registered {
            session: id.as_str().to_string(),
        },
    )
    .await?;
    Ok(id)
}

/// Run the client side of the control exchange and return the session it claims.
pub async fn join_client(
    relay: &Arc<Relay>,
    sock: &mut TcpStream,
) -> Result<SessionId, ServeError> {
    let first = read_frame(sock).await?;
    join_client_with(relay, sock, first).await
}

/// As [`join_client`], for a caller that has already read the first frame.
pub async fn join_client_with(
    relay: &Arc<Relay>,
    _sock: &mut TcpStream,
    first: ControlFrame,
) -> Result<SessionId, ServeError> {
    let (v, session) = match first {
        ControlFrame::Join { v, session } => (v, session),
        _ => return Err(ServeError::Unexpected),
    };
    if !frame::version_accepted(v) {
        return Err(ServeError::Version(v));
    }
    // Shape first, then the table. A malformed id never becomes a map key, and
    // it is refused with the SAME words an unknown one gets.
    let id = SessionId::parse(&session).ok_or(ServeError::Table(TableError::UnknownSession))?;
    {
        let mut table = relay.sessions.lock().unwrap_or_else(|p| p.into_inner());
        table
            .claim(&id, Instant::now())
            .map_err(ServeError::Table)?;
    }
    Ok(id)
}

/// Tell the client its splice is live.
///
/// **Called only once the host's data connection has actually been received.**
/// Confirming at claim time — which is what an earlier shape of this file did —
/// has the phone start its Noise handshake into a socket joined to nothing,
/// and the failure surfaces as a handshake timeout rather than as what it is.
pub async fn confirm_join(sock: &mut TcpStream) -> Result<(), ServeError> {
    write_frame(sock, &ControlFrame::Joined).await
}

/// Mint a ticket for a waiting client and arm the slot that will receive the
/// host's data connection — **in one call, so they cannot be done out of
/// order**.
///
/// A ticket that exists before anything is waiting for it is a ticket the host
/// can redeem into a hole: the redemption succeeds, the data connection is
/// accepted, and the client is left waiting for a socket that was already
/// thrown away. Minting and arming together makes that ordering unrepresentable
/// rather than merely discouraged.
pub fn mint_attach(
    relay: &Arc<Relay>,
    session: &SessionId,
) -> Result<(Ticket, AttachWaiter), ServeError> {
    let ticket = {
        let mut table = relay.attaches.lock().unwrap_or_else(|p| p.into_inner());
        table
            .mint(session, Instant::now())
            .map_err(ServeError::Table)?
    };
    let (tx, rx) = oneshot::channel();
    relay
        .waiting
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(ticket.clone(), tx);
    Ok((
        ticket.clone(),
        AttachWaiter {
            relay: relay.clone(),
            ticket,
            rx,
        },
    ))
}

/// A client waiting for the host to dial back with its ticket.
pub struct AttachWaiter {
    relay: Arc<Relay>,
    ticket: Ticket,
    rx: oneshot::Receiver<TcpStream>,
}

impl AttachWaiter {
    /// Wait for the host's data connection.
    ///
    /// On timeout — or if the host never dials back — the ticket is abandoned
    /// rather than left to age out, so the slot is free immediately and a
    /// ticket nobody is waiting for cannot be redeemed later.
    pub async fn wait(self, within: Duration) -> Result<TcpStream, ServeError> {
        let AttachWaiter { relay, ticket, rx } = self;
        match tokio::time::timeout(within, rx).await {
            Ok(Ok(sock)) => Ok(sock),
            // The host dialled back and then vanished, or the attachment was
            // dropped without delivering. Either way there is no data path.
            Ok(Err(_)) => {
                abandon(&relay, &ticket);
                Err(ServeError::Io)
            }
            Err(_) => {
                abandon(&relay, &ticket);
                Err(ServeError::Io)
            }
        }
    }

    /// The ticket this waiter is holding, for the `ClientWaiting` frame.
    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }
}

fn abandon(relay: &Arc<Relay>, ticket: &Ticket) {
    relay
        .attaches
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .abandon(ticket);
    relay
        .waiting
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(ticket);
}

/// A redeemed ticket, holding the channel to the client that is waiting.
///
/// Dropping this without calling [`DataAttachment::deliver`] lets the waiting
/// client fail immediately instead of sitting out the timeout.
pub struct DataAttachment {
    tx: oneshot::Sender<TcpStream>,
}

impl DataAttachment {
    /// Hand the host's data connection to the waiting client.
    pub fn deliver(self, sock: TcpStream) -> Result<(), ServeError> {
        self.tx.send(sock).map_err(|_| ServeError::Io)
    }
}

/// Host → relay on a FRESH data connection: read `Attach`, redeem the ticket,
/// and answer.
///
/// The ticket is redeemed and the waiting client taken together, BEFORE
/// `Attached` is written. A host that is told `Attached` and then finds nothing
/// to be attached to has been lied to by its own relay.
pub async fn accept_data(
    relay: &Arc<Relay>,
    sock: &mut TcpStream,
) -> Result<DataAttachment, ServeError> {
    let first = read_frame(sock).await?;
    accept_data_with(relay, sock, first).await
}

/// As [`accept_data`], for a caller that has already read the first frame.
pub async fn accept_data_with(
    relay: &Arc<Relay>,
    sock: &mut TcpStream,
    first: ControlFrame,
) -> Result<DataAttachment, ServeError> {
    let (v, ticket) = match first {
        ControlFrame::Attach { v, ticket } => (v, ticket),
        _ => return Err(ServeError::Unexpected),
    };
    if !frame::version_accepted(v) {
        return Err(ServeError::Version(v));
    }
    // Shape first, then the table — a malformed ticket never becomes a map key,
    // and it is refused with the SAME words an unknown one gets.
    let ticket = Ticket::parse(&ticket).ok_or(ServeError::Table(TableError::UnknownTicket))?;
    {
        let mut table = relay.attaches.lock().unwrap_or_else(|p| p.into_inner());
        // Redeeming REMOVES it. That is the single use.
        table
            .redeem(&ticket, Instant::now())
            .map_err(ServeError::Table)?;
    }
    let tx = relay
        .waiting
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&ticket)
        // The ticket was valid but its client has gone. Same words again: the
        // host learns it was refused, not which half of the relay's state moved.
        .ok_or(ServeError::Table(TableError::UnknownTicket))?;

    write_frame(sock, &ControlFrame::Attached).await?;
    Ok(DataAttachment { tx })
}

/// Ping an idle control connection and require an answer.
///
/// The host sends nothing else on the control connection, so anything but
/// `Pong` is a peer that is not speaking this protocol.
///
/// `Err` means the session should be released: a host that cannot be reached is
/// holding a slot nobody can ever attach to, and the invite carrying that
/// session id is already in someone's hands.
pub async fn heartbeat(sock: &mut TcpStream, grace: Duration) -> Result<(), ServeError> {
    write_frame(sock, &ControlFrame::Ping).await?;
    match tokio::time::timeout(grace, read_frame(sock)).await {
        Ok(Ok(ControlFrame::Pong)) => Ok(()),
        Ok(Ok(_)) => Err(ServeError::Unexpected),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ServeError::Io),
    }
}

/// Copy bytes both ways until either side closes. **Nothing is inspected.**
///
/// Returns the byte counts, which are all the relay ever learns about a
/// session: how much went each way and for how long.
pub async fn splice(a: &mut TcpStream, b: &mut TcpStream) -> (u64, u64) {
    match tokio::io::copy_bidirectional(a, b).await {
        Ok((to_b, to_a)) => (to_b, to_a),
        // A session that ends by one side vanishing is ordinary, not an error:
        // a phone goes out of signal and the host sees the socket close.
        Err(_) => (0, 0),
    }
}

/// Drop a session from the table — the host went away, or the splice ended.
pub fn release(relay: &Arc<Relay>, id: &SessionId) {
    relay
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(id);
    // The control channel goes with it. Leaving it would let a client mint a
    // ticket and hand it to a task that has already exited, which reads to the
    // client as a host that is there and silent rather than one that is gone.
    relay
        .controls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(id);
}

/// Register the host's control channel and take the receiving end.
///
/// Called by the control loop once registration has succeeded. Replaces any
/// previous entry for the same id, which cannot arise from a fresh random id
/// but would otherwise be a silent second writer if it ever did.
pub fn attach_control(relay: &Arc<Relay>, id: &SessionId) -> mpsc::UnboundedReceiver<Ticket> {
    let (tx, rx) = mpsc::unbounded_channel();
    relay
        .controls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id.clone(), tx);
    rx
}

/// Tell a host that a client is waiting for it.
///
/// `Err` means there is no live control connection for that session — the host
/// went away between the client's join and this moment. The client is refused in
/// the SAME words an unknown session gets, because "the host was there a second
/// ago" is not something a stranger needs confirmed.
pub fn notify_host(relay: &Arc<Relay>, id: &SessionId, ticket: Ticket) -> Result<(), ServeError> {
    let guard = relay.controls.lock().unwrap_or_else(|p| p.into_inner());
    let tx = guard
        .get(id)
        .ok_or(ServeError::Table(TableError::UnknownSession))?;
    tx.send(ticket)
        .map_err(|_| ServeError::Table(TableError::UnknownSession))
}

/// Record that a host is still there, and say whether its session survived.
pub fn touch_session(relay: &Arc<Relay>, id: &SessionId) -> bool {
    relay
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .touch(id, Instant::now())
}

/// Free a session's occupancy when its client's splice ends.
pub fn vacate_session(relay: &Arc<Relay>, id: &SessionId) {
    relay
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .vacate(id);
}

/// Serve one connection to completion: work out what it is, then run it.
///
/// **One port carries all three kinds.** A host's control connection, a client
/// joining, and a host's data connection are told apart by their first frame and
/// nothing else — no port per role, no flag, no guess from the source address.
/// That is one firewall rule to reason about instead of three, and it means a
/// stranger scanning the port learns the same thing whichever it is.
///
/// The first frame is read under [`CONTROL_TIMEOUT`], so a socket that connects
/// and says nothing costs a task for ten seconds and not a minute longer.
pub async fn serve_connection(relay: &Arc<Relay>, mut sock: TcpStream) -> Result<(), ServeError> {
    let first = match tokio::time::timeout(CONTROL_TIMEOUT, read_frame(&mut sock)).await {
        Ok(frame) => frame?,
        Err(_) => return Err(ServeError::Io),
    };
    match first {
        ControlFrame::Register { .. } => serve_host(relay, sock, first).await,
        ControlFrame::Join { .. } => serve_client(relay, sock, first).await,
        ControlFrame::Attach { .. } => serve_data(relay, sock, first).await,
        // Every other frame is one only the RELAY sends. A peer opening with one
        // is not speaking this protocol.
        _ => {
            deny(&mut sock, ServeError::Unexpected.public_reason()).await;
            Err(ServeError::Unexpected)
        }
    }
}

/// A host's control connection: register, then hold it open and tell the host
/// when clients arrive.
async fn serve_host(
    relay: &Arc<Relay>,
    mut sock: TcpStream,
    first: ControlFrame,
) -> Result<(), ServeError> {
    let id = match register_host_with(relay, &mut sock, first).await {
        Ok(id) => id,
        Err(e) => {
            deny(&mut sock, e.public_reason()).await;
            return Err(e);
        }
    };

    let mut waiting = attach_control(relay, &id);
    let mut ticks = tokio::time::interval(CONTROL_KEEPALIVE);
    // The first tick fires immediately; a ping the instant a host registers is
    // noise, not liveness.
    ticks.tick().await;

    let outcome = loop {
        tokio::select! {
            Some(ticket) = waiting.recv() => {
                if write_frame(
                    &mut sock,
                    &ControlFrame::ClientWaiting { ticket: ticket.as_str().to_string() },
                )
                .await
                .is_err()
                {
                    break Err(ServeError::Io);
                }
            }
            _ = ticks.tick() => {
                if let Err(e) = heartbeat(&mut sock, KEEPALIVE_GRACE).await {
                    break Err(e);
                }
                // A host that answered is a host that is there. If its session
                // expired anyway the relay has forgotten the id its invite
                // names, and saying so beats serving an id nothing recognises.
                if !touch_session(relay, &id) {
                    break Err(ServeError::Table(TableError::UnknownSession));
                }
            }
        }
    };

    // Whatever ended it, the session goes. A registered session with no control
    // connection is an id a client can present and nothing can ever answer.
    release(relay, &id);
    outcome
}

/// A client joining: occupy the session, get the host to dial back, splice.
async fn serve_client(
    relay: &Arc<Relay>,
    mut client: TcpStream,
    first: ControlFrame,
) -> Result<(), ServeError> {
    let id = match join_client_with(relay, &mut client, first).await {
        Ok(id) => id,
        Err(e) => {
            deny(&mut client, e.public_reason()).await;
            return Err(e);
        }
    };

    // PAST THIS POINT THE SESSION IS OCCUPIED, and every exit must free it.
    // A session left occupied by a client that failed here is a session the
    // host can never serve again, and the operator's only clue would be a phone
    // that pairs and then silently cannot connect.
    let outcome = splice_one_client(relay, &mut client, &id).await;
    vacate_session(relay, &id);
    outcome
}

async fn splice_one_client(
    relay: &Arc<Relay>,
    client: &mut TcpStream,
    id: &SessionId,
) -> Result<(), ServeError> {
    let (ticket, waiter) = match mint_attach(relay, id) {
        Ok(v) => v,
        Err(e) => {
            deny(client, e.public_reason()).await;
            return Err(e);
        }
    };

    // The host may have gone between the join and now. Same words as an unknown
    // session: a stranger does not get told that the id was real.
    if let Err(e) = notify_host(relay, id, ticket) {
        deny(client, TableError::UnknownSession.public_reason()).await;
        return Err(e);
    }

    let mut host_data = match waiter.wait(ATTACH_TTL).await {
        Ok(sock) => sock,
        Err(e) => {
            deny(client, TableError::UnknownSession.public_reason()).await;
            return Err(e);
        }
    };

    // Only now, with something on the other end.
    confirm_join(client).await?;
    splice(&mut host_data, client).await;
    Ok(())
}

/// A host's data connection: redeem the ticket and hand the socket over.
async fn serve_data(
    relay: &Arc<Relay>,
    mut sock: TcpStream,
    first: ControlFrame,
) -> Result<(), ServeError> {
    match accept_data_with(relay, &mut sock, first).await {
        Ok(attachment) => attachment.deliver(sock),
        Err(e) => {
            deny(&mut sock, e.public_reason()).await;
            Err(e)
        }
    }
}

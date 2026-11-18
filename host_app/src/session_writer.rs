//! The session's socket writes, off the session loop.
//!
//! ## Why this exists
//!
//! Measured on the operator's phone, 2026-09-13, over a Wi-Fi link losing a
//! quarter of what the host sent: the session loop awaited every socket write
//! in place, and that loop is also the only thing that handles input, runs the
//! idle key release and re-checks revocation. So each time the link stalled,
//! all three stopped with it — taps arrived in a burst seconds late, a held key
//! could not be let go, and a revoked phone stayed connected. A peer that
//! simply stops reading stalls them for as long as it likes.
//!
//! The same session showed 3 MB waiting unsent in the kernel's buffer. The
//! stream already drops frames when its own queue is full (`stream_backpressure`),
//! but that queue emptied straight into a socket buffer with room for several
//! seconds of screen, so the drop rarely fired and the delay built up underneath
//! it — the limit `stream_ladder`'s header names.
//!
//! ## The shape
//!
//! One writer task owns the write half. The session loop still owns the Noise
//! transport and encrypts everything, and it queues ciphertext here in the order
//! it encrypted it, down ONE channel — so frames leave in nonce order no matter
//! what else changes. The loop never awaits the network again.
//!
//! * **Replies** queue without waiting. They are small, and every one answers a
//!   command the peer sent, so they cannot outgrow what the peer asked for —
//!   unless the peer stops reading. [`MAX_UNWRITTEN_BYTES`] bounds that: past it
//!   the peer is not reading and the session is closed rather than buffered.
//! * **Stream chunks** need one of [`STREAM_CHUNKS_IN_FLIGHT`] slots, held until
//!   the chunk is actually written. While the link is slow the loop stops taking
//!   chunks, the stream's own queue fills, and `stream_backpressure` drops the
//!   frame — the newest screen wins, as it should.
//! * **The kernel buffer** is bounded with `TCP_NOTSENT_LOWAT` on Linux, so a
//!   write completes only when the socket has actually drained. Without it the
//!   slots above would empty into megabytes of kernel memory and measure nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

/// Stream chunks that may be queued or being written at once.
///
/// Two chunks is about 120 KB: enough that a frame's chunks flow on a healthy
/// link, small enough that a stalled one holds less than a frame of old screen.
pub const STREAM_CHUNKS_IN_FLIGHT: usize = 2;

/// Bytes queued for a peer that has not read them yet, before the session is
/// closed.
///
/// Replies are one per command, so on a live link this sits near zero. Eight
/// MiB is minutes of pointer-move acknowledgements with nothing read, and far
/// past any Wi-Fi stall a phone recovers from; beyond it, holding more for a
/// peer that is not reading only grows the host. With
/// `host_controller::SessionLimit::MAX_TOTAL` sessions this bounds the whole
/// host at 64 MiB of unsent replies.
pub const MAX_UNWRITTEN_BYTES: usize = 8 * 1024 * 1024;

/// Longest one write may make no progress before the session is ended.
///
/// Measured 2026-09-14: a phone that dropped off Wi-Fi left the host's session
/// retrying on TCP's exponential backoff, already at a 120 s interval, holding
/// the session open for minutes with nothing going anywhere. A link that moves
/// no bytes in 30 s is gone; a slow one moves some. Ending the write ends the
/// writer task, which ends the session.
pub const WRITE_STALL: std::time::Duration = std::time::Duration::from_secs(30);

/// Unsent bytes the kernel may hold for a session socket (`TCP_NOTSENT_LOWAT`).
///
/// The 2026-09-13 session measured 3 MB. 128 KB is about two stream chunks:
/// enough to keep a healthy link full, and a fraction of a second of screen when
/// it is not.
#[cfg(target_os = "linux")]
pub const UNSENT_LOWAT_BYTES: u32 = 128 * 1024;

/// Why a frame could not be queued.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The peer has left more than [`MAX_UNWRITTEN_BYTES`] unread. Close the session.
    PeerNotReading,
    /// The writer has exited, so the socket is gone. Close the session.
    WriterGone,
}

struct Outbound {
    /// Length prefix and ciphertext, as they go on the wire.
    bytes: Vec<u8>,
    /// A stream chunk's slot, released once the chunk is written.
    _slot: Option<OwnedSemaphorePermit>,
}

/// The session loop's side of the writer.
pub struct SessionWriter {
    tx: mpsc::UnboundedSender<Outbound>,
    unwritten: Arc<AtomicUsize>,
    slots: Arc<Semaphore>,
}

impl SessionWriter {
    /// Start a writer task that owns `w`.
    ///
    /// The task ends with `Ok` when this handle is dropped and everything queued
    /// is written, or with the first write error. Abort it to close the socket
    /// without waiting.
    pub fn spawn<W>(w: W) -> (Self, tokio::task::JoinHandle<std::io::Result<()>>)
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel();
        let unwritten = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(write_all_queued(w, rx, unwritten.clone()));
        let writer = SessionWriter {
            tx,
            unwritten,
            slots: Arc::new(Semaphore::new(STREAM_CHUNKS_IN_FLIGHT)),
        };
        (writer, task)
    }

    /// Queue a reply. Never waits.
    pub fn queue_reply(&self, ciphertext: &[u8]) -> Result<(), Refused> {
        self.queue(ciphertext, None)
    }

    /// Queue a stream chunk under a slot from [`Self::stream_slots`]. Never waits.
    pub fn queue_chunk(
        &self,
        ciphertext: &[u8],
        slot: OwnedSemaphorePermit,
    ) -> Result<(), Refused> {
        self.queue(ciphertext, Some(slot))
    }

    /// The slots a stream chunk must hold. Acquiring one is the wait.
    pub fn stream_slots(&self) -> Arc<Semaphore> {
        self.slots.clone()
    }

    /// Bytes queued and not yet written.
    pub fn unwritten(&self) -> usize {
        self.unwritten.load(Ordering::SeqCst)
    }

    fn queue(&self, ciphertext: &[u8], slot: Option<OwnedSemaphorePermit>) -> Result<(), Refused> {
        let len = 4 + ciphertext.len();
        if self.unwritten() + len > MAX_UNWRITTEN_BYTES {
            return Err(Refused::PeerNotReading);
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(ciphertext);
        // Counted before sending, so the writer never decrements past zero.
        self.unwritten.fetch_add(len, Ordering::SeqCst);
        self.tx.send(Outbound { bytes, _slot: slot }).map_err(|_| {
            self.unwritten.fetch_sub(len, Ordering::SeqCst);
            Refused::WriterGone
        })
    }
}

async fn write_all_queued<W: AsyncWrite + Unpin>(
    mut w: W,
    mut rx: mpsc::UnboundedReceiver<Outbound>,
    unwritten: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    while let Some(item) = rx.recv().await {
        tokio::time::timeout(WRITE_STALL, w.write_all(&item.bytes))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the peer took nothing for the whole write stall limit",
                )
            })??;
        unwritten.fetch_sub(item.bytes.len(), Ordering::SeqCst);
        // `item` drops here, releasing a chunk's slot only now that it is written.
    }
    w.flush().await
}

/// Set up a session socket: small messages leave at once, and on Linux the
/// kernel's unsent backlog is bounded.
///
/// Nagle's algorithm is off because every reply here answers a command the
/// phone is waiting on, and on the 2026-09-14 lossy link a small reply queued
/// behind an unacknowledged one waits exactly as long as the loss lasts. Both
/// options are attempted; the first failure is returned, and neither failure
/// is a safety problem, only latency.
pub fn tune(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    let nodelay = stream.set_nodelay(true);
    let unsent = bound_unsent(stream);
    nodelay.and(unsent)
}

/// Bound the unsent bytes the kernel holds for a session socket.
#[cfg(target_os = "linux")]
pub fn bound_unsent(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    socket2::SockRef::from(stream).set_tcp_notsent_lowat(UNSENT_LOWAT_BYTES)
}

/// No `TCP_NOTSENT_LOWAT` here. The writer task still keeps the session loop
/// off the network; only the kernel buffer underneath is left at its default.
#[cfg(not(target_os = "linux"))]
pub fn bound_unsent(_stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    const PATIENCE: std::time::Duration = std::time::Duration::from_millis(300);

    #[tokio::test]
    async fn frames_leave_in_the_order_they_were_queued() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let (writer, task) = SessionWriter::spawn(near);
        let slots = writer.stream_slots();
        writer.queue_reply(b"one").unwrap();
        let slot = slots.clone().acquire_owned().await.unwrap();
        writer.queue_chunk(b"two", slot).unwrap();
        writer.queue_reply(b"three").unwrap();
        drop(writer);
        task.await.unwrap().unwrap();

        let mut wire = Vec::new();
        far.read_to_end(&mut wire).await.unwrap();
        let mut expected = Vec::new();
        for frame in [&b"one"[..], b"two", b"three"] {
            expected.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            expected.extend_from_slice(frame);
        }
        // Noise nonces are consumed in queue order; any reordering would make
        // every later frame undecryptable.
        assert_eq!(wire, expected);
    }

    #[tokio::test]
    async fn queuing_never_waits_on_a_peer_that_is_not_reading() {
        let (near, _far) = tokio::io::duplex(64);
        let (writer, _task) = SessionWriter::spawn(near);
        let started = std::time::Instant::now();
        for _ in 0..10_000 {
            writer.queue_reply(&[0u8; 24]).unwrap();
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "queuing 10 000 replies took {:?} with nothing read",
            started.elapsed()
        );
        assert!(
            writer.unwritten() > 0,
            "the peer read nothing, so bytes must be pending"
        );
    }

    #[tokio::test]
    async fn a_peer_that_never_reads_is_refused_at_the_cap() {
        let (near, _far) = tokio::io::duplex(64);
        let (writer, _task) = SessionWriter::spawn(near);
        let frame = [0u8; 4096];
        let mut queued = 0usize;
        let refusal = loop {
            match writer.queue_reply(&frame) {
                Ok(()) => queued += 1,
                Err(e) => break e,
            }
            assert!(
                queued < 10_000,
                "no cap: {queued} frames queued for a peer that reads nothing"
            );
        };
        assert_eq!(refusal, Refused::PeerNotReading);
        assert!(writer.unwritten() <= MAX_UNWRITTEN_BYTES);
        assert!(
            writer.unwritten() + 2 * (4 + frame.len()) > MAX_UNWRITTEN_BYTES,
            "refused early, at {} of {MAX_UNWRITTEN_BYTES} bytes",
            writer.unwritten()
        );
    }

    #[tokio::test]
    async fn a_chunk_holds_its_slot_until_it_is_written() {
        let (near, mut far) = tokio::io::duplex(8);
        let (writer, _task) = SessionWriter::spawn(near);
        let slots = writer.stream_slots();
        for _ in 0..STREAM_CHUNKS_IN_FLIGHT {
            let slot = slots.clone().acquire_owned().await.unwrap();
            writer.queue_chunk(&[7u8; 1024], slot).unwrap();
        }
        assert!(
            tokio::time::timeout(PATIENCE, slots.clone().acquire_owned())
                .await
                .is_err(),
            "a slot came back while its chunk was still unwritten"
        );

        // The peer reads; the chunks drain; the slots return.
        let mut drained = vec![0u8; STREAM_CHUNKS_IN_FLIGHT * (4 + 1024)];
        far.read_exact(&mut drained).await.unwrap();
        let slot = tokio::time::timeout(std::time::Duration::from_secs(2), slots.acquire_owned())
            .await
            .expect("a slot must return once its chunk is written");
        drop(slot);
        assert_eq!(writer.unwritten(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_that_makes_no_progress_ends_the_writer() {
        // Nothing reads `_far`, so the first write that does not fit never completes.
        let (near, _far) = tokio::io::duplex(1024);
        let (writer, task) = SessionWriter::spawn(near);
        writer.queue_reply(&[3u8; 8 * 1024]).unwrap();
        let started = tokio::time::Instant::now();
        let ended = tokio::time::timeout(2 * WRITE_STALL, task)
            .await
            .expect("the writer was still waiting on a peer that took nothing")
            .unwrap();
        let err = ended.expect_err("a writer whose peer takes nothing must give up");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() >= WRITE_STALL,
            "gave up after {:?}, before the stall limit",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_closed_socket_is_reported_rather_than_queued_into() {
        let (near, far) = tokio::io::duplex(8);
        let (writer, task) = SessionWriter::spawn(near);
        drop(far);
        writer.queue_reply(&[1u8; 64]).unwrap();
        assert!(
            task.await.unwrap().is_err(),
            "a write to a closed peer must fail the writer"
        );
        assert_eq!(writer.queue_reply(b"after"), Err(Refused::WriterGone));
    }

    #[tokio::test]
    async fn a_tuned_session_socket_sends_small_messages_without_nagle_delay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let (server, _) = accepted.unwrap();
        let _client = client.unwrap();
        tune(&server).unwrap();
        assert!(server.nodelay().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_session_socket_bounds_its_unsent_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let (server, _) = accepted.unwrap();
        let _client = client.unwrap();
        tune(&server).unwrap();
        assert_eq!(
            socket2::SockRef::from(&server).tcp_notsent_lowat().unwrap(),
            UNSENT_LOWAT_BYTES
        );
    }
}

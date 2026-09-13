//! Pure policy: may this frame join the outbound queue, or must it be dropped?
//!
//! Defect D, measured on a real session 2026-08-25. The stream thread queued
//! every frame it captured regardless of whether the previous one had left the
//! machine, behind a 512-chunk channel — roughly 30 MB, several seconds of
//! video. On a link narrower than the host's fixed output that guarantees
//! collapse, and it did:
//!
//! ```text
//! cwnd:1                    congestion window collapsed to a single segment
//! bytes_retrans: 2,927,908  of 97 MB sent
//! send 89863bps             90 kbit/s effective on a 54 Mbit/s link
//! rto:9504                  retransmit timeout backed off to 9.5 seconds
//! snd_wnd: 2052096          receiver wide open — the phone was never the problem
//! ```
//!
//! The operator saw a desktop over a minute stale. Dropping the resolution from
//! 1080p to 720p moved the cliff and did not remove it, because the cause is
//! not the bitrate — it is that **nothing ever says no**.
//!
//! A remote desktop wants the NEWEST frame. Delivering every frame late is
//! strictly worse than delivering some frames on time, so a frame that cannot
//! be queued now is discarded rather than buffered: the next capture is fresher
//! anyway. Dropping is also what stops overdriving the link, which is what
//! caused the loss that collapsed `cwnd` in the first place.
//!
//! Pure on purpose — no channel, no socket, no clock — so the rule is provable
//! without a network. Same shape as `module11::capture_health`.

/// Chunks the outbound stream channel may hold.
///
/// Was 512 (~30 MB). At 60 000-byte payloads this is ~720 KB: about three 1080p
/// frames or eight 720p ones. Small enough that the queue stops being a latency
/// reservoir, large enough to absorb an ordinary scheduling hiccup.
pub const STREAM_QUEUE_CHUNKS: usize = 12;

/// What to do with a freshly encoded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Enqueue every chunk of it.
    Send,
    /// Discard it whole. Never partially: chunks belong to frames, and a frame
    /// missing chunks is not a slightly worse frame, it is a corrupt one.
    Drop,
}

/// How many wire chunks a frame of `encoded_len` bytes will occupy.
///
/// Mirrors `stream_chunk::chunk_frame`, including its rule that an empty frame
/// still takes one chunk so the receiver sees it. Computed before chunking so
/// the decision costs nothing when the answer is Drop.
pub const fn chunks_needed(encoded_len: usize, max_payload: usize) -> usize {
    let max_payload = if max_payload == 0 { 1 } else { max_payload };
    if encoded_len == 0 {
        1
    } else {
        // div_ceil, spelled out to stay const.
        (encoded_len + max_payload - 1) / max_payload
    }
}

/// Decide whether a frame needing `needed` chunks may be queued, given `free`
/// permits now and `total` capacity overall.
pub const fn decide(free: usize, needed: usize, total: usize) -> Decision {
    if needed > total {
        // It can never fit, so dropping it would starve the stream forever —
        // a permanently black screen is worse than a late frame. Send it and
        // let the queue block; the alternative is no picture at all.
        Decision::Send
    } else if needed <= free {
        Decision::Send
    } else {
        Decision::Drop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: usize = 60_000;

    #[test]
    fn chunk_counts_match_the_wire_chunker() {
        assert_eq!(
            chunks_needed(0, PAYLOAD),
            1,
            "an empty frame still ships one chunk"
        );
        assert_eq!(chunks_needed(1, PAYLOAD), 1);
        assert_eq!(
            chunks_needed(PAYLOAD, PAYLOAD),
            1,
            "an exact fit is one chunk"
        );
        assert_eq!(chunks_needed(PAYLOAD + 1, PAYLOAD), 2);
        assert_eq!(chunks_needed(3 * PAYLOAD, PAYLOAD), 3);
        assert_eq!(
            chunks_needed(100, 0),
            100,
            "a zero payload size must not divide by zero"
        );
    }

    #[test]
    fn a_frame_that_fits_is_sent() {
        assert_eq!(decide(12, 3, 12), Decision::Send);
        assert_eq!(
            decide(3, 3, 12),
            Decision::Send,
            "an exact fit is still a fit"
        );
    }

    #[test]
    fn a_frame_that_does_not_fit_is_dropped_whole() {
        assert_eq!(decide(2, 3, 12), Decision::Drop);
        assert_eq!(decide(0, 1, 12), Decision::Drop);
    }

    /// The failure mode that would turn this fix into a permanently black
    /// screen: a frame bigger than the whole queue can never fit, so refusing
    /// it would starve the stream forever.
    #[test]
    fn a_frame_larger_than_the_entire_queue_is_sent_rather_than_starving_the_stream() {
        assert_eq!(decide(0, 20, 12), Decision::Send);
        assert_eq!(decide(12, 20, 12), Decision::Send);
    }

    /// The defect itself, as a simulation: a producer faster than the drain.
    ///
    /// Without a drop rule the backlog grows without bound — which is exactly
    /// what put 30 MB and two minutes of latency between the operator's finger
    /// and the desktop. With it, occupancy stays inside the queue and every
    /// frame that IS sent is whole.
    #[test]
    fn a_producer_faster_than_the_drain_cannot_grow_the_backlog() {
        let total = STREAM_QUEUE_CHUNKS;
        let needed = 3; // ~a 720p frame
        let drain_per_tick = 1; // the link is slower than the encoder
        let mut queued: usize = 0;
        let mut sent = 0;
        let mut dropped = 0;

        for _ in 0..1_000 {
            queued = queued.saturating_sub(drain_per_tick);
            let free = total.saturating_sub(queued);
            match decide(free, needed, total) {
                Decision::Send => {
                    queued += needed;
                    sent += 1;
                }
                Decision::Drop => dropped += 1,
            }
            assert!(
                queued <= total,
                "backlog grew past the queue: {queued} > {total}"
            );
        }

        assert!(sent > 0, "the stream must not stall completely");
        assert!(dropped > 0, "a saturated link must actually drop frames");
    }
}

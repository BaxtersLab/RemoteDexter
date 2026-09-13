//! Frame chunking for a size-limited transport — the RemoteDexter stream wire
//! format, shared verbatim by both ends.
//!
//! A compressed screen frame (JPEG, often hundreds of KB) is larger than a
//! single Noise message (plaintext capped at ~64 KiB). This splits one encoded
//! frame into self-describing wire chunks that fit, and reassembles them on the
//! receiving side.
//!
//! It lives in its own zero-dependency crate rather than inside module11
//! because the *client* needs the reassembling half while module11 is the
//! *host's* capture and encode stack — depending on module11 from the Android
//! `.so` would drag in 85 crates for a 14-byte header. `module11` re-exports it
//! as `module11::chunk`, so there is still exactly one implementation of this
//! format in the tree and producer and consumer cannot drift apart.
//!
//! Wire chunk layout (big-endian), one per transport message:
//! ```text
//! [0]      tag = 0x01 (STREAM_CHUNK) — distinguishes stream frames from the
//!                                       host's JSON command responses (which
//!                                       start with '{' = 0x7B)
//! [1..5]   frame_seq : u32
//! [5..7]   chunk_idx : u16   (0-based)
//! [7..9]   chunk_cnt : u16
//! [9..11]  width     : u16
//! [11..13] height    : u16
//! [13]     flags     : u8    (bit0 = keyframe)
//! [14..]   payload bytes
//! ```

pub const STREAM_TAG: u8 = 0x01;
pub const HEADER_LEN: usize = 14;
const FLAG_KEYFRAME: u8 = 0x01;

/// Split one encoded frame into wire chunks of at most `max_payload` bytes of
/// frame data each (plus the 14-byte header). `max_payload` must be >= 1.
pub fn chunk_frame(
    seq: u32,
    width: u16,
    height: u16,
    keyframe: bool,
    data: &[u8],
    max_payload: usize,
) -> Vec<Vec<u8>> {
    let max_payload = max_payload.max(1);
    // A zero-byte frame still gets one (empty) chunk so the receiver sees it.
    let count = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(max_payload)
    };
    let count_u16 = count.min(u16::MAX as usize) as u16;
    let flags = if keyframe { FLAG_KEYFRAME } else { 0 };

    let mut chunks = Vec::with_capacity(count);
    for idx in 0..count {
        let start = idx * max_payload;
        let end = (start + max_payload).min(data.len());
        let payload = &data[start..end.max(start)];
        let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
        buf.push(STREAM_TAG);
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&(idx as u16).to_be_bytes());
        buf.extend_from_slice(&count_u16.to_be_bytes());
        buf.extend_from_slice(&width.to_be_bytes());
        buf.extend_from_slice(&height.to_be_bytes());
        buf.push(flags);
        buf.extend_from_slice(payload);
        chunks.push(buf);
    }
    chunks
}

/// A parsed chunk header + its payload slice offset.
struct ChunkHdr {
    seq: u32,
    idx: u16,
    count: u16,
    width: u16,
    height: u16,
    keyframe: bool,
}

fn parse(chunk: &[u8]) -> Option<(ChunkHdr, &[u8])> {
    if chunk.len() < HEADER_LEN || chunk[0] != STREAM_TAG {
        return None;
    }
    let hdr = ChunkHdr {
        seq: u32::from_be_bytes([chunk[1], chunk[2], chunk[3], chunk[4]]),
        idx: u16::from_be_bytes([chunk[5], chunk[6]]),
        count: u16::from_be_bytes([chunk[7], chunk[8]]),
        width: u16::from_be_bytes([chunk[9], chunk[10]]),
        height: u16::from_be_bytes([chunk[11], chunk[12]]),
        keyframe: chunk[13] & FLAG_KEYFRAME != 0,
    };
    Some((hdr, &chunk[HEADER_LEN..]))
}

/// A fully reassembled frame.
#[derive(Debug, Clone, PartialEq)]
pub struct ReassembledFrame {
    pub seq: u32,
    pub width: u16,
    pub height: u16,
    pub keyframe: bool,
    pub data: Vec<u8>,
}

/// Reassembles wire chunks into whole frames. Tolerates out-of-order chunks
/// within a frame; drops a partial frame if a newer frame's chunks arrive.
#[derive(Default)]
pub struct FrameReassembler {
    seq: Option<u32>,
    count: u16,
    width: u16,
    height: u16,
    keyframe: bool,
    parts: Vec<Option<Vec<u8>>>,
    have: usize,
}

impl FrameReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one wire chunk. Returns `Some(frame)` when a frame completes.
    /// Non-stream messages (wrong tag) return `None` and are ignored.
    pub fn push(&mut self, chunk: &[u8]) -> Option<ReassembledFrame> {
        let (hdr, payload) = parse(chunk)?;

        // New frame (or first) — reset accumulation.
        if self.seq != Some(hdr.seq) {
            self.seq = Some(hdr.seq);
            self.count = hdr.count.max(1);
            self.width = hdr.width;
            self.height = hdr.height;
            self.keyframe = hdr.keyframe;
            self.parts = vec![None; self.count as usize];
            self.have = 0;
        }

        let i = hdr.idx as usize;
        if i >= self.parts.len() {
            return None; // malformed index
        }
        if self.parts[i].is_none() {
            self.parts[i] = Some(payload.to_vec());
            self.have += 1;
        }

        if self.have == self.count as usize {
            let mut data = Vec::new();
            for p in self.parts.drain(..) {
                data.extend_from_slice(&p.unwrap_or_default());
            }
            let frame = ReassembledFrame {
                seq: self.seq.unwrap(),
                width: self.width,
                height: self.height,
                keyframe: self.keyframe,
                data,
            };
            self.seq = None;
            self.have = 0;
            return Some(frame);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_chunk_roundtrip() {
        let data = vec![9u8; 100];
        let chunks = chunk_frame(1, 640, 480, true, &data, 65000);
        assert_eq!(chunks.len(), 1);
        let mut r = FrameReassembler::new();
        let f = r.push(&chunks[0]).expect("complete");
        assert_eq!(f.seq, 1);
        assert_eq!((f.width, f.height), (640, 480));
        assert!(f.keyframe);
        assert_eq!(f.data, data);
    }

    #[test]
    fn multi_chunk_in_order() {
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let chunks = chunk_frame(7, 1920, 1080, false, &data, 1000);
        assert_eq!(chunks.len(), 5);
        let mut r = FrameReassembler::new();
        let mut done = None;
        for c in &chunks {
            if let Some(f) = r.push(c) {
                done = Some(f);
            }
        }
        let f = done.expect("complete");
        assert_eq!(f.seq, 7);
        assert!(!f.keyframe);
        assert_eq!(f.data, data);
    }

    #[test]
    fn multi_chunk_out_of_order() {
        let data: Vec<u8> = (0..3000).map(|i| (i * 7 % 256) as u8).collect();
        let mut chunks = chunk_frame(3, 800, 600, true, &data, 1000);
        chunks.reverse();
        let mut r = FrameReassembler::new();
        let mut done = None;
        for c in &chunks {
            if let Some(f) = r.push(c) {
                done = Some(f);
            }
        }
        assert_eq!(done.expect("complete").data, data);
    }

    #[test]
    fn newer_frame_discards_partial() {
        let a = chunk_frame(1, 10, 10, true, &[1u8; 3000], 1000); // 3 chunks
        let b = chunk_frame(2, 10, 10, true, &[2u8; 1000], 1000); // 1 chunk
        let mut r = FrameReassembler::new();
        assert!(r.push(&a[0]).is_none()); // partial frame 1
        let f = r.push(&b[0]).expect("frame 2 completes"); // frame 2 arrives whole
        assert_eq!(f.seq, 2);
        assert_eq!(f.data, vec![2u8; 1000]);
    }

    /// A rotation mid-stream. Untested until 2026-08-26, when Windows Round 2
    /// left "the client never received the new geometry" and "it received it
    /// and failed to render it" indistinguishable — this is the reassembler's
    /// half of that question.
    #[test]
    fn a_geometry_change_mid_stream_is_reported_from_the_new_header() {
        let land = chunk_frame(1, 1440, 900, true, &[1u8; 500], 1000);
        let port = chunk_frame(2, 900, 1440, true, &[2u8; 500], 1000);
        let back = chunk_frame(3, 1440, 900, true, &[3u8; 500], 1000);
        let mut r = FrameReassembler::new();

        let a = r.push(&land[0]).expect("landscape completes");
        assert_eq!((a.width, a.height), (1440, 900));

        let b = r.push(&port[0]).expect("the turn completes");
        assert_eq!(
            (b.width, b.height),
            (900, 1440),
            "the turn must be reported"
        );

        let c = r.push(&back[0]).expect("the revert completes");
        assert_eq!(
            (c.width, c.height),
            (1440, 900),
            "the revert must be reported too — F2 is the revert failing"
        );
    }

    /// The dangerous case: a partial frame of the OLD geometry is still
    /// accumulating when the first frame of the NEW geometry arrives. The
    /// abandoned frame's dimensions must not leak into it, or the client would
    /// render a portrait desktop at landscape dimensions.
    #[test]
    fn a_partial_old_frame_cannot_leak_its_geometry_into_the_new_one() {
        let old = chunk_frame(1, 1440, 900, true, &[1u8; 3000], 1000); // 3 chunks
        let new = chunk_frame(2, 900, 1440, true, &[2u8; 1000], 1000); // 1 chunk
        let mut r = FrameReassembler::new();

        assert!(
            r.push(&old[0]).is_none(),
            "landscape frame is still partial"
        );
        let f = r.push(&new[0]).expect("the portrait frame completes");

        assert_eq!(f.seq, 2);
        assert_eq!(
            (f.width, f.height),
            (900, 1440),
            "geometry must come from the frame being delivered, not the one abandoned"
        );
        assert_eq!(
            f.data,
            vec![2u8; 1000],
            "and none of the old payload may survive"
        );
    }

    #[test]
    fn non_stream_message_ignored() {
        let mut r = FrameReassembler::new();
        assert!(r.push(b"{\"type\":\"pong\"}").is_none());
    }
}

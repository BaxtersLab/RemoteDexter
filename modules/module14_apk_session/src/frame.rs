/// One inbound video frame, carrying everything the wire format supplied.
///
/// The stream chunks the host sends already describe each frame's sequence
/// number, pixel size and keyframe flag (`stream_chunk::ReassembledFrame`).
/// This type used to hold only `{timestamp, data}`, so all of that was
/// discarded one line before the queue and the viewer would have had to be
/// handed invented constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameEnvelope {
    /// Receipt time, in **microseconds** since the epoch.
    ///
    /// Microseconds, not milliseconds: the engine paces frames against
    /// `frame_interval_hint`, which is 16_000 for a 16 ms interval.
    pub timestamp: u64,
    /// Frame sequence number as sent by the host.
    pub sequence: u32,
    pub width: u16,
    pub height: u16,
    pub keyframe: bool,
    /// The encoded frame — JPEG bytes on the current stream path.
    pub data: Vec<u8>,
}

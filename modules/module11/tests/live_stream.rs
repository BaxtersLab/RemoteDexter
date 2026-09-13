//! Hardware-gated live streaming proof.
//!
//! Runs only when `RD_USE_HW=1`. Drives the `StreamPump` against the real
//! screen for several frames, sends the wire chunks through a `FrameReassembler`
//! (as the client would), decodes each reassembled JPEG, and writes one to the
//! temp dir for visual confirmation — proof the full capture→encode→chunk→
//! reassemble→decode path works end to end with a size-limited transport.

use module11::chunk::FrameReassembler;
use module11::stream_pump::StreamPump;

#[test]
fn live_stream_pipeline_produces_decodable_frames() {
    if std::env::var("RD_USE_HW").as_deref() != Ok("1") {
        eprintln!("skipping live_stream_pipeline (set RD_USE_HW=1)");
        return;
    }

    // Small per-chunk budget so a 1080p JPEG must span many chunks — exercises
    // real fragmentation/reassembly.
    let mut pump = StreamPump::new(75, 8000);
    assert!(pump.is_real(), "no real screen capture");
    let (w, h) = pump.dimensions();
    eprintln!("streaming {w}x{h}");

    let mut reassembler = FrameReassembler::new();
    let mut decoded = 0usize;
    let mut total_chunks = 0usize;
    let mut last_bytes = 0usize;
    let mut saved = false;

    // Up to ~20 ticks; force a keyframe each tick so a static screen still
    // yields a real frame every time (no waiting on screen changes).
    for tick in 0..20 {
        pump.request_keyframe();
        let chunks = pump.next_frame_chunks().expect("pump");
        if chunks.is_empty() {
            continue;
        }
        total_chunks += chunks.len();
        for c in &chunks {
            if let Some(frame) = reassembler.push(c) {
                let img = image::load_from_memory(&frame.data)
                    .expect("reassembled frame is a valid JPEG");
                assert_eq!((img.width(), img.height()), (w, h));
                last_bytes = frame.data.len();
                decoded += 1;

                if !saved {
                    let out = std::env::temp_dir().join("rd_live_stream_frame.jpg");
                    std::fs::write(&out, &frame.data).expect("write jpg");
                    eprintln!("wrote proof frame: {} ({} bytes)", out.display(), frame.data.len());
                    saved = true;
                }
            }
        }
        if decoded >= 5 {
            eprintln!("decoded {decoded} frames by tick {tick}");
            break;
        }
    }

    eprintln!(
        "decoded={decoded} total_chunks={total_chunks} last_frame_bytes={last_bytes}"
    );
    assert!(decoded >= 5, "expected >=5 decoded frames, got {decoded}");
    assert!(total_chunks > decoded, "frames should span multiple chunks");
    assert!(last_bytes > 2000, "a real 1080p JPEG should be > 2KB");
}

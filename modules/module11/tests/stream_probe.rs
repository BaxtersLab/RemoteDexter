//! Sustained-capture probe: 90 frames at ~30fps off a live portal session.
use module11::capture::ScreenCapturer;
use std::time::{Duration, Instant};

#[test]
fn portal_capture_sustains_a_stream() {
    if std::env::var("RD_USE_HW").as_deref() != Ok("1") { return; }
    let mut cap = ScreenCapturer::new(1920, 1080);
    assert!(cap.is_real(), "portal backend not active");
    let (w, h) = cap.dimensions();
    let mut fresh = 0usize;
    let mut reemit = 0usize;
    let mut last: Option<Vec<u8>> = None;
    let start = Instant::now();
    for _ in 0..90 {
        let t = Instant::now();
        let f = cap.capture().expect("capture");
        assert_eq!(f.data.len(), (w*h*4) as usize, "frame size drifted");
        match &last { Some(p) if *p == f.data => reemit += 1, _ => fresh += 1 }
        last = Some(f.data);
        let el = t.elapsed();
        if el < Duration::from_millis(33) { std::thread::sleep(Duration::from_millis(33) - el); }
    }
    let secs = start.elapsed().as_secs_f64();
    eprintln!("90 frames in {secs:.2}s ({:.1} fps) — {fresh} fresh, {reemit} re-emitted", 90.0/secs);
    assert!(fresh > 0, "stream produced no fresh frames at all");
}

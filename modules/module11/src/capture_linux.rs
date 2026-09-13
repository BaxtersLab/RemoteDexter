//! Linux screen capture: xdg-desktop-portal ScreenCast -> PipeWire -> GStreamer.
//!
//! This is the Wayland-native counterpart to the Windows DXGI backend in
//! `capture::dxgi`. It is deliberately the *same* mechanism OBS uses to share a
//! GNOME/Wayland desktop, and the same one the sibling SOC Ultralight suite was
//! proven on end-to-end on this hardware (Ubuntu 26.04 / GNOME 50 / Wayland).
//!
//! **Why not X11 / XGetImage / XShm.** Under a native Wayland session the X11
//! root window contains nothing — a capture off it comes back solid black, with
//! no error. Measured on this box: mean 0.00, stdev 0.00. There is no Xorg
//! fallback to chase either; the compositor never draws the desktop into an X
//! drawable. The portal is not a workaround, it is the only sanctioned path.
//!
//! **Session lifetime.** A portal session dies with the D-Bus connection that
//! created it, so the connection is owned by a dedicated thread that outlives
//! the handshake and is only torn down in `Drop`. The handshake also costs real
//! time (~100 ms), so it happens once and the stream is held open across frames
//! — the same shape as holding a DXGI duplication handle.
//!
//! **The first run shows GNOME's screen-share picker.** `persist_mode = 2`
//! makes the portal hand back a restore token, which is cached at
//! `$XDG_CACHE_HOME/remotedexter/screencast_restore_token`; every later run
//! reconnects silently.

use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;
use gstreamer_video as gst_video;
use gstreamer_video::prelude::*;

use crate::types::RawFrame;

/// How long to wait for the very first frame before declaring the backend
/// unusable. Generous: it covers the portal dialog being approved on a first
/// run, format negotiation, and a desktop that is not repainting.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the portal handshake may take before the host gives up.
///
/// A FIRST grant is a person reading a dialog and pressing a button, so this
/// cannot be short. A reconnect carrying the cached restore token answers in
/// milliseconds, so the bound is only ever reached when something is wrong —
/// which, before it existed, meant hanging forever.
const PORTAL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long dropping a capture waits for the portal session to actually close.
///
/// Short: this runs on the capture path, and the only reason to wait at all is
/// so a rebuild does not race the previous teardown. A portal that will not
/// acknowledge must not be able to wedge the host.
const PORTAL_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Extra buffers pulled at startup. PipeWire's early buffers can be blank while
/// the format is still negotiating, so later ones overwrite earlier ones.
const WARMUP_FRAMES: usize = 4;

/// Bound on how many queued buffers a single non-forced capture will drain to
/// reach the newest one.
const MAX_DRAIN: usize = 30;

/// Portal-side handshake results, handed back from the connection thread.
struct PortalStream {
    node_id: u32,
    fd: OwnedFd,
    size: Option<(i32, i32)>,
}

/// Holds the portal session open. Dropping it closes the session.
///
/// No thread of its own any more — see [`portal_runtime`]. It carries a
/// shutdown signal and a bounded acknowledgement, so a caller still knows the
/// old session is gone before opening a new one, without being able to hang
/// waiting for it.
struct PortalConnection {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    closed: Option<mpsc::Receiver<()>>,
}

impl Drop for PortalConnection {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Wait for the close to actually happen, so a capture rebuilt straight
        // after this one does not race the old session's teardown — but only
        // for a bounded time. The unbounded version of this idea is what hung a
        // host for ten minutes.
        if let Some(rx) = self.closed.take() {
            let _ = rx.recv_timeout(PORTAL_CLOSE_TIMEOUT);
        }
    }
}

/// The one runtime every portal session runs on, for the life of the process.
///
/// # The defect this exists for
///
/// Each capture session used to build its own `current_thread` runtime on its
/// own thread, and destroy both when the session closed. `ashpd` caches the
/// D-Bus connection it opens in a **process-global**, and that connection's
/// executor was running on the destroyed runtime — so the cache went on handing
/// out a connection that nobody was polling.
///
/// The result: the FIRST screen-share acquisition in a process worked, and
/// every later one hung forever. The method call went out, the reply was never
/// processed, and there was no dialog, no error and no timeout. Restarting the
/// host "fixed" it, because a fresh process meant a fresh cache.
///
/// Measured on 2026-08-29: Start, connect, stream, Stop, Start, connect —
/// black screen, with the host's last line "opening a portal". A retry failed
/// identically, which is what ruled out a race and pointed here: poisoning that
/// survives every later attempt is a cached object, not a timing window.
///
/// One worker thread, never shut down, so the cached connection is polled for
/// as long as the process lives.
fn portal_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RT: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("rd-portal")
            .enable_all()
            .build()
            .ok()
    })
    .as_ref()
    .ok_or_else(|| "could not start the portal runtime".to_string())
}

/// Persistent portal + PipeWire capturer for the whole desktop.
pub struct PortalCapturer {
    // Field order is the drop order, and it matters:
    //   pipeline (stops reading the fd) -> fd -> portal connection.
    // Closing the fd or the session while pipewiresrc still holds it is a use
    // after close.
    pipeline: gst::Pipeline,
    appsink: gst_app::AppSink,
    _fd: OwnedFd,
    _connection: PortalConnection,
    width: u32,
    height: u32,
}

impl PortalCapturer {
    /// Run the portal handshake, start the stream, and prove it produces a
    /// frame. Returns `Err` rather than a silently-empty capturer — a backend
    /// that reports success and then delivers black frames is the exact failure
    /// this whole module exists to avoid.
    pub fn new() -> Result<Self, String> {
        if std::env::var("RD_NO_PORTAL").as_deref() == Ok("1") {
            return Err("RD_NO_PORTAL=1 set".into());
        }
        if std::env::var_os("WAYLAND_DISPLAY").is_none()
            && std::env::var_os("DISPLAY").is_none()
        {
            return Err("no graphical session (WAYLAND_DISPLAY and DISPLAY both unset)".into());
        }

        let (stream, connection) = start_portal_session()?;

        gst::init().map_err(|e| format!("gst::init: {e}"))?;

        // drop=true is not a tuning knob. With drop=false the appsink queue
        // fills, back-pressures, and PipeWire STOPS PRODUCING: the stream
        // delivers one burst and then freezes forever. Measured in the sibling
        // suite as two captures either side of a window move coming back 0.0%
        // different.
        let desc = format!(
            "pipewiresrc fd={fd} path={node} ! videoconvert ! video/x-raw,format=RGBA ! \
             appsink name=sink max-buffers=4 drop=true sync=false",
            fd = stream.fd.as_raw_fd(),
            node = stream.node_id,
        );

        let element =
            gst::parse::launch(&desc).map_err(|e| format!("gst parse ({desc}): {e}"))?;
        let pipeline = element
            .downcast::<gst::Pipeline>()
            .map_err(|_| "parsed element is not a pipeline".to_string())?;
        let appsink = pipeline
            .by_name("sink")
            .ok_or_else(|| "pipeline has no element named 'sink'".to_string())?
            .downcast::<gst_app::AppSink>()
            .map_err(|_| "'sink' is not an appsink".to_string())?;

        pipeline
            .set_state(gst::State::Playing)
            .map_err(|e| format!("set pipeline PLAYING: {e}"))?;

        let (fallback_w, fallback_h) = stream
            .size
            .map(|(w, h)| (w.max(0) as u32, h.max(0) as u32))
            .unwrap_or((0, 0));

        let mut cap = Self {
            pipeline,
            appsink,
            _fd: stream.fd,
            _connection: connection,
            width: fallback_w,
            height: fallback_h,
        };

        // Warm up. The first frame is mandatory — it is what proves the stream
        // is live, and its caps are the authoritative frame size (the portal's
        // advertised size can be the logical, pre-scaling one).
        let first = cap
            .pull_frame(FIRST_FRAME_TIMEOUT)
            .ok_or_else(|| {
                format!(
                    "portal session started (node {}) but no frame arrived within {:?} — \
                     the grant may have been cancelled or the stream revoked",
                    stream.node_id, FIRST_FRAME_TIMEOUT
                )
            })?;
        cap.width = first.width;
        cap.height = first.height;
        for _ in 0..WARMUP_FRAMES {
            if let Some(f) = cap.pull_frame(Duration::from_millis(300)) {
                cap.width = f.width;
                cap.height = f.height;
            }
        }

        eprintln!(
            "[module11] portal capture live: node={} {}x{}",
            stream.node_id, cap.width, cap.height
        );
        Ok(cap)
    }

    /// Has the stream actually died, as opposed to merely gone quiet?
    ///
    /// This is the distinction the capture layer could not previously make. A
    /// missing buffer is ambiguous — a damage-driven stream produces nothing
    /// over a still desktop — but end-of-stream and a bus error are not.
    /// GNOME destroys the PipeWire node when the display mode changes, and
    /// this is how that becomes an error instead of a frozen picture.
    pub fn stream_ended(&self) -> Option<String> {
        if self.appsink.is_eos() {
            return Some("end of stream".to_string());
        }
        let bus = self.pipeline.bus()?;
        while let Some(msg) = bus.pop() {
            match msg.view() {
                gst::MessageView::Eos(_) => return Some("end of stream".to_string()),
                gst::MessageView::Error(e) => {
                    return Some(format!("{} ({})", e.error(), e.debug().unwrap_or_default()))
                }
                _ => {}
            }
        }
        None
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Grab one frame.
    ///
    /// Returns `Ok(None)` when nothing new has arrived since the last call —
    /// exactly the meaning DXGI's wait-timeout carries, so the caller re-emits
    /// its previous frame. That is not an error: a PipeWire screencast stream
    /// is **damage-driven**, and a desktop that has not repainted genuinely
    /// produces no buffers while still looking exactly like its last frame.
    ///
    /// `force` waits properly for a fresh frame instead of giving up, for the
    /// keyframe path where a stale frame is not acceptable.
    pub fn capture_rgba(&mut self, force: bool) -> Result<Option<RawFrame>, String> {
        // Drain whatever is queued so we act on the NEWEST frame, not the
        // oldest. A zero timeout only reports what is already waiting.
        let mut newest = None;
        for _ in 0..MAX_DRAIN {
            match self.pull_frame(Duration::ZERO) {
                Some(f) => newest = Some(f),
                None => break,
            }
        }
        if newest.is_none() && force {
            newest = self.pull_frame(Duration::from_secs(2));
        }
        if let Some(f) = &newest {
            self.width = f.width;
            self.height = f.height;
        }
        Ok(newest)
    }

    fn pull_frame(&self, timeout: Duration) -> Option<RawFrame> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let clock = gst::ClockTime::from_nseconds(remaining.as_nanos() as u64);
            let sample = self.appsink.try_pull_sample(clock)?;
            match sample_to_frame(&sample) {
                Ok(frame) => return Some(frame),
                Err(e) => {
                    // A malformed sample is worth saying out loud rather than
                    // silently returning "no frame", which reads as a static
                    // desktop and hides a real fault.
                    eprintln!("[module11] dropping unusable sample: {e}");
                    if Instant::now() >= deadline {
                        return None;
                    }
                }
            }
        }
    }
}

impl Drop for PortalCapturer {
    fn drop(&mut self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

/// Copy one GStreamer sample into a tightly-packed RGBA `RawFrame`.
///
/// The copy is per row because GStreamer pads rows to its own stride, which is
/// not necessarily `width * 4`. Reading `width * height * 4` bytes straight out
/// of the mapped buffer produces a picture that shears progressively down the
/// frame — the classic version of this bug.
fn sample_to_frame(sample: &gst::Sample) -> Result<RawFrame, String> {
    let caps = sample.caps().ok_or("sample carries no caps")?;
    let info =
        gst_video::VideoInfo::from_caps(caps).map_err(|e| format!("VideoInfo::from_caps: {e}"))?;
    let buffer = sample.buffer().ok_or("sample carries no buffer")?;
    let frame = gst_video::VideoFrameRef::from_buffer_ref_readable(buffer, &info)
        .map_err(|e| format!("map video frame: {e}"))?;

    let w = frame.width() as usize;
    let h = frame.height() as usize;
    if w == 0 || h == 0 {
        return Err(format!("degenerate frame size {w}x{h}"));
    }
    let stride = frame.plane_stride()[0] as usize;
    let src = frame
        .plane_data(0)
        .map_err(|e| format!("plane_data(0): {e}"))?;
    let row = w * 4;
    if stride < row {
        return Err(format!("stride {stride} shorter than a {row}-byte row"));
    }

    let mut data = vec![0u8; row * h];
    for y in 0..h {
        let s = y * stride;
        if s + row > src.len() {
            return Err(format!(
                "buffer is {} bytes, short of row {y} at offset {}",
                src.len(),
                s + row
            ));
        }
        data[y * row..(y + 1) * row].copy_from_slice(&src[s..s + row]);
    }

    Ok(RawFrame {
        data,
        width: w as u32,
        height: h as u32,
    })
}

/// Where the ScreenCast restore token is cached. Its presence is what makes
/// every run after the first one silent.
fn restore_token_path() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("remotedexter").join("screencast_restore_token")
}

fn read_restore_token() -> Option<String> {
    let s = std::fs::read_to_string(restore_token_path()).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn write_restore_token(token: &str) {
    let path = restore_token_path();
    let Some(dir) = path.parent() else { return };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    // 0600: the token is a standing grant to capture this desktop.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(&path) {
        let _ = f.write_all(token.as_bytes());
    }
}

/// Cursor handling. A remote-desktop viewer needs to see the pointer, so the
/// cursor is composited into the stream by default — the opposite of the
/// sibling OCR automation, which hides it because it occludes the very targets
/// it is looking for. `RD_CAPTURE_CURSOR=hidden` selects that behaviour.
fn cursor_mode() -> ashpd::desktop::screencast::CursorMode {
    use ashpd::desktop::screencast::CursorMode;
    match std::env::var("RD_CAPTURE_CURSOR").as_deref() {
        Ok("hidden") => CursorMode::Hidden,
        Ok("metadata") => CursorMode::Metadata,
        _ => CursorMode::Embedded,
    }
}

/// Run the ScreenCast handshake on a dedicated thread and keep that thread —
/// and therefore the D-Bus connection and the portal session — alive until the
/// returned `PortalConnection` is dropped.
fn start_portal_session() -> Result<(PortalStream, PortalConnection), String> {
    let (ready_tx, ready_rx) = mpsc::channel::<Result<PortalStream, String>>();
    let (closed_tx, closed_rx) = mpsc::channel::<()>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawned on the PROCESS-LIFETIME runtime, not a per-session one. See
    // `portal_runtime` for why that distinction is the whole bug.
    portal_runtime()?.spawn(async move {
        match handshake().await {
            Ok((session, stream)) => {
                if ready_tx.send(Ok(stream)).is_err() {
                    let _ = session.close().await;
                    let _ = closed_tx.send(());
                    return;
                }
                // Park here holding the session open. The portal tears it down
                // when this task closes it below.
                let _ = shutdown_rx.await;
                let _ = session.close().await;
                let _ = closed_tx.send(());
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                let _ = closed_tx.send(());
            }
        }
    });

    // BOUNDED. This was `recv()` with no timeout, and on 2026-08-29 that hung a
    // host forever: the SECOND ScreenCast session in one process was never
    // answered by the portal, so this call parked — holding the capture slot
    // lock — and the client sat on a black screen while the host's last line
    // was "opening a portal". Nothing timed out, nothing logged, nothing failed.
    //
    // A host that waits forever is worse than one that gives up and says so:
    // the give-up is visible, is reported to the client, and lets the next
    // attempt happen after the rebuild backoff.
    //
    // The bound is generous because a FIRST grant is a human pressing a button
    // in the portal dialog. A reconnect carrying a restore token answers in
    // milliseconds, so this only ever elapses when something is genuinely wrong.
    let stream = match ready_rx.recv_timeout(PORTAL_HANDSHAKE_TIMEOUT) {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // The task is left on the shared runtime rather than waited for:
            // it is parked inside the handshake, and waiting here would inherit
            // exactly the hang this timeout exists to escape.
            return Err(format!(
                "the desktop portal did not answer within {PORTAL_HANDSHAKE_TIMEOUT:?} — \
                 no screen-share session was established"
            ));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err("the portal task ended without answering".into());
        }
    };

    Ok((
        stream,
        PortalConnection {
            shutdown: Some(shutdown_tx),
            closed: Some(closed_rx),
        },
    ))
}

async fn handshake() -> Result<
    (
        ashpd::desktop::Session<ashpd::desktop::screencast::Screencast>,
        PortalStream,
    ),
    String,
> {
    use ashpd::desktop::screencast::{
        Screencast, SelectSourcesOptions, SourceType, StartCastOptions,
    };
    use ashpd::desktop::{CreateSessionOptions, PersistMode};

    let proxy = Screencast::new()
        .await
        .map_err(|e| format!("connect to ScreenCast portal: {e}"))?;
    let session = proxy
        .create_session(CreateSessionOptions::default())
        .await
        .map_err(|e| format!("ScreenCast.CreateSession: {e}"))?;

    // The restore token encodes WHAT WAS PREVIOUSLY GRANTED. Feeding back a
    // token that was issued for a different source type makes the portal
    // silently restore the old grant and ignore the types asked for here.
    let restore = read_restore_token();
    let mut opts = SelectSourcesOptions::default()
        .set_multiple(false)
        .set_cursor_mode(cursor_mode())
        .set_sources(ashpd::enumflags2::BitFlags::from(SourceType::Monitor))
        .set_persist_mode(PersistMode::ExplicitlyRevoked);
    if let Some(tok) = restore.as_deref() {
        opts = opts.set_restore_token(tok);
    }
    proxy
        .select_sources(&session, opts)
        .await
        .map_err(|e| format!("ScreenCast.SelectSources: {e}"))?
        .response()
        .map_err(|e| format!("SelectSources refused: {e}"))?;

    let streams = proxy
        .start(&session, None, StartCastOptions::default())
        .await
        .map_err(|e| format!("ScreenCast.Start: {e}"))?
        .response()
        .map_err(|e| {
            format!("screen share was not granted ({e}) — the portal dialog may have been dismissed")
        })?;

    if let Some(tok) = streams.restore_token() {
        write_restore_token(tok);
    }

    let stream = streams
        .streams()
        .first()
        .ok_or_else(|| "ScreenCast.Start returned no streams".to_string())?;
    let node_id = stream.pipe_wire_node_id();
    let size = stream.size();

    let fd = proxy
        .open_pipe_wire_remote(&session, Default::default())
        .await
        .map_err(|e| format!("ScreenCast.OpenPipeWireRemote: {e}"))?;

    Ok((session, PortalStream { node_id, fd, size }))
}

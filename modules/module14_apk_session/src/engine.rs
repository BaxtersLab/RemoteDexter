// greenlight: no allow band-aids
use crate::state::APKSessionState;
use crate::commands::{APKSessionCommand, APKSessionConfig, NegotiationRequest};
use crate::events::APKSessionEvent;
use crate::codec::encode_negotiation_request;
use crate::frame::FrameEnvelope;
use crate::media::{MediaStreamKind, MediaControl, MediaFrame};
use module13_transport::TransportEngine;
use module13_transport::envelope::{Envelope, tags};
use bytes::Bytes;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::VecDeque;
use std::sync::Arc;

/// The inbound video queue's hard bound. Public because the client's delivery
/// tests assert against the real bound rather than a repeated literal.
pub const MAX_FRAMES: usize = 32;

const MIC_SAMPLE_RATE: u32 = 16000; // 16kHz
const MIC_FRAME_DURATION_MS: u64 = 20; // 20ms frames
const MIC_BYTES_PER_FRAME: usize = (MIC_SAMPLE_RATE as u64 * MIC_FRAME_DURATION_MS * 2 / 1000) as usize; // 16-bit = 2 bytes/sample

const CAMERA_MAX_PAYLOAD: usize = 256 * 1024; // 256KB cap

pub struct APKSessionEngine {
    state: APKSessionState,
    transport: Option<TransportEngine>,
    config: Option<APKSessionConfig>,
    /// Whether the transport is currently up. A transport fact only — see
    /// `frame_receiver_registered` for the viewer.
    connected: bool,
    /// Whether a Kotlin `FrameReceiver` is attached and wants frames.
    ///
    /// Deliberately separate from `connected`: a viewer attaching does not
    /// create a transport, and a transport dropping does not detach the viewer.
    /// These two facts shared one Boolean before Phase 3.
    frame_receiver_registered: bool,
    /// Whether the Android service has initialised and not yet shut down.
    /// Owns the decision of whether a (re)connect may reopen the frame path.
    service_running: bool,
    negotiated: bool,
    frame_queue: Vec<FrameEnvelope>,
    last_frame_time: Option<u64>,
    frame_interval_hint: u64,
    backpressure_active: bool,
    standby_active: bool,
    _last_active_timestamp: u64,
    wake_pending: bool,
    last_transport_event: u64,
    resume_possible: bool,
    camera_active: bool,
    mic_active: bool,
    mic_buffer: Vec<u8>,
    mic_buffer_timestamp: Option<u64>,
    media_out_queue: VecDeque<MediaFrame>,
    camera_skip_counter: u32,
    camera_skip_rate: u32,
    prev_backpressure_active: bool,
    /// `Arc`, not `Box`, so a caller can clone it out from under the engine's
    /// lock and invoke it unlocked — see [`agent2_callback`](Self::agent2_callback).
    agent2_callback: Option<Arc<dyn Fn(&str) + Send + Sync>>,
}

impl APKSessionEngine {
    pub fn new() -> Self {
        Self {
            state: APKSessionState::Idle,
            transport: None,
            config: None,
            connected: false,
            frame_receiver_registered: false,
            service_running: false,
            negotiated: false,
            frame_queue: Vec::new(),
            last_frame_time: None,
            frame_interval_hint: 16_000, // 16ms placeholder
            backpressure_active: false,
            standby_active: false,
            _last_active_timestamp: 0,
            wake_pending: false,
            last_transport_event: 0,
            resume_possible: false,
            camera_active: false,
            mic_active: false,
            mic_buffer: Vec::new(),
            mic_buffer_timestamp: None,
            media_out_queue: VecDeque::new(),
            camera_skip_counter: 0,
            camera_skip_rate: 1,
            prev_backpressure_active: false,
            agent2_callback: None,
        }
    }

    pub fn state(&self) -> APKSessionState {
        self.state.clone()
    }

    pub fn handle_command(&mut self, cmd: APKSessionCommand) {
        match cmd {
            APKSessionCommand::Connect(config) => {
                if self.state != APKSessionState::Idle {
                    return;
                }
                self.config = Some(config);
                // Placeholder: create TransportEngine with buffer size
                let te = TransportEngine::new(1024);
                self.transport = Some(te);
                self.state = APKSessionState::Connecting;
            }
            APKSessionCommand::Disconnect => {
                self.transport.take();
                self.state = APKSessionState::Closed;
                self.clear_frames();
                self.resume_possible = false;
            }
            APKSessionCommand::SendNegotiationRequest => {
                if self.state == APKSessionState::Negotiating {
                    let req = NegotiationRequest { client_version: 1 };
                    let encoded = encode_negotiation_request(&req);
                    if let Some(t) = &mut self.transport {
                        let envelope = Envelope::new(tags::HEARTBEAT, encoded.into());
                        let _ = t.send_envelope(envelope);
                    }
                }
            }
            APKSessionCommand::RequestKeyframe => {
                if self.state == APKSessionState::Active {
                    if let Some(t) = &mut self.transport {
                        let envelope = module13_transport::envelope::ForceKeyframeEnvelope::new().encode();
                        let _ = t.send_envelope(envelope);
                    }
                }
            }
            APKSessionCommand::BackpressureNotice => {
                if self.state == APKSessionState::Active {
                    if let Some(t) = &mut self.transport {
                        // Placeholder: send backpressure update
                        let envelope = module13_transport::envelope::BackpressureUpdateEnvelope::new(1).encode(); // level 1
                        let _ = t.send_envelope(envelope);
                    }
                }
            }
            APKSessionCommand::EnterEcoStandby => {
                if self.state == APKSessionState::Active {
                    self.standby_active = true;
                    self.state = APKSessionState::EcoStandby;
                    self.clear_frames();
                    self.last_frame_time = None;
                    self.backpressure_active = false;
                    self.pause_media_streams();
                }
            }
            APKSessionCommand::ExitEcoStandby => {
                if self.state == APKSessionState::EcoStandby {
                    self.standby_active = false;
                    self.state = APKSessionState::Active;
                    self.last_frame_time = None;
                    self.backpressure_active = false;
                    self.wake_pending = false;
                    self.resume_media_streams();
                    // Send DeviceAwake to host (stub)
                }
            }
            APKSessionCommand::HostWakeRequest => {
                if self.state == APKSessionState::Active {
                    return;
                }
                if self.state == APKSessionState::EcoStandby {
                    self.wake_pending = true;
                    self.perform_wake();
                } else if self.state == APKSessionState::Suspended {
                    self.wake_pending = true;
                }
            }
            APKSessionCommand::DeviceAwake => {
                // Internal use only
            }
            _ => {}
        }
    }

    pub fn handle_event(&mut self, evt: APKSessionEvent) {
        match evt {
            APKSessionEvent::TransportConnected => {
                self.connected = true;
                match self.state {
                    // The negotiated path is unchanged.
                    APKSessionState::Connecting => self.state = APKSessionState::Negotiating,
                    // Reconnect. A disconnect closes the session and clears the
                    // queue, so without this a second connect would leave the
                    // engine `Closed` and silently drop every later frame. Only
                    // the service's own lifecycle may reopen it, so a connect
                    // after `shutdown()` does not resurrect a dead session.
                    APKSessionState::Closed | APKSessionState::Idle if self.service_running => {
                        self.state = APKSessionState::Active;
                        self.last_frame_time = None;
                        self.backpressure_active = false;
                    }
                    // Active, standby and suspended are left alone: a transport
                    // event must not yank the session out of a power state.
                    _ => {}
                }
            }
            APKSessionEvent::TransportDisconnected => {
                self.connected = false;
                self.state = APKSessionState::Closed;
                self.clear_frames();
                self.resume_possible = false;
            }
            APKSessionEvent::Fatal(_msg) => {
                self.connected = false;
                self.state = APKSessionState::Closed;
                self.clear_frames();
                self.resume_possible = false;
            }
            APKSessionEvent::NegotiationResponse(resp) => {
                if self.state == APKSessionState::Negotiating {
                    if resp.server_version == 1 {
                        self.state = APKSessionState::Active;
                        self.negotiated = true;
                        self.last_frame_time = None;
                        self.backpressure_active = false;
                        self.resume_possible = true;
                    } else {
                        self.state = APKSessionState::Closed;
                        self.clear_frames();
                        self.resume_possible = false;
                    }
                }
            }
            APKSessionEvent::InboundFrame(frame) => {
                if self.state == APKSessionState::Active {
                    if self.frame_queue.len() >= MAX_FRAMES {
                        self.frame_queue.remove(0); // drop oldest
                    }
                    self.frame_queue.push(frame);
                    if self.frame_queue.len() == MAX_FRAMES {
                        // Trigger backpressure
                        if let Some(t) = &mut self.transport {
                            let envelope = module13_transport::envelope::BackpressureUpdateEnvelope::new(1).encode();
                            let _ = t.send_envelope(envelope);
                        }
                        self.backpressure_active = true;
                    }
                }
            }
            APKSessionEvent::SystemSleep => {
                if self.state == APKSessionState::EcoStandby {
                    return;
                }
                if self.state == APKSessionState::Active || self.state == APKSessionState::EcoStandby {
                    if self.state == APKSessionState::EcoStandby {
                        self.state = APKSessionState::Suspended;
                        self.clear_frames();
                        self.last_frame_time = None;
                        self.backpressure_active = false;
                        // Transport may enter idle
                    } else {
                        self.standby_active = true;
                        self.state = APKSessionState::EcoStandby;
                        self.clear_frames();
                        self.last_frame_time = None;
                        self.backpressure_active = false;
                        self.pause_media_streams();
                    }
                }
            }
            APKSessionEvent::SystemWake => {
                if self.state == APKSessionState::Active {
                    return;
                }
                if self.state == APKSessionState::EcoStandby || self.state == APKSessionState::Suspended {
                    if self.state == APKSessionState::Suspended {
                        self.state = APKSessionState::EcoStandby;
                        self.resume_media_streams();
                    } else {
                        // Already in EcoStandby, wait for explicit exit
                    }
                    if self.wake_pending && self.state == APKSessionState::EcoStandby {
                        self.perform_wake();
                    }
                }
            }
            APKSessionEvent::TransportIdle => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                if now - self.last_transport_event < 500 {
                    return;
                }
                self.last_transport_event = now;
                // Update flags if needed
            }
            APKSessionEvent::TransportWake => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                if now - self.last_transport_event < 500 {
                    return;
                }
                self.last_transport_event = now;
                if self.state == APKSessionState::Suspended {
                    self.state = APKSessionState::EcoStandby;
                    self.resume_media_streams();
                    if self.wake_pending {
                        self.perform_wake();
                    }
                }
            }
            APKSessionEvent::InboundMediaControl(control) => {
                match control {
                    MediaControl::Start(kind) => {
                        if self.state == APKSessionState::Active {
                            match kind {
                                MediaStreamKind::Camera => {
                                    self.camera_active = true;
                                    self.start_camera_capture();
                                }
                                MediaStreamKind::Microphone => {
                                    self.mic_active = true;
                                    self.start_mic_capture();
                                }
                            }
                        }
                    }
                    MediaControl::Stop(kind) => {
                        match kind {
                            MediaStreamKind::Camera => {
                                self.camera_active = false;
                                self.stop_camera_capture();
                            }
                            MediaStreamKind::Microphone => {
                                self.mic_active = false;
                                self.stop_mic_capture();
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    pub fn take_next_frame(&mut self) -> Option<FrameEnvelope> {
        if self.state == APKSessionState::Active && !self.frame_queue.is_empty() {
            Some(self.frame_queue.remove(0))
        } else {
            None
        }
    }

    pub fn peek_next_frame(&self) -> Option<&FrameEnvelope> {
        if self.state == APKSessionState::Active {
            self.frame_queue.first()
        } else {
            None
        }
    }

    pub fn clear_frames(&mut self) {
        self.frame_queue.clear();
    }

    /// How many frames are waiting. The queue is bounded at [`MAX_FRAMES`];
    /// this exists so that bound can be asserted rather than assumed.
    pub fn queued_frame_count(&self) -> usize {
        self.frame_queue.len()
    }

    /// Take the newest queued frame for display, discarding any staler ones.
    ///
    /// This is the drain the viewer path uses. The queue exists to absorb
    /// bursts, and a stale JPEG is worthless once a newer one has arrived — so
    /// this is the same drop-oldest policy the queue already applies when it
    /// overflows, applied at drain time as well. Pacing and the backpressure
    /// recovery signal still run, in [`consume_frame`](Self::consume_frame).
    pub fn consume_latest_frame(&mut self) -> Option<FrameEnvelope> {
        if self.state != APKSessionState::Active {
            return None;
        }
        let stale = self.frame_queue.len().saturating_sub(1);
        if stale > 0 {
            self.frame_queue.drain(..stale);
        }
        self.consume_frame()
    }

    pub fn consume_frame(&mut self) -> Option<FrameEnvelope> {
        if self.state != APKSessionState::Active {
            return None;
        }
        let frame = self.take_next_frame()?;
        // Pacing logic
        if let Some(last) = self.last_frame_time {
            let delta = frame.timestamp.saturating_sub(last);
            if delta < self.frame_interval_hint / 2 {
                return None; // drop frame
            }
        }
        self.last_frame_time = Some(frame.timestamp);
        // Recovery logic
        if self.frame_queue.len() < MAX_FRAMES / 2 && self.backpressure_active {
            // Send RequestKeyframe directly
            if let Some(t) = &mut self.transport {
                let envelope = module13_transport::envelope::ForceKeyframeEnvelope::new().encode();
                let _ = t.send_envelope(envelope);
            }
            self.backpressure_active = false;
        }
        Some(frame)
    }

    fn pause_media_streams(&mut self) {
        // Stub for Block 2
        if self.camera_active {
            // pause camera
        }
        if self.mic_active {
            // pause mic
        }
    }

    fn resume_media_streams(&mut self) {
        // Stub for Block 2
        if self.camera_active {
            // resume camera
        }
        if self.mic_active {
            // resume mic
        }
    }

    fn perform_wake(&mut self) {
        self.state = APKSessionState::Active;
        self.last_frame_time = None;
        self.backpressure_active = false;
        self.resume_media_streams();
        // Send DeviceAwake { resumed: self.resume_possible }
        if let Some(_t) = &mut self.transport {
            // Placeholder: send DeviceAwakeEnvelope
            // Assume module13_transport::envelope::DeviceAwakeEnvelope::new(self.resume_possible).encode()
            // For now, stub
        }
        if self.resume_possible {
            // Send RequestKeyframe
            if let Some(t) = &mut self.transport {
                let envelope = module13_transport::envelope::ForceKeyframeEnvelope::new().encode();
                let _ = t.send_envelope(envelope);
            }
        }
        self.wake_pending = false;
    }

    fn start_camera_capture(&mut self) {
        // Stub
    }

    fn stop_camera_capture(&mut self) {
        // Stub
    }

    fn start_mic_capture(&mut self) {
        // Stub
    }

    fn stop_mic_capture(&mut self) {
        // Stub
    }

    fn send_media_frame(&mut self, _frame: MediaFrame) {
        // Wrap and enqueue a DataEnvelope::MediaFrame(frame)
        // Placeholder: assume module13_transport::envelope::DataEnvelope::MediaFrame exists
        if let Some(_t) = &mut self.transport {
            // Pseudocode: let env = DataEnvelope::MediaFrame(frame).encode();
            // let _ = t.send_envelope(env);
            // For now, stub
        }
    }

    pub fn on_camera_frame_captured(&mut self, data: Vec<u8>, timestamp: u64) {
        if !self.camera_active {
            return;
        }
        if data.len() > CAMERA_MAX_PAYLOAD {
            return; // drop frame
        }
        let frame = MediaFrame {
            kind: MediaStreamKind::Camera,
            timestamp,
            payload: data,
        };
        self.media_out_queue.push_back(frame);
    }

    pub fn on_mic_frame_captured(&mut self, data: Vec<u8>, timestamp: u64) {
        if !self.mic_active {
            return;
        }
        if self.mic_buffer.is_empty() {
            self.mic_buffer_timestamp = Some(timestamp);
        }
        self.mic_buffer.extend(data);
        while self.mic_buffer.len() >= MIC_BYTES_PER_FRAME {
            let frame_bytes: Vec<u8> = self.mic_buffer.drain(0..MIC_BYTES_PER_FRAME).collect();
            let frame_timestamp = self.mic_buffer_timestamp.unwrap();
            let frame = MediaFrame {
                kind: MediaStreamKind::Microphone,
                timestamp: frame_timestamp,
                payload: frame_bytes,
            };
            self.media_out_queue.push_back(frame);
            self.mic_buffer_timestamp = Some(frame_timestamp + MIC_FRAME_DURATION_MS * 1_000_000); // ns
        }
    }

    pub fn media_scheduler_tick(&mut self) {
        // Keyframe resync on recovery
        if !self.backpressure_active && self.prev_backpressure_active {
            // Send RequestKeyframe
            if let Some(t) = &mut self.transport {
                let envelope = module13_transport::envelope::ForceKeyframeEnvelope::new().encode();
                let _ = t.send_envelope(envelope);
            }
        }
        self.prev_backpressure_active = self.backpressure_active;

        // Thin camera frames if backpressure
        if self.backpressure_active {
            // Keep only the most recent camera frame
            let mut recent_camera = None;
            let mut new_queue = VecDeque::new();
            while let Some(frame) = self.media_out_queue.pop_front() {
                match frame.kind {
                    MediaStreamKind::Camera => {
                        recent_camera = Some(frame);
                    }
                    MediaStreamKind::Microphone => {
                        new_queue.push_back(frame);
                    }
                }
            }
            self.media_out_queue = new_queue;
            if let Some(frame) = recent_camera {
                self.media_out_queue.push_back(frame);
            }
        }

        // Drop oldest mic frames if queue too full (arbitrary limit)
        const MAX_QUEUE: usize = 100;
        while self.media_out_queue.len() > MAX_QUEUE {
            if let Some(frame) = self.media_out_queue.front() {
                if matches!(frame.kind, MediaStreamKind::Microphone) {
                    self.media_out_queue.pop_front();
                } else {
                    break; // don't drop camera
                }
            }
        }

        // Adaptive camera rate
        if self.backpressure_active {
            self.camera_skip_rate = 2; // send 1/2 frames
        } else {
            self.camera_skip_rate = 1; // full rate
        }

        // Send next frame if not backpressured
        if !self.backpressure_active {
            if let Some(frame) = self.media_out_queue.pop_front() {
                match frame.kind {
                    MediaStreamKind::Camera => {
                        self.camera_skip_counter += 1;
                        if self.camera_skip_counter >= self.camera_skip_rate {
                            self.send_media_frame(frame);
                            self.camera_skip_counter = 0;
                        }
                        // else drop
                    }
                    MediaStreamKind::Microphone => {
                        self.send_media_frame(frame);
                    }
                }
            }
        }
    }

    /// Service initialisation — called from `RDService.onCreate`.
    ///
    /// Pacing state is reset here so the first frame of a new session is not
    /// measured against the last frame of the previous one, which would drop it.
    pub fn init(&mut self) {
        self.service_running = true;
        self.state = APKSessionState::Active;
        self.last_frame_time = None;
        self.backpressure_active = false;
    }

    /// Service shutdown — called from `RDService.onDestroy`. After this no
    /// frame is queued or delivered until [`init`](Self::init) runs again; a
    /// transport reconnect alone will not restart it.
    pub fn shutdown(&mut self) {
        self.service_running = false;
        self.connected = false;
        self.state = APKSessionState::Idle;
        self.clear_frames();
        self.media_out_queue.clear();
    }

    pub fn on_clipboard_update(&mut self, data: &[u8]) {
        if let Some(transport) = &self.transport {
            let envelope = Envelope::new(tags::CLIPBOARD_UPDATE, Bytes::from(data.to_vec()));
            let _ = transport.send_envelope(envelope);
        }
    }

    pub fn request_screenshot(&mut self) {
        if let Some(transport) = &self.transport {
            let envelope = Envelope::new(tags::SCREENSHOT_REQUEST, Bytes::new());
            let _ = transport.send_envelope(envelope);
        }
    }

    pub fn on_camera_frame(&mut self, data: &[u8], timestamp: u64) {
        self.on_camera_frame_captured(data.to_vec(), timestamp);
    }

    pub fn on_mic_frame(&mut self, data: &[u8], timestamp: u64) {
        self.on_mic_frame_captured(data.to_vec(), timestamp);
    }

    /// Forward one Agent2 command to the registered callback.
    ///
    /// **Do not call this while holding a lock the callback might re-enter.**
    /// The registered callback crosses into Kotlin, and `Agent2Router.handle`
    /// calls straight back into native methods that lock the client's engine
    /// mutex. Use [`agent2_callback`](Self::agent2_callback) to take the
    /// callback out and invoke it unlocked instead.
    pub fn on_agent2_command(&mut self, json: &str) {
        if let Some(cb) = &self.agent2_callback {
            cb(json);
        }
    }

    /// The registered Agent2 callback, cloned so it can be invoked *after* the
    /// engine's lock is released. This is how the client dispatches: holding the
    /// lock across the call into Kotlin is a deadlock, because the Kotlin router
    /// re-enters native methods that take the same non-reentrant mutex.
    pub fn agent2_callback(&self) -> Option<Arc<dyn Fn(&str) + Send + Sync>> {
        self.agent2_callback.clone()
    }

    /// Register a callback that will be invoked when an Agent2 command
    /// arrives from the host.  The cdylib JNI layer uses this to forward
    /// JSON payloads to the Kotlin side.
    pub fn set_agent2_callback<F: Fn(&str) + Send + Sync + 'static>(&mut self, cb: F) {
        self.agent2_callback = Some(Arc::new(cb));
    }

    /// Attach or detach the Kotlin `FrameReceiver`.
    ///
    /// Only whether a viewer wants frames. It is not a transport fact and must
    /// not be confused with one: frames keep arriving and keep being queued (up
    /// to [`MAX_FRAMES`], drop-oldest) while no viewer is attached, and the
    /// delivery path simply does not push them at Kotlin.
    pub fn set_frame_receiver_registered(&mut self, registered: bool) {
        self.frame_receiver_registered = registered;
    }

    /// Whether a Kotlin `FrameReceiver` is attached.
    pub fn is_frame_receiver_registered(&self) -> bool {
        self.frame_receiver_registered
    }

    /// Whether the transport is up. Independent of the viewer.
    pub fn is_transport_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame carrying the metadata the wire format actually supplies.
    fn frame(sequence: u32, timestamp_us: u64) -> FrameEnvelope {
        FrameEnvelope {
            timestamp: timestamp_us,
            sequence,
            width: 1920,
            height: 1080,
            keyframe: sequence == 1,
            data: vec![0xFF, 0xD8, sequence as u8],
        }
    }

    /// A service that has initialised and whose transport is up.
    fn active_engine() -> APKSessionEngine {
        let mut e = APKSessionEngine::new();
        e.init();
        e
    }

    /// Receiver registration and transport connection are different facts.
    /// They shared one Boolean before this phase, so attaching a viewer claimed
    /// a transport and a dropped transport unregistered the viewer.
    #[test]
    fn frame_receiver_registration_is_independent_of_transport_state() {
        let mut e = APKSessionEngine::new();
        assert!(!e.is_frame_receiver_registered());
        assert!(!e.is_transport_connected());

        e.set_frame_receiver_registered(true);
        assert!(e.is_frame_receiver_registered());
        assert!(
            !e.is_transport_connected(),
            "attaching a viewer must not claim a transport connection"
        );

        e.handle_event(APKSessionEvent::TransportConnected);
        assert!(e.is_transport_connected());
        assert!(e.is_frame_receiver_registered());

        e.handle_event(APKSessionEvent::TransportDisconnected);
        assert!(!e.is_transport_connected());
        assert!(
            e.is_frame_receiver_registered(),
            "a dropped transport must not unregister the viewer"
        );

        e.set_frame_receiver_registered(false);
        assert!(!e.is_frame_receiver_registered());
        assert!(!e.is_transport_connected());
    }

    /// The wire metadata must survive the queue untouched — no constants.
    #[test]
    fn the_queue_preserves_every_frame_field() {
        let mut e = active_engine();
        e.handle_event(APKSessionEvent::InboundFrame(FrameEnvelope {
            timestamp: 42,
            sequence: 7,
            width: 1280,
            height: 720,
            keyframe: true,
            data: vec![1, 2, 3],
        }));
        let f = e.consume_latest_frame().expect("a frame was queued");
        assert_eq!(f.timestamp, 42);
        assert_eq!(f.sequence, 7);
        assert_eq!((f.width, f.height), (1280, 720));
        assert!(f.keyframe);
        assert_eq!(f.data, vec![1, 2, 3]);
    }

    /// No viewer attached: frames must stay inside the existing bounded queue
    /// and never accumulate waiting for a UI that may never arrive.
    #[test]
    fn frames_stay_bounded_when_nothing_consumes_them() {
        let mut e = active_engine();
        for i in 0..(MAX_FRAMES as u32 * 4) {
            e.handle_event(APKSessionEvent::InboundFrame(frame(i, i as u64 * 33_000)));
        }
        assert!(!e.is_frame_receiver_registered());
        assert_eq!(
            e.queued_frame_count(),
            MAX_FRAMES,
            "the queue must stay at its bound, not grow"
        );
    }

    /// Drop-oldest: under overload the newest frame is the survivor.
    #[test]
    fn overflow_drops_the_oldest_frames() {
        let mut e = active_engine();
        let total = MAX_FRAMES as u32 * 2;
        for i in 0..total {
            e.handle_event(APKSessionEvent::InboundFrame(frame(i, i as u64 * 33_000)));
        }
        let f = e.consume_latest_frame().expect("a frame survived");
        assert_eq!(
            f.sequence,
            total - 1,
            "the newest frame must survive an overflow"
        );
    }

    /// A viewer wants the current picture. Staler queued frames are discarded
    /// at drain time — the same drop-oldest policy the queue applies at push.
    #[test]
    fn consuming_takes_the_newest_frame_and_discards_staler_ones() {
        let mut e = active_engine();
        for i in 1..=5u32 {
            e.handle_event(APKSessionEvent::InboundFrame(frame(i, i as u64 * 100_000)));
        }
        assert_eq!(e.queued_frame_count(), 5);
        let f = e.consume_latest_frame().expect("newest frame");
        assert_eq!(f.sequence, 5);
        assert_eq!(
            e.queued_frame_count(),
            0,
            "staler frames must be discarded, not left to age in the queue"
        );
    }

    /// `frame_interval_hint` is 16_000 for 16 ms, so frame timestamps are
    /// **microseconds**. Stamping milliseconds would put the pacing threshold at
    /// 8 seconds and the viewer would show one frame every 8 s.
    #[test]
    fn thirty_fps_frames_are_not_paced_out() {
        let mut e = active_engine();
        e.handle_event(APKSessionEvent::InboundFrame(frame(1, 1_000_000)));
        assert!(e.consume_latest_frame().is_some(), "first frame");
        e.handle_event(APKSessionEvent::InboundFrame(frame(2, 1_033_000)));
        assert!(
            e.consume_latest_frame().is_some(),
            "a frame 33 ms later is 30 fps and must not be paced out"
        );
    }

    /// The reconnect defect: `TransportDisconnected` closes the session and
    /// clears the queue, so without an explicit reopen a reconnect left the
    /// engine `Closed` and silently dropped every future frame.
    #[test]
    fn disconnect_then_reconnect_accepts_frames_again() {
        let mut e = active_engine();
        e.handle_event(APKSessionEvent::InboundFrame(frame(1, 1_000_000)));
        assert_eq!(e.queued_frame_count(), 1);

        e.handle_event(APKSessionEvent::TransportDisconnected);
        assert_eq!(e.state(), APKSessionState::Closed);
        assert_eq!(e.queued_frame_count(), 0, "a disconnect clears the queue");
        e.handle_event(APKSessionEvent::InboundFrame(frame(2, 2_000_000)));
        assert_eq!(
            e.queued_frame_count(),
            0,
            "a closed session must not queue frames"
        );

        e.handle_event(APKSessionEvent::TransportConnected);
        assert_eq!(
            e.state(),
            APKSessionState::Active,
            "reconnecting while the service is up must reopen the frame path"
        );
        e.handle_event(APKSessionEvent::InboundFrame(frame(3, 3_000_000)));
        assert_eq!(e.queued_frame_count(), 1);
        assert_eq!(e.consume_latest_frame().map(|f| f.sequence), Some(3));
    }

    /// Service shutdown ends delivery, and a transport event must not resurrect
    /// a session whose service is gone.
    #[test]
    fn shutdown_stops_delivery_and_a_reconnect_cannot_resurrect_it() {
        let mut e = active_engine();
        e.set_frame_receiver_registered(true);
        e.handle_event(APKSessionEvent::InboundFrame(frame(1, 1_000_000)));

        e.shutdown();
        assert_eq!(e.queued_frame_count(), 0);
        assert!(e.consume_latest_frame().is_none());

        e.handle_event(APKSessionEvent::InboundFrame(frame(2, 2_000_000)));
        assert_eq!(
            e.queued_frame_count(),
            0,
            "a shut-down service must not queue frames"
        );

        e.handle_event(APKSessionEvent::TransportConnected);
        assert_ne!(
            e.state(),
            APKSessionState::Active,
            "a transport connect must not restart a service that was shut down"
        );
        assert!(e.consume_latest_frame().is_none());
    }

    /// A fresh session must not be paced against the previous session's last
    /// frame, or the first frame after a restart is silently dropped.
    #[test]
    fn init_resets_pacing_state() {
        let mut e = active_engine();
        e.handle_event(APKSessionEvent::InboundFrame(frame(1, 9_000_000)));
        assert!(e.consume_latest_frame().is_some());

        e.shutdown();
        e.init();
        e.handle_event(APKSessionEvent::InboundFrame(frame(2, 9_001_000)));
        assert!(
            e.consume_latest_frame().is_some(),
            "the first frame of a new session must not be paced against the old one"
        );
    }
}

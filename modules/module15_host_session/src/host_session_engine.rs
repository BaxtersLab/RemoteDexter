use crate::{
    host_session_state::HostSessionState,
    host_session_event::HostSessionEvent,
    host_session_config::HostSessionConfig,
    media::{MediaPreviewSink, decode_camera_frame, decode_audio_frame, MediaStreamKind, MediaFrame, AudioPlayer, VideoSurface},
};

use module13_transport::{
    FrameEnvelope,
    ControlEnvelope,
    AsyncTransportSender,
};
use module13_transport::backpressure_level::BackpressureLevel;
use module14_apk_session::NegotiationResponse;

// Simple encoder engine placeholder for Block 5
pub struct EncoderEngine {
    running: bool,
    paused: bool,
}

impl EncoderEngine {
    pub fn new() -> Self {
        Self { running: false, paused: false }
    }

    pub async fn start(&mut self, _width: u32, _height: u32, _fps: u32) -> Result<(), String> {
        self.running = true;
        self.paused = false;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        self.paused = false;
        Ok(())
    }

    pub async fn pause(&mut self) -> Result<(), String> {
        if self.running {
            self.paused = true;
        }
        Ok(())
    }

    pub async fn resume(&mut self) -> Result<(), String> {
        if self.running {
            self.paused = false;
        }
        Ok(())
    }

    pub async fn next_frame(&mut self) -> Option<bytes::Bytes> {
        if self.running && !self.paused {
            // Return a dummy frame for testing
            Some(bytes::Bytes::from("dummy_encoded_frame"))
        } else {
            None
        }
    }
}

pub struct HostSessionEngine {
    state: HostSessionState,
    config: Option<HostSessionConfig>,
    encoder: EncoderEngine,
    sender: Option<AsyncTransportSender>,
    last_clipboard_text: Option<String>,
    media_sink: Option<MediaPreviewSink>,
    audio_player: Option<AudioPlayer>,
    video_surface: Option<Box<dyn VideoSurface>>,
}

impl HostSessionEngine {
    pub fn new() -> Self {
        Self {
            state: HostSessionState::Idle,
            config: None,
            encoder: EncoderEngine::new(),
            sender: None,
            last_clipboard_text: None,
            media_sink: None,
            audio_player: None,
            video_surface: None,
        }
    }

    pub fn state(&self) -> &HostSessionState {
        &self.state
    }

    pub fn config(&self) -> Option<&HostSessionConfig> {
        self.config.as_ref()
    }

    pub fn attach_sender(&mut self, sender: AsyncTransportSender) {
        self.sender = Some(sender);
    }

    pub fn set_media_sink(&mut self, sink: MediaPreviewSink) {
        self.media_sink = Some(sink);
    }

    pub fn set_audio_player(&mut self, player: AudioPlayer) {
        self.audio_player = Some(player);
    }

    pub fn set_video_surface(&mut self, surface: Box<dyn VideoSurface>) {
        self.video_surface = Some(surface);
    }

    async fn start_encoder(&mut self) {
        if let Some(cfg) = &self.config {
            let _ = self.encoder.start(cfg.width, cfg.height, cfg.max_fps).await;
        }
    }

    async fn _stop_encoder(&mut self) {
        let _ = self.encoder.stop().await;
    }

    async fn pause_encoder(&mut self) {
        let _ = self.encoder.pause().await;
    }

    async fn resume_encoder(&mut self) {
        let _ = self.encoder.resume().await;
    }

    async fn deliver_frame(&mut self, frame: bytes::Bytes) {
        if let Some(s) = &self.sender {
            let env = FrameEnvelope::new(frame).encode();
            let _ = s.send_envelope(env).await;
        }
    }

    async fn send_pause(&mut self) {
        if let Some(s) = &self.sender {
            let ctrl = ControlEnvelope::Backpressure {
                level: BackpressureLevel::Pause,
            };
            let _ = s.send_control(ctrl).await;
        }
    }

    async fn send_resume(&mut self) {
        if let Some(s) = &self.sender {
            let ctrl = ControlEnvelope::Backpressure {
                level: BackpressureLevel::Ready,
            };
            let _ = s.send_control(ctrl).await;
        }
    }

    async fn _send_keyframe_request(&mut self) {
        if let Some(s) = &self.sender {
            let ctrl = ControlEnvelope::RequestKeyframe;
            let _ = s.send_control(ctrl).await;
        }
    }

    async fn send_error(&mut self, msg: String) {
        if let Some(s) = &self.sender {
            use module13_transport::envelope::ErrorMessageEnvelope;
            let error_msg = ErrorMessageEnvelope::new(msg);
            let error_env = error_msg.encode();
            let _ = s.send_envelope(error_env).await;
        }
    }

    pub async fn handle_event(&mut self, event: HostSessionEvent) {
        match (&self.state, event) {

            // IDLE → NEGOTIATING
            (HostSessionState::Idle, HostSessionEvent::Start) => {
                self.state = HostSessionState::Negotiating;
            }

            // NEGOTIATING → STREAMING/ERROR
            (HostSessionState::Negotiating, HostSessionEvent::ApkProposedConfig(cfg)) => {
                if cfg.width == 0 || cfg.height == 0 || cfg.max_fps == 0 {
                    self.state = HostSessionState::Error("Invalid config: zero dimensions or fps".into());
                } else {
                    self.config = Some(cfg.clone());
                    self.state = HostSessionState::Streaming;
                    self.start_encoder().await;
                }
            }

            // NEGOTIATING → STREAMING
            (HostSessionState::Negotiating, HostSessionEvent::NegotiationSuccess(cfg)) => {
                self.config = Some(cfg);
                self.state = HostSessionState::Streaming;
                self.start_encoder().await;
            }

            // NEGOTIATING → ERROR
            (HostSessionState::Negotiating, HostSessionEvent::NegotiationFailure(reason)) => {
                self.state = HostSessionState::Error(reason);
            }

            // STREAMING → PAUSED
            (HostSessionState::Streaming, HostSessionEvent::Pause) => {
                self.state = HostSessionState::Paused;
                self.pause_encoder().await;
                self.send_pause().await;
            }

            // PAUSED → STREAMING
            (HostSessionState::Paused, HostSessionEvent::Resume) => {
                self.state = HostSessionState::Streaming;
                self.resume_encoder().await;
                self.send_resume().await;
            }

            // STREAMING/PAUSED/NEGOTIATING → CLOSED
            (HostSessionState::Streaming, HostSessionEvent::Stop)
            | (HostSessionState::Paused, HostSessionEvent::Stop)
            | (HostSessionState::Negotiating, HostSessionEvent::Stop) => {
                self.teardown().await;
                self.state = HostSessionState::Closed;
            }

            // ANY → ERROR (Fatal)
            (_, HostSessionEvent::Fatal(reason)) => {
                self.send_error(reason.clone()).await;
                self.teardown().await;
                self.state = HostSessionState::Error(reason);
            }

            // Transport events ignored until Block 5 (encoder integration)
            (HostSessionState::Streaming, HostSessionEvent::TransportFrame(_)) => {}
            (HostSessionState::Streaming, HostSessionEvent::TransportControl(_)) => {}

            // All other combinations ignored
            _ => {}
        }
    }

    async fn teardown(&mut self) {
        let _ = self.encoder.stop().await;
        self.sender = None;
        self.config = None;
    }

    pub async fn on_transport_frame(&mut self, _frame: FrameEnvelope) {
        match self.state {
            HostSessionState::Streaming => {
                // Host does not consume inbound frames
            }
            HostSessionState::Paused => {
                // Ignore
            }
            _ => {
                // After teardown: ignore everything
            }
        }
    }

    pub async fn on_transport_control(&mut self, env: ControlEnvelope) {
        match self.state {
            HostSessionState::Closed | HostSessionState::Error(_) => {
                return; // ignore after teardown
            }
            _ => {}
        }

        // Existing Block 4 logic remains
        match &env {
            ControlEnvelope::Backpressure { level } => {
                match level {
                    BackpressureLevel::Ready => {
                        self.handle_event(HostSessionEvent::Resume).await;
                    }
                    BackpressureLevel::Congested | BackpressureLevel::Pause => {
                        self.handle_event(HostSessionEvent::Pause).await;
                    }
                }
            }

            ControlEnvelope::RequestKeyframe => {
                self.handle_event(HostSessionEvent::TransportControl(env)).await;
            }
        }
    }

    pub async fn on_transport_data(&mut self, frame: MediaFrame) {
        if let Some(ref sink) = self.media_sink {
            match frame.kind {
                MediaStreamKind::Camera => {
                    if let Some(decoded) = decode_camera_frame(&frame.payload, frame.timestamp) {
                        sink.on_camera_frame_decoded(decoded.clone());
                        if let Some(ref mut surface) = self.video_surface {
                            surface.present(&decoded);
                        }
                    }
                }
                MediaStreamKind::Microphone => {
                    let decoded = decode_audio_frame(&frame.payload, frame.timestamp);
                    sink.on_audio_frame_decoded(decoded.clone());
                    if let Some(ref player) = self.audio_player {
                        player.push_frame(decoded);
                    }
                }
            }
        }
    }

    pub async fn pump_encoder(&mut self) {
        match self.state {
            HostSessionState::Streaming => {
                if let Some(frame) = self.encoder.next_frame().await {
                    self.deliver_frame(frame).await;
                }
            }
            HostSessionState::Paused => {
                // Drop frames while paused
            }
            _ => {
                // Ignore encoder output in all other states
            }
        }
    }

    pub async fn on_clipboard_update(&mut self, data: bytes::Bytes) {
        // Apply incoming clipboard text from the APK to the host.
        // For now log/store it; real platform clipboard (arboard / win32) comes
        // in a later block.  Storing makes the round-trip testable.
        if let Ok(text) = String::from_utf8(data.to_vec()) {
            self.last_clipboard_text = Some(text);
        }
    }

    pub async fn on_screenshot_request(&mut self) {
        // Capture a synthetic frame (F9) and send back over transport.
        let frame = Self::capture_screenshot();
        self.deliver_frame(frame).await;
    }

    /// Produce a small screenshot frame (synthetic for now; real DXGI later).
    fn capture_screenshot() -> bytes::Bytes {
        let width: u32 = 640;
        let height: u32 = 360;
        let mut pixels = vec![0u8; (width * height * 4) as usize];
        for y in 0..height {
            for x in 0..width {
                let i = ((y * width + x) * 4) as usize;
                pixels[i]     = (x & 0xFF) as u8;
                pixels[i + 1] = (y & 0xFF) as u8;
                pixels[i + 2] = 128;
                pixels[i + 3] = 255;
            }
        }
        bytes::Bytes::from(pixels)
    }

    pub async fn on_agent2_command(&mut self, _json: bytes::Bytes) {
        // Stub: Agent2 command forwarding will be implemented in a later block
    }

    pub async fn on_negotiation_response(&mut self, _resp: NegotiationResponse) {
        // Create default config from negotiation — real resolution in a later block
        let config = crate::host_session_config::HostSessionConfig {
            width: 1920,
            height: 1080,
            pixel_format: "NV12".to_string(),
            max_fps: 30,
        };
        self.handle_event(HostSessionEvent::NegotiationSuccess(config)).await;
    }
}
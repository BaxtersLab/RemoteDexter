use std::time::Duration;
use tokio::time::MissedTickBehavior;
use module13_transport::{FrameEnvelope, ControlEnvelope, AsyncTransportSender, AsyncTransportReceiver};
use module13_transport::envelope::{Envelope, tags};
use module13_transport::backpressure_level::BackpressureLevel;
use module14_apk_session::{NegotiationRequest, encode_negotiation_request, decode_negotiation_response};
use crate::{HostSessionEngine, HostSessionEvent, HostSessionState};

pub struct HostSessionIntegration {
    session: HostSessionEngine,
    sender: AsyncTransportSender,
    receiver: AsyncTransportReceiver,
}

impl HostSessionIntegration {
    pub fn new(session: HostSessionEngine, sender: AsyncTransportSender, receiver: AsyncTransportReceiver) -> Self {
        Self { session, sender, receiver }
    }

    pub async fn start(mut self) {
        // Attach sender clone to session engine for outbound envelopes
        self.session.attach_sender(self.sender.clone());
        self.session.handle_event(HostSessionEvent::Start).await;

        // Kick off feature negotiation (F6)
        self.start_negotiation().await;

        let mut frame_interval = tokio::time::interval(Duration::from_millis(16)); // ~60 fps
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(5));
        heartbeat_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            // Check if session is done
            match self.session.state() {
                HostSessionState::Closed | HostSessionState::Error(_) => break,
                _ => {}
            }

            tokio::select! {
                result = self.receiver.receive_envelope() => {
                    match result {
                        Ok(Some(envelope)) => {
                            self.handle_envelope(envelope).await;
                        }
                        Ok(None) => {
                            // Transport closed → stop session
                            self.session.handle_event(HostSessionEvent::Stop).await;
                            break;
                        }
                        Err(_) => {
                            // Transport error → fatal
                            self.session.handle_event(HostSessionEvent::Fatal("Transport error".into())).await;
                            break;
                        }
                    }
                }

                _ = frame_interval.tick() => {
                    self.session.pump_encoder().await;
                }

                _ = heartbeat_interval.tick() => {
                    let _ = self.sender.send_heartbeat().await;
                }
            }
        }
    }

    async fn start_negotiation(&mut self) {
        let req = NegotiationRequest { client_version: 1 };
        let bytes = encode_negotiation_request(&req);
        let envelope = Envelope::new(tags::NEGOTIATION, bytes::Bytes::from(bytes));
        let _ = self.sender.send_envelope(envelope).await;
    }

    async fn handle_envelope(&mut self, envelope: Envelope) {
        match envelope.tag {
            tags::FRAME_DATA => {
                if let Some(frame) = FrameEnvelope::decode(&envelope) {
                    self.session.on_transport_frame(frame).await;
                }
            }
            tags::BACKPRESSURE_UPDATE | tags::FORCE_KEYFRAME => {
                if let Some(ctrl) = Self::decode_control_envelope(&envelope) {
                    self.session.on_transport_control(ctrl).await;
                }
            }
            tags::CLIPBOARD_UPDATE => {
                self.session.on_clipboard_update(envelope.payload).await;
            }
            tags::SCREENSHOT_REQUEST => {
                self.session.on_screenshot_request().await;
            }
            tags::AGENT2_COMMAND => {
                self.session.on_agent2_command(envelope.payload).await;
            }
            tags::NEGOTIATION => {
                if let Some(resp) = decode_negotiation_response(&envelope.payload) {
                    self.session.on_negotiation_response(resp).await;
                }
            }
            _ => {
                // Ignore unknown tags
            }
        }
    }

    fn decode_control_envelope(envelope: &Envelope) -> Option<ControlEnvelope> {
        use module13_transport::envelope::*;

        match envelope.tag {
            tags::BACKPRESSURE_UPDATE => {
                BackpressureUpdateEnvelope::decode(envelope)
                    .and_then(|update| BackpressureLevel::from_u8(update.level))
                    .map(|level| ControlEnvelope::Backpressure { level })
            }
            tags::FORCE_KEYFRAME => {
                ForceKeyframeEnvelope::decode(envelope)
                    .map(|_| ControlEnvelope::RequestKeyframe)
            }
            _ => None,
        }
    }
}
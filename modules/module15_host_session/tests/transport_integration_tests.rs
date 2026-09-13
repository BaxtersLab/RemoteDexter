use module15_host_session::{HostSessionEngine, HostSessionEvent, HostSessionState, HostSessionConfig};
use module13_transport::{ControlEnvelope};
use module13_transport::backpressure_level::BackpressureLevel;

#[tokio::test]
async fn backpressure_triggers_pause_resume() {
    let mut engine = HostSessionEngine::new();
    engine.handle_event(HostSessionEvent::Start).await;

    engine.handle_event(HostSessionEvent::NegotiationSuccess(
        HostSessionConfig {
            width: 1280,
            height: 720,
            pixel_format: "RGBA".into(),
            max_fps: 60,
        }
    )).await;

    engine.on_transport_control(ControlEnvelope::Backpressure {
        level: BackpressureLevel::Pause,
    }).await;
    assert!(matches!(engine.state(), HostSessionState::Paused));

    engine.on_transport_control(ControlEnvelope::Backpressure {
        level: BackpressureLevel::Ready,
    }).await;
    assert!(matches!(engine.state(), HostSessionState::Streaming));
}
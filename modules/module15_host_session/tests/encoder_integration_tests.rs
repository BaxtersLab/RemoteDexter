use module15_host_session::{HostSessionEngine, HostSessionEvent, HostSessionConfig};
use module15_host_session::HostSessionState;

#[tokio::test]
async fn encoder_starts_on_streaming() {
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

    assert!(matches!(engine.state(), HostSessionState::Streaming));
}
use module15_host_session::{HostSessionEngine, HostSessionEvent, HostSessionConfig};

#[tokio::test]
async fn pump_encoder_drops_frames_when_paused() {
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

    engine.handle_event(HostSessionEvent::Pause).await;
    engine.pump_encoder().await; // should drop silently
}
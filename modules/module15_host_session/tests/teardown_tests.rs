use module15_host_session::{HostSessionEngine, HostSessionEvent, HostSessionConfig, HostSessionState};

#[tokio::test]
async fn teardown_clears_resources() {
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

    engine.handle_event(HostSessionEvent::Stop).await;

    assert!(matches!(engine.state(), HostSessionState::Closed));
    assert!(engine.config().is_none());
}
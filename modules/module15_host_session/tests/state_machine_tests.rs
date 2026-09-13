use module15_host_session::{
    HostSessionEngine,
    HostSessionEvent,
    HostSessionState,
    HostSessionConfig,
};

#[tokio::test]
async fn state_machine_basic_flow() {
    let mut engine = HostSessionEngine::new();

    engine.handle_event(HostSessionEvent::Start).await;
    assert!(matches!(engine.state(), HostSessionState::Negotiating));

    let cfg = HostSessionConfig {
        width: 1280,
        height: 720,
        pixel_format: "RGBA".into(),
        max_fps: 60,
    };

    engine.handle_event(HostSessionEvent::NegotiationSuccess(cfg)).await;
    assert!(matches!(engine.state(), HostSessionState::Streaming));

    engine.handle_event(HostSessionEvent::Pause).await;
    assert!(matches!(engine.state(), HostSessionState::Paused));

    engine.handle_event(HostSessionEvent::Resume).await;
    assert!(matches!(engine.state(), HostSessionState::Streaming));

    engine.handle_event(HostSessionEvent::Stop).await;
    assert!(matches!(engine.state(), HostSessionState::Closed));
}
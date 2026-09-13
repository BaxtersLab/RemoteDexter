use module15_host_session::{
    HostSessionEngine,
    HostSessionEvent,
    HostSessionState,
    HostSessionConfig,
};

#[tokio::test]
async fn negotiation_rejects_invalid_config() {
    let mut engine = HostSessionEngine::new();
    engine.handle_event(HostSessionEvent::Start).await;

    let bad_cfg = HostSessionConfig {
        width: 0,
        height: 720,
        pixel_format: "RGBA".into(),
        max_fps: 60,
    };

    engine.handle_event(HostSessionEvent::ApkProposedConfig(bad_cfg)).await;
    assert!(matches!(engine.state(), HostSessionState::Error(_)));
}
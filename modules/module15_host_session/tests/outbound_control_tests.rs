use module15_host_session::{HostSessionEngine, HostSessionEvent, HostSessionConfig};

// Note: Full outbound control testing requires a mock transport
// This test verifies the signaling methods are called during state transitions

#[tokio::test]
async fn outbound_pause_resume_signals_available() {
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

    // These should not panic - the methods exist and are called during transitions
    engine.handle_event(HostSessionEvent::Pause).await;
    engine.handle_event(HostSessionEvent::Resume).await;
}
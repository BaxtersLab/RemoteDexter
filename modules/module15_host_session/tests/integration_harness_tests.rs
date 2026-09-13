use module15_host_session::{HostSessionEngine, HostSessionIntegration};
use module13_transport::new_async_transport;

#[tokio::test]
async fn integration_harness_runs_without_panic() {
    let session = HostSessionEngine::new();
    let (sender, receiver) = new_async_transport(1024);

    let harness = HostSessionIntegration::new(session, sender, receiver);

    // HostSessionEngine contains non-Send types (rodio internals), so we
    // must use a LocalSet instead of tokio::spawn.
    let local = tokio::task::LocalSet::new();
    local.run_until(async move {
        let handle = tokio::task::spawn_local(async move {
            harness.start().await;
        });

        // Let it run for a short time
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Cancel the task (since it would run forever otherwise)
        handle.abort();
    }).await;
}
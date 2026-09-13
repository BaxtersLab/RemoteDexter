//! Substrate Integration Layer (SIL)
//!
//! Provides a stable lifecycle boundary for subsystems to integrate with the orchestrator
//! and the Shutdown Governor.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

pub type TaskId = u64;

/// Minimal CancellationToken for SIL. Implementations may extend or replace this with
/// the governor's token type when wiring into the runtime.
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<CancellationTokenInner>,
}

struct CancellationTokenInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self { inner: Arc::new(CancellationTokenInner { cancelled: AtomicBool::new(false), notify: Notify::new() }) }
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// Async await for cancellation. If already cancelled, returns immediately.
    pub async fn cancelled(&self) {
        if self.inner.cancelled.load(Ordering::SeqCst) { return; }
        let notified = self.inner.notify.notified();
        notified.await;
    }
}

/// TaskRegistrar is a small wrapper used by subsystems to spawn tasks under the governor.
/// The concrete implementation is provided by the orchestrator when wiring the system.
pub trait TaskRegistrar: Send + Sync + 'static {
    /// Request a child cancellation token for the subsystem/task about to be spawned.
    /// Implementations should produce a token tied to the governor so cancellations
    /// propagate from the governor's root token.
    fn child_token(&self, task_name: &str) -> CancellationToken;

    /// Spawn a boxed future under registrar control and return the assigned TaskId.
    fn spawn_boxed(&self, name: &str, fut: Pin<Box<dyn Future<Output = ()> + Send>>) -> TaskId;
}

/// Logger abstraction used by SIL and subsystems. Matches the governor's logger surface.
pub trait Logger: Send + Sync + 'static {
    fn info(&self, msg: &str);
    fn warn(&self, msg: &str);
    fn error(&self, msg: &str);
}

/// Result of initializing a subsystem.
pub struct SubsystemInitResult {
    /// Task IDs spawned during init (registered via the provided TaskRegistrar).
    pub task_ids: Vec<TaskId>,

    /// Optional subsystem-level handle (e.g., a control handle, stream receiver, etc.).
    /// This is intentionally untyped to allow per-subsystem flexibility; callers will downcast.
    pub handles: Option<Box<dyn Any + Send + Sync>>,
}

impl SubsystemInitResult {
    pub fn empty() -> Self {
        Self { task_ids: Vec::new(), handles: None }
    }
}

/// Context passed to each subsystem at initialization.
pub struct SubsystemInitContext {
    pub cancellation: CancellationToken,
    pub registrar: Arc<dyn TaskRegistrar>,
    pub logger: Arc<dyn Logger>,
    /// Optional per-subsystem configuration blob. Use downcast on concrete types.
    pub config: Option<Box<dyn Any + Send + Sync>>,
}

/// Subsystem lifecycle trait. All subsystems must implement this to participate in SIL.
pub trait Subsystem: Send + Sync + 'static {
    /// Short static name for ordering and logging.
    fn name(&self) -> &'static str;

    /// Initialize the subsystem. Implementations must spawn long-running work via `ctx.registrar`
    /// so the governor can track and cancel them.
    fn init(&self, ctx: &SubsystemInitContext) -> SubsystemInitResult;

    /// Called prior to initiating shutdown; synchronous hook for deterministic actions.
    fn pre_shutdown(&self);

    /// Called when cancellation is observed. Implementations should react promptly.
    fn on_cancel(&self);

    /// Finalize and release resources. Called after tasks have been stopped.
    fn finalize(&self);
}

pub mod governor_registrar;
pub use governor_registrar::GovernorRegistrar;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    struct DummyRegistrar { next: Mutex<TaskId>, }
    impl DummyRegistrar {
        fn new() -> Self { Self { next: Mutex::new(1) } }
    }
    impl TaskRegistrar for DummyRegistrar {
        fn child_token(&self, _task_name: &str) -> CancellationToken {
            CancellationToken::new()
        }

        fn spawn_boxed(&self, _name: &str, _fut: Pin<Box<dyn Future<Output = ()> + Send>>) -> TaskId {
            let mut n = self.next.lock().unwrap();
            let id = *n;
            *n += 1;
            id
        }
    }

    struct DummyLogger;
    impl Logger for DummyLogger {
        fn info(&self, _msg: &str) {}
        fn warn(&self, _msg: &str) {}
        fn error(&self, _msg: &str) {}
    }

    struct DummySubsystem { cancelled: Arc<AtomicBool> }
    impl DummySubsystem { fn new() -> Self { Self { cancelled: Arc::new(AtomicBool::new(false)) } } }
    impl Subsystem for DummySubsystem {
        fn name(&self) -> &'static str { "dummy" }
        fn init(&self, ctx: &SubsystemInitContext) -> SubsystemInitResult {
            let token = ctx.cancellation.clone();
            let registrar = ctx.registrar.clone();
            let id = registrar.spawn_boxed("dummy-task", Box::pin(async move {
                token.cancelled().await;
            }));
            let mut res = SubsystemInitResult::empty();
            res.task_ids.push(id);
            res
        }
        fn pre_shutdown(&self) {}
        fn on_cancel(&self) { self.cancelled.store(true, Ordering::SeqCst); }
        fn finalize(&self) {}
    }

    #[tokio::test]
    async fn sil_init_and_cancel() {
        let token = CancellationToken::new();
        let registrar = Arc::new(DummyRegistrar::new());
        let logger = Arc::new(DummyLogger);
        let ctx = SubsystemInitContext { cancellation: token.clone(), registrar, logger, config: None };
        let s = DummySubsystem::new();
        let res = s.init(&ctx);
        assert_eq!(res.task_ids.len(), 1);
        // signal cancellation and ensure task would observe it (no hard assertion here)
        token.cancel();
    }
}

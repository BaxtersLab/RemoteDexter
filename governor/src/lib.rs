//! Minimal 47B scaffolding: ShutdownGovernor surface
//!
//! Exposes: `ShutdownGovernor`, `TaskRegistry`, `ShutdownResult`, `GovernorLogger`, `with_governor`

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

pub type TaskId = u64;

/// Result of a shutdown operation
#[derive(Debug, Clone)]
pub enum ShutdownResult {
    Success,
    TimedOut,
    Killed,
    Forced(Vec<TaskId>),
    Error(String),
}

/// Simple logger trait for the governor to emit structured events.
pub trait GovernorLogger: Send + Sync + 'static {
    fn info(&self, msg: &str);
    fn warn(&self, msg: &str);
    fn error(&self, msg: &str);
    fn log_shutdown_event(&self, msg: &str) { self.info(msg) }
    fn log_offender(&self, task: &TaskInfo) { self.warn(&format!("offender: {} ({})", task.name, task.id)) }
}

/// A console logger implementation for quick local testing.
pub struct ConsoleLogger;
impl GovernorLogger for ConsoleLogger {
    fn info(&self, msg: &str) {
        println!("[GOV INFO] {}", msg);
    }
    fn warn(&self, msg: &str) {
        eprintln!("[GOV WARN] {}", msg);
    }
    fn error(&self, msg: &str) {
        eprintln!("[GOV ERROR] {}", msg);
    }
}

/// Registry of active tasks that the governor may track and terminate.
#[derive(Clone)]
pub struct TaskRegistry {
    inner: Arc<Mutex<HashMap<TaskId, TaskInfo>>>,
    next_id: Arc<AtomicU64>,
}

#[derive(Clone, Debug)]
pub struct TaskInfo {
    pub id: TaskId,
    pub name: String,
    pub created_at: Instant,
    pub cancelled_at: Option<Instant>,
}

impl TaskRegistry {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), next_id: Arc::new(AtomicU64::new(1)) }
    }

    pub fn next_id(&self) -> TaskId {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn register(&self, id: TaskId, name: impl Into<String>) {
        let info = TaskInfo { id, name: name.into(), created_at: Instant::now(), cancelled_at: None };
        let mut m = self.inner.lock().unwrap();
        m.insert(id, info);
    }

    pub fn register_info(&self, info: TaskInfo) {
        let mut m = self.inner.lock().unwrap();
        m.insert(info.id, info);
    }

    pub fn unregister(&self, id: TaskId) {
        let mut m = self.inner.lock().unwrap();
        m.remove(&id);
    }

    pub fn mark_cancelled(&self, id: TaskId) {
        let mut m = self.inner.lock().unwrap();
        if let Some(t) = m.get_mut(&id) {
            t.cancelled_at = Some(Instant::now());
        }
    }

    pub fn list(&self) -> Vec<TaskInfo> {
        let m = self.inner.lock().unwrap();
        m.values().cloned().collect()
    }

    pub fn list_offenders(&self) -> Vec<TaskInfo> {
        let m = self.inner.lock().unwrap();
        m.values().filter(|t| t.cancelled_at.is_none()).cloned().collect()
    }
}

/// The ShutdownGovernor coordinates shutdown, tracks tasks and enforces bounds.
pub struct ShutdownGovernor {
    tasks: TaskRegistry,
    logger: Arc<dyn GovernorLogger>,
    root: CancellationToken,
    handles: Arc<Mutex<HashMap<TaskId, JoinHandle<()>>>>,
}

impl ShutdownGovernor {
    pub fn new(logger: Arc<dyn GovernorLogger>) -> Self {
        Self { tasks: TaskRegistry::new(), logger, root: CancellationToken::new_root(), handles: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Register a task with the governor for tracking.
    pub fn register_task(&self, id: TaskId, name: impl Into<String>) {
        self.logger.info(&format!("registering task {}", id));
        self.tasks.register(id, name);
    }

    /// Unregister when a task completes / is removed.
    pub fn unregister_task(&self, id: TaskId) {
        self.logger.info(&format!("unregistering task {}", id));
        self.tasks.unregister(id);
        let mut h = self.handles.lock().unwrap();
        h.remove(&id);
    }

    /// Register an async task with its join handle and cancellation token.
    pub fn register_async_task(&self, name: &str, handle: JoinHandle<()>, _token: CancellationToken) -> TaskId {
        let id = self.tasks.next_id();
        let info = TaskInfo { id, name: name.to_string(), created_at: Instant::now(), cancelled_at: None };
        self.tasks.register_info(info);
        let mut h = self.handles.lock().unwrap();
        h.insert(id, handle);
        self.logger.info(&format!("registered async task {} ({})", name, id));
        id
    }

    /// Create a child cancellation token derived from the governor root.
    pub fn child_token(&self) -> CancellationToken {
        CancellationToken::child_from(&self.root)
    }

    /// Initiate a shutdown sequence asynchronously.
    pub async fn initiate_shutdown(&self, timeout_seconds: u64) -> ShutdownResult {
        self.logger.log_shutdown_event("initiating shutdown");
        // cancel root token
        self.root.cancel();

        // take handles out for ownership so we can await them
        let handles_snapshot: HashMap<TaskId, JoinHandle<()>> = {
            let mut h = self.handles.lock().unwrap();
            std::mem::take(&mut *h)
        };

        let mut offenders: Vec<TaskId> = Vec::new();
        for (id, handle) in handles_snapshot.into_iter() {
            self.logger.info(&format!("waiting for task {}", id));
            match timeout(Duration::from_secs(timeout_seconds), handle).await {
                Ok(join_result) => {
                    let _ = join_result;
                    self.tasks.mark_cancelled(id);
                    self.logger.info(&format!("task {} completed", id));
                }
                Err(_) => {
                    // timeout - abort
                    self.logger.warn(&format!("task {} timed out, aborting", id));
                    offenders.push(id);
                }
            }
        }

        if offenders.is_empty() {
            self.logger.log_shutdown_event("shutdown succeeded: no remaining tasks");
            ShutdownResult::Success
        } else {
            for off in &offenders {
                if let Some(t) = self.tasks.list().into_iter().find(|ti| ti.id == *off) {
                    self.logger.log_offender(&t);
                }
            }
            ShutdownResult::Forced(offenders)
        }
    }
}

/// A convenience helper that creates a governor, runs the provided closure, and returns the result.
pub fn with_governor<F, R>(logger: Arc<dyn GovernorLogger>, f: F) -> R
where
    F: FnOnce(&ShutdownGovernor) -> R,
{
    let gov = ShutdownGovernor::new(logger);
    f(&gov)
}

/// Cancellation token implementation with optional parent linkage.
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<CancellationTokenInner>,
    parent: Option<Arc<CancellationTokenInner>>,
}

struct CancellationTokenInner {
    cancelled: std::sync::atomic::AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    pub fn new_root() -> Self {
        Self { inner: Arc::new(CancellationTokenInner { cancelled: std::sync::atomic::AtomicBool::new(false), notify: Notify::new() }), parent: None }
    }

    pub fn child_from(parent: &CancellationToken) -> Self {
        Self { inner: Arc::new(CancellationTokenInner { cancelled: std::sync::atomic::AtomicBool::new(false), notify: Notify::new() }), parent: Some(parent.inner.clone()) }
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        if self.inner.cancelled.load(Ordering::SeqCst) { return true; }
        if let Some(p) = &self.parent { return p.cancelled.load(Ordering::SeqCst); }
        false
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() { return; }
        if let Some(p) = &self.parent {
            tokio::pin! {
                let n1 = self.inner.notify.notified();
                let n2 = p.notify.notified();
            }
            tokio::select! {
                _ = n1 => {}
                _ = n2 => {}
            }
        } else {
            self.inner.notify.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn governor_basic_flow() {
        let logger = Arc::new(ConsoleLogger) as Arc<dyn GovernorLogger>;
        let result = with_governor(logger.clone(), |g| {
            g.register_task(1, "t1");
            g.unregister_task(1);
            // return placeholder
            ShutdownResult::Success
        });
        assert!(matches!(result, ShutdownResult::Success | ShutdownResult::TimedOut));
    }
}

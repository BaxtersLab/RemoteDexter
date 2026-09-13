use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::future::Future;

use tokio::task::JoinHandle;

use crate::{CancellationToken, TaskId, TaskRegistrar};

/// Glue that adapts the `governor::ShutdownGovernor` into a `sil::TaskRegistrar`.
pub struct GovernorRegistrar {
    gov: Arc<governor::ShutdownGovernor>,
    pending: Arc<Mutex<VecDeque<governor::CancellationToken>>>,
}

impl GovernorRegistrar {
    pub fn new(gov: Arc<governor::ShutdownGovernor>) -> Self {
        Self { gov, pending: Arc::new(Mutex::new(VecDeque::new())) }
    }

    /// Bridge a governor token into a local `sil::CancellationToken`.
    fn bridge_token(&self, gtok: governor::CancellationToken) -> CancellationToken {
        let t = CancellationToken::new();
        let t2 = t.clone();
        // Spawn a background task that will notify the sil token when governor token cancels.
        tokio::spawn(async move {
            gtok.cancelled().await;
            t2.cancel();
        });
        t
    }
}

impl TaskRegistrar for GovernorRegistrar {
    fn child_token(&self, _task_name: &str) -> CancellationToken {
        let gtok = self.gov.child_token();
        let bridged = self.bridge_token(gtok.clone());
        let mut p = self.pending.lock().unwrap();
        p.push_back(gtok);
        bridged
    }

    fn spawn_boxed(&self, name: &str, fut: Pin<Box<dyn Future<Output = ()> + Send>>) -> TaskId {
        // Pop the matching governor token created earlier (assumes child_token() called previously).
        let gtok = {
            let mut p = self.pending.lock().unwrap();
            p.pop_front()
        };

        let handle: JoinHandle<()> = tokio::spawn(fut);
        if let Some(gt) = gtok {
            self.gov.register_async_task(name, handle, gt)
        } else {
            // No governor token available — register with a fresh token.
            let gt = self.gov.child_token();
            self.gov.register_async_task(name, handle, gt)
        }
    }
}

impl From<Arc<governor::ShutdownGovernor>> for GovernorRegistrar {
    fn from(g: Arc<governor::ShutdownGovernor>) -> Self {
        GovernorRegistrar::new(g)
    }
}

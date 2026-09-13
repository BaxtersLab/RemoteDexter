/// Logical status for a session managed by Module6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalStatus {
    Healthy,
    Degraded,
    Reconnecting,
    Dead,
}

#[derive(Debug)]
pub struct LogicalError(pub String);

/// Lightweight logical session representation owned by Module6.
pub struct LogicalSession {
    pub id: String,
    status: LogicalStatus,
}

impl LogicalSession {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into(), status: LogicalStatus::Healthy }
    }

    pub fn status(&self) -> &LogicalStatus { &self.status }

    pub fn set_status(&mut self, s: LogicalStatus) { self.status = s }
}

#[derive(Debug, Clone)]
pub enum HostSessionState {
    Idle,
    Negotiating,
    Streaming,
    Paused,
    Error(String),
    Closed,
}
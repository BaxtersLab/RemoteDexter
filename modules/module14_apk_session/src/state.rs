#[derive(Debug, Clone, PartialEq)]
pub enum APKSessionState {
    Idle,
    Connecting,
    Negotiating,
    Active,
    Standby,
    EcoStandby,
    Suspended,
    Closed,
}
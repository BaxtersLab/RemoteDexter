#[derive(Debug)]
pub struct APKSessionConfig {
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
}

#[derive(Debug)]
pub struct NegotiationRequest {
    pub client_version: u32,
}

#[derive(Debug)]
pub enum APKSessionCommand {
    Connect(APKSessionConfig),
    Disconnect,
    SendControl(Vec<u8>),
    EnterStandby,
    ExitStandby,
    SendNegotiationRequest,
    RequestKeyframe,
    BackpressureNotice,
    EnterEcoStandby,
    ExitEcoStandby,
    HostWakeRequest,
    DeviceAwake,
}
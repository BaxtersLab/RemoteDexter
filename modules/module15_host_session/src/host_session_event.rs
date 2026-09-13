use crate::host_session_config::HostSessionConfig;
use module13_transport::{FrameEnvelope, ControlEnvelope};

#[derive(Debug)]
pub enum HostSessionEvent {
    Start,
    ApkProposedConfig(HostSessionConfig),
    NegotiationSuccess(HostSessionConfig),
    NegotiationFailure(String),
    TransportFrame(FrameEnvelope),
    TransportControl(ControlEnvelope),
    Pause,
    Resume,
    Stop,
    Fatal(String),
}
use crate::frame::FrameEnvelope;
use crate::media::MediaControl;

#[derive(Debug)]
pub enum APKSessionEvent {
    InboundFrame(FrameEnvelope),
    InboundControl(Vec<u8>),
    TransportConnected,
    TransportDisconnected,
    Fatal(String),
    NegotiationResponse(NegotiationResponse),
    SystemSleep,
    SystemWake,
    TransportIdle,
    TransportWake,
    InboundMediaControl(MediaControl),
}

#[derive(Debug)]
pub struct NegotiationResponse {
    pub server_version: u32,
}
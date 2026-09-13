//! Envelope definitions for transport messages

use bytes::{Bytes, BytesMut, Buf, BufMut};
use crate::backpressure_level::BackpressureLevel;

/// Canonical envelope tags
pub mod tags {
    pub const FRAME_DATA: u8 = 0x01;
    pub const RESET: u8 = 0x02;
    pub const FORCE_KEYFRAME: u8 = 0x03;
    pub const BACKPRESSURE_UPDATE: u8 = 0x04;
    pub const ERROR_MESSAGE: u8 = 0x05;
    pub const HEARTBEAT: u8 = 0x06;
    pub const CLIPBOARD_UPDATE: u8 = 0x07;
    pub const SCREENSHOT_REQUEST: u8 = 0x08;
    pub const NEGOTIATION: u8 = 0x09;
    pub const AGENT2_COMMAND: u8 = 0x21;
}

/// Transport envelope
#[derive(Clone, Debug, PartialEq)]
pub struct Envelope {
    pub tag: u8,
    pub payload: Bytes,
}

impl Envelope {
    /// Create a new envelope
    pub fn new(tag: u8, payload: Bytes) -> Self {
        Self { tag, payload }
    }

    /// Encode envelope to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + self.payload.len());
        buf.put_u8(self.tag);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    /// Decode envelope from bytes
    pub fn decode(mut data: Bytes) -> Option<Self> {
        if data.len() < 1 {
            return None;
        }

        let tag = data.get_u8();
        let payload = data;

        Some(Self { tag, payload })
    }

    /// Check if tag is valid
    pub fn is_valid_tag(tag: u8) -> bool {
        matches!(tag, 
            tags::FRAME_DATA |
            tags::RESET |
            tags::FORCE_KEYFRAME |
            tags::BACKPRESSURE_UPDATE |
            tags::ERROR_MESSAGE |
            tags::HEARTBEAT |
            tags::CLIPBOARD_UPDATE |
            tags::SCREENSHOT_REQUEST |
            tags::NEGOTIATION |
            tags::AGENT2_COMMAND
        )
    }
}

/// Frame data envelope
#[derive(Clone, Debug, PartialEq)]
pub struct FrameDataEnvelope {
    pub frame_data: Bytes,
}

impl FrameDataEnvelope {
    pub fn new(frame_data: Bytes) -> Self {
        Self { frame_data }
    }

    pub fn encode(&self) -> Envelope {
        Envelope::new(tags::FRAME_DATA, self.frame_data.clone())
    }

    pub fn decode(envelope: &Envelope) -> Option<Self> {
        if envelope.tag == tags::FRAME_DATA {
            Some(Self { frame_data: envelope.payload.clone() })
        } else {
            None
        }
    }
}

/// Reset envelope
#[derive(Clone, Debug, PartialEq)]
pub struct ResetEnvelope;

impl ResetEnvelope {
    pub fn new() -> Self {
        Self
    }

    pub fn encode(&self) -> Envelope {
        Envelope::new(tags::RESET, Bytes::new())
    }

    pub fn decode(envelope: &Envelope) -> Option<Self> {
        if envelope.tag == tags::RESET && envelope.payload.is_empty() {
            Some(Self)
        } else {
            None
        }
    }
}

/// Force keyframe envelope
#[derive(Clone, Debug, PartialEq)]
pub struct ForceKeyframeEnvelope;

impl ForceKeyframeEnvelope {
    pub fn new() -> Self {
        Self
    }

    pub fn encode(&self) -> Envelope {
        Envelope::new(tags::FORCE_KEYFRAME, Bytes::new())
    }

    pub fn decode(envelope: &Envelope) -> Option<Self> {
        if envelope.tag == tags::FORCE_KEYFRAME && envelope.payload.is_empty() {
            Some(Self)
        } else {
            None
        }
    }
}

/// Backpressure update envelope
#[derive(Clone, Debug, PartialEq)]
pub struct BackpressureUpdateEnvelope {
    pub level: u8,
}

impl BackpressureUpdateEnvelope {
    pub fn new(level: u8) -> Self {
        Self { level }
    }

    pub fn encode(&self) -> Envelope {
        let mut payload = BytesMut::with_capacity(1);
        payload.put_u8(self.level);
        Envelope::new(tags::BACKPRESSURE_UPDATE, payload.freeze())
    }

    pub fn decode(envelope: &Envelope) -> Option<Self> {
        if envelope.tag == tags::BACKPRESSURE_UPDATE && envelope.payload.len() == 1 {
            let level = envelope.payload[0];
            Some(Self { level })
        } else {
            None
        }
    }
}

/// Error message envelope
#[derive(Clone, Debug, PartialEq)]
pub struct ErrorMessageEnvelope {
    pub message: String,
}

impl ErrorMessageEnvelope {
    pub fn new(message: String) -> Self {
        Self { message }
    }

    pub fn encode(&self) -> Envelope {
        let payload = Bytes::from(self.message.clone());
        Envelope::new(tags::ERROR_MESSAGE, payload)
    }

    pub fn decode(envelope: &Envelope) -> Option<Self> {
        if envelope.tag == tags::ERROR_MESSAGE {
            let message = String::from_utf8_lossy(&envelope.payload).to_string();
            Some(Self { message })
        } else {
            None
        }
    }
}

/// Heartbeat envelope
#[derive(Clone, Debug, PartialEq)]
pub struct HeartbeatEnvelope;

impl HeartbeatEnvelope {
    pub fn new() -> Self {
        Self
    }

    pub fn encode(&self) -> Envelope {
        Envelope::new(tags::HEARTBEAT, Bytes::new())
    }

    pub fn decode(envelope: &Envelope) -> Option<Self> {
        if envelope.tag == tags::HEARTBEAT && envelope.payload.is_empty() {
            Some(Self)
        } else {
            None
        }
    }
}

/// Control envelope enum for session layer convenience
#[derive(Clone, Debug, PartialEq)]
pub enum ControlEnvelope {
    Backpressure { level: BackpressureLevel },
    RequestKeyframe,
}

impl ControlEnvelope {
    pub fn encode(&self) -> Envelope {
        match self {
            ControlEnvelope::Backpressure { level } => {
                BackpressureUpdateEnvelope::new(level.to_u8()).encode()
            }
            ControlEnvelope::RequestKeyframe => {
                ForceKeyframeEnvelope::new().encode()
            }
        }
    }
}
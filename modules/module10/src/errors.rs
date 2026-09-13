use std::fmt;

#[derive(Debug)]
pub enum InputControlError {
    UnknownMessageType(u8),
    UnsupportedVersion(u8),
    Malformed,
    Oversize,
    InvalidCoordinate,
    /// OS-level input injection failed (SendInput rejected the event, etc.).
    Injection(String),
}

impl fmt::Display for InputControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputControlError::UnknownMessageType(t) => write!(f, "Unknown message type: {}", t),
            InputControlError::UnsupportedVersion(v) => write!(f, "Unsupported version: {}", v),
            InputControlError::Malformed => write!(f, "Malformed message"),
            InputControlError::Oversize => write!(f, "Oversized payload"),
            InputControlError::InvalidCoordinate => write!(f, "Invalid coordinate range"),
            InputControlError::Injection(e) => write!(f, "Injection error: {}", e),
        }
    }
}

impl std::error::Error for InputControlError {}
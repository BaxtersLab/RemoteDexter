//! Backpressure level definitions

/// Backpressure levels for transport flow control
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackpressureLevel {
    /// Transport is ready to accept data
    Ready = 0,
    /// Transport is congested, slow down sending
    Congested = 1,
    /// Transport is severely backlogged, pause sending
    Pause = 2,
}

impl BackpressureLevel {
    /// Convert from u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ready),
            1 => Some(Self::Congested),
            2 => Some(Self::Pause),
            _ => None,
        }
    }

    /// Convert to u8 value
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Check if this level allows sending
    pub fn can_send(self) -> bool {
        matches!(self, Self::Ready | Self::Congested)
    }

    /// Check if this level requires pausing
    pub fn should_pause(self) -> bool {
        matches!(self, Self::Pause)
    }
}
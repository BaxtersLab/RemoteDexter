//! Transport error definitions

use std::io;
use thiserror::Error;

/// Transport layer errors
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Frame size {size} exceeds maximum {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("Frame size {size} below minimum {min}")]
    FrameTooSmall { size: usize, min: usize },

    #[error("CRC32 mismatch: expected {expected:08x}, got {actual:08x}")]
    CrcMismatch { expected: u32, actual: u32 },

    #[error("Invalid envelope tag: {tag}")]
    InvalidTag { tag: u8 },

    #[error("Unexpected EOF while reading frame")]
    UnexpectedEof,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Backpressure timeout")]
    BackpressureTimeout,

    #[error("Invalid backpressure level: {level}")]
    InvalidBackpressureLevel { level: u8 },

    #[error("Transport protocol error: {message}")]
    ProtocolError { message: String },
}
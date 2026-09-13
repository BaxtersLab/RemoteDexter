//! Types for Module 11: Delta Engine

use thiserror::Error;

#[derive(Clone)]
pub struct RawFrame {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone)]
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub is_keyframe: bool,
    pub rect: Option<DirtyRect>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DirtyRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChromaSubsampling {
    Yuv420,
    Yuv444,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BitratePreset {
    Fast,
    Medium,
    Slow,
    Auto,
    Thermal,
}

#[derive(Clone, Debug)]
pub enum ScreenStreamControl {
    SetBitratePreset(BitratePreset),
    RequestKeyframe,
    Pause,
    Resume,
}

#[derive(Error, Debug)]
pub enum StreamError {
    #[error("Platform capture permission denied or failed")]
    CaptureFailed,
    #[error("CPU Encoding failed")]
    EncodeFailed,
    #[error("Multiplexer backpressure")]
    MuxerCongested,
}
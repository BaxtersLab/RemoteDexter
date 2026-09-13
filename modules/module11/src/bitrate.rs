//! Bitrate management utilities for Module 11

use crate::types::{BitratePreset, ChromaSubsampling};

/// Encoder parameters derived from bitrate preset
#[derive(Debug, Clone, Copy)]
pub struct EncoderParams {
    pub fps: u32,
    pub quality: u8,
    pub chroma: ChromaSubsampling,
}

impl EncoderParams {
    /// Get encoder parameters for a given bitrate preset
    pub fn from_preset(preset: BitratePreset) -> Self {
        match preset {
            BitratePreset::Fast => Self {
                fps: 30,
                quality: 60,
                chroma: ChromaSubsampling::Yuv420,
            },
            BitratePreset::Medium => Self {
                fps: 30,
                quality: 75,
                chroma: ChromaSubsampling::Yuv420,
            },
            BitratePreset::Slow => Self {
                fps: 15,
                quality: 90,
                chroma: ChromaSubsampling::Yuv444,
            },
            BitratePreset::Auto => Self {
                fps: 25,
                quality: 80,
                chroma: ChromaSubsampling::Yuv420,
            },
            BitratePreset::Thermal => Self {
                fps: 10,
                quality: 50,
                chroma: ChromaSubsampling::Yuv420,
            },
        }
    }

    /// Get FPS for a preset
    pub fn fps_for_preset(preset: BitratePreset) -> u32 {
        Self::from_preset(preset).fps
    }

    /// Get quality for a preset
    pub fn quality_for_preset(preset: BitratePreset) -> u8 {
        Self::from_preset(preset).quality
    }

    /// Get chroma subsampling for a preset
    pub fn chroma_for_preset(preset: BitratePreset) -> ChromaSubsampling {
        Self::from_preset(preset).chroma
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChromaSubsampling;

    #[test]
    fn fast_preset_params() {
        let params = EncoderParams::from_preset(BitratePreset::Fast);
        assert_eq!(params.fps, 30);
        assert_eq!(params.quality, 60);
        assert_eq!(params.chroma, ChromaSubsampling::Yuv420);
    }

    #[test]
    fn thermal_preset_params() {
        let params = EncoderParams::from_preset(BitratePreset::Thermal);
        assert_eq!(params.fps, 10);
        assert_eq!(params.quality, 50);
        assert_eq!(params.chroma, ChromaSubsampling::Yuv420);
    }

    #[test]
    fn slow_preset_uses_yuv444() {
        let params = EncoderParams::from_preset(BitratePreset::Slow);
        assert_eq!(params.chroma, ChromaSubsampling::Yuv444);
    }

    #[test]
    fn helper_functions_match_struct() {
        for &preset in &[BitratePreset::Fast, BitratePreset::Medium, BitratePreset::Slow, BitratePreset::Auto, BitratePreset::Thermal] {
            let params = EncoderParams::from_preset(preset);
            assert_eq!(EncoderParams::fps_for_preset(preset), params.fps);
            assert_eq!(EncoderParams::quality_for_preset(preset), params.quality);
            assert_eq!(EncoderParams::chroma_for_preset(preset), params.chroma);
        }
    }
}
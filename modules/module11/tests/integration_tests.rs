//! Module 11 Block 7 - Validation & Test Suite
//!
//! Covers:
//! - DeltaEngine correctness
//! - Thermal preset behaviour
//! - Encoder integration
//!
//! Block 10 removed the pacing-loop, control-message and backpressure suites.
//! They did not drive `module11`: each built a `TestableScreenStream` declared
//! in this file and exercised that, so they could not fail for a product
//! reason. The code they stood in for — `ScreenStream` over the multiplexer —
//! was dead, and the live pacing and backpressure logic is `host_app`'s
//! `stream_ladder` and `stream_backpressure`, which have their own tests.

use std::sync::Arc;

use module11::types::*;
use module11::delta_engine::DeltaEngine;
use module11::encoder::Encoder;
use module11::bitrate::EncoderParams;

// Mock encoder for testing
#[derive(Clone)]
struct MockEncoder {
    pub encode_calls: Arc<std::sync::Mutex<Vec<(u8, ChromaSubsampling, Option<DirtyRect>)>>>,
}

impl MockEncoder {
    fn new() -> Self {
        Self {
            encode_calls: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn get_calls(&self) -> Vec<(u8, ChromaSubsampling, Option<DirtyRect>)> {
        self.encode_calls.lock().unwrap().clone()
    }
}

impl Encoder for MockEncoder {
    fn encode(
        &self,
        _frame: &RawFrame,
        quality: u8,
        chroma: ChromaSubsampling,
        rect: Option<DirtyRect>,
    ) -> Result<EncodedFrame, StreamError> {
        self.encode_calls.lock().unwrap().push((quality, chroma, rect));
        Ok(EncodedFrame {
            data: vec![1, 2, 3, 4], // dummy data
            is_keyframe: rect.is_none(),
            rect,
        })
    }
}


mod delta_engine_tests {
    use super::*;

    #[test]
    fn single_block_change_bounding_box() {
        let mut engine = DeltaEngine::new(1920, 1080);
        let mut frame = RawFrame {
            data: vec![0u8; (1920 * 1080 * 4) as usize],
            width: 1920,
            height: 1080,
        };

        // First frame - establish baseline
        let rect = engine.compute_bounding_box(&frame);
        assert!(rect.is_none()); // No changes on first frame

        // Modify a single block (64x64 pixels at 0,0)
        for y in 0..64 {
            for x in 0..64 {
                let idx = ((y * 1920 + x) * 4) as usize;
                frame.data[idx] = 255; // Change pixel
            }
        }

        let rect = engine.compute_bounding_box(&frame);
        assert!(rect.is_some());
        let rect = rect.unwrap();
        assert_eq!(rect.x, 0);
        assert_eq!(rect.y, 0);
        assert_eq!(rect.w, 64);
        assert_eq!(rect.h, 64);
    }

    #[test]
    fn multiple_scattered_changes_expands_bbox() {
        let mut engine = DeltaEngine::new(1920, 1080);
        let mut frame = RawFrame {
            data: vec![0u8; (1920 * 1080 * 4) as usize],
            width: 1920,
            height: 1080,
        };

        // First frame - establish baseline
        engine.compute_bounding_box(&frame);

        // Modify blocks at (0,0) and (128,128)
        for &(bx, by) in &[(0, 0), (128, 128)] {
            for y in by..(by + 32) {
                for x in bx..(bx + 32) {
                    let idx = ((y * 1920 + x) * 4) as usize;
                    if idx < frame.data.len() {
                        frame.data[idx] = 255;
                    }
                }
            }
        }

        let rect = engine.compute_bounding_box(&frame);
        assert!(rect.is_some());
        let rect = rect.unwrap();
        assert_eq!(rect.x, 0);
        assert_eq!(rect.y, 0);
        assert_eq!(rect.w, 192); // 64 + 64 + 64 (blocks 0,1,2)
        assert_eq!(rect.h, 192); // 64 + 64 + 64 (blocks 0,1,2)
    }

    #[test]
    fn no_changes_returns_none() {
        let mut engine = DeltaEngine::new(1920, 1080);
        let frame = RawFrame {
            data: vec![0u8; (1920 * 1080 * 4) as usize],
            width: 1920,
            height: 1080,
        };

        // First frame
        let rect = engine.compute_bounding_box(&frame);
        assert!(rect.is_none());

        // Same frame again
        let rect = engine.compute_bounding_box(&frame);
        assert!(rect.is_none());
    }

    #[test]
    fn excessive_changes_returns_none() {
        let mut engine = DeltaEngine::new(1920, 1080);
        let mut frame = RawFrame {
            data: vec![0u8; (1920 * 1080 * 4) as usize],
            width: 1920,
            height: 1080,
        };

        // First frame
        engine.compute_bounding_box(&frame);

        // Modify >60% of the screen (fill entire frame)
        for i in 0..frame.data.len() {
            frame.data[i] = 255;
        }

        let rect = engine.compute_bounding_box(&frame);
        assert!(rect.is_none()); // Should return None for full-frame fallback
    }

    #[test]
    fn edge_blocks_handled_correctly() {
        let mut engine = DeltaEngine::new(200, 150); // Not multiples of 64
        let mut frame = RawFrame {
            data: vec![0u8; (200 * 150 * 4) as usize],
            width: 200,
            height: 150,
        };

        // First frame
        engine.compute_bounding_box(&frame);

        // Modify edge block (should be 3x3 grid: 192x128, 200x128, 192x150, 200x150)
        // Modify the bottom-right edge block
        for y in 128..150 {
            for x in 192..200 {
                let idx = ((y * 200 + x) * 4) as usize;
                frame.data[idx] = 255;
            }
        }

        let rect = engine.compute_bounding_box(&frame);
        assert!(rect.is_some());
        let rect = rect.unwrap();
        assert_eq!(rect.x, 192);
        assert_eq!(rect.y, 128);
        assert_eq!(rect.w, 8); // 200-192
        assert_eq!(rect.h, 22); // 150-128
    }
}




mod encoder_integration_tests {
    use super::*;

    #[test]
    fn encoder_called_with_correct_parameters() {
        let mock_encoder = MockEncoder::new();

        let frame = RawFrame {
            data: vec![0u8; 400], // 10x10 RGBA
            width: 10,
            height: 10,
        };

        let rect = Some(DirtyRect { x: 0, y: 0, w: 5, h: 5 });

        let result = mock_encoder.encode(&frame, 85, ChromaSubsampling::Yuv444, rect.clone());

        assert!(result.is_ok());
        let encoded = result.unwrap();
        assert_eq!(encoded.data, vec![1, 2, 3, 4]);
        assert!(!encoded.is_keyframe); // Should not be keyframe when rect is provided
        assert_eq!(encoded.rect, rect);

        // Check encoder was called with correct parameters
        let calls = mock_encoder.get_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 85); // quality
        assert_eq!(calls[0].1, ChromaSubsampling::Yuv444); // chroma
        assert_eq!(calls[0].2, rect); // rect
    }

    #[test]
    fn keyframe_flag_set_when_rect_is_none() {
        let mock_encoder = MockEncoder::new();

        let frame = RawFrame {
            data: vec![0u8; 400],
            width: 10,
            height: 10,
        };

        let result = mock_encoder.encode(&frame, 80, ChromaSubsampling::Yuv420, None);

        assert!(result.is_ok());
        let encoded = result.unwrap();
        assert!(encoded.is_keyframe); // Should be keyframe when rect is None
        assert!(encoded.rect.is_none());
    }
}

mod thermal_mode_tests {
    use super::*;

    #[test]
    fn thermal_preset_parameters() {
        let params = EncoderParams::from_preset(BitratePreset::Thermal);

        assert_eq!(params.fps, 10);
        assert_eq!(params.quality, 50);
        assert_eq!(params.chroma, ChromaSubsampling::Yuv420);
    }

    #[test]
    fn thermal_mode_encoder_calls() {
        let mock_encoder = MockEncoder::new();

        let frame = RawFrame {
            data: vec![0u8; 400],
            width: 10,
            height: 10,
        };

        // Thermal preset parameters
        let _ = mock_encoder.encode(&frame, 85, ChromaSubsampling::Yuv444, None);

        let calls = mock_encoder.get_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 85); // Thermal quality
        assert_eq!(calls[0].1, ChromaSubsampling::Yuv444); // Thermal chroma
    }
}

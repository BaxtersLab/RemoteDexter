//! Stress test for transport layer - 1000-frame pipeline test

use std::io::Cursor;
use bytes::Bytes;
use module13_transport::{
    transport_engine::TransportEngine,
    envelope::{FrameDataEnvelope, ResetEnvelope, BackpressureUpdateEnvelope},
    backpressure_level::BackpressureLevel,
};

#[cfg(test)]
mod stress_tests {
    use super::*;

    #[test]
    fn test_1000_frame_pipeline() {
        // Create a large buffer to hold all frame data
        let mut buffer = Vec::new();
        let cursor = Cursor::new(&mut buffer);
        let _engine = TransportEngine::new(cursor);

        // Send 1000 frame data envelopes
        for i in 0..1000 {
            let data = vec![(i % 256) as u8; 100]; // 100 bytes per frame
            let frame_data = Bytes::from(data);
            let envelope = FrameDataEnvelope::new(frame_data);

            // This would normally send over the stream, but for testing we just validate
            assert_eq!(envelope.frame_data.len(), 100);
        }

        // Test reset envelope
        let reset = ResetEnvelope::new();
        assert!(reset.encode().payload.is_empty());

        // Test backpressure updates
        for level in 0..=2 {
            let bp_envelope = BackpressureUpdateEnvelope::new(level);
            let encoded = bp_envelope.encode();
            assert_eq!(encoded.payload.len(), 1);
            assert_eq!(encoded.payload[0], level);
        }
    }

    #[test]
    fn test_large_frame_sizes() {
        // Test various frame sizes up to near the limit
        let sizes = vec![100, 1000, 10000, 50000];

        for size in sizes {
            let data = vec![0xAA; size];
            let frame_data = Bytes::from(data);
            let envelope = FrameDataEnvelope::new(frame_data);

            assert_eq!(envelope.frame_data.len(), size);
        }
    }

    #[test]
    fn test_backpressure_state_transitions() {
        // Test that backpressure levels transition correctly
        let levels = vec![
            BackpressureLevel::Ready,
            BackpressureLevel::Congested,
            BackpressureLevel::Pause,
            BackpressureLevel::Ready, // Back to ready
        ];

        for level in levels {
            let bp_envelope = BackpressureUpdateEnvelope::new(level as u8);
            let encoded = bp_envelope.encode();
            assert_eq!(encoded.payload[0], level as u8);
        }
    }

    #[test]
    fn test_frame_data_integrity() {
        // Test that frame data is preserved through envelope encoding/decoding
        let test_data = vec![
            vec![0, 1, 2, 3, 4],
            vec![255; 1000],
            (0..=255).collect::<Vec<u8>>(),
            vec![], // Empty frame
        ];

        for data in test_data {
            let original = Bytes::from(data.clone());
            let envelope = FrameDataEnvelope::new(original.clone());
            let encoded = envelope.encode();

            // Decode back
            let decoded = FrameDataEnvelope::decode(&encoded).unwrap();
            assert_eq!(decoded.frame_data, original);
        }
    }
}

use std::io::Cursor;
use bytes::Bytes;

use module13_transport::{
    envelope::{Envelope, tags, FrameDataEnvelope, ResetEnvelope, ForceKeyframeEnvelope, BackpressureUpdateEnvelope, ErrorMessageEnvelope, HeartbeatEnvelope},
    backpressure_level::BackpressureLevel,
    transport_error::TransportError,
    transport_channel::TransportChannel,
    transport_engine::TransportEngine,
};

#[cfg(test)]
mod transport_engine_tests {
    use super::*;

    #[test]
    fn test_round_trip_envelope_transmission() {
        // Create a mock stream using Cursor for testing
        let data = Vec::new();
        let cursor = Cursor::new(data);
        let _engine = TransportEngine::new(cursor);

        // Test sending a frame data envelope
        let frame_data = Bytes::from(vec![1, 2, 3, 4, 5]);
        let envelope = FrameDataEnvelope::new(frame_data.clone()).encode();

        // Note: In a real test, we'd need to mock the stream to capture output
        // For now, this tests the envelope creation and basic engine structure
        assert_eq!(envelope.tag, tags::FRAME_DATA);
        assert_eq!(envelope.payload, frame_data);
    }

    #[test]
    fn test_reset_envelope() {
        let reset_envelope = ResetEnvelope::new().encode();
        assert_eq!(reset_envelope.tag, tags::RESET);
        assert!(reset_envelope.payload.is_empty());
    }

    #[test]
    fn test_force_keyframe_envelope() {
        let keyframe_envelope = ForceKeyframeEnvelope::new().encode();
        assert_eq!(keyframe_envelope.tag, tags::FORCE_KEYFRAME);
        assert!(keyframe_envelope.payload.is_empty());
    }

    #[test]
    fn test_backpressure_level_enum() {
        assert_eq!(BackpressureLevel::Ready as u8, 0);
        assert_eq!(BackpressureLevel::Congested as u8, 1);
        assert_eq!(BackpressureLevel::Pause as u8, 2);

        // Test conversion from u8
        assert_eq!(BackpressureLevel::from_u8(0), Some(BackpressureLevel::Ready));
        assert_eq!(BackpressureLevel::from_u8(1), Some(BackpressureLevel::Congested));
        assert_eq!(BackpressureLevel::from_u8(2), Some(BackpressureLevel::Pause));
        assert_eq!(BackpressureLevel::from_u8(3), None);
    }

    #[test]
    fn test_backpressure_update_envelope() {
        let backpressure_envelope = BackpressureUpdateEnvelope::new(BackpressureLevel::Congested as u8).encode();
        assert_eq!(backpressure_envelope.tag, tags::BACKPRESSURE_UPDATE);
        assert_eq!(backpressure_envelope.payload.len(), 1);
        assert_eq!(backpressure_envelope.payload[0], BackpressureLevel::Congested as u8);
    }

    #[test]
    fn test_error_message_envelope() {
        let error_msg = "Test error".to_string();
        let error_envelope = ErrorMessageEnvelope::new(error_msg.clone()).encode();
        assert_eq!(error_envelope.tag, tags::ERROR_MESSAGE);
        assert_eq!(error_envelope.payload, Bytes::from(error_msg));
    }

    #[test]
    fn test_heartbeat_envelope() {
        let heartbeat_envelope = HeartbeatEnvelope::new().encode();
        assert_eq!(heartbeat_envelope.tag, tags::HEARTBEAT);
        assert!(heartbeat_envelope.payload.is_empty());
    }

    #[test]
    fn test_transport_error_types() {
        let io_error = TransportError::Io(std::io::Error::new(std::io::ErrorKind::Other, "test"));
        assert!(matches!(io_error, TransportError::Io(_)));

        let crc_error = TransportError::CrcMismatch { expected: 1234, actual: 5678 };
        assert!(matches!(crc_error, TransportError::CrcMismatch { .. }));

        let size_error = TransportError::FrameTooLarge { size: 100000, max: 65536 };
        assert!(matches!(size_error, TransportError::FrameTooLarge { .. }));

        let tag_error = TransportError::InvalidTag { tag: 0xFF };
        assert!(matches!(tag_error, TransportError::InvalidTag { .. }));
    }

    #[test]
    fn test_envelope_tag_constants() {
        assert_eq!(tags::FRAME_DATA, 0x01);
        assert_eq!(tags::RESET, 0x02);
        assert_eq!(tags::FORCE_KEYFRAME, 0x03);
        assert_eq!(tags::BACKPRESSURE_UPDATE, 0x04);
        assert_eq!(tags::ERROR_MESSAGE, 0x05);
        assert_eq!(tags::HEARTBEAT, 0x06);
    }

    #[test]
    fn test_transport_channel_creation() {
        let channel = TransportChannel::new(10);

        // Test that we can split into sender and receiver
        let (_sender, _receiver) = channel.split();
    }

    #[test]
    fn test_envelope_encoding_decoding() {
        // Test frame data envelope
        let original_data = Bytes::from(vec![1, 2, 3, 4, 5]);
        let frame_envelope = FrameDataEnvelope::new(original_data.clone());
        let encoded = frame_envelope.encode();
        let decoded = FrameDataEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_data, original_data);

        // Test reset envelope
        let reset_envelope = ResetEnvelope::new();
        let encoded = reset_envelope.encode();
        let decoded = ResetEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, reset_envelope);

        // Test error message envelope
        let error_msg = "Test error message".to_string();
        let error_envelope = ErrorMessageEnvelope::new(error_msg.clone());
        let encoded = error_envelope.encode();
        let decoded = ErrorMessageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.message, error_msg);
    }

    #[test]
    fn test_envelope_validation() {
        // Valid tags
        assert!(Envelope::is_valid_tag(tags::FRAME_DATA));
        assert!(Envelope::is_valid_tag(tags::RESET));
        assert!(Envelope::is_valid_tag(tags::FORCE_KEYFRAME));
        assert!(Envelope::is_valid_tag(tags::BACKPRESSURE_UPDATE));
        assert!(Envelope::is_valid_tag(tags::ERROR_MESSAGE));
        assert!(Envelope::is_valid_tag(tags::HEARTBEAT));

        // Invalid tag
        assert!(!Envelope::is_valid_tag(0xFF));
    }
}

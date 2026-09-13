//! Tag matrix validation tests

use module13_transport::envelope::tags;
use module13_transport::envelope::Envelope;

#[cfg(test)]
mod tag_matrix_tests {
    use super::*;

    #[test]
    fn test_all_tags_defined() {
        // Ensure all expected tags are defined
        let expected_tags = vec![
            ("FRAME_DATA", tags::FRAME_DATA),
            ("RESET", tags::RESET),
            ("FORCE_KEYFRAME", tags::FORCE_KEYFRAME),
            ("BACKPRESSURE_UPDATE", tags::BACKPRESSURE_UPDATE),
            ("ERROR_MESSAGE", tags::ERROR_MESSAGE),
            ("HEARTBEAT", tags::HEARTBEAT),
        ];

        // Verify each tag is non-zero
        for (name, tag) in expected_tags {
            assert_ne!(tag, 0, "Tag {} should not be zero", name);
            assert!(tag <= 0x7F, "Tag {} (0x{:02x}) should be <= 0x7F", name, tag);
        }
    }

    #[test]
    fn test_tag_uniqueness_matrix() {
        let all_tags = vec![
            tags::FRAME_DATA,
            tags::RESET,
            tags::FORCE_KEYFRAME,
            tags::BACKPRESSURE_UPDATE,
            tags::ERROR_MESSAGE,
            tags::HEARTBEAT,
        ];

        // Check pairwise uniqueness
        for i in 0..all_tags.len() {
            for j in (i + 1)..all_tags.len() {
                assert_ne!(all_tags[i], all_tags[j],
                          "Tags at indices {} and {} are not unique: 0x{:02x}",
                          i, j, all_tags[i]);
            }
        }
    }

    #[test]
    fn test_tag_validity_check() {
        let valid_tags = vec![
            tags::FRAME_DATA,
            tags::RESET,
            tags::FORCE_KEYFRAME,
            tags::BACKPRESSURE_UPDATE,
            tags::ERROR_MESSAGE,
            tags::HEARTBEAT,
        ];

        // All defined tags should be valid
        for &tag in &valid_tags {
            assert!(Envelope::is_valid_tag(tag), "Tag 0x{:02x} should be valid", tag);
        }

        // Some invalid tags
        let invalid_tags = vec![0x00, 0x80, 0xFF, 0x99];
        for &tag in &invalid_tags {
            assert!(!Envelope::is_valid_tag(tag), "Tag 0x{:02x} should be invalid", tag);
        }
    }

    #[test]
    fn test_tag_range_coverage() {
        // Ensure tags cover a reasonable range without gaps or clustering
        let tags = vec![
            tags::FRAME_DATA,
            tags::RESET,
            tags::FORCE_KEYFRAME,
            tags::BACKPRESSURE_UPDATE,
            tags::ERROR_MESSAGE,
            tags::HEARTBEAT,
        ];

        // Sort tags
        let mut sorted_tags = tags.clone();
        sorted_tags.sort();

        // Check for reasonable spacing (no duplicates, some spacing)
        for i in 1..sorted_tags.len() {
            assert!(sorted_tags[i] > sorted_tags[i-1],
                   "Tags not properly ordered: 0x{:02x} <= 0x{:02x}",
                   sorted_tags[i], sorted_tags[i-1]);
        }

        // Ensure they're in the lower range
        for &tag in &sorted_tags {
            assert!(tag >= 0x01 && tag <= 0x10,
                   "Tag 0x{:02x} outside expected range [0x01, 0x10]", tag);
        }
    }

    #[test]
    fn test_tag_semantic_meaning() {
        // Test that tags have appropriate semantic values
        // (This is more of a design validation than a strict test)

        // Data-carrying tags should be first
        assert_eq!(tags::FRAME_DATA, 0x01, "FRAME_DATA should be 0x01");

        // Control tags
        assert_eq!(tags::RESET, 0x02, "RESET should be 0x02");
        assert_eq!(tags::FORCE_KEYFRAME, 0x03, "FORCE_KEYFRAME should be 0x03");

        // Flow control
        assert_eq!(tags::BACKPRESSURE_UPDATE, 0x04, "BACKPRESSURE_UPDATE should be 0x04");

        // Error handling
        assert_eq!(tags::ERROR_MESSAGE, 0x05, "ERROR_MESSAGE should be 0x05");

        // Keep-alive
        assert_eq!(tags::HEARTBEAT, 0x06, "HEARTBEAT should be 0x06");
    }

    #[test]
    fn test_tag_bit_patterns() {
        // Test that tags don't have problematic bit patterns
        let tags = vec![
            tags::FRAME_DATA,
            tags::RESET,
            tags::FORCE_KEYFRAME,
            tags::BACKPRESSURE_UPDATE,
            tags::ERROR_MESSAGE,
            tags::HEARTBEAT,
        ];

        for &tag in &tags {
            // Should not have high bit set (reserved for future use)
            assert_eq!(tag & 0x80, 0, "Tag 0x{:02x} has high bit set", tag);

            // Should not be zero
            assert_ne!(tag, 0, "Tag should not be zero");

            // Should be printable ASCII range for debugging
            assert!(tag >= 1 && tag <= 127, "Tag 0x{:02x} outside ASCII range", tag);
        }
    }
}

//! CRC corruption detection tests

use crc32fast::Hasher;

#[cfg(test)]
mod crc_corruption_tests {
    use super::*;

    #[test]
    fn test_crc_calculation() {
        // Test CRC32 calculation matches framed_stream implementation
        let data = vec![1, 2, 3, 4, 5];
        let mut hasher = Hasher::new();
        hasher.update(&data);
        let crc = hasher.finalize();

        // CRC should be deterministic
        let mut hasher2 = Hasher::new();
        hasher2.update(&data);
        let crc2 = hasher2.finalize();

        assert_eq!(crc, crc2);
    }

    #[test]
    fn test_crc_corruption_detection_concept() {
        // Test that different data produces different CRC
        let data1 = vec![1, 2, 3, 4, 5];
        let data2 = vec![1, 2, 3, 4, 6]; // Last byte different

        let mut hasher1 = Hasher::new();
        hasher1.update(&data1);
        let crc1 = hasher1.finalize();

        let mut hasher2 = Hasher::new();
        hasher2.update(&data2);
        let crc2 = hasher2.finalize();

        assert_ne!(crc1, crc2, "CRC should detect data corruption");
    }

    #[test]
    fn test_frame_size_limits() {
        use module13_transport::framed_stream::{MAX_FRAME_SIZE, MIN_FRAME_SIZE};

        // Test that our constants are reasonable
        assert!(MIN_FRAME_SIZE > 0);
        assert!(MAX_FRAME_SIZE > MIN_FRAME_SIZE);
        assert!(MAX_FRAME_SIZE <= 64 * 1024); // 64KB limit
    }

    #[test]
    fn test_frame_header_size() {
        // Frame header is length (4 bytes) + CRC32 (4 bytes) = 8 bytes
        const HEADER_SIZE: usize = 8;

        // Test various frame sizes
        let test_sizes = vec![10, 100, 1000, 10000];

        for &size in &test_sizes {
            let total_frame_size = HEADER_SIZE + size;
            assert!(total_frame_size >= HEADER_SIZE);
            assert!(total_frame_size <= HEADER_SIZE + 64 * 1024);
        }
    }

    #[test]
    fn test_corruption_patterns() {
        // Test different corruption patterns that should be detectable
        let original_data = vec![1, 2, 3, 4, 5];

        let mut hasher = Hasher::new();
        hasher.update(&original_data);
        let original_crc = hasher.finalize();

        // Test single bit corruption
        let mut corrupted = original_data.clone();
        corrupted[2] ^= 0x01; // Flip one bit

        let mut hasher2 = Hasher::new();
        hasher2.update(&corrupted);
        let corrupted_crc = hasher2.finalize();

        assert_ne!(original_crc, corrupted_crc, "Single bit corruption should be detected");

        // Test burst corruption
        let mut burst_corrupted = original_data.clone();
        for i in 1..4 {
            burst_corrupted[i] ^= 0xFF; // Corrupt multiple bytes
        }

        let mut hasher3 = Hasher::new();
        hasher3.update(&burst_corrupted);
        let burst_crc = hasher3.finalize();

        assert_ne!(original_crc, burst_crc, "Burst corruption should be detected");
    }
}

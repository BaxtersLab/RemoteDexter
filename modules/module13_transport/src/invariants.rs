//! Transport layer invariants and validation

use crate::envelope::tags;

/// Validate that all envelope tags are unique
pub fn validate_tag_uniqueness() -> Result<(), String> {
    let tags = vec![
        tags::FRAME_DATA,
        tags::RESET,
        tags::FORCE_KEYFRAME,
        tags::BACKPRESSURE_UPDATE,
        tags::ERROR_MESSAGE,
        tags::HEARTBEAT,
        tags::CLIPBOARD_UPDATE,
        tags::SCREENSHOT_REQUEST,
        tags::NEGOTIATION,
        tags::AGENT2_COMMAND,
    ];

    let mut seen = std::collections::HashSet::new();
    for tag in tags {
        if !seen.insert(tag) {
            return Err(format!("Duplicate tag found: 0x{:02x}", tag));
        }
    }

    Ok(())
}

/// Validate that all tags are within valid range (1-255)
pub fn validate_tag_range() -> Result<(), String> {
    let tags = vec![
        tags::FRAME_DATA,
        tags::RESET,
        tags::FORCE_KEYFRAME,
        tags::BACKPRESSURE_UPDATE,
        tags::ERROR_MESSAGE,
        tags::HEARTBEAT,
        tags::CLIPBOARD_UPDATE,
        tags::SCREENSHOT_REQUEST,
        tags::NEGOTIATION,
        tags::AGENT2_COMMAND,
    ];

    for &tag in &tags {
        if tag == 0 {
            return Err("Tag cannot be zero".to_string());
        }
        if tag > 0x7F {
            return Err(format!("Tag 0x{:02x} is in reserved range (> 0x7F)", tag));
        }
    }

    Ok(())
}

/// Validate frame size limits
pub fn validate_frame_limits() -> Result<(), String> {
    use crate::framed_stream::{MAX_FRAME_SIZE, MIN_FRAME_SIZE};

    if MIN_FRAME_SIZE >= MAX_FRAME_SIZE {
        return Err(format!("MIN_FRAME_SIZE ({}) >= MAX_FRAME_SIZE ({})",
                          MIN_FRAME_SIZE, MAX_FRAME_SIZE));
    }

    if MIN_FRAME_SIZE < 8 {
        return Err(format!("MIN_FRAME_SIZE ({}) too small, must be at least 8 bytes",
                          MIN_FRAME_SIZE));
    }

    if MAX_FRAME_SIZE > 64 * 1024 {
        return Err(format!("MAX_FRAME_SIZE ({}) exceeds 64KB limit",
                          MAX_FRAME_SIZE));
    }

    Ok(())
}

/// Validate backpressure level mappings
pub fn validate_backpressure_levels() -> Result<(), String> {
    use crate::backpressure_level::BackpressureLevel;

    // Test all valid levels
    for level in 0..=2 {
        if BackpressureLevel::from_u8(level).is_none() {
            return Err(format!("Backpressure level {} not mapped", level));
        }
    }

    // Test invalid level
    if BackpressureLevel::from_u8(255).is_some() {
        return Err("Invalid backpressure level 255 should not be mapped".to_string());
    }

    Ok(())
}

/// Run all transport layer invariants
pub fn run_all_invariants() -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if let Err(e) = validate_tag_uniqueness() {
        errors.push(format!("Tag uniqueness: {}", e));
    }

    if let Err(e) = validate_tag_range() {
        errors.push(format!("Tag range: {}", e));
    }

    if let Err(e) = validate_frame_limits() {
        errors.push(format!("Frame limits: {}", e));
    }

    if let Err(e) = validate_backpressure_levels() {
        errors.push(format!("Backpressure levels: {}", e));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_uniqueness() {
        assert!(validate_tag_uniqueness().is_ok());
    }

    #[test]
    fn test_tag_range() {
        assert!(validate_tag_range().is_ok());
    }

    #[test]
    fn test_frame_limits() {
        assert!(validate_frame_limits().is_ok());
    }

    #[test]
    fn test_backpressure_levels() {
        assert!(validate_backpressure_levels().is_ok());
    }

    #[test]
    fn test_all_invariants() {
        assert!(run_all_invariants().is_ok());
    }
}

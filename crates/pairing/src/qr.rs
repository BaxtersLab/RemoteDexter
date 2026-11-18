//! QR rendering — to pixels in memory, never to a file.
//!
//! The implementation this replaces wrote the QR to `/tmp/rdv3_invite_qr.png`
//! and opened it with `xdg-open`. Three problems with that, in ascending order
//! of seriousness: it depended on a desktop file association; it left a
//! credential on disk with whatever permissions the temp dir happened to have;
//! and a stale viewer window from a previous run kept displaying a dead token,
//! so the operator could scan a code that had already been replaced and get a
//! failure that looked nothing like "stale invite".
//!
//! This returns a bitmap. The host UI draws it. Nothing touches the filesystem.

/// A 1-bit-per-pixel QR bitmap, row-major, `true` = dark module.
pub struct QrBitmap {
    /// Side length in modules, including the quiet zone.
    pub size: usize,
    /// `size * size` booleans.
    pub modules: Vec<bool>,
}

impl QrBitmap {
    /// Is the module at `(x, y)` dark?
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.modules[y * self.size + x]
    }

    /// Expand to 8-bit greyscale at `scale` pixels per module, for a UI that
    /// wants a texture rather than modules. Still in memory.
    pub fn to_luma8(&self, scale: usize) -> (usize, Vec<u8>) {
        let scale = scale.max(1);
        let side = self.size * scale;
        let mut out = vec![255u8; side * side];
        for y in 0..self.size {
            for x in 0..self.size {
                if !self.is_dark(x, y) {
                    continue;
                }
                for dy in 0..scale {
                    for dx in 0..scale {
                        out[(y * scale + dy) * side + (x * scale + dx)] = 0;
                    }
                }
            }
        }
        (side, out)
    }
}

/// Encode `text` as a QR bitmap with a 4-module quiet zone.
///
/// The quiet zone is not decoration: without it many scanners simply fail, and
/// the failure looks like a bad invite rather than a bad render.
///
/// The code is the SMALLER of two encodings: the library's mixed-mode one and a
/// single byte-mode segment. The library's segment optimizer is not optimal —
/// measured 2026-09-17, it put a 560-byte payload with short digit runs at 113
/// modules where plain byte mode needs 97, and made 23-36% of real dual-route
/// invites a version larger than their length requires. Taking the smaller
/// means a code is never larger than byte mode for its length, which is a bound
/// the density tests can pin; mixed mode still wins where it genuinely helps.
pub fn encode(text: &str) -> Result<QrBitmap, String> {
    const QUIET: usize = 4;
    const EC: qrcode::EcLevel = qrcode::EcLevel::M;
    let mixed = qrcode::QrCode::with_error_correction_level(text, EC)
        .map_err(|e| format!("QR encode failed: {e}"))?;
    let code = match byte_mode(text.as_bytes(), EC) {
        Some(bytes) if bytes.width() < mixed.width() => bytes,
        _ => mixed,
    };
    let width = code.width();
    let colors = code.to_colors();
    let size = width + QUIET * 2;
    let mut modules = vec![false; size * size];
    for y in 0..width {
        for x in 0..width {
            let dark = colors[y * width + x] == qrcode::Color::Dark;
            modules[(y + QUIET) * size + (x + QUIET)] = dark;
        }
    }
    Ok(QrBitmap { size, modules })
}

/// `data` as ONE byte-mode segment at the smallest version that holds it, or
/// `None` if no version does.
fn byte_mode(data: &[u8], ec: qrcode::EcLevel) -> Option<qrcode::QrCode> {
    (1..=40).find_map(|v| {
        let mut bits = qrcode::bits::Bits::new(qrcode::Version::Normal(v));
        bits.push_byte_data(data).ok()?;
        bits.push_terminator(ec).ok()?;
        qrcode::QrCode::with_bits(bits, ec).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_has_a_quiet_zone() {
        let qr = encode("{\"kind\":\"remotedexter-pair\"}").unwrap();
        assert!(qr.size > 8);
        // Every module in the 4-wide border must be light, on all four sides.
        for i in 0..qr.size {
            for q in 0..4 {
                assert!(!qr.is_dark(i, q), "top quiet zone");
                assert!(!qr.is_dark(i, qr.size - 1 - q), "bottom quiet zone");
                assert!(!qr.is_dark(q, i), "left quiet zone");
                assert!(!qr.is_dark(qr.size - 1 - q, i), "right quiet zone");
            }
        }
    }

    #[test]
    fn a_finder_pattern_is_present() {
        // Top-left finder: dark 7x7 with a light ring, just inside the quiet
        // zone. If this is absent the bitmap is not a QR code whatever its size.
        let qr = encode("hello").unwrap();
        assert!(qr.is_dark(4, 4), "finder corner");
        assert!(qr.is_dark(10, 4), "finder runs 7 wide");
        assert!(!qr.is_dark(11, 4), "and stops");
    }

    #[test]
    fn scaling_preserves_the_pattern() {
        let qr = encode("hello").unwrap();
        let (side, px) = qr.to_luma8(3);
        assert_eq!(side, qr.size * 3);
        assert_eq!(px.len(), side * side);
        // The dark module at (4,4) becomes a 3x3 dark block at (12,12).
        assert_eq!(px[12 * side + 12], 0);
        assert_eq!(px[14 * side + 14], 0);
        // The quiet zone stays light.
        assert_eq!(px[0], 255);
    }

    /// Regression, 2026-09-17: the library's mixed-mode optimizer put this
    /// 560-byte payload at 113 modules. One byte-mode segment holds it in 97.
    #[test]
    fn a_payload_the_optimizer_inflates_is_drawn_at_its_byte_mode_size() {
        let text = &"ab1234".repeat(110)[..560];
        assert_eq!(encode(text).unwrap().size, 97);
    }

    /// And where mixed mode genuinely wins (97 against byte mode's 101), the
    /// smaller code is still the one drawn.
    #[test]
    fn mixed_mode_is_kept_where_it_is_the_smaller_code() {
        let text = &"0123456789abcdef".repeat(40)[..600];
        assert_eq!(encode(text).unwrap().size, 97);
    }

    #[test]
    fn oversized_input_is_refused_rather_than_truncated() {
        // A QR has a hard capacity. Silently encoding a prefix would produce a
        // scannable code carrying half an invite.
        let huge = "x".repeat(8000);
        assert!(encode(&huge).is_err());
    }
}

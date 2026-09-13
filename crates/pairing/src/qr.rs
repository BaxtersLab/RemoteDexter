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
pub fn encode(text: &str) -> Result<QrBitmap, String> {
    const QUIET: usize = 4;
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M)
        .map_err(|e| format!("QR encode failed: {e}"))?;
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

    #[test]
    fn oversized_input_is_refused_rather_than_truncated() {
        // A QR has a hard capacity. Silently encoding a prefix would produce a
        // scannable code carrying half an invite.
        let huge = "x".repeat(8000);
        assert!(encode(&huge).is_err());
    }
}

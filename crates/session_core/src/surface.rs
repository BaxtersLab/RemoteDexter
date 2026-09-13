//! What a host can share, and where it is on screen.
//!
//! VoDesktop's vocabulary was *windows*: a contractor was granted specific
//! `HWND`s on someone else's machine. RemoteDexter's is *surfaces*, because the
//! thing being shared is usually the whole desktop and the owner is on both
//! ends. The rules did not get weaker in the move — a surface must still be
//! explicitly permitted, and nothing is permitted by default — but the noun had
//! to change, because "share the desktop window" is not a sentence.
//!
//! Wayland is the reason this is not merely cosmetic. It refuses to enumerate
//! windows or capture one by id on principle, so a per-window model cannot be
//! implemented on Linux at all. One `Desktop` surface is what the platform can
//! actually offer.

/// Opaque, platform-agnostic surface identifier.
///
/// On Windows this wraps an `HWND` value; on Linux the single desktop surface
/// uses a reserved id. The core never interprets it — it only compares
/// identities. Keeping it opaque means the security logic is testable without
/// any OS handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SurfaceId(pub u64);

impl SurfaceId {
    /// The reserved id meaning "this workstation's whole desktop".
    ///
    /// It lives here, in the crate that owns `SurfaceId`, because from Block 8
    /// onward BOTH platforms use it and a sentinel with two definitions is a
    /// sentinel waiting to disagree with itself. `host_app::share_source`
    /// re-exports it; nothing defines its own.
    ///
    /// **It is `i64::MAX`, not `u64::MAX`,** and that is not a stylistic
    /// choice. Every value above `i64::MAX` is unrepresentable as a signed
    /// 64-bit integer, which is what most JSON parsers use for whole numbers —
    /// `org.json`, the Android client's, included. `u64::MAX` sent as a JSON
    /// number silently saturates to `Long.MAX_VALUE` on receipt, which happens
    /// to equal `i64::MAX`, so the client echoes back an id the host never
    /// sent and the host correctly refuses to capture a surface it does not
    /// recognise. Chosen so the value survives a signed-64-bit round trip
    /// intact; `SurfaceKind::Desktop` remains the durable answer to "is this
    /// the desktop", because leaning on any numeric sentinel is the weaker
    /// design.
    pub const DESKTOP: SurfaceId = SurfaceId(i64::MAX as u64);

    /// Construct from a raw platform handle or reserved id.
    pub const fn new(raw: u64) -> Self {
        SurfaceId(raw)
    }

    /// The raw value (e.g. to map back to an `HWND` in the host layer).
    ///
    /// `const` so callers can re-export [`SurfaceId::DESKTOP`] as a plain `u64`
    /// constant instead of keeping a second literal in step with this one.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// True for the reserved whole-desktop id.
    ///
    /// Prefer matching on [`SurfaceKind::Desktop`] where a descriptor is in
    /// hand. This exists for the wire boundary, where an id arrives with no
    /// descriptor attached.
    pub const fn is_desktop(self) -> bool {
        // Field comparison, not `==`: `PartialEq` is not const.
        self.0 == SurfaceId::DESKTOP.0
    }
}

/// What kind of thing a surface is.
///
/// This exists so a host can never *accidentally* widen from a window to the
/// desktop: the kind is stated when the surface is offered, and the two are not
/// interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    /// The whole workstation desktop. What RemoteDexter shares on Linux, and
    /// what it will share on Windows from Block 8 onward.
    Desktop,
    /// A single application window. The VoDesktop model, retained on Windows
    /// only until the full-desktop DXGI capture lands.
    Window,
}

/// On-screen rectangle of a surface, in desktop pixels.
///
/// `right` and `bottom` are exclusive, matching the platform APIs this is read
/// from and the half-open convention the clamp below relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceGeometry {
    /// Left edge, inclusive.
    pub left: i32,
    /// Top edge, inclusive.
    pub top: i32,
    /// Right edge, exclusive.
    pub right: i32,
    /// Bottom edge, exclusive.
    pub bottom: i32,
}

impl SurfaceGeometry {
    /// Build from a platform `(left, top, right, bottom)` tuple.
    pub fn new(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        SurfaceGeometry {
            left,
            top,
            right,
            bottom,
        }
    }

    /// Does this rectangle contain the given desktop-pixel point?
    ///
    /// Widened to `i64` deliberately: absolute coordinates arrive off the wire
    /// and must not be able to overflow the comparison before it is made.
    pub fn contains(&self, x: i64, y: i64) -> bool {
        x >= self.left as i64
            && x < self.right as i64
            && y >= self.top as i64
            && y < self.bottom as i64
    }
}

/// One surface a host offers for sharing: identity, kind, label, and where it is.
///
/// `geometry` is `Option` because it genuinely may not be knowable — a window
/// that has been closed or minimised has no rect, and a surface id that this
/// host does not offer has none either. Every consumer of this type must treat
/// `None` as a refusal, never as "skip the check".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceDescriptor {
    /// Identity used on the wire and in the allow-list.
    pub id: SurfaceId,
    /// Desktop or a single window.
    pub kind: SurfaceKind,
    /// Human-readable label for the client's picker.
    pub title: String,
    /// Where it is on screen, when that can be established.
    pub geometry: Option<SurfaceGeometry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_is_half_open() {
        let g = SurfaceGeometry::new(0, 0, 1920, 1080);
        assert!(g.contains(0, 0), "top-left corner is inside");
        assert!(g.contains(1919, 1079), "last real pixel is inside");
        assert!(!g.contains(1920, 0), "right edge is exclusive");
        assert!(!g.contains(0, 1080), "bottom edge is exclusive");
        assert!(!g.contains(-1, 0), "left of the origin is outside");
    }

    /// The desktop sentinel must survive the trip through a signed 64-bit
    /// JSON number and come back the same value. `u64::MAX` does not: it
    /// saturates to `Long.MAX_VALUE` on the Android side, which is a DIFFERENT
    /// number from the one the host sent, and the host then refuses to capture
    /// a surface it does not recognise. That bug cost a debugging session; this
    /// is what stops it returning if somebody "tidies" the constant.
    #[test]
    fn the_desktop_id_round_trips_through_a_signed_64_bit_wire() {
        let raw = SurfaceId::DESKTOP.raw();
        let as_signed = i64::try_from(raw).expect("must be representable as i64");
        let back = u64::try_from(as_signed).expect("and back again");
        assert_eq!(back, raw, "the desktop id must survive a signed round trip");
        assert_eq!(SurfaceId::new(back), SurfaceId::DESKTOP);
        assert!(SurfaceId::DESKTOP.is_desktop());
        assert!(!SurfaceId::new(0).is_desktop());
        assert!(
            !SurfaceId::new(u64::MAX).is_desktop(),
            "u64::MAX is the value this constant deliberately is NOT"
        );
    }

    #[test]
    fn geometry_comparison_does_not_overflow() {
        // Absolute coordinates arrive off the wire. A client sending i64::MAX
        // must get a clean `false`, not a wrapped comparison that says `true`.
        let g = SurfaceGeometry::new(0, 0, 1920, 1080);
        assert!(!g.contains(i64::MAX, i64::MAX));
        assert!(!g.contains(i64::MIN, i64::MIN));
    }
}

//! [`ShareSession`] — the single authorization authority for RemoteDexter.
//!
//! It composes the [`SurfaceScope`] allow-list and the [`ControlLevel`] consent
//! into one state machine and exposes the gates the host layer must call:
//! [`ShareSession::authorize_frame`] before any capture leaves the machine,
//! [`ShareSession::authorize_input`] before any event is injected, and
//! [`ShareSession::authorize_absolute_input`] before a pointer is teleported to
//! a coordinate.
//!
//! The three input conditions are independent and all must hold: the host must
//! have the capability, the surface must be permitted, and input must have been
//! granted separately from viewing. Viewing never grants control.
//!
//! Time is passed in as Unix epoch seconds (`now`) rather than read from the
//! clock, so the rules are deterministic and unit-testable.

use crate::consent::ControlLevel;
use crate::scope::SurfaceScope;
use crate::surface::{SurfaceGeometry, SurfaceId};

/// Unix epoch seconds. Supplied by the caller (the host layer reads the clock).
pub type Timestamp = u64;

/// Lifecycle of a share session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Created, but the secure (Noise) handshake has NOT completed yet.
    /// Nothing may be captured or injected. This is the state the v3 prototype
    /// skipped — it activated on a plaintext token *before* the handshake.
    AwaitingHandshake,
    /// Handshake done; waiting for the owner to pick which surfaces to share.
    /// Still nothing captured.
    AwaitingConsent,
    /// Client has consented and sharing is live. Capture is allowed for
    /// permitted surfaces; input only if `InputControl` was granted.
    Active,
    /// Session is over (revoked, expired, or closed). Permanently inert.
    Ended,
}

/// Why an action was refused. Every denial is explicit and typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareError {
    /// `handshake_complete` was called more than once.
    HandshakeAlreadyDone,
    /// An action requires the secure handshake to have completed first.
    HandshakeRequired,
    /// `start` was called with no surfaces permitted — there is nothing to share.
    NoSurfacesPermitted,
    /// The session is not `Active` (e.g. still awaiting consent).
    NotActive,
    /// The session's timebox has elapsed.
    Expired,
    /// The session has ended and cannot be used again.
    Ended,
    /// The target surface is not in the permitted allow-list.
    SurfaceNotPermitted(SurfaceId),
    /// Input was attempted but only view-only access was granted.
    InputNotGranted,
    /// An absolute pointer move was attempted but the surface's on-screen
    /// geometry could not be established, so there is nothing to clamp it
    /// against. This is a refusal, never a reason to skip the clamp.
    GeometryUnknown(SurfaceId),
    /// An absolute pointer move named a coordinate outside the permitted
    /// surface.
    CoordinatesOutsideSurface(SurfaceId),
}

/// A single owner↔device remote session, scoped to one paired peer.
#[derive(Debug, Clone)]
pub struct ShareSession {
    session_id: String,
    /// Which paired device this session belongs to. Was `contract_id` in
    /// VoDesktop, where a session was scoped to a piece of contracted work.
    /// RemoteDexter scopes to a device the owner has paired, so the identity
    /// that matters is the peer's, not a contract's.
    peer_id: String,
    state: SessionState,
    scope: SurfaceScope,
    control: ControlLevel,
    /// Epoch seconds at which the session auto-expires.
    expires_at: Timestamp,
}

impl ShareSession {
    /// Create a session bound to a peer, with an absolute expiry time.
    /// Begins in [`SessionState::AwaitingHandshake`]: view-only, nothing shared.
    pub fn new(
        session_id: impl Into<String>,
        peer_id: impl Into<String>,
        expires_at: Timestamp,
    ) -> Self {
        ShareSession {
            session_id: session_id.into(),
            peer_id: peer_id.into(),
            state: SessionState::AwaitingHandshake,
            scope: SurfaceScope::new(),
            control: ControlLevel::ViewOnly,
            expires_at,
        }
    }

    // ── State transitions ──────────────────────────────────────────────────

    /// Mark the secure handshake complete. Only valid once, and only from
    /// [`SessionState::AwaitingHandshake`]. Moves to `AwaitingConsent`.
    pub fn handshake_complete(&mut self) -> Result<(), ShareError> {
        match self.state {
            SessionState::AwaitingHandshake => {
                self.state = SessionState::AwaitingConsent;
                Ok(())
            }
            SessionState::Ended => Err(ShareError::Ended),
            _ => Err(ShareError::HandshakeAlreadyDone),
        }
    }

    /// Owner adds a surface to the share allow-list. Permitted only after the
    /// handshake (in `AwaitingConsent` or `Active`), never before.
    pub fn permit_surface(&mut self, surface: SurfaceId) -> Result<(), ShareError> {
        match self.state {
            SessionState::AwaitingHandshake => Err(ShareError::HandshakeRequired),
            SessionState::Ended => Err(ShareError::Ended),
            SessionState::AwaitingConsent | SessionState::Active => {
                self.scope.permit(surface);
                Ok(())
            }
        }
    }

    /// Owner removes a surface from the allow-list. Takes effect immediately;
    /// allowed in any non-ended state.
    pub fn revoke_surface(&mut self, surface: SurfaceId) -> Result<(), ShareError> {
        if self.state == SessionState::Ended {
            return Err(ShareError::Ended);
        }
        self.scope.revoke(surface);
        Ok(())
    }

    /// Begin live sharing. Requires the handshake done and at least one
    /// permitted surface. Moves `AwaitingConsent` → `Active`.
    pub fn start(&mut self, now: Timestamp) -> Result<(), ShareError> {
        match self.state {
            SessionState::AwaitingHandshake => Err(ShareError::HandshakeRequired),
            SessionState::Ended => Err(ShareError::Ended),
            SessionState::Active => Ok(()), // already sharing — idempotent
            SessionState::AwaitingConsent => {
                if now >= self.expires_at {
                    self.state = SessionState::Ended;
                    return Err(ShareError::Expired);
                }
                if self.scope.is_empty() {
                    return Err(ShareError::NoSurfacesPermitted);
                }
                self.state = SessionState::Active;
                Ok(())
            }
        }
    }

    /// Owner grants input control. Only valid while `Active`.
    pub fn grant_input(&mut self) -> Result<(), ShareError> {
        self.require_active()?;
        self.control = ControlLevel::InputControl;
        Ok(())
    }

    /// Owner drops back to view-only. Only valid while `Active`.
    pub fn revoke_input(&mut self) -> Result<(), ShareError> {
        self.require_active()?;
        self.control = ControlLevel::ViewOnly;
        Ok(())
    }

    /// End the session immediately (manual revoke or disconnect). Idempotent.
    /// Clears the allow-list and resets control to view-only.
    pub fn end(&mut self) {
        self.state = SessionState::Ended;
        self.scope.clear();
        self.control = ControlLevel::ViewOnly;
    }

    /// Drive the expiry timebox. Call periodically with the current time.
    /// Returns `true` if this tick ended the session due to expiry.
    pub fn on_tick(&mut self, now: Timestamp) -> bool {
        if self.state != SessionState::Ended && now >= self.expires_at {
            self.end();
            return true;
        }
        false
    }

    // ── Authorization gates (the security boundary) ─────────────────────────

    /// Authorize capturing a frame from `surface` at time `now`.
    ///
    /// `Ok` only if the session is `Active`, not expired, and `surface` is in
    /// the permitted allow-list. The host's [`crate::traits::FrameSource`] must
    /// call this and propagate any error before capturing.
    pub fn authorize_frame(&self, surface: SurfaceId, now: Timestamp) -> Result<(), ShareError> {
        self.require_live(now)?;
        if !self.scope.is_permitted(surface) {
            return Err(ShareError::SurfaceNotPermitted(surface));
        }
        Ok(())
    }

    /// Authorize injecting input into `surface` at time `now`.
    ///
    /// `Ok` only if [`authorize_frame`](Self::authorize_frame) would pass AND
    /// input control was granted. This is what keeps input inside the permitted
    /// surfaces, and what makes viewing insufficient for control.
    pub fn authorize_input(&self, surface: SurfaceId, now: Timestamp) -> Result<(), ShareError> {
        self.authorize_frame(surface, now)?;
        if !self.control.allows_input() {
            return Err(ShareError::InputNotGranted);
        }
        Ok(())
    }

    /// Authorize an **absolute** pointer move to `(x, y)` desktop pixels.
    ///
    /// Everything [`authorize_input`](Self::authorize_input) requires, plus a
    /// known geometry that contains the point.
    ///
    /// `geometry` is `None` whenever the host cannot establish where the
    /// surface is — a window that is no longer visible, or an id this host does
    /// not offer at all. **That is a refusal.** This rule used to live in the
    /// host binary written as `if let Some(rect) = ...`, so on Linux, where the
    /// per-window lookup returns `None` for everything, the clamp silently did
    /// not run: a peer granted one surface could steer the pointer across the
    /// whole desktop and click anything. It is in the core now, with a test,
    /// because a fail-open clamp is indistinguishable from a working one until
    /// someone looks.
    ///
    /// Relative moves deliberately do NOT go through here: they have no
    /// coordinate to clamp and depend on no geometry.
    pub fn authorize_absolute_input(
        &self,
        surface: SurfaceId,
        now: Timestamp,
        geometry: Option<SurfaceGeometry>,
        x: i64,
        y: i64,
    ) -> Result<SurfaceGeometry, ShareError> {
        self.authorize_input(surface, now)?;
        let Some(geom) = geometry else {
            return Err(ShareError::GeometryUnknown(surface));
        };
        if !geom.contains(x, y) {
            return Err(ShareError::CoordinatesOutsideSurface(surface));
        }
        Ok(geom)
    }

    // ── Accessors (for the "currently sharing" indicator / UI) ──────────────

    /// Current lifecycle state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Current control level.
    pub fn control_level(&self) -> ControlLevel {
        self.control
    }

    /// True while live sharing is in progress (drives the visible indicator).
    pub fn is_sharing(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Read-only view of the permitted surfaces.
    pub fn scope(&self) -> &SurfaceScope {
        &self.scope
    }

    /// The session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The paired peer this session is bound to.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Absolute expiry (epoch seconds).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    // ── internal helpers ────────────────────────────────────────────────────

    fn require_active(&self) -> Result<(), ShareError> {
        match self.state {
            SessionState::Active => Ok(()),
            SessionState::Ended => Err(ShareError::Ended),
            _ => Err(ShareError::NotActive),
        }
    }

    fn require_live(&self, now: Timestamp) -> Result<(), ShareError> {
        match self.state {
            SessionState::Ended => Err(ShareError::Ended),
            SessionState::AwaitingHandshake | SessionState::AwaitingConsent => {
                Err(ShareError::NotActive)
            }
            SessionState::Active => {
                if now >= self.expires_at {
                    Err(ShareError::Expired)
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAR_FUTURE: Timestamp = 10_000;
    const NOW: Timestamp = 100;

    fn fresh() -> ShareSession {
        ShareSession::new("sess-1", "peer-1", FAR_FUTURE)
    }

    /// Walks the intended happy path and asserts each gate.
    fn activated_with(surface: SurfaceId) -> ShareSession {
        let mut s = fresh();
        s.handshake_complete().unwrap();
        s.permit_surface(surface).unwrap();
        s.start(NOW).unwrap();
        s
    }

    #[test]
    fn nothing_authorized_before_handshake() {
        let s = fresh();
        let w = SurfaceId::new(1);
        assert_eq!(s.authorize_frame(w, NOW), Err(ShareError::NotActive));
        assert_eq!(s.authorize_input(w, NOW), Err(ShareError::NotActive));
    }

    #[test]
    fn cannot_permit_or_start_before_handshake() {
        let mut s = fresh();
        assert_eq!(
            s.permit_surface(SurfaceId::new(1)),
            Err(ShareError::HandshakeRequired)
        );
        assert_eq!(s.start(NOW), Err(ShareError::HandshakeRequired));
    }

    #[test]
    fn handshake_is_one_shot() {
        let mut s = fresh();
        s.handshake_complete().unwrap();
        assert_eq!(
            s.handshake_complete(),
            Err(ShareError::HandshakeAlreadyDone)
        );
    }

    #[test]
    fn cannot_start_without_a_surface() {
        let mut s = fresh();
        s.handshake_complete().unwrap();
        assert_eq!(s.start(NOW), Err(ShareError::NoSurfacesPermitted));
    }

    #[test]
    fn happy_path_view_only_allows_frame_denies_input() {
        let w = SurfaceId::new(42);
        let s = activated_with(w);
        assert!(s.is_sharing());
        // Frame from the permitted surface is allowed...
        assert_eq!(s.authorize_frame(w, NOW), Ok(()));
        // ...but input is denied while view-only (the default).
        assert_eq!(s.authorize_input(w, NOW), Err(ShareError::InputNotGranted));
    }

    #[test]
    fn non_permitted_surface_is_never_captured() {
        let permitted = SurfaceId::new(42);
        let other = SurfaceId::new(99); // a surface that was never offered
        let s = activated_with(permitted);
        assert_eq!(
            s.authorize_frame(other, NOW),
            Err(ShareError::SurfaceNotPermitted(other))
        );
        assert_eq!(
            s.authorize_input(other, NOW),
            Err(ShareError::SurfaceNotPermitted(other))
        );
    }

    #[test]
    fn granting_input_enables_only_permitted_surfaces() {
        let w = SurfaceId::new(42);
        let other = SurfaceId::new(99);
        let mut s = activated_with(w);
        s.grant_input().unwrap();
        assert_eq!(s.authorize_input(w, NOW), Ok(()));
        // Input control does NOT widen the surface scope.
        assert_eq!(
            s.authorize_input(other, NOW),
            Err(ShareError::SurfaceNotPermitted(other))
        );
    }

    #[test]
    fn revoke_input_reverts_to_view_only() {
        let w = SurfaceId::new(42);
        let mut s = activated_with(w);
        s.grant_input().unwrap();
        assert_eq!(s.authorize_input(w, NOW), Ok(()));
        s.revoke_input().unwrap();
        assert_eq!(s.authorize_input(w, NOW), Err(ShareError::InputNotGranted));
        // Viewing still works.
        assert_eq!(s.authorize_frame(w, NOW), Ok(()));
    }

    #[test]
    fn revoking_a_surface_cuts_it_off_immediately() {
        let w = SurfaceId::new(42);
        let mut s = activated_with(w);
        assert_eq!(s.authorize_frame(w, NOW), Ok(()));
        s.revoke_surface(w).unwrap();
        assert_eq!(
            s.authorize_frame(w, NOW),
            Err(ShareError::SurfaceNotPermitted(w))
        );
    }

    #[test]
    fn ending_session_denies_everything() {
        let w = SurfaceId::new(42);
        let mut s = activated_with(w);
        s.end();
        assert_eq!(s.state(), SessionState::Ended);
        assert_eq!(s.authorize_frame(w, NOW), Err(ShareError::Ended));
        assert_eq!(s.grant_input(), Err(ShareError::Ended));
        assert!(!s.is_sharing());
    }

    #[test]
    fn expiry_timebox_denies_capture() {
        let w = SurfaceId::new(42);
        let s = activated_with(w);
        // After expiry, authorization fails even though state is still Active.
        assert_eq!(s.authorize_frame(w, FAR_FUTURE), Err(ShareError::Expired));
        assert_eq!(
            s.authorize_frame(w, FAR_FUTURE + 1),
            Err(ShareError::Expired)
        );
    }

    #[test]
    fn on_tick_ends_expired_session() {
        let w = SurfaceId::new(42);
        let mut s = activated_with(w);
        assert!(!s.on_tick(NOW)); // not yet expired
        assert!(s.on_tick(FAR_FUTURE)); // expires now
        assert_eq!(s.state(), SessionState::Ended);
        assert!(!s.on_tick(FAR_FUTURE)); // idempotent — already ended
    }

    // ── Rename-specific and RemoteDexter-specific cases ─────────────────────
    //
    // Everything above this line is a VoDesktop invariant carried across
    // unchanged. Everything below exists because RemoteDexter shares a desktop
    // rather than a window, and because one rule moved into this crate from the
    // host binary.

    /// The reserved id RemoteDexter's Linux host uses for "this workstation's
    /// desktop". `i64::MAX`, not `u64::MAX`: the Android client parses ids with
    /// a signed 64-bit JSON reader, and `u64::MAX` saturates to `Long.MAX_VALUE`
    /// on receipt, so the client would echo back an id the host never sent.
    const DESKTOP: SurfaceId = SurfaceId(i64::MAX as u64);

    /// The desktop is a surface like any other: it must be permitted by id.
    /// There is no "share the desktop" mode that bypasses the allow-list.
    #[test]
    fn desktop_surface_must_be_permitted_explicitly() {
        let mut s = fresh();
        s.handshake_complete().unwrap();
        // Not permitted yet — starting has nothing to share.
        assert_eq!(s.start(NOW), Err(ShareError::NoSurfacesPermitted));
        s.permit_surface(DESKTOP).unwrap();
        s.start(NOW).unwrap();
        assert_eq!(s.authorize_frame(DESKTOP, NOW), Ok(()));
    }

    /// Permitting the desktop does not permit anything else. On Linux the
    /// desktop is the only surface offered, so any other id is one the host
    /// never advertised and must be refused rather than resolved.
    #[test]
    fn other_surfaces_are_denied_when_only_the_desktop_is_permitted() {
        let s = activated_with(DESKTOP);
        let stray = SurfaceId::new(0);
        assert_eq!(
            s.authorize_frame(stray, NOW),
            Err(ShareError::SurfaceNotPermitted(stray))
        );
        assert_eq!(
            s.authorize_input(stray, NOW),
            Err(ShareError::SurfaceNotPermitted(stray))
        );
    }

    /// Expiry denies desktop frames exactly as it denies window frames. Worth
    /// asserting on the desktop id specifically: it is a reserved sentinel, and
    /// a sentinel that accidentally short-circuits a check is a classic bug.
    #[test]
    fn expired_session_denies_desktop_frames() {
        let s = activated_with(DESKTOP);
        assert_eq!(s.authorize_frame(DESKTOP, NOW), Ok(()));
        assert_eq!(
            s.authorize_frame(DESKTOP, FAR_FUTURE),
            Err(ShareError::Expired)
        );
    }

    /// **The invariant this whole crate exists for.** Viewing is not control.
    ///
    /// Named as the plan names it, because it is the regression test used to
    /// prove the move did not introduce a bypass: delete the
    /// `control.allows_input()` check in `authorize_input` and this goes red.
    #[test]
    fn authorize_input_requires_explicit_grant() {
        let s = activated_with(DESKTOP);
        // The happy path, minus the grant. Frames flow...
        assert_eq!(s.authorize_frame(DESKTOP, NOW), Ok(()));
        // ...and input does not.
        assert_eq!(
            s.authorize_input(DESKTOP, NOW),
            Err(ShareError::InputNotGranted)
        );
        // Absolute input is refused at the same gate, before geometry is even
        // consulted — so a missing grant cannot be masked by a valid rect.
        let geom = SurfaceGeometry::new(0, 0, 1920, 1080);
        assert_eq!(
            s.authorize_absolute_input(DESKTOP, NOW, Some(geom), 100, 100),
            Err(ShareError::InputNotGranted)
        );
    }

    /// Unknown geometry refuses an absolute move. It does not skip the clamp.
    #[test]
    fn unknown_geometry_denies_absolute_input() {
        let mut s = activated_with(DESKTOP);
        s.grant_input().unwrap();
        // Relative input is fine: it has no coordinate to clamp.
        assert_eq!(s.authorize_input(DESKTOP, NOW), Ok(()));
        // Absolute input with no rect is refused.
        assert_eq!(
            s.authorize_absolute_input(DESKTOP, NOW, None, 100, 100),
            Err(ShareError::GeometryUnknown(DESKTOP))
        );
        // With a rect, inside passes and outside is refused.
        let geom = SurfaceGeometry::new(0, 0, 1920, 1080);
        assert_eq!(
            s.authorize_absolute_input(DESKTOP, NOW, Some(geom), 100, 100),
            Ok(geom)
        );
        assert_eq!(
            s.authorize_absolute_input(DESKTOP, NOW, Some(geom), 5000, 100),
            Err(ShareError::CoordinatesOutsideSurface(DESKTOP))
        );
    }

    /// Revoking input mid-session must deny the absolute path too. A pointer
    /// that keeps teleporting after control is revoked is the failure this
    /// gate exists to prevent.
    #[test]
    fn revoking_input_denies_absolute_moves_immediately() {
        let mut s = activated_with(DESKTOP);
        s.grant_input().unwrap();
        let geom = SurfaceGeometry::new(0, 0, 1920, 1080);
        assert!(s
            .authorize_absolute_input(DESKTOP, NOW, Some(geom), 10, 10)
            .is_ok());
        s.revoke_input().unwrap();
        assert_eq!(
            s.authorize_absolute_input(DESKTOP, NOW, Some(geom), 10, 10),
            Err(ShareError::InputNotGranted)
        );
        // Viewing survives the revoke.
        assert_eq!(s.authorize_frame(DESKTOP, NOW), Ok(()));
    }

    #[test]
    fn starting_after_expiry_fails() {
        let mut s = fresh();
        s.handshake_complete().unwrap();
        s.permit_surface(SurfaceId::new(1)).unwrap();
        assert_eq!(s.start(FAR_FUTURE), Err(ShareError::Expired));
        assert_eq!(s.state(), SessionState::Ended);
    }
}

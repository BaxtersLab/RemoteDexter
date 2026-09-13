//! Surface allow-list — the heart of "nothing is shared until it is chosen".
//!
//! A [`SurfaceScope`] is the explicit set of surfaces the owner has approved
//! for the current session. The capture layer must consult this on *every*
//! frame; a surface that is not in the set can never be captured.

use crate::surface::SurfaceId;
use std::collections::HashSet;

/// The set of surfaces explicitly permitted for sharing in a session.
///
/// Starts **empty** — nothing is shareable until it is deliberately added.
/// There is intentionally no "permit everything" option: on Linux the desktop
/// is a surface that must be permitted by id like any other, not a mode the
/// session can be switched into.
#[derive(Debug, Clone, Default)]
pub struct SurfaceScope {
    permitted: HashSet<SurfaceId>,
}

impl SurfaceScope {
    /// A new, empty scope. Nothing may be captured yet.
    pub fn new() -> Self {
        SurfaceScope {
            permitted: HashSet::new(),
        }
    }

    /// Add a surface to the allow-list (a deliberate consent action).
    /// Returns `true` if it was newly added.
    pub fn permit(&mut self, surface: SurfaceId) -> bool {
        self.permitted.insert(surface)
    }

    /// Remove a surface from the allow-list (instant per-surface revoke).
    /// Returns `true` if it had been permitted.
    pub fn revoke(&mut self, surface: SurfaceId) -> bool {
        self.permitted.remove(&surface)
    }

    /// Drop every permitted surface (e.g. on session end).
    pub fn clear(&mut self) {
        self.permitted.clear();
    }

    /// Is this specific surface permitted to be captured/controlled?
    pub fn is_permitted(&self, surface: SurfaceId) -> bool {
        self.permitted.contains(&surface)
    }

    /// Number of permitted surfaces.
    pub fn len(&self) -> usize {
        self.permitted.len()
    }

    /// True if nothing is shared yet.
    pub fn is_empty(&self) -> bool {
        self.permitted.is_empty()
    }

    /// Snapshot of the permitted surfaces (for the "currently sharing" UI).
    pub fn permitted_surfaces(&self) -> Vec<SurfaceId> {
        let mut v: Vec<SurfaceId> = self.permitted.iter().copied().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scope_permits_nothing() {
        let scope = SurfaceScope::new();
        assert!(scope.is_empty());
        assert!(!scope.is_permitted(SurfaceId::new(1)));
    }

    #[test]
    fn permit_then_check() {
        let mut scope = SurfaceScope::new();
        assert!(scope.permit(SurfaceId::new(42)));
        assert!(scope.is_permitted(SurfaceId::new(42)));
        // A different surface is still denied.
        assert!(!scope.is_permitted(SurfaceId::new(43)));
    }

    #[test]
    fn permit_is_idempotent() {
        let mut scope = SurfaceScope::new();
        assert!(scope.permit(SurfaceId::new(7)));
        assert!(!scope.permit(SurfaceId::new(7))); // already present
        assert_eq!(scope.len(), 1);
    }

    #[test]
    fn revoke_removes_access_immediately() {
        let mut scope = SurfaceScope::new();
        scope.permit(SurfaceId::new(7));
        assert!(scope.revoke(SurfaceId::new(7)));
        assert!(!scope.is_permitted(SurfaceId::new(7)));
        assert!(!scope.revoke(SurfaceId::new(7))); // already gone
    }
}

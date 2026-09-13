//! Per-session control level — what the connected peer is allowed to do.
//!
//! Every share starts at [`ControlLevel::ViewOnly`]. The owner must take an
//! explicit action to grant [`ControlLevel::InputControl`], and can drop back
//! to view-only at any moment. This module holds only the control-level value;
//! the [`crate::session::ShareSession`] decides when it may change.

/// What the remote party may do within the *permitted* surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlLevel {
    /// The peer can see permitted surfaces but cannot move the pointer,
    /// type, or otherwise inject input. This is the default for every session.
    ViewOnly,
    /// The peer may inject input — but still only into surfaces that are in
    /// the permitted [`crate::scope::SurfaceScope`]. Granting this requires a
    /// deliberate owner action.
    InputControl,
}

impl Default for ControlLevel {
    fn default() -> Self {
        ControlLevel::ViewOnly
    }
}

impl ControlLevel {
    /// True if input injection is permitted at this level.
    pub fn allows_input(self) -> bool {
        matches!(self, ControlLevel::InputControl)
    }

    /// Human-readable label for the "currently sharing" indicator.
    pub fn label(self) -> &'static str {
        match self {
            ControlLevel::ViewOnly => "view-only",
            ControlLevel::InputControl => "input control granted",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_view_only() {
        assert_eq!(ControlLevel::default(), ControlLevel::ViewOnly);
        assert!(!ControlLevel::default().allows_input());
    }

    #[test]
    fn input_control_allows_input() {
        assert!(ControlLevel::InputControl.allows_input());
    }
}

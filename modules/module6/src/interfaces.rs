/// Interfaces that Module6 uses to interact with sealed modules and event sources.
/// These are trait definitions intended to be implemented by external crates
/// or provided as mocks during testing. They explicitly expose only read-only
/// operations against sealed modules.

/// Read-only accessor for Module5. Implementations must not mutate Module5.
pub trait Module5Reader {
    /// Return an opaque snapshot identifier for provenance.
    fn snapshot_id(&self) -> String;

    /// Fetch a read-only, serializable representation of recent transitions.
    fn get_transition_history(&self) -> Vec<String>;

    /// Evaluate invariants and return a textual report (read-only).
    fn evaluate_invariants(&self) -> String;
}

/// Minimal event source contract for log tailing.
pub trait EventSource {
    /// Read new events since `offset` (opaque) and return new offset plus events.
    fn read_events(&mut self, offset: Option<String>) -> (Option<String>, Vec<String>);
}

/// Minimal connector interface to Module4 for orchestrating reconnects and
/// requesting rekeys. Implementations must not expose Module4 internal errors
/// directly; errors should be returned as strings and mapped by Module6.
pub trait Module4Connector {
    fn orchestrate_reconnect(&mut self, session_id: &str) -> Result<(), String>;
    fn request_rekey(&mut self, session_id: &str) -> Result<(), String>;
}

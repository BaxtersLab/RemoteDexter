//! What the console should say about capture, separately from the connection.
//!
//! # The defect this exists for (defect C)
//!
//! A capture failure was reported to the **client** — `json_err("stream", …)`
//! over the session — and to stderr, and nowhere else. The console went on
//! showing `● Connected — 1 device(s) connected`, because `HostState` is
//! derived purely from the listener and the peer count and knows nothing about
//! whether any pixels are moving.
//!
//! So the two people who need to know disagreed. The phone showed a frozen or
//! black picture; the operator's own screen said everything was fine. The
//! operator's most likely reading of that is "the phone is broken", which sends
//! them to the wrong machine.
//!
//! # Why the connection state was not simply extended
//!
//! `HostState::Connected` is true. The socket is up, the peer is authenticated,
//! and input still works if it was granted. Folding a capture fault into it
//! would make the console say `Error` for a session that is very much alive,
//! and would lose the distinction between "nobody is connected" and "someone is
//! connected but sees nothing" — which are different problems with different
//! fixes.
//!
//! Capture health is therefore its own line, and this module decides what it
//! says.
//!
//! # Staleness is the hard part
//!
//! A fault is a fact about one stream, not about the host. The failure mode
//! that matters is the opposite of the original defect: a fault left standing
//! after a successful restart, so the console warns about a stream that is now
//! healthy. Trust in a warning that cries wolf is spent once.
//!
//! [`CaptureFault::note`] and [`CaptureFault::clear`] therefore bracket a
//! stream's life, and `clear` runs at every *start*, not only at a clean stop —
//! a stream that faults never gets to run its own cleanup.

/// What the console should display about capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureBanner {
    /// Say nothing. Either capture is fine, or there is nobody to serve.
    Silent,
    /// Capture has stopped while a peer is still connected.
    Faulted {
        /// Safe to display: the reason the capture path produced, never an
        /// address, token or key.
        reason: String,
    },
}

/// Decide what the console shows.
///
/// `peers` is the live peer count, `fault` the last unresolved capture failure.
///
/// A fault with **no peer connected** is deliberately silent. It is not news:
/// capture stops when the last client goes away, and warning about it would
/// leave a red line on an idle host that the operator can do nothing about.
/// The banner exists to explain a live session that is showing nothing.
pub fn banner(peers: usize, fault: Option<&str>) -> CaptureBanner {
    match fault {
        Some(reason) if peers > 0 => CaptureBanner::Faulted {
            reason: reason.to_string(),
        },
        _ => CaptureBanner::Silent,
    }
}

/// The process-wide record of the last capture failure.
///
/// A `Mutex<Option<String>>` rather than a channel: the console is an
/// immediate-mode UI that repaints on a timer and asks for the current truth
/// each frame. A channel would need the UI to drain it and hold the result
/// itself, which is the same state with an extra copy that can fall out of
/// step.
#[derive(Debug, Default)]
pub struct CaptureFault {
    reason: std::sync::Mutex<Option<String>>,
}

impl CaptureFault {
    pub const fn new() -> Self {
        CaptureFault {
            reason: std::sync::Mutex::new(None),
        }
    }

    /// Record a failure. The first one wins.
    ///
    /// A failing capture path can produce several errors as it unwinds, and the
    /// first is the cause while the rest are consequences. Keeping the first
    /// means the operator reads why it broke rather than what broke last.
    pub fn note(&self, reason: &str) {
        let mut slot = self.reason.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_none() {
            *slot = Some(reason.to_string());
        }
    }

    /// Forget any fault. Called when a stream **starts**.
    pub fn clear(&self) {
        *self.reason.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// The current unresolved fault, if any.
    pub fn get(&self) -> Option<String> {
        self.reason
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// Report one capture failure to **both** audiences, in one call.
///
/// The client learns over the session; the operator learns from the console.
/// Defect C was that only the first happened, and the two calls sitting next to
/// each other is exactly how that recurs — a later edit moves or removes one
/// and nothing complains.
///
/// Returns the reason string, escaped for embedding in the JSON error sent to
/// the client, so the caller cannot report a different reason to each side.
pub fn report_failure(fault: &CaptureFault, error: &str) -> String {
    let reason = format!("capture failed: {error}");
    fault.note(&reason);
    reason.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_healthy_session_says_nothing() {
        assert_eq!(banner(1, None), CaptureBanner::Silent);
    }

    #[test]
    fn a_fault_with_a_peer_connected_is_shown() {
        assert_eq!(
            banner(1, Some("capture failed: portal grant revoked")),
            CaptureBanner::Faulted {
                reason: "capture failed: portal grant revoked".to_string()
            }
        );
    }

    /// The original defect, as an assertion: connected plus dead capture must
    /// not be silent.
    #[test]
    fn connected_with_dead_capture_is_not_silent() {
        assert_ne!(banner(2, Some("capture failed")), CaptureBanner::Silent);
    }

    /// A fault on an idle host is not news and must not sit on screen.
    #[test]
    fn a_fault_with_nobody_connected_is_silent() {
        assert_eq!(banner(0, Some("capture failed")), CaptureBanner::Silent);
    }

    /// The failure mode that would destroy trust in the banner.
    #[test]
    fn a_restarted_stream_clears_the_previous_fault() {
        let fault = CaptureFault::new();
        fault.note("capture failed: no portal grant");
        assert!(fault.get().is_some());

        // The operator re-granted and pressed start again.
        fault.clear();
        assert_eq!(fault.get(), None);
        assert_eq!(banner(1, fault.get().as_deref()), CaptureBanner::Silent);
    }

    /// The first error is the cause; the rest are its consequences.
    #[test]
    fn the_first_reason_is_kept_not_the_last() {
        let fault = CaptureFault::new();
        fault.note("capture failed: portal closed");
        fault.note("capture failed: stream ended");
        assert_eq!(
            fault.get().as_deref(),
            Some("capture failed: portal closed")
        );
    }

    #[test]
    fn clearing_an_unfaulted_recorder_is_harmless() {
        let fault = CaptureFault::new();
        fault.clear();
        assert_eq!(fault.get(), None);
    }

    /// One call, both audiences. This is the defect as a structural guarantee:
    /// the console cannot be left uninformed while the client is told.
    #[test]
    fn reporting_a_failure_informs_the_console_and_the_client() {
        let fault = CaptureFault::new();
        let for_client = report_failure(&fault, "portal grant revoked");
        assert_eq!(
            fault.get().as_deref(),
            Some("capture failed: portal grant revoked"),
            "the console was not told"
        );
        assert!(
            for_client.contains("portal grant revoked"),
            "the client was not told: {for_client}"
        );
    }

    /// The reason is embedded in a JSON string, so quotes and backslashes in an
    /// error message must not be able to end it early.
    ///
    /// Asserted by round-tripping through a real JSON parser rather than by
    /// looking for escape sequences: a substring check here is easy to write
    /// wrongly (the first attempt searched for `" and`, which the *correctly*
    /// escaped `\" and` contains) and proves nothing about whether the client
    /// can actually read the message.
    #[test]
    fn a_reason_containing_json_metacharacters_survives_the_wire() {
        let fault = CaptureFault::new();
        let raw = r#"bad "quote" and \ slash"#;
        let for_client = report_failure(&fault, raw);

        let wire = format!(r#"{{"type":"error","for":"stream","reason":"{for_client}"}}"#);
        let parsed: serde_json::Value =
            serde_json::from_str(&wire).expect("the escaped reason must produce parseable JSON");
        assert_eq!(
            parsed["reason"].as_str(),
            Some(format!("capture failed: {raw}").as_str()),
            "the client must read back exactly what went wrong"
        );

        // The console gets the readable form, not the escaped one.
        assert_eq!(
            fault.get().as_deref(),
            Some(format!("capture failed: {raw}").as_str())
        );
    }

    /// The reason crosses a thread boundary in the product: the capture thread
    /// writes it and the UI thread reads it.
    #[test]
    fn a_fault_noted_on_another_thread_is_visible() {
        use std::sync::Arc;
        let fault = Arc::new(CaptureFault::new());
        let writer = Arc::clone(&fault);
        std::thread::spawn(move || writer.note("capture failed: from the stream thread"))
            .join()
            .unwrap();
        assert_eq!(
            fault.get().as_deref(),
            Some("capture failed: from the stream thread")
        );
    }
}

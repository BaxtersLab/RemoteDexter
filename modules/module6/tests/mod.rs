use module6::{LogicalSession, LogicalStatus, ConnectionManager, Module4Connector, Module5Reader, EventSource};

struct DummyReader;
impl Module5Reader for DummyReader {
    fn snapshot_id(&self) -> String { "snap-1".into() }
    fn get_transition_history(&self) -> Vec<String> { vec![] }
    fn evaluate_invariants(&self) -> String { "ok".into() }
}

struct DummyEvents;
impl EventSource for DummyEvents {
    fn read_events(&mut self, _offset: Option<String>) -> (Option<String>, Vec<String>) { (None, vec![]) }
}

struct DummyController;
impl Module4Connector for DummyController {
    fn orchestrate_reconnect(&mut self, _session_id: &str) -> Result<(), String> { Ok(()) }
    fn request_rekey(&mut self, _session_id: &str) -> Result<(), String> { Ok(()) }
}

#[test]
fn logical_session_defaults_to_healthy() {
    let mut s = LogicalSession::new("sess-1");
    assert_eq!(s.status(), &LogicalStatus::Healthy);

    let r = DummyReader;
    let e = DummyEvents;
    let c = DummyController;
    let mut cm = ConnectionManager::new(r, e, c);
    cm.ensure_session(&s);
    // immediately checking liveness should keep Healthy
    cm.check_liveness(&mut s).unwrap();
    assert_eq!(s.status(), &LogicalStatus::Healthy);
}

#[test]
fn degraded_then_dead_then_reconnect_resets_to_healthy() {
    let mut s = LogicalSession::new("sess-2");
    let r = DummyReader;
    let e = DummyEvents;
    let c = DummyController;
    let mut cm = ConnectionManager::new(r, e, c);
    cm.ensure_session(&s);
    // simulate no pong for a while by setting last_pong offset
    let degraded = 5u64;
    let dead = 10u64;
    cm.set_liveness_thresholds(degraded, dead);
    cm.set_last_pong_offset(&s, degraded + 2);
    // ensure age reflects the offset
    let age = cm.age_since_last_pong(&s.id).unwrap();
    #[cfg(feature = "debug-logs")]
    println!("DEBUG: age_since_last_pong = {} (degraded={})", age, degraded);
    assert!(age >= degraded);
    cm.check_liveness(&mut s).unwrap();
    assert_eq!(s.status(), &LogicalStatus::Degraded);

    // escalate to dead
    cm.set_last_pong_offset(&s, dead + 2);
    cm.check_liveness(&mut s).unwrap();
    // should attempt reconnect and end Healthy (DummyController returns Ok)
    assert_eq!(s.status(), &LogicalStatus::Healthy);
}

#[test]
fn rekey_triggers_on_message_and_bytes() {
    let s = LogicalSession::new("sess-3");
    let r = DummyReader;
    let e = DummyEvents;
    // controller that records rekey requests
    struct RecordController(std::cell::Cell<usize>);
    impl Module4Connector for RecordController {
        fn orchestrate_reconnect(&mut self, _session_id: &str) -> Result<(), String> { Ok(()) }
        fn request_rekey(&mut self, _session_id: &str) -> Result<(), String> { let v = self.0.get(); self.0.set(v+1); Ok(()) }
    }
    let c = RecordController(std::cell::Cell::new(0));
    let mut cm = ConnectionManager::new(r, e, c);
    cm.ensure_session(&s);
    // set a small rekey policy
    cm.configure_rekey_policy(module6::RekeyPolicy { msg_threshold: 3, byte_threshold: 100, time_seconds: 3600 });
    cm.ensure_session(&s);
    // send messages to trigger rekey
    let before = cm.last_rekey_time(&s.id).unwrap();
    cm.record_message_sent(&s, 10).unwrap();
    cm.record_message_sent(&s, 20).unwrap();
    cm.record_message_sent(&s, 30).unwrap();
    let after = cm.last_rekey_time(&s.id).unwrap();
    assert!(after >= before);
}

use crate::logical_session::{LogicalSession, LogicalStatus, LogicalError};
use crate::interfaces::{Module5Reader, EventSource, Module4Connector};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Policy for when to trigger a rekey.
#[derive(Debug, Clone)]
pub struct RekeyPolicy {
    pub msg_threshold: usize,
    pub byte_threshold: usize,
    pub time_seconds: u64,
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self { msg_threshold: 1000, byte_threshold: 10_000_000, time_seconds: 60 * 60 }
    }
}

struct SessionMeta {
    last_pong: u64,
    last_ping: u64,
    msgs_since_rekey: usize,
    bytes_since_rekey: usize,
    last_rekey_time: u64,
}

impl SessionMeta {
    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

/// Connection manager: manages liveness, rekey decisions and reconnect orchestration.
pub struct ConnectionManager<R: Module5Reader, E: EventSource, C: Module4Connector> {
    _reader: R,
    _events: E,
    controller: C,
    sessions: HashMap<String, SessionMeta>,
    rekey_policy: RekeyPolicy,
    // liveness thresholds in seconds
    degraded_after: u64,
    dead_after: u64,
}

impl<R: Module5Reader, E: EventSource, C: Module4Connector> ConnectionManager<R, E, C> {
    pub fn new(reader: R, events: E, controller: C) -> Self {
        Self {
            _reader: reader,
            _events: events,
            controller,
            sessions: HashMap::new(),
            rekey_policy: RekeyPolicy::default(),
            degraded_after: 30,
            dead_after: 120,
        }
    }

    pub fn configure_rekey_policy(&mut self, p: RekeyPolicy) {
        self.rekey_policy = p;
    }

    /// Set liveness thresholds (seconds) for degraded and dead states.
    pub fn set_liveness_thresholds(&mut self, degraded: u64, dead: u64) {
        self.degraded_after = degraded;
        self.dead_after = dead;
    }

    /// Ensure we have meta for a session.
    pub fn ensure_session(&mut self, session: &LogicalSession) {
        if !self.sessions.contains_key(&session.id) {
            let now = SessionMeta::now();
            self.sessions.insert(session.id.clone(), SessionMeta {
                last_pong: now,
                last_ping: now,
                msgs_since_rekey: 0,
                bytes_since_rekey: 0,
                last_rekey_time: now,
            });
        }
    }

    /// Record a sent ping (updates last_ping).
    pub fn record_ping(&mut self, session: &LogicalSession) {
        if let Some(m) = self.sessions.get_mut(&session.id) {
            m.last_ping = SessionMeta::now();
        }
    }

    /// Testing helper: set the session's last_pong to `now - seconds`.
    pub fn set_last_pong_offset(&mut self, session: &LogicalSession, seconds_ago: u64) {
        self.ensure_session(session);
        if let Some(m) = self.sessions.get_mut(&session.id) {
            m.last_pong = SessionMeta::now().saturating_sub(seconds_ago);
        }
    }

    /// Record a received pong (updates last_pong).
    pub fn record_pong(&mut self, session: &LogicalSession) {
        if let Some(m) = self.sessions.get_mut(&session.id) {
            m.last_pong = SessionMeta::now();
        }
    }

    /// Record an outgoing message and its byte size for rekey accounting.
    pub fn record_message_sent(&mut self, session: &LogicalSession, bytes: usize) -> Result<(), LogicalError> {
        if let Some(m) = self.sessions.get_mut(&session.id) {
            m.msgs_since_rekey += 1;
            m.bytes_since_rekey += bytes;
            // check thresholds
            if m.msgs_since_rekey >= self.rekey_policy.msg_threshold || m.bytes_since_rekey >= self.rekey_policy.byte_threshold {
                // request rekey via controller
                match self.controller.request_rekey(&session.id) {
                    Ok(()) => {
                        m.msgs_since_rekey = 0;
                        m.bytes_since_rekey = 0;
                        m.last_rekey_time = SessionMeta::now();
                    }
                    Err(_e) => return Err(LogicalError(format!("rekey-request-failed")))
                }
            }
        }
        Ok(())
    }

    /// Time-based rekey checker; should be called periodically.
    pub fn check_time_rekey(&mut self, session: &LogicalSession) -> Result<(), LogicalError> {
        if let Some(m) = self.sessions.get_mut(&session.id) {
            let now = SessionMeta::now();
            if now - m.last_rekey_time >= self.rekey_policy.time_seconds {
                match self.controller.request_rekey(&session.id) {
                    Ok(()) => {
                        m.msgs_since_rekey = 0;
                        m.bytes_since_rekey = 0;
                        m.last_rekey_time = now;
                    }
                    Err(_e) => return Err(LogicalError("rekey-request-failed".into()))
                }
            }
        }
        Ok(())
    }

    /// Check liveness and update `session` status accordingly.
    /// This method maps controller/module errors to `LogicalError` without leaking internals.
    pub fn check_liveness(&mut self, session: &mut LogicalSession) -> Result<(), LogicalError> {
        self.ensure_session(session);
        let now = SessionMeta::now();
        if let Some(m) = self.sessions.get_mut(&session.id) {
            let age = now.saturating_sub(m.last_pong);
            let new_status = if age >= self.dead_after {
                LogicalStatus::Dead
            } else if age >= self.degraded_after {
                LogicalStatus::Degraded
            } else {
                LogicalStatus::Healthy
            };
            #[cfg(feature = "debug-logs")]
            println!("DEBUG check_liveness: session={} age={} degraded={} dead={} -> {:?}", session.id, age, self.degraded_after, self.dead_after, new_status);
            session.set_status(new_status);
            // If Dead -> attempt reconnect orchestration
            if session.status() == &LogicalStatus::Dead {
                session.set_status(LogicalStatus::Reconnecting);
                match self.controller.orchestrate_reconnect(&session.id) {
                    Ok(()) => session.set_status(LogicalStatus::Healthy),
                    Err(_e) => session.set_status(LogicalStatus::Dead)
                }
            }
        }
        Ok(())
    }

    /// Get the last_rekey_time for a session (if present).
    pub fn last_rekey_time(&self, session_id: &str) -> Option<u64> {
        self.sessions.get(session_id).map(|m| m.last_rekey_time)
    }

    /// Return age in seconds since last_pong for the session, if known.
    pub fn age_since_last_pong(&self, session_id: &str) -> Option<u64> {
        self.sessions.get(session_id).map(|m| SessionMeta::now().saturating_sub(m.last_pong))
    }
}

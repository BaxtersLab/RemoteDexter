//! Session manager (Module 4)
//!
//! Minimal scaffold that demonstrates how higher-level code can consume and
//! verify SCP messages using `scp_consumer`.

pub use scp_consumer::{parse_and_verify, Ed25519MetadataVerifier, NoopTrust, ScpMessage};
use scp_consumer::ScpError;

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Mutex};
use sil::{Subsystem, SubsystemInitContext, SubsystemInitResult};
use tokio::time as tokio_time;
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use std::thread;

/// RD-03: invite token TTL, shortened from the original 5 minutes. The token
/// is sent in a plaintext pre-Noise frame, so a shorter TTL bounds how long a
/// captured-but-unused token remains valid without breaking the human-scale
/// scan/tap/join flow (QR/NFC/Wi-Fi) that needs at least tens of seconds.
const INVITE_TOKEN_TTL_SECS: u64 = 60;

/// Session identifier (UUID v4 string)
pub type SessionId = String;

/// Session state
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    Pending,
    Active,
    Closed,
    Expired,
}

/// Stored session record
#[derive(Clone)]
pub struct SessionRecord {
    pub id: SessionId,
    pub msg: ScpMessage,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub transport: Option<Arc<dyn TransportHandle>>,
    pub state: SessionState,
}

/// Lightweight session view used by upstream consumers
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrSession {
    pub host_ed25519_pubkey: [u8; 32],
    pub noise_static_pubkey: [u8; 32],
    pub session_token: [u8; 32],
    pub signal_server_url: String,
    pub dht_hint: Option<String>,
}

impl QrSession {
    /// Convenience constructor used by tests and consumers.
    pub fn new(
        host_ed25519_pubkey: [u8; 32],
        noise_static_pubkey: [u8; 32],
        session_token: [u8; 32],
        signal_server_url: String,
        dht_hint: Option<String>,
    ) -> Self {
        QrSession { host_ed25519_pubkey, noise_static_pubkey, session_token, signal_server_url, dht_hint }
    }
}

/// Thread-safe session manager with an in-memory store.
pub trait TransportHandle: Send + Sync {
    fn send(&self, bytes: &[u8]) -> Result<(), TransportError>;
    fn close(&self);
}

#[derive(Debug)]
pub enum TransportError {
    SendFailed,
}

/// Callback hooks for session lifecycle events.
pub struct SessionCallbacks {
    pub on_created: Option<Arc<dyn Fn(&SessionId) + Send + Sync>>,
    pub on_verified: Option<Arc<dyn Fn(&SessionId) + Send + Sync>>,
    pub on_attached: Option<Arc<dyn Fn(&SessionId) + Send + Sync>>,
    pub on_closed: Option<Arc<dyn Fn(&SessionId) + Send + Sync>>,
    pub on_expired: Option<Arc<dyn Fn(&SessionId) + Send + Sync>>,
}
/// Errors returned by session operations.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    NotFound,
    NoTransport,
    InvalidState,
    Transport,
}

impl Default for SessionCallbacks {
    fn default() -> Self {
        SessionCallbacks {
            on_created: None,
            on_verified: None,
            on_attached: None,
            on_closed: None,
            on_expired: None,
        }
    }
}

#[derive(Clone)]
pub struct SessionManager {
    store: Arc<RwLock<HashMap<SessionId, SessionRecord>>>,
    callbacks: Arc<Mutex<SessionCallbacks>>,
    accepting_new_sessions: Arc<std::sync::atomic::AtomicBool>,
    sil_token: Arc<Mutex<Option<sil::CancellationToken>>>,
    registrar: Arc<Mutex<Option<Arc<dyn sil::TaskRegistrar>>>>,
    /// Pending invite tokens: token string → expiry time.
    /// Tokens are created by `generate_invite_token()` and consumed/validated
    /// by `validate_token()`.  Each token is single-use with a short TTL
    /// (`INVITE_TOKEN_TTL_SECS`) — RD-03: shortened from 5 minutes because the
    /// token is sent in plaintext before the Noise handshake, so a smaller TTL
    /// bounds how long a captured-but-unused token stays valid.
    pending_tokens: Arc<RwLock<HashMap<String, SystemTime>>>,
}

impl SessionManager {
    /// Create a new SessionManager with an empty store.
    pub fn new() -> Self {
        SessionManager { 
            store: Arc::new(RwLock::new(HashMap::new())), 
            callbacks: Arc::new(Mutex::new(SessionCallbacks::default())),
            accepting_new_sessions: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            sil_token: Arc::new(Mutex::new(None)),
            registrar: Arc::new(Mutex::new(None)),
            pending_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a session from raw SCP wire bytes. Returns the generated `SessionId`.
    /// `ttl_secs` controls the session expiration time.
    pub fn create_session_from_scp(&self, raw: &[u8], ttl_secs: u64) -> Result<SessionId, ScpError> {
        if !self.accepting_new_sessions.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ScpError::InvalidInput); // or a new error, but for now
        }
        // Parse and verify via Module 3
        let verifier = Ed25519MetadataVerifier;
        let trust = NoopTrust;
        let msg = parse_and_verify(raw, &verifier, &trust)?;

        let id = Uuid::new_v4().to_string();
        let now = SystemTime::now();
        let expires = now + Duration::from_secs(ttl_secs);

        let record = SessionRecord {
            id: id.clone(),
            msg: msg.clone(),
            created_at: now,
            expires_at: expires,
            transport: None,
            state: SessionState::Pending,
        };

        {
            let mut map = self.store.write().unwrap();
            map.insert(id.clone(), record);
        }

        // Fire callbacks: created then verified
        if let Some(cb) = &self.callbacks.lock().unwrap().on_created {
            cb(&id);
        }
        if let Some(cb) = &self.callbacks.lock().unwrap().on_verified {
            cb(&id);
        }

        Ok(id)
    }

    /// Lookup a session by id. Returns a clone of the stored `SessionRecord` if found.
    pub fn lookup_session(&self, id: &str) -> Option<SessionRecord> {
        let map = self.store.read().unwrap();
        map.get(id).cloned()
    }

    /// Export a `QrSession` view for the given session id.
    /// Returns `None` if the session is not found or metadata parsing fails.
    pub fn export_qr_session(&self, id: &str) -> Option<QrSession> {
        let rec = self.lookup_session(id)?;
        // Attempt to parse metadata as Module 3's METADATA_V1
        let meta = &rec.msg.pkg.metadata;
        let parsed = match scp_consumer::metadata::parse_metadata(meta) {
            Ok(p) => p,
            Err(_) => return None,
        };

        // host ed25519 pubkey comes from metadata tail
        let mut host_pk = [0u8; 32];
        host_pk.copy_from_slice(parsed.pk);

        // noise static pubkey (X25519) is the pc_x25519_pk field on the ConnectionPackage
        let mut noise_pk = [0u8; 32];
        noise_pk.copy_from_slice(&rec.msg.pkg.pc_x25519_pk);

        // session token: deterministic 32-byte digest of the session id
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let token_bytes = hasher.finalize();
        let mut token = [0u8; 32];
        token.copy_from_slice(&token_bytes[..32]);

        // signal_server_url: best-effort parse from claims (claims often opaque); fallback to default
        let claims = parsed.claims;
        let default_url = "https://signal.local".to_string();
        let mut server_url = default_url.clone();
        if let Ok(s) = std::str::from_utf8(claims) {
            // simple heuristic: look for 'signal_url=' prefix in claims text
            if let Some(idx) = s.find("signal_url=") {
                let rest = &s[idx + "signal_url=".len()..];
                if let Some(end) = rest.find(|c: char| c == ';' || c == '\n' || c == ' ') {
                    server_url = rest[..end].to_string();
                } else {
                    server_url = rest.to_string();
                }
            }
        }

        // dht_hint: not currently encoded in tests/claims; leave None
        let dht_hint = None;

        Some(QrSession::new(host_pk, noise_pk, token, server_url, dht_hint))
    }

    /// Generate a cryptographically random invite token, store it with a short
    /// TTL (see `INVITE_TOKEN_TTL_SECS`), and return the token string. The
    /// token is a UUID v4 — 36 ASCII chars.
    /// **NOT the pairing authority.** Do not wire this back into the host.
    ///
    /// This UUID store predates `crates/pairing` and is no longer on any
    /// production path. Until the Block 4 integration repair, the shipping
    /// handshake validated against it while the console minted tokens from
    /// `PairingService` — two independent stores, so a token from a real QR
    /// could never be accepted. The single live authority is
    /// `pairing::RedemptionHandle`.
    ///
    /// Retained only because this crate's own tests exercise it; Block 10
    /// removes it with the rest of the dormant surface.
    pub fn generate_invite_token(&self) -> String {
        let token = Uuid::new_v4().to_string();
        let expires = SystemTime::now() + Duration::from_secs(INVITE_TOKEN_TTL_SECS);
        self.pending_tokens.write().unwrap().insert(token.clone(), expires);
        token
    }

    /// Validate a session token.  Returns `true` if the token exists and has not expired.
    /// A valid token is consumed (single-use) to prevent replay.
    /// **NOT the pairing authority.** See [`SessionManager::generate_invite_token`].
    pub fn validate_token(&self, token: &str) -> bool {
        let mut map = self.pending_tokens.write().unwrap();
        if let Some(expires) = map.get(token) {
            if SystemTime::now() <= *expires {
                map.remove(token);
                return true;
            }
            // Expired — remove and reject
            map.remove(token);
        }
        false
    }

    /// Attach a transport handle (string placeholder) and mark session Active.
    pub fn attach_transport(&self, id: &str, transport: Arc<dyn TransportHandle>) -> Result<(), ()> {
        let mut map = self.store.write().unwrap();
        if let Some(rec) = map.get_mut(id) {
            rec.transport = Some(transport);
            rec.state = SessionState::Active;
            // fire on_attached
            if let Some(cb) = &self.callbacks.lock().unwrap().on_attached {
                cb(&rec.id);
            }
            Ok(())
        } else {
            Err(())
        }
    }

    /// Close a session and mark it Closed.
    pub fn close_session(&self, id: &str) -> Result<(), ()> {
        let mut map = self.store.write().unwrap();
        if let Some(rec) = map.get_mut(id) {
            rec.state = SessionState::Closed;
            if let Some(cb) = &self.callbacks.lock().unwrap().on_closed {
                cb(&rec.id);
            }
            Ok(())
        } else {
            Err(())
        }
    }

    /// Send raw bytes to the transport attached to the given session.
    /// Returns an error if the session does not exist, has no transport, or the
    /// transport fails to send.
    pub fn send_to_session(&self, id: &str, bytes: &[u8]) -> Result<(), SessionError> {
        if let Some(rec) = self.lookup_session(id) {
            if let Some(transport) = rec.transport {
                // Attempt to parse channel id and payload length for richer logging
                if bytes.len() >= 6 {
                    let _cid = u16::from_be_bytes([bytes[1], bytes[2]]);
                    let _plen = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
                    // If payload contains transfer id + seq, try to parse seq for tracing
                    if bytes.len() >= 14 {
                        let _seq = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
                        #[cfg(feature = "debug-logs")]
                        eprintln!("SM: send_to_session id={} cid={} payload_len={} seq={}", id, cid, plen, seq);
                    } else {
                        #[cfg(feature = "debug-logs")]
                        eprintln!("SM: send_to_session id={} cid={} payload_len={}", id, cid, plen);
                    }
                    let res = transport.send(bytes);
                    #[cfg(feature = "debug-logs")]
                    eprintln!("SM: transport.send result={:?} cid={} payload_len={}", res, cid, plen);
                    return res.map_err(|_| SessionError::Transport);
                } else {
                    #[cfg(feature = "debug-logs")]
                    eprintln!("SM: send_to_session id={} malformed frame len={}", id, bytes.len());
                    let res = transport.send(bytes);
                    #[cfg(feature = "debug-logs")]
                    eprintln!("SM: transport.send result={:?} len={}", res, bytes.len());
                    return res.map_err(|_| SessionError::Transport);
                }
            } else {
                Err(SessionError::NoTransport)
            }
        } else {
            Err(SessionError::NotFound)
        }
    }

    /// Remove expired sessions and return number removed.
    pub fn expire_old_sessions(&self) -> usize {
        let now = SystemTime::now();
        let mut map = self.store.write().unwrap();
        let before = map.len();
        let mut removed = Vec::new();
        map.retain(|k, v| {
            if v.expires_at <= now {
                removed.push(k.clone());
                false
            } else {
                true
            }
        });
        for id in removed.iter() {
            if let Some(cb) = &self.callbacks.lock().unwrap().on_expired {
                cb(id);
            }
        }
        before - map.len()
    }

    /// Start a background thread to expire sessions every `interval_secs` seconds.
    /// The thread runs detached for the lifetime of the process.
    pub fn start_expiration_task(&self, interval_secs: u64) {
        let store = self.store.clone();
        let callbacks = self.callbacks.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(interval_secs));
            let now = SystemTime::now();
            let mut map = store.write().unwrap();
            let expired: Vec<String> = map.iter()
                .filter(|(_k, v)| v.expires_at <= now)
                .map(|(k, _v)| k.clone())
                .collect();
            for k in expired.iter() {
                map.remove(k);
                if let Some(cb) = &callbacks.lock().unwrap().on_expired {
                    cb(k);
                }
            }
        });
    }

    /// Register lifecycle callbacks (replaces the existing callbacks struct).
    pub fn set_callbacks(&self, cbs: SessionCallbacks) {
        let mut lock = self.callbacks.lock().unwrap();
        *lock = cbs;
    }


}

impl Subsystem for SessionManager {
    fn name(&self) -> &'static str { "session_manager" }

    fn init(&self, ctx: &SubsystemInitContext) -> SubsystemInitResult {
        // Store the SIL token and registrar
        *self.sil_token.lock().unwrap() = Some(ctx.cancellation.clone());
        *self.registrar.lock().unwrap() = Some(ctx.registrar.clone());

        // Spawn a session maintenance task that periodically expires old sessions
        let registrar = ctx.registrar.clone();
        let token = ctx.cancellation.clone();
        let store = self.store.clone();
        let fut = async move {
            let mut interval = tokio_time::interval(tokio::time::Duration::from_secs(10)); // check every 10 seconds
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = interval.tick() => {
                        // Expire old sessions
                        let mut map = store.write().unwrap();
                        let _before = map.len();
                        let mut removed = Vec::new();
                        let now = std::time::SystemTime::now();
                        map.retain(|k, v| {
                            if v.expires_at <= now {
                                removed.push(k.clone());
                                false
                            } else {
                                true
                            }
                        });
                        // Note: callbacks are not called here, as per original expire_old_sessions
                    }
                }
            }
        };
        let _task_id = registrar.as_ref().spawn_boxed("session_maintenance", Box::pin(fut));

        SubsystemInitResult::empty()
    }

    fn pre_shutdown(&self) {
        // Stop accepting new sessions
        self.accepting_new_sessions.store(false, std::sync::atomic::Ordering::SeqCst);

        // Mark all active sessions as closing
        let mut map = self.store.write().unwrap();
        for rec in map.values_mut() {
            if rec.state == SessionState::Active {
                rec.state = SessionState::Closed; // or a new state, but for now
            }
        }
    }

    fn on_cancel(&self) {
        // Close all transports
        let map = self.store.read().unwrap();
        for rec in map.values() {
            if let Some(transport) = &rec.transport {
                transport.close();
            }
        }
    }

    fn finalize(&self) {
        // Clear the store
        let mut map = self.store.write().unwrap();
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connection_package_generator::serialize::serialize_without_signature;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;
    use std::sync::mpsc;

    #[test]
    fn lifecycle_create_lookup_attach_close() {
        // build deterministic keypair
        let secret_bytes = [42u8; 32];
        let keypair = SigningKey::from_bytes(&secret_bytes);

        // claims
        let claims = b"claims-v1".to_vec();

        // build package with claims
        let mut pkg = connection_package_generator::types::ConnectionPackage {
            topic_id: [1u8; 32],
            pc_x25519_pk: [2u8; 32],
            android_x25519_pk: [3u8; 32],
            nat_hint: 0,
            port_hints: vec![9000u16],
            metadata: claims.clone(),
        };

        let signed = serialize_without_signature(&pkg);
        let sig = keypair.sign(&signed);
        let full_meta = scp_consumer::build_metadata_v1(&claims, &keypair.verifying_key().to_bytes(), &sig.to_bytes());
        pkg.metadata = full_meta.clone();
        let raw = serialize_without_signature(&pkg);

        let mgr = SessionManager::new();
        let id = mgr.create_session_from_scp(&raw, 60).expect("create");
        let rec = mgr.lookup_session(&id).expect("found");
        assert_eq!(rec.state, SessionState::Pending);
        // use a dummy transport for testing
        struct Dummy;
        impl super::TransportHandle for Dummy {
            fn send(&self, _bytes: &[u8]) -> Result<(), super::TransportError> { Ok(()) }
            fn close(&self) {}
        }
        let transport = Arc::new(Dummy) as Arc<dyn super::TransportHandle>;
        mgr.attach_transport(&id, transport).expect("attach");
        let rec2 = mgr.lookup_session(&id).expect("found");
        assert_eq!(rec2.state, SessionState::Active);
        mgr.close_session(&id).expect("close");
        let rec3 = mgr.lookup_session(&id).expect("found");
        assert_eq!(rec3.state, SessionState::Closed);
    }

    #[test]
    fn expire_task_removes() {
        let secret_bytes = [42u8; 32];
        let keypair = SigningKey::from_bytes(&secret_bytes);

        let claims = b"claims-v1".to_vec();
        let mut pkg = connection_package_generator::types::ConnectionPackage {
            topic_id: [1u8; 32],
            pc_x25519_pk: [2u8; 32],
            android_x25519_pk: [3u8; 32],
            nat_hint: 0,
            port_hints: vec![9000u16],
            metadata: claims.clone(),
        };
        let signed = serialize_without_signature(&pkg);
        let sig = keypair.sign(&signed);
        let full_meta = scp_consumer::build_metadata_v1(&claims, &keypair.verifying_key().to_bytes(), &sig.to_bytes());
        pkg.metadata = full_meta.clone();
        let raw = serialize_without_signature(&pkg);

        let mgr = SessionManager::new();
        let id = mgr.create_session_from_scp(&raw, 1).expect("create");
        assert!(mgr.lookup_session(&id).is_some());
        // expire old sessions manually
        std::thread::sleep(std::time::Duration::from_secs(2));
        let removed = mgr.expire_old_sessions();
        assert!(removed >= 1);
        assert!(mgr.lookup_session(&id).is_none());
    }

    #[test]
    fn callbacks_ordering() {
        use std::sync::{Arc, Mutex};

        let secret_bytes = [42u8; 32];
        let keypair = SigningKey::from_bytes(&secret_bytes);

        let claims = b"claims-v1".to_vec();
        let mut pkg = connection_package_generator::types::ConnectionPackage {
            topic_id: [1u8; 32],
            pc_x25519_pk: [2u8; 32],
            android_x25519_pk: [3u8; 32],
            nat_hint: 0,
            port_hints: vec![9000u16],
            metadata: claims.clone(),
        };
        let signed = serialize_without_signature(&pkg);
        let sig = keypair.sign(&signed);
        let full_meta = scp_consumer::build_metadata_v1(&claims, &keypair.verifying_key().to_bytes(), &sig.to_bytes());
        pkg.metadata = full_meta.clone();
        let raw = serialize_without_signature(&pkg);

        let mgr = SessionManager::new();

        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let ev1 = events.clone();
        let ev2 = events.clone();
        let ev3 = events.clone();
        let ev4 = events.clone();
        let ev5 = events.clone();

        let mut cbs = super::SessionCallbacks::default();
        cbs.on_created = Some(Arc::new(move |_id| { ev1.lock().unwrap().push("created".to_string()); }));
        cbs.on_verified = Some(Arc::new(move |_id| { ev2.lock().unwrap().push("verified".to_string()); }));
        cbs.on_attached = Some(Arc::new(move |_id| { ev3.lock().unwrap().push("attached".to_string()); }));
        cbs.on_closed = Some(Arc::new(move |_id| { ev4.lock().unwrap().push("closed".to_string()); }));
        cbs.on_expired = Some(Arc::new(move |_id| { ev5.lock().unwrap().push("expired".to_string()); }));
        mgr.set_callbacks(cbs);

        let id = mgr.create_session_from_scp(&raw, 60).expect("create");

        // attach transport
        struct Dummy;
        impl super::TransportHandle for Dummy {
            fn send(&self, _bytes: &[u8]) -> Result<(), super::TransportError> { Ok(()) }
            fn close(&self) {}
        }
        let transport = Arc::new(Dummy) as Arc<dyn super::TransportHandle>;
        mgr.attach_transport(&id, transport).expect("attach");

        // close
        mgr.close_session(&id).expect("close");

        // expire (none remain but call anyway)
        mgr.expire_old_sessions();

        let evs = events.lock().unwrap().clone();
        // check ordering for first three
        assert!(evs.len() >= 3);
        assert_eq!(evs[0], "created");
        assert_eq!(evs[1], "verified");
        assert_eq!(evs[2], "attached");
    }

    #[test]
    fn transport_inmemory_demo() {
        use std::sync::mpsc::Receiver;

        // helper: create a transport pair A<->B. Messages sent on A appear on rx_b.
        fn make_pair() -> (Arc<dyn super::TransportHandle>, Receiver<Vec<u8>>, Arc<dyn super::TransportHandle>, Receiver<Vec<u8>>) {
            let (tx_a, rx_a) = mpsc::channel::<Vec<u8>>();
            let (tx_b, rx_b) = mpsc::channel::<Vec<u8>>();

            struct Ep { tx: mpsc::Sender<Vec<u8>> }
            impl super::TransportHandle for Ep {
                fn send(&self, bytes: &[u8]) -> Result<(), super::TransportError> {
                    self.tx.send(bytes.to_vec()).map_err(|_| super::TransportError::SendFailed)
                }
                fn close(&self) {}
            }

            let a = Arc::new(Ep { tx: tx_b.clone() }) as Arc<dyn super::TransportHandle>;
            let b = Arc::new(Ep { tx: tx_a.clone() }) as Arc<dyn super::TransportHandle>;
            (a, rx_a, b, rx_b)
        }

        // deterministic keypair and signed SCP as before
        let secret_bytes = [42u8; 32];
        let keypair = SigningKey::from_bytes(&secret_bytes);

        let claims = b"claims-v1".to_vec();
        let mut pkg = connection_package_generator::types::ConnectionPackage {
            topic_id: [1u8; 32],
            pc_x25519_pk: [2u8; 32],
            android_x25519_pk: [3u8; 32],
            nat_hint: 0,
            port_hints: vec![9000u16],
            metadata: claims.clone(),
        };
        let signed = serialize_without_signature(&pkg);
        let sig = keypair.sign(&signed);
        let full_meta = scp_consumer::build_metadata_v1(&claims, &keypair.verifying_key().to_bytes(), &sig.to_bytes());
        pkg.metadata = full_meta.clone();
        let raw = serialize_without_signature(&pkg);

        let mgr = SessionManager::new();
        let (handle_a, rx_a, _handle_b, rx_b) = make_pair();

        let id = mgr.create_session_from_scp(&raw, 60).expect("create");
        // attach A to session
        mgr.attach_transport(&id, handle_a).expect("attach");

        // send bytes from the attached transport (session side)
        let rec = mgr.lookup_session(&id).expect("found");
        let t = rec.transport.expect("transport");
        t.send(b"hello").expect("send");

        // receiver on the remote side should get the message
        let got = rx_b.recv().expect("recv");
        assert_eq!(got, b"hello".to_vec());

        // sanity: ensure rx_a is empty (no message from remote)
        assert!(rx_a.try_recv().is_err());
    }

    // ── RD-03: invite token TTL/single-use ───────────────────────────────

    #[test]
    fn invite_token_is_valid_once() {
        let mgr = SessionManager::new();
        let token = mgr.generate_invite_token();
        assert!(mgr.validate_token(&token));
        // single-use: a second validation of the same token must fail
        assert!(!mgr.validate_token(&token));
    }

    #[test]
    fn unknown_invite_token_is_rejected() {
        let mgr = SessionManager::new();
        assert!(!mgr.validate_token("not-a-real-token"));
    }

    #[test]
    fn invite_token_ttl_is_short() {
        // RD-03: shortened from 5 minutes so a captured-but-unused token
        // doesn't stay valid indefinitely. Regression guard against silently
        // reverting to a long TTL.
        assert!(INVITE_TOKEN_TTL_SECS <= 120);
    }
}

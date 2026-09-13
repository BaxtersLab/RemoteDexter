//! Which devices this host has enrolled, and whether one may come back.
//!
//! Block 9. Until now every connection had to redeem a one-use pairing token,
//! so a phone that had already enrolled had nothing left to present and was
//! refused — proven by `a_paired_device_reconnects_without_a_new_qr`. This is
//! the record that lets it return.
//!
//! ## What identifies a device
//!
//! Its **Noise static public key**, which the host already holds for free at
//! the end of every XX handshake and has never until now looked at. Nothing
//! else is an identity: not a name, not an address, not a token. A name is a
//! label the owner can change; an address changes with the network; a token is
//! spent the moment it is used.
//!
//! ## Why revocation is a tombstone
//!
//! Revoking sets `revoked_at` and **keeps the record**. Deleting it would mean
//! an in-flight or replayed enrolment could recreate the same identity and
//! silently restore access the owner just withdrew. A tombstone cannot be
//! walked around: the key stays known-and-refused until someone presents a
//! fresh signed QR, which is a deliberate act by the owner at the host.
//!
//! ## What this module does NOT do
//!
//! It never validates a token — that is `service::PairingService`'s single
//! authority and must stay there. `enroll` is what the host calls *after* a
//! token has been spent successfully. Keeping the two apart is what stops this
//! store from becoming a second, weaker way to authenticate.
//!
//! Pure: no clock, no I/O, no sockets. `now` is always passed in.

use std::collections::HashMap;

/// A device the owner has enrolled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// Noise static public key. The identity.
    pub public_key: [u8; 32],
    /// Owner-facing label. Not an identity — two devices may share a name.
    pub display_name: String,
    /// When the owner first enrolled it.
    pub created_at: u64,
    /// When it last authenticated. Refreshed on every accepted reconnect.
    pub last_seen_at: u64,
    /// `Some` once revoked. The record is kept; see the module docs.
    pub revoked_at: Option<u64>,
}

impl DeviceRecord {
    /// Has the owner withdrawn this device?
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Why a device was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedReason {
    /// No record for this key — it has never enrolled, or the host is new.
    Unknown,
    /// Known, and deliberately withdrawn by the owner.
    Revoked,
}

impl RefusedReason {
    /// Deliberately identical wording for both cases.
    ///
    /// A peer that guesses learns only that it was refused — never whether the
    /// key is unknown or known-and-revoked, which would turn the host into an
    /// oracle for which devices it has ever paired with.
    pub fn public_reason(self) -> &'static str {
        "not authorized"
    }
}

/// How a connection is claiming the right to a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// First contact: a one-use token from a signed QR.
    Enroll {
        /// The one-use token presented from the invite.
        token: String,
    },
    /// A device that has been here before, presenting only its static key.
    Paired,
}

/// The enrolled devices.
#[derive(Debug, Default, Clone)]
pub struct DeviceStore {
    records: HashMap<[u8; 32], DeviceRecord>,
}

impl DeviceStore {
    /// An empty store — a host that has enrolled nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many devices are on record, revoked ones included.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when no device has ever enrolled.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The record for a key, if this host has ever seen it.
    pub fn get(&self, public_key: &[u8; 32]) -> Option<&DeviceRecord> {
        self.records.get(public_key)
    }

    /// Every record, revoked ones included, for the owner's device list.
    pub fn iter(&self) -> impl Iterator<Item = &DeviceRecord> {
        self.records.values()
    }

    /// Record a device after its token has been spent.
    ///
    /// Idempotent: enrolling a key that is already present refreshes it rather
    /// than adding a second record, so a client that retries mid-handshake
    /// cannot fill the store with duplicates of itself.
    ///
    /// **Enrolling clears a tombstone.** That is not a hole in revocation: the
    /// caller only reaches here by spending a fresh signed token, which the
    /// owner had to mint at the host. Revocation blocks *reconnects*, not the
    /// owner's deliberate decision to pair the device again.
    pub fn enroll(&mut self, public_key: [u8; 32], display_name: &str, now: u64) {
        match self.records.get_mut(&public_key) {
            Some(existing) => {
                existing.last_seen_at = now;
                existing.revoked_at = None;
                if !display_name.is_empty() {
                    existing.display_name = display_name.to_string();
                }
            }
            None => {
                self.records.insert(
                    public_key,
                    DeviceRecord {
                        public_key,
                        display_name: display_name.to_string(),
                        created_at: now,
                        last_seen_at: now,
                        revoked_at: None,
                    },
                );
            }
        }
    }

    /// The authorization decision on its own, with NO side effect.
    ///
    /// Split out from [`authorize_paired`](Self::authorize_paired) on
    /// 2026-09-07 so a LIVE session can keep asking "am I still allowed?"
    /// without rewriting the store every time it asks. `authorize_paired`
    /// records `last_seen_at` and therefore persists; calling that on a timer,
    /// per connection, would turn a liveness check into a continuous disk
    /// write — which is a denial-of-service surface, not a security check.
    ///
    /// Both callers share this one function deliberately. If the reconnect
    /// answer and the still-connected answer were computed separately they
    /// could drift, and "revoked" would come to mean two different things
    /// depending on which path asked.
    ///
    /// Revocation is a flag, not a deadline, so this needs no clock.
    pub fn is_authorized(&self, public_key: &[u8; 32]) -> Result<(), RefusedReason> {
        match self.records.get(public_key) {
            None => Err(RefusedReason::Unknown),
            Some(record) if record.is_revoked() => Err(RefusedReason::Revoked),
            Some(_) => Ok(()),
        }
    }

    /// May this device reconnect on its key alone?
    ///
    /// Updates `last_seen_at` on success. Fails closed: unknown and revoked are
    /// both refusals, and both report the same thing to the peer.
    ///
    /// The decision itself is [`is_authorized`](Self::is_authorized); this adds
    /// only the bookkeeping, so a reconnect and a live session can never
    /// disagree about whether a device is allowed.
    pub fn authorize_paired(
        &mut self,
        public_key: &[u8; 32],
        now: u64,
    ) -> Result<(), RefusedReason> {
        self.is_authorized(public_key)?;
        if let Some(record) = self.records.get_mut(public_key) {
            record.last_seen_at = now;
        }
        Ok(())
    }

    /// Withdraw a device. Tombstoned, never deleted.
    ///
    /// Returns whether a record was actually marked, so a UI can tell "revoked"
    /// from "there was nothing to revoke". Revoking twice keeps the FIRST
    /// timestamp: when access was withdrawn is a fact, and a second click must
    /// not rewrite it.
    pub fn revoke(&mut self, public_key: &[u8; 32], now: u64) -> bool {
        match self.records.get_mut(public_key) {
            Some(record) if !record.is_revoked() => {
                record.revoked_at = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Remove a **revoked** record entirely, so the owner's list stops growing.
    ///
    /// # Why only revoked
    ///
    /// The tombstone is not bookkeeping. It exists so that an enrolment already
    /// in flight — or a replayed one — cannot recreate an identity the owner
    /// just withdrew: `enroll` clears a revocation, so a record that merely
    /// vanished would be recreated by the very race the tombstone is there to
    /// lose.
    ///
    /// Forgetting an already-revoked record does not reopen that. An absent
    /// key and a revoked key are refused **identically** — both answer
    /// "not authorized", and the host is deliberately not an oracle for which.
    /// What the record still holds by then is history, not authority.
    ///
    /// Forgetting an ACTIVE device is refused for exactly the reason above: it
    /// would be a revoke without the tombstone, which is the unsafe half of the
    /// operation wearing a tidier name. Revoke first, then forget — two
    /// deliberate acts, in an order that is never briefly permissive.
    pub fn forget(&mut self, public_key: &[u8; 32]) -> ForgetOutcome {
        match self.records.get(public_key) {
            None => ForgetOutcome::Unknown,
            Some(record) if !record.is_revoked() => ForgetOutcome::StillActive,
            Some(_) => {
                self.records.remove(public_key);
                ForgetOutcome::Forgotten
            }
        }
    }
}

/// What [`DeviceStore::forget`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgetOutcome {
    /// The record is gone.
    Forgotten,
    /// Refused: the device is still active. Revoke it first.
    StillActive,
    /// There was no such record. Not an error — the list is already as the
    /// caller wanted it — but distinguishable, so a UI does not claim to have
    /// removed something that was never there.
    Unknown,
}

/// The on-disk form of one record.
///
/// The key is stored as **hex**, not as a 32-element array. A byte array would
/// serialise to `[171,205,...]` — unreadable to an operator inspecting their
/// own device list, and brittle if the field type ever changes. Hex is stable,
/// greppable, and matches how fingerprints already appear in logs.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredDevice {
    public_key: String,
    display_name: String,
    created_at: u64,
    last_seen_at: u64,
    #[serde(default)]
    revoked_at: Option<u64>,
}

/// The on-disk file.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredDevices {
    /// Format version, so a future change can be recognised rather than
    /// guessed at. An unknown version is a refusal, never a silent reset.
    version: u32,
    devices: Vec<StoredDevice>,
}

/// The only version this build writes or accepts.
const STORE_VERSION: u32 = 1;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Why a stored device list could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Not valid JSON, or not the expected shape.
    Malformed(String),
    /// Written by a build that is not this one.
    UnknownVersion(u32),
}

impl DeviceStore {
    /// Serialise for storage.
    pub fn to_json(&self) -> String {
        let mut devices: Vec<StoredDevice> = self
            .records
            .values()
            .map(|r| StoredDevice {
                public_key: to_hex(&r.public_key),
                display_name: r.display_name.clone(),
                created_at: r.created_at,
                last_seen_at: r.last_seen_at,
                revoked_at: r.revoked_at,
            })
            .collect();
        // Stable order, so an unchanged store produces an unchanged file and a
        // diff of the device list means something.
        devices.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        serde_json::to_string_pretty(&StoredDevices {
            version: STORE_VERSION,
            devices,
        })
        .unwrap_or_else(|_| String::from("{\"version\":1,\"devices\":[]}"))
    }

    /// Read a stored device list.
    ///
    /// A record whose key is not 32 hex bytes is **skipped**, not fatal: one
    /// unreadable entry must not cost the operator the rest of their list. A
    /// file that is not parseable at all IS an error — see `device_file` for
    /// what the host does about it, which is never to overwrite it.
    pub fn from_json(text: &str) -> Result<Self, StoreError> {
        let parsed: StoredDevices =
            serde_json::from_str(text).map_err(|e| StoreError::Malformed(e.to_string()))?;
        if parsed.version != STORE_VERSION {
            return Err(StoreError::UnknownVersion(parsed.version));
        }
        let mut store = DeviceStore::new();
        for d in parsed.devices {
            let Some(key) = from_hex(&d.public_key) else {
                continue;
            };
            store.records.insert(
                key,
                DeviceRecord {
                    public_key: key,
                    display_name: d.display_name,
                    created_at: d.created_at,
                    last_seen_at: d.last_seen_at,
                    revoked_at: d.revoked_at,
                },
            );
        }
        Ok(store)
    }
}

/// A shareable handle to one host's [`DeviceStore`].
///
/// Mirrors `service::RedemptionHandle`: cheap to clone, handed to each
/// connection, and the single place device state is read or written. Lock
/// poisoning is absorbed rather than panicking — a poisoned device list must
/// not take the host down, and every operation is already fail-closed.
#[derive(Clone, Default)]
pub struct DeviceHandle {
    store: std::sync::Arc<std::sync::Mutex<DeviceStore>>,
    /// Called after every change, so the caller can persist it.
    ///
    /// A callback rather than a path, so this crate keeps knowing nothing about
    /// files: the store stays pure and testable, and the host owns where its
    /// data lives.
    on_change: Option<std::sync::Arc<dyn Fn(&DeviceStore) + Send + Sync>>,
}

impl DeviceHandle {
    /// A handle to a new, empty store that persists nowhere.
    pub fn new() -> Self {
        Self::default()
    }

    /// A handle over an existing store that reports every change.
    pub fn restored(
        store: DeviceStore,
        on_change: std::sync::Arc<dyn Fn(&DeviceStore) + Send + Sync>,
    ) -> Self {
        DeviceHandle {
            store: std::sync::Arc::new(std::sync::Mutex::new(store)),
            on_change: Some(on_change),
        }
    }

    fn changed(&self, store: &DeviceStore) {
        if let Some(sink) = &self.on_change {
            sink(store);
        }
    }

    /// See [`DeviceStore::enroll`].
    pub fn enroll(&self, public_key: [u8; 32], display_name: &str, now: u64) {
        let mut guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        guard.enroll(public_key, display_name, now);
        self.changed(&guard);
    }

    /// See [`DeviceStore::authorize_paired`].
    pub fn authorize_paired(&self, public_key: &[u8; 32], now: u64) -> Result<(), RefusedReason> {
        let mut guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let outcome = guard.authorize_paired(public_key, now);
        // Only a successful reconnect changes anything (`last_seen_at`); a
        // refusal must not cause a write, or a stranger could make the host
        // rewrite its device list on demand.
        if outcome.is_ok() {
            self.changed(&guard);
        }
        outcome
    }

    /// See [`DeviceStore::is_authorized`]. Read-only: it deliberately does NOT
    /// call `changed`, so a live session may ask as often as it likes without
    /// touching the disk.
    pub fn is_authorized(&self, public_key: &[u8; 32]) -> Result<(), RefusedReason> {
        let guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        guard.is_authorized(public_key)
    }

    /// See [`DeviceStore::revoke`].
    pub fn revoke(&self, public_key: &[u8; 32], now: u64) -> bool {
        let mut guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let changed = guard.revoke(public_key, now);
        if changed {
            self.changed(&guard);
        }
        changed
    }

    /// See [`DeviceStore::forget`].
    ///
    /// Only a change is written. A refused forget must not rewrite the device
    /// file: a stranger able to provoke one would otherwise make the host
    /// rewrite its list on demand.
    pub fn forget(&self, public_key: &[u8; 32]) -> ForgetOutcome {
        let mut guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let outcome = guard.forget(public_key);
        if outcome == ForgetOutcome::Forgotten {
            self.changed(&guard);
        }
        outcome
    }

    /// Every record, for the owner's device list.
    pub fn snapshot(&self) -> Vec<DeviceRecord> {
        self.store
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    // ── forgetting a revoked device ──────────────────────────────────────

    /// The operator's problem: revoked entries accumulated with no way to
    /// clear them, so the console's list grew forever with dead rows.
    #[test]
    fn a_revoked_device_can_be_forgotten() {
        let mut store = DeviceStore::new();
        let key = [7u8; 32];
        store.enroll(key, "phone", 100);
        assert!(store.revoke(&key, 200));
        assert_eq!(store.forget(&key), ForgetOutcome::Forgotten);
        assert_eq!(store.len(), 0);
    }

    /// **The rule that keeps this safe.** Forgetting an active device would be
    /// a revoke without the tombstone — the unsafe half of the operation
    /// wearing a tidier name, and it would reopen the race that lets an
    /// in-flight enrolment recreate a withdrawn identity.
    #[test]
    fn an_active_device_cannot_be_forgotten() {
        let mut store = DeviceStore::new();
        let key = [7u8; 32];
        store.enroll(key, "phone", 100);
        assert_eq!(store.forget(&key), ForgetOutcome::StillActive);
        assert_eq!(store.len(), 1, "the record must survive a refused forget");
        // And it is still authorized, so the refusal changed nothing at all.
        assert!(store.authorize_paired(&key, 300).is_ok());
    }

    /// Forgetting something that was never there is not an error, but it is
    /// distinguishable — a UI must not claim to have removed a row that did
    /// not exist.
    #[test]
    fn forgetting_an_unknown_device_reports_that_nothing_happened() {
        let mut store = DeviceStore::new();
        assert_eq!(store.forget(&[9u8; 32]), ForgetOutcome::Unknown);
    }

    /// A forgotten device is refused exactly as a revoked one was, which is
    /// what makes removing the record safe: the host answers "not authorized"
    /// either way and never becomes an oracle for which.
    #[test]
    fn a_forgotten_device_is_still_refused_and_indistinguishably_so() {
        let mut store = DeviceStore::new();
        let key = [7u8; 32];
        store.enroll(key, "phone", 100);
        store.revoke(&key, 200);
        let while_revoked = store.authorize_paired(&key, 300);
        store.forget(&key);
        let after_forget = store.authorize_paired(&key, 400);

        assert!(while_revoked.is_err());
        assert!(after_forget.is_err());
        assert_eq!(
            while_revoked.unwrap_err().public_reason(),
            after_forget.unwrap_err().public_reason(),
            "revoked and forgotten must look the same to the peer"
        );
    }

    /// Forgetting one device must not disturb the others — the operator is
    /// tidying a list, not resetting it.
    #[test]
    fn forgetting_one_device_leaves_the_rest_untouched() {
        let mut store = DeviceStore::new();
        let gone = [1u8; 32];
        let kept = [2u8; 32];
        store.enroll(gone, "old", 100);
        store.enroll(kept, "current", 100);
        store.revoke(&gone, 200);
        assert_eq!(store.forget(&gone), ForgetOutcome::Forgotten);
        assert_eq!(store.len(), 1);
        assert!(store.authorize_paired(&kept, 300).is_ok());
    }

    /// A forgotten device can pair again with a fresh QR — the same as any
    /// device the host has never seen, which is exactly what it now is.
    #[test]
    fn a_forgotten_device_can_be_enrolled_again_by_a_fresh_pairing() {
        let mut store = DeviceStore::new();
        let key = [7u8; 32];
        store.enroll(key, "phone", 100);
        store.revoke(&key, 200);
        store.forget(&key);
        store.enroll(key, "phone again", 300);
        assert!(store.authorize_paired(&key, 400).is_ok());
    }

    /// A forgotten device must not come back on the next start — otherwise the
    /// operator tidies the list and finds it exactly as it was after a restart,
    /// which is worse than no button at all.
    #[test]
    fn a_forgotten_device_does_not_return_after_a_reload() {
        let mut store = DeviceStore::new();
        let gone = [1u8; 32];
        let kept = [2u8; 32];
        store.enroll(gone, "old", 100);
        store.enroll(kept, "current", 100);
        store.revoke(&gone, 200);
        store.forget(&gone);

        let reloaded = DeviceStore::from_json(&store.to_json()).expect("round trip");
        assert_eq!(reloaded.len(), 1);
        assert!(
            reloaded.get(&gone).is_none(),
            "the forgotten device came back"
        );
        assert!(reloaded.get(&kept).is_some(), "the kept device was lost");
    }

    /// A refused forget must not make the host rewrite its device file: a
    /// stranger able to provoke one would otherwise have a way to make it
    /// write on demand.
    #[test]
    fn a_refused_forget_does_not_report_a_change() {
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&writes);
        let handle = DeviceHandle::restored(
            DeviceStore::new(),
            std::sync::Arc::new(move |_: &DeviceStore| {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        );
        let key = [5u8; 32];
        handle.enroll(key, "phone", 100);
        let after_enroll = writes.load(std::sync::atomic::Ordering::SeqCst);

        assert_eq!(handle.forget(&key), ForgetOutcome::StillActive);
        assert_eq!(
            writes.load(std::sync::atomic::Ordering::SeqCst),
            after_enroll,
            "a refused forget wrote to the device file"
        );

        handle.revoke(&key, 200);
        let before = writes.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(handle.forget(&key), ForgetOutcome::Forgotten);
        assert!(
            writes.load(std::sync::atomic::Ordering::SeqCst) > before,
            "a real forget must be persisted"
        );
    }

    use super::*;

    const A: [u8; 32] = [1u8; 32];
    const B: [u8; 32] = [2u8; 32];

    #[test]
    fn a_fresh_host_knows_no_devices() {
        let mut s = DeviceStore::new();
        assert!(s.is_empty());
        assert_eq!(s.authorize_paired(&A, 10), Err(RefusedReason::Unknown));
    }

    #[test]
    fn an_enrolled_device_may_reconnect_on_its_key_alone() {
        let mut s = DeviceStore::new();
        s.enroll(A, "Baxter's S10", 100);
        assert_eq!(s.authorize_paired(&A, 200), Ok(()));
        assert_eq!(
            s.get(&A).unwrap().last_seen_at,
            200,
            "a reconnect must be recorded as a sighting"
        );
        assert_eq!(
            s.get(&A).unwrap().created_at,
            100,
            "enrolment time is a fact"
        );
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let mut s = DeviceStore::new();
        s.enroll(A, "known", 100);
        assert_eq!(s.authorize_paired(&B, 200), Err(RefusedReason::Unknown));
    }

    /// The defect this whole module exists to prevent: revocation that can be
    /// walked around.
    #[test]
    fn a_revoked_device_is_refused_and_the_record_survives() {
        let mut s = DeviceStore::new();
        s.enroll(A, "stolen phone", 100);
        assert!(s.revoke(&A, 150));

        assert_eq!(s.authorize_paired(&A, 200), Err(RefusedReason::Revoked));
        assert_eq!(
            s.len(),
            1,
            "the record must survive: deleting it would let a replay recreate the identity"
        );
        assert_eq!(s.get(&A).unwrap().revoked_at, Some(150));
    }

    #[test]
    fn revoking_twice_keeps_the_first_timestamp() {
        let mut s = DeviceStore::new();
        s.enroll(A, "d", 100);
        assert!(s.revoke(&A, 150));
        assert!(!s.revoke(&A, 900), "a second revoke changes nothing");
        assert_eq!(
            s.get(&A).unwrap().revoked_at,
            Some(150),
            "when access was withdrawn is a fact; a second click must not rewrite it"
        );
    }

    #[test]
    fn revoking_an_unknown_device_reports_that_nothing_happened() {
        let mut s = DeviceStore::new();
        assert!(!s.revoke(&A, 10));
    }

    /// A client that retries mid-handshake must not fill the store with copies
    /// of itself.
    #[test]
    fn enrolment_is_idempotent() {
        let mut s = DeviceStore::new();
        s.enroll(A, "phone", 100);
        s.enroll(A, "phone", 120);
        assert_eq!(s.len(), 1);
        assert_eq!(s.get(&A).unwrap().created_at, 100);
        assert_eq!(s.get(&A).unwrap().last_seen_at, 120);
    }

    /// Re-pairing after revocation is the owner's decision, and it requires a
    /// fresh signed token to reach `enroll` at all.
    #[test]
    fn enrolling_again_clears_a_tombstone() {
        let mut s = DeviceStore::new();
        s.enroll(A, "phone", 100);
        s.revoke(&A, 150);
        assert_eq!(s.authorize_paired(&A, 160), Err(RefusedReason::Revoked));

        s.enroll(A, "phone", 200);
        assert_eq!(
            s.authorize_paired(&A, 210),
            Ok(()),
            "a fresh QR is the owner deliberately pairing it again"
        );
        assert_eq!(s.len(), 1, "and it is still one device, not two");
    }

    /// The host must not become an oracle for which devices it has ever seen.
    #[test]
    fn unknown_and_revoked_are_indistinguishable_to_the_peer() {
        assert_eq!(
            RefusedReason::Unknown.public_reason(),
            RefusedReason::Revoked.public_reason(),
            "telling them apart leaks which keys this host has paired with"
        );
    }

    #[test]
    fn an_empty_name_does_not_erase_an_existing_one() {
        let mut s = DeviceStore::new();
        s.enroll(A, "Baxter's S10", 100);
        s.enroll(A, "", 200);
        assert_eq!(s.get(&A).unwrap().display_name, "Baxter's S10");
    }

    #[test]
    fn a_store_round_trips_through_json() {
        let mut s = DeviceStore::new();
        s.enroll(A, "Baxter's S10", 100);
        s.enroll(B, "tablet", 110);
        let back = DeviceStore::from_json(&s.to_json()).expect("round trip");
        assert_eq!(back.len(), 2);
        assert_eq!(back.get(&A).unwrap().display_name, "Baxter's S10");
        assert_eq!(back.get(&A).unwrap().created_at, 100);
    }

    /// The one that matters: a revocation that does not survive a restart is
    /// not a revocation. The host would come back up and let the withdrawn
    /// device straight in.
    #[test]
    fn revocation_survives_a_round_trip() {
        let mut s = DeviceStore::new();
        s.enroll(A, "stolen", 100);
        s.revoke(&A, 150);
        let mut back = DeviceStore::from_json(&s.to_json()).expect("round trip");
        assert_eq!(back.get(&A).unwrap().revoked_at, Some(150));
        assert_eq!(
            back.authorize_paired(&A, 200),
            Err(RefusedReason::Revoked),
            "a restart must not un-revoke a device"
        );
    }

    #[test]
    fn an_empty_store_round_trips() {
        let back = DeviceStore::from_json(&DeviceStore::new().to_json()).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn the_serialised_order_is_stable() {
        let mut s = DeviceStore::new();
        s.enroll(B, "b", 100);
        s.enroll(A, "a", 100);
        let first = s.to_json();
        let mut t = DeviceStore::new();
        t.enroll(A, "a", 100);
        t.enroll(B, "b", 100);
        assert_eq!(
            first,
            t.to_json(),
            "insertion order must not change the file, or every save looks like a change"
        );
    }

    #[test]
    fn unparseable_text_is_an_error_not_an_empty_store() {
        assert!(matches!(
            DeviceStore::from_json("not json"),
            Err(StoreError::Malformed(_))
        ));
    }

    #[test]
    fn a_future_version_is_refused_rather_than_misread() {
        let text = r#"{"version":99,"devices":[]}"#;
        assert!(matches!(
            DeviceStore::from_json(text),
            Err(StoreError::UnknownVersion(99))
        ));
    }

    /// One unreadable entry must not cost the operator the rest of the list.
    #[test]
    fn a_bad_key_is_skipped_and_the_rest_survive() {
        let good = to_hex(&A);
        let text = format!(
            r#"{{"version":1,"devices":[
                {{"public_key":"zz","display_name":"bad","created_at":1,"last_seen_at":1}},
                {{"public_key":"{good}","display_name":"good","created_at":2,"last_seen_at":2}}
            ]}}"#
        );
        let store = DeviceStore::from_json(&text).expect("parses");
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&A).unwrap().display_name, "good");
    }

    /// Two connections must see ONE store, or a device enrolled on one
    /// connection would be a stranger on the next.
    #[test]
    fn a_cloned_handle_shares_the_same_store() {
        let a = DeviceHandle::new();
        let b = a.clone();
        a.enroll(A, "phone", 100);
        assert_eq!(b.authorize_paired(&A, 110), Ok(()));
        assert!(b.revoke(&A, 120));
        assert_eq!(
            a.authorize_paired(&A, 130),
            Err(RefusedReason::Revoked),
            "a revoke on one handle must bind on every handle"
        );
        assert_eq!(a.snapshot().len(), 1);
    }

    /// Every change must reach the sink, or the device list on disk drifts
    /// away from the one the host is enforcing.
    /// A live session asks "am I still allowed?" repeatedly. That question must
    /// not cost a disk write, or the security check becomes a denial-of-service
    /// surface — a connection could make the host rewrite its device list on a
    /// timer, forever.
    ///
    /// This is why `is_authorized` exists separately from `authorize_paired`:
    /// the latter records `last_seen_at`, which is a legitimate write on a
    /// reconnect and an illegitimate one on a heartbeat.
    #[test]
    fn asking_if_a_device_is_authorized_never_writes_the_store() {
        use std::sync::{Arc, Mutex};
        let seen = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&seen);
        let h = DeviceHandle::restored(
            DeviceStore::new(),
            Arc::new(move |_: &DeviceStore| {
                *counter.lock().unwrap() += 1;
            }),
        );

        h.enroll(A, "phone", 100);
        let after_enrol = *seen.lock().unwrap();

        for _ in 0..100 {
            assert!(h.is_authorized(&A).is_ok());
        }
        assert_eq!(
            *seen.lock().unwrap(),
            after_enrol,
            "100 authorization queries must produce zero writes"
        );

        // The contrast, so this cannot pass by the sink being broken.
        assert!(h.authorize_paired(&A, 110).is_ok());
        assert_eq!(
            *seen.lock().unwrap(),
            after_enrol + 1,
            "a real reconnect still records last_seen_at"
        );
    }

    /// Revocation must change the answer immediately, in the same store the
    /// live session is reading.
    #[test]
    fn revoking_flips_the_authorization_answer_at_once() {
        let h = DeviceHandle::new();
        h.enroll(A, "phone", 100);
        assert!(h.is_authorized(&A).is_ok(), "enrolled");
        assert!(h.revoke(&A, 120));
        assert_eq!(h.is_authorized(&A), Err(RefusedReason::Revoked));
    }

    /// A device that was never enrolled, or was forgotten, is refused the same
    /// way. Fails closed.
    #[test]
    fn an_unknown_device_is_not_authorized() {
        let h = DeviceHandle::new();
        assert_eq!(h.is_authorized(&A), Err(RefusedReason::Unknown));
    }

    #[test]
    fn every_change_is_reported_and_refusals_are_not() {
        use std::sync::{Arc, Mutex};
        let seen = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&seen);
        let h = DeviceHandle::restored(
            DeviceStore::new(),
            Arc::new(move |_: &DeviceStore| {
                *counter.lock().unwrap() += 1;
            }),
        );

        h.enroll(A, "phone", 100);
        assert_eq!(*seen.lock().unwrap(), 1, "an enrolment is a change");
        assert!(h.authorize_paired(&A, 110).is_ok());
        assert_eq!(*seen.lock().unwrap(), 2, "a reconnect updates last_seen_at");
        assert!(h.revoke(&A, 120));
        assert_eq!(*seen.lock().unwrap(), 3, "a revoke is a change");

        assert!(h.authorize_paired(&A, 130).is_err());
        assert_eq!(
            *seen.lock().unwrap(),
            3,
            "a refusal must not write: a stranger could otherwise make the host \
             rewrite its device list on demand"
        );
        assert!(!h.revoke(&A, 140));
        assert_eq!(*seen.lock().unwrap(), 3, "a second revoke changes nothing");
    }

    #[test]
    fn the_owner_list_includes_revoked_devices() {
        let mut s = DeviceStore::new();
        s.enroll(A, "kept", 100);
        s.enroll(B, "withdrawn", 100);
        s.revoke(&B, 150);
        assert_eq!(
            s.iter().count(),
            2,
            "the owner must still see what they revoked"
        );
        assert_eq!(s.iter().filter(|r| r.is_revoked()).count(), 1);
    }
}

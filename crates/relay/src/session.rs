//! Which host a phone gets spliced to, and for how long.
//!
//! A session id is the only thing a phone presents to reach a host, so it is
//! treated exactly like the pairing token it travels beside: **high entropy,
//! single use, short lived**. It is not a secret in the sense that leaking it
//! breaks the session — Noise XX with a pinned host key still refuses an
//! impostor — but a guessable id lets a stranger occupy the host's waiting
//! slot, which is a denial of service against the operator.

use rand::RngCore;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a session survives without a word from its host.
///
/// **This is a liveness timeout, not a lifetime.** It was a lifetime, measured
/// from registration, and that was wrong the moment the host began holding a
/// persistent control connection: the session id is what the invite names, so a
/// session that expired on a fixed clock would strand a host that was still
/// connected and make the id move — the exact thing the control/data split was
/// chosen to avoid.
///
/// The host's keepalive refreshes it. With `CONTROL_KEEPALIVE` at 20s a live
/// host is heard from three times over, and a host that has genuinely gone is
/// dropped within a minute. The bound still does its job — a relay cannot
/// accumulate sessions for hosts that vanished — without punishing one that is
/// there.
pub const SESSION_TTL: Duration = Duration::from_secs(60);

/// The number of random bytes behind a session id.
///
/// 16 bytes is 128 bits. The id is base64 of that — not a counter and not a
/// timestamp. It is now DERIVED for an enrolled host (see [`SessionKey`]), but
/// through a keyed hash, so it still tells a watcher nothing about the host.
const SESSION_ID_BYTES: usize = 16;

/// A relay session id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

/// The shape both [`SessionId`] and [`Ticket`] use: 16 random bytes, base64url,
/// unpadded — 22 characters.
///
/// Shared so the two cannot drift apart in entropy or in what `parse` accepts.
/// They remain DIFFERENT TYPES; see [`Ticket`] for why that matters.
fn generate_id_string() -> String {
    let mut raw = [0u8; SESSION_ID_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// Whether a peer-supplied id is the right SHAPE to be looked up at all.
fn id_string_is_well_formed(s: &str) -> bool {
    const EXPECTED: usize = 22; // base64url of 16 bytes, unpadded
    s.len() == EXPECTED
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The relay's key for deriving a host's session id.
///
/// # Why a key at all
///
/// A session id has to be **stable for a host across its own restarts**, or a
/// paired phone needs a fresh QR every time the operator restarts the host —
/// which is what stops the relay being a usable default route.
///
/// The obvious way is to hash the enrolled identity. The cost is that the id
/// becomes computable by **anyone holding the host's public key**, and the QR
/// carries that key: a device that was paired once — including one the operator
/// has since REVOKED — could compute the id for ever and sit in the host's join
/// slot. Revocation would stop it pairing but not squatting.
///
/// Keying the hash removes that. The id is stable for as long as `relayd` runs,
/// and nobody outside the relay can compute one.
///
/// # What it costs
///
/// **The key lives in memory only, so ids change when `relayd` restarts.** A
/// deploy therefore invalidates every outstanding relay invite and each phone
/// needs a fresh QR. That is the operator's choice (2026-09-16): a restart
/// drops every live session anyway, and the alternative is a secret at rest on
/// the server plus a state directory to provision.
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// A fresh key from the OS random source. One per `relayd` run.
    pub fn generate() -> Self {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        SessionKey(raw)
    }

    /// The session id this relay gives that host, every time it registers.
    ///
    /// An envelope MAC — the key on both sides of the identity — rather than a
    /// bare `hash(key || id)`, so the construction owes nothing to arguments
    /// about length extension. Truncated to the same 16 bytes a random id has,
    /// so every shape check, every log line and the invite format are unchanged.
    pub fn session_id_for(&self, identity: &[u8; 32]) -> SessionId {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.0);
        // Domain separation: this key derives session ids and nothing else, and
        // a later use of it must not be able to collide with this one.
        h.update(b"remotedexter/relay/session-id/v1");
        h.update(identity);
        h.update(self.0);
        let digest = h.finalize();
        use base64::Engine;
        SessionId(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..SESSION_ID_BYTES]),
        )
    }
}

impl std::fmt::Debug for SessionKey {
    /// Never renders the key. A `Debug` that printed it would put the one
    /// secret this relay holds into the first log line that formatted state.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

impl SessionId {
    /// Generate a fresh id from the OS random source.
    ///
    /// Still used for a host that has no enrolled identity to derive from — the
    /// bearer method, where the credential IS the registration frame and the
    /// relay knows no public key. Such a host gets the old behaviour: a random
    /// id, and a new one each time it registers.
    pub fn generate() -> Self {
        SessionId(generate_id_string())
    }

    /// Accept an id a peer sent, without trusting it.
    ///
    /// Length-bounded before it is used as a map key, so a peer cannot make the
    /// relay hold an arbitrarily long string. Rejecting by SHAPE rather than by
    /// lookup also means a malformed id never reaches the table at all.
    pub fn parse(s: &str) -> Option<Self> {
        if !id_string_is_well_formed(s) {
            return None;
        }
        Some(SessionId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a table operation was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum TableError {
    /// No such session, or it has expired. **These are one answer on purpose.**
    ///
    /// Telling a stranger "that id existed but expired" confirms the id was
    /// real, which is a probing oracle. An unknown id and a dead one are
    /// indistinguishable from outside.
    UnknownSession,
    /// A phone is already spliced to this session.
    AlreadyClaimed,
    /// No such attach ticket, or it has expired or already been used.
    ///
    /// Separate from [`TableError::UnknownSession`] for the relay's own
    /// clarity, and **deliberately indistinguishable from outside**: see
    /// `public_reason`, and the test that pins the two strings equal.
    UnknownTicket,
    /// The relay is at its concurrent-session limit.
    AtCapacity,
    /// This session id is being joined faster than any real phone joins.
    ///
    /// **The peer is told exactly what an unknown session is told.** Saying
    /// "you are being rate limited" confirms the id names something real, which
    /// is the one thing a stranger churning ids wants to learn.
    TooManyJoins,
}

impl TableError {
    /// What the peer is told. `UnknownSession` and `AlreadyClaimed` deliberately
    /// give the same words, for the reason above.
    pub fn public_reason(&self) -> &'static str {
        match self {
            TableError::UnknownSession
            | TableError::AlreadyClaimed
            | TableError::UnknownTicket
            | TableError::TooManyJoins => "no such session",
            TableError::AtCapacity => "relay at capacity",
        }
    }
}

/// The most sessions the relay will hold at once.
///
/// A bound rather than unlimited, because a registration costs the relay a slot
/// and an authenticated host that misbehaves — or a host key that leaked —
/// should not be able to exhaust the server for everyone else.
pub const MAX_SESSIONS: usize = 64;

struct Entry {
    /// When the host was last heard from. Refreshed by [`SessionTable::touch`].
    last_seen: Instant,
    /// Whether a client is spliced to this session RIGHT NOW.
    ///
    /// Not "has ever been": a session serves one client at a time and as many
    /// in succession as the host stays up for. Making this once-only — which it
    /// was — means a phone that reconnects is refused by its own host.
    occupied: bool,
}

/// Live sessions, keyed by id.
pub struct SessionTable {
    entries: HashMap<SessionId, Entry>,
    capacity: usize,
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::with_capacity(MAX_SESSIONS)
    }
}

impl SessionTable {
    pub fn with_capacity(capacity: usize) -> Self {
        SessionTable {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Register a fresh session for a host that has already authenticated.
    ///
    /// Takes `now` rather than reading the clock, so expiry is provable without
    /// sleeping. The same reason `should_release_idle` takes a duration.
    pub fn register(&mut self, now: Instant) -> Result<SessionId, TableError> {
        self.insert(SessionId::generate(), now)
    }

    /// Register the session a host ALWAYS gets: the same id every time that
    /// identity registers, for as long as this relay has been running.
    ///
    /// **Re-registration replaces, it does not accumulate.** A host that
    /// reconnects — a restart, or a network change that dropped its control
    /// connection — arrives at an id the table may still hold, because the old
    /// entry lives until [`SESSION_TTL`] passes without a keepalive. Treating
    /// that as a new session would take a second slot for a host that has one,
    /// and the invite would name a session whose control connection is dead.
    ///
    /// So the entry is reset: heard from now, and not occupied. Any client the
    /// previous connection was serving is gone with it — a splice cannot outlive
    /// the control connection that arranged it — and leaving `occupied` set
    /// would lock the host's own phone out of the session it just re-made.
    pub fn register_derived(
        &mut self,
        key: &SessionKey,
        identity: &[u8; 32],
        now: Instant,
    ) -> Result<SessionId, TableError> {
        self.insert(key.session_id_for(identity), now)
    }

    /// The shared half: take a slot for this id, or refresh the one it has.
    ///
    /// The capacity check deliberately runs only for an id the table does NOT
    /// already hold. A full relay must still let its registered hosts reconnect;
    /// refusing them would mean a host that dropped and came back cannot get in
    /// while strangers that registered first keep their slots.
    fn insert(&mut self, id: SessionId, now: Instant) -> Result<SessionId, TableError> {
        self.expire(now);
        let returning = self.entries.contains_key(&id);
        if !returning && self.entries.len() >= self.capacity {
            return Err(TableError::AtCapacity);
        }
        self.entries.insert(
            id.clone(),
            Entry {
                last_seen: now,
                occupied: false,
            },
        );
        Ok(id)
    }

    /// The most sessions this table will hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How full the relay is, as a percentage of its capacity.
    ///
    /// Reported so the ceiling is visible BEFORE it is hit. With hosts dialling
    /// in on start, the relay fills up without anyone doing anything, and
    /// "relay at capacity" arriving with no warning is how the first person to
    /// be refused finds out there was a limit.
    pub fn load_percent(&self) -> usize {
        if self.capacity == 0 {
            return 100;
        }
        self.entries.len() * 100 / self.capacity
    }

    /// Occupy a session for a phone. One at a time, and no limit on how many in
    /// succession.
    ///
    /// Deliberately NOT once-only. A session id lives in an invite the operator
    /// has already shown someone; if the first phone to use it spent it, a phone
    /// that dropped signal for ten seconds could never come back, and the
    /// operator would have to mint a new code for every reconnection. The
    /// exclusion that matters is two phones at once, and that is what this is.
    pub fn claim(&mut self, id: &SessionId, now: Instant) -> Result<(), TableError> {
        self.expire(now);
        let entry = self.entries.get_mut(id).ok_or(TableError::UnknownSession)?;
        if entry.occupied {
            return Err(TableError::AlreadyClaimed);
        }
        entry.occupied = true;
        Ok(())
    }

    /// Free a session when its client goes, so the next one can be served.
    ///
    /// Idempotent, and silent about sessions it does not know: a splice that
    /// ends after its host has already gone is ordinary, not an error.
    pub fn vacate(&mut self, id: &SessionId) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.occupied = false;
        }
    }

    /// Record that the host is still there.
    ///
    /// Returns whether the session still existed. `false` means it had already
    /// expired, and the caller should stop treating the host as registered
    /// rather than silently re-creating a session under an id the relay no
    /// longer recognises.
    pub fn touch(&mut self, id: &SessionId, now: Instant) -> bool {
        match self.entries.get_mut(id) {
            Some(entry) => {
                entry.last_seen = now;
                true
            }
            None => false,
        }
    }

    /// Whether this id names a live session — WITHOUT claiming it and without
    /// changing anything.
    ///
    /// The join path asks this first. An id the table does not hold is refused
    /// there and never reaches the join limiter, so a stranger inventing ids
    /// cannot grow the limiter; and a known id is checked against the limiter
    /// BEFORE it is claimed, so churning it never takes and frees the host's
    /// slot on its way to being refused.
    pub fn is_live(&self, id: &SessionId, now: Instant) -> bool {
        self.entries
            .get(id)
            .is_some_and(|e| now.saturating_duration_since(e.last_seen) < SESSION_TTL)
    }

    /// Whether a client is spliced to this session right now.
    pub fn is_occupied(&self, id: &SessionId) -> bool {
        self.entries.get(id).map(|e| e.occupied).unwrap_or(false)
    }

    /// Drop a session — the host disconnected, or the splice ended.
    pub fn remove(&mut self, id: &SessionId) {
        self.entries.remove(id);
    }

    /// Forget every session whose host has not been heard from within
    /// [`SESSION_TTL`].
    pub fn expire(&mut self, now: Instant) {
        self.entries
            .retain(|_, e| now.duration_since(e.last_seen) < SESSION_TTL);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// How long a join-rate window lasts.
pub const JOIN_WINDOW: Duration = Duration::from_secs(10);

/// How many joins one session id may attract within [`JOIN_WINDOW`].
///
/// Generous for a phone: a real one joins once, and retries a handful of times
/// on a bad network. It is not generous for something churning the host's slot.
pub const MAX_JOINS_PER_WINDOW: usize = 5;

/// Refuses a session id that is being joined over and over.
///
/// # Why this exists
///
/// A session id is now STABLE for a host, so a stranger who learns one has it
/// for as long as the relay runs rather than until the next host restart. What
/// a stranger can do with it is bounded already — the Noise handshake against
/// the pinned host key refuses them, and they hold no pairing token — but each
/// attempt occupies the host's one session slot for the moments it takes to
/// fail, and repeated endlessly that is a denial of service against the
/// operator's own machine.
///
/// This does not make a stolen id harmless. It makes churning one expensive
/// enough to be pointless, and it is the guard the design named when the
/// operator accepted stable ids.
#[derive(Default)]
pub struct JoinLimiter {
    /// When each session id was recently joined.
    recent: HashMap<SessionId, Vec<Instant>>,
    /// When every entry was last swept for staleness.
    last_sweep: Option<Instant>,
    /// How many full sweeps have run, so the "at most once per window" bound is
    /// something a test can hold rather than a claim in a comment.
    sweeps: u64,
}

impl JoinLimiter {
    /// Record a join attempt and say whether it is allowed.
    ///
    /// Takes `now` rather than reading the clock, so the window is provable
    /// without sleeping through it.
    ///
    /// # Cost
    ///
    /// **Amortised constant per call**, however many ids are tracked. It swept
    /// the WHOLE map on every call, which the deploy agent measured at 5 ms per
    /// join with 100k ids tracked — under a lock, on the async executor. Now the
    /// joining id's own entry is pruned every time, which keeps its limit exact,
    /// and everything else is swept at most once per [`JOIN_WINDOW`], which is
    /// all it takes for nothing to outlive the window by more than one window.
    ///
    /// The relay also only ever asks about ids its table holds (see
    /// `join_client_with`), so a stranger inventing ids never reaches this at
    /// all. This bound is the second line, and it holds for any caller.
    pub fn allow(&mut self, id: &SessionId, now: Instant) -> bool {
        let sweep_due = match self.last_sweep {
            None => true,
            Some(at) => now.saturating_duration_since(at) >= JOIN_WINDOW,
        };
        if sweep_due {
            // Ids nobody is joining any more: without this an entry that is
            // never revisited would live for ever.
            self.recent.retain(|_, times| {
                times.retain(|t| now.saturating_duration_since(*t) < JOIN_WINDOW);
                !times.is_empty()
            });
            self.last_sweep = Some(now);
            self.sweeps += 1;
        }
        let times = self.recent.entry(id.clone()).or_default();
        times.retain(|t| now.saturating_duration_since(*t) < JOIN_WINDOW);
        if times.len() >= MAX_JOINS_PER_WINDOW {
            // Deliberately NOT recorded. Counting refused attempts would let a
            // flood hold its own window open for ever, so a client that stops
            // for one window is served again.
            return false;
        }
        times.push(now);
        true
    }

    /// How many ids are being tracked. For tests and for a bound nobody has to
    /// take on trust.
    pub fn tracked(&self) -> usize {
        self.recent.len()
    }

    /// How many full sweeps have run. For tests and for cost harnesses.
    pub fn sweeps(&self) -> u64 {
        self.sweeps
    }
}

/// How long a minted attach ticket is good for.
///
/// This is a dial-out round trip, not a human's attention span: the host is
/// already connected and has just been told to dial back. Short on purpose —
/// a ticket that outlives the client's patience is a slot nobody can use, and
/// a string still worth guessing.
pub const ATTACH_TTL: Duration = Duration::from_secs(15);

/// The most unredeemed tickets the relay will hold.
///
/// A ticket is minted only when a claimed session gets a client, and a session
/// is claimable once, so this cannot exceed [`MAX_SESSIONS`] in ordinary
/// operation. It is bounded anyway: "cannot happen by construction" is how
/// unbounded growth gets shipped when the construction later changes.
pub const MAX_PENDING_ATTACHES: usize = MAX_SESSIONS;

/// A single-use ticket naming one waiting client.
///
/// **A DIFFERENT TYPE FROM [`SessionId`] on purpose.** Both are 22 characters
/// of base64url, so no shape check can tell them apart — if they shared a type,
/// a session id presented where a ticket belongs would be one lookup away from
/// working, and the only thing standing between them would be a map miss. The
/// type system refuses it before the table is asked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ticket(String);

impl Ticket {
    /// Mint a fresh ticket from the OS random source.
    pub fn generate() -> Self {
        Ticket(generate_id_string())
    }

    /// Accept a ticket a peer sent, without trusting it.
    ///
    /// Shape only. Whether it names anything is the table's question.
    pub fn parse(s: &str) -> Option<Self> {
        if !id_string_is_well_formed(s) {
            return None;
        }
        Some(Ticket(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

struct Pending {
    session: SessionId,
    minted_at: Instant,
}

/// Tickets minted for clients waiting on a host to dial back.
///
/// This holds the DECISION half only — which ticket names which session, for
/// how long, and that it works exactly once. The waiting socket itself is
/// parked in `server`, so every rule here is provable without a socket. That
/// separation is the same one the rest of this crate keeps.
pub struct AttachTable {
    entries: HashMap<Ticket, Pending>,
    capacity: usize,
}

impl Default for AttachTable {
    fn default() -> Self {
        Self::with_capacity(MAX_PENDING_ATTACHES)
    }
}

impl AttachTable {
    pub fn with_capacity(capacity: usize) -> Self {
        AttachTable {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Mint a ticket for a client waiting on `session`.
    pub fn mint(&mut self, session: &SessionId, now: Instant) -> Result<Ticket, TableError> {
        self.expire(now);
        if self.entries.len() >= self.capacity {
            return Err(TableError::AtCapacity);
        }
        let ticket = Ticket::generate();
        self.entries.insert(
            ticket.clone(),
            Pending {
                session: session.clone(),
                minted_at: now,
            },
        );
        Ok(ticket)
    }

    /// Redeem a ticket, naming the session it was minted for.
    ///
    /// **Removes it.** Redemption is the single use: a second attempt with the
    /// same ticket finds nothing, and is refused in the same words a ticket
    /// that never existed gets.
    pub fn redeem(&mut self, ticket: &Ticket, now: Instant) -> Result<SessionId, TableError> {
        self.expire(now);
        let pending = self
            .entries
            .remove(ticket)
            .ok_or(TableError::UnknownTicket)?;
        Ok(pending.session)
    }

    /// Drop a ticket that was minted and never redeemed — the client gave up,
    /// or the host never dialled back.
    pub fn abandon(&mut self, ticket: &Ticket) {
        self.entries.remove(ticket);
    }

    /// Forget everything past [`ATTACH_TTL`].
    pub fn expire(&mut self, now: Instant) {
        self.entries
            .retain(|_, p| now.duration_since(p.minted_at) < ATTACH_TTL);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_id_is_the_shape_parse_accepts() {
        for _ in 0..50 {
            let id = SessionId::generate();
            assert!(
                SessionId::parse(id.as_str()).is_some(),
                "generate produced an id parse refuses: {}",
                id.as_str()
            );
        }
    }

    /// Two ids must not collide, and must not look sequential to a watcher.
    #[test]
    fn ids_do_not_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            assert!(seen.insert(SessionId::generate()), "a session id repeated");
        }
    }

    #[test]
    fn a_malformed_id_never_reaches_the_table() {
        for bad in [
            "",
            "short",
            &"x".repeat(23),
            &"x".repeat(21),
            "has spaces here!!!!!!!",
            "sl/ash+plus+padding===",
        ] {
            assert!(SessionId::parse(bad).is_none(), "parse accepted {bad:?}");
        }
    }

    #[test]
    fn a_session_can_be_claimed_once() {
        let now = Instant::now();
        let mut t = SessionTable::default();
        let id = t.register(now).unwrap();
        assert_eq!(t.claim(&id, now), Ok(()));
        assert_eq!(t.claim(&id, now), Err(TableError::AlreadyClaimed));
    }

    #[test]
    fn an_unknown_session_is_refused() {
        let mut t = SessionTable::default();
        let stranger = SessionId::generate();
        assert_eq!(
            t.claim(&stranger, Instant::now()),
            Err(TableError::UnknownSession)
        );
    }

    /// An expired session and one that never existed must be indistinguishable
    /// from outside, or the relay becomes an oracle for guessing ids.
    #[test]
    fn an_expired_session_answers_exactly_like_an_unknown_one() {
        let t0 = Instant::now();
        let mut t = SessionTable::default();
        let id = t.register(t0).unwrap();
        let later = t0 + SESSION_TTL + Duration::from_secs(1);

        let expired = t.claim(&id, later);
        let never_existed = t.claim(&SessionId::generate(), later);

        assert_eq!(expired, Err(TableError::UnknownSession));
        assert_eq!(expired, never_existed);
        assert_eq!(
            TableError::UnknownSession.public_reason(),
            TableError::AlreadyClaimed.public_reason(),
            "a claimed session must not be distinguishable from an unknown one"
        );
    }

    #[test]
    fn expiry_frees_the_slot() {
        let t0 = Instant::now();
        let mut t = SessionTable::with_capacity(1);
        let _first = t.register(t0).unwrap();
        assert_eq!(t.register(t0), Err(TableError::AtCapacity));
        let later = t0 + SESSION_TTL + Duration::from_secs(1);
        assert!(t.register(later).is_ok(), "expiry did not free the slot");
    }

    /// A registration costs a slot, so the count is bounded even for a host
    /// that authenticated and then misbehaved.
    #[test]
    fn the_table_is_bounded() {
        let now = Instant::now();
        let mut t = SessionTable::with_capacity(4);
        for _ in 0..4 {
            t.register(now).unwrap();
        }
        assert_eq!(t.register(now), Err(TableError::AtCapacity));
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn removing_a_session_frees_it() {
        let now = Instant::now();
        let mut t = SessionTable::with_capacity(1);
        let id = t.register(now).unwrap();
        t.remove(&id);
        assert!(t.is_empty());
        assert!(t.register(now).is_ok());
    }

    // ---------------------------------------------------------------- tickets

    #[test]
    fn a_generated_ticket_is_the_shape_parse_accepts() {
        for _ in 0..50 {
            let t = Ticket::generate();
            assert!(
                Ticket::parse(t.as_str()).is_some(),
                "generate produced a ticket parse refuses: {}",
                t.as_str()
            );
        }
    }

    #[test]
    fn tickets_do_not_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            assert!(seen.insert(Ticket::generate()), "a ticket repeated");
        }
    }

    /// Redemption is the single use. A ticket that worked once is gone.
    #[test]
    fn a_ticket_works_exactly_once() {
        let now = Instant::now();
        let mut sessions = SessionTable::default();
        let session = sessions.register(now).unwrap();
        let mut attaches = AttachTable::default();

        let ticket = attaches.mint(&session, now).unwrap();
        assert_eq!(attaches.redeem(&ticket, now), Ok(session));
        assert_eq!(
            attaches.redeem(&ticket, now),
            Err(TableError::UnknownTicket),
            "a ticket was redeemable twice — the second dial-out would be spliced to a session that already has its client"
        );
    }

    #[test]
    fn an_expired_ticket_is_refused() {
        let t0 = Instant::now();
        let mut sessions = SessionTable::default();
        let session = sessions.register(t0).unwrap();
        let mut attaches = AttachTable::default();
        let ticket = attaches.mint(&session, t0).unwrap();

        let later = t0 + ATTACH_TTL + Duration::from_secs(1);
        assert_eq!(
            attaches.redeem(&ticket, later),
            Err(TableError::UnknownTicket)
        );
        assert!(attaches.is_empty(), "an expired ticket kept its slot");
    }

    /// No oracle: a ticket that never existed, one already used, and one that
    /// expired must be one answer from outside.
    #[test]
    fn every_refused_ticket_is_refused_in_the_same_words() {
        let now = Instant::now();
        let mut sessions = SessionTable::default();
        let session = sessions.register(now).unwrap();
        let mut attaches = AttachTable::default();

        let used = attaches.mint(&session, now).unwrap();
        attaches.redeem(&used, now).unwrap();
        let never = Ticket::generate();

        let a = attaches.redeem(&used, now).unwrap_err();
        let b = attaches.redeem(&never, now).unwrap_err();
        assert_eq!(a.public_reason(), b.public_reason());
        assert_eq!(
            a.public_reason(),
            TableError::UnknownSession.public_reason(),
            "a refused ticket is distinguishable from a refused session id, which tells a prober which half it guessed"
        );
    }

    /// The two id types are the same shape, so only the TABLE can tell them
    /// apart — and it must.
    #[test]
    fn a_session_id_is_not_an_attach_ticket() {
        let now = Instant::now();
        let mut sessions = SessionTable::default();
        let session = sessions.register(now).unwrap();
        let mut attaches = AttachTable::default();
        let _real = attaches.mint(&session, now).unwrap();

        // The session id passes the SHAPE check — that is the point.
        let as_ticket = Ticket::parse(session.as_str())
            .expect("a session id is the same shape as a ticket, so parse accepts it");
        assert_eq!(
            attaches.redeem(&as_ticket, now),
            Err(TableError::UnknownTicket),
            "a session id was redeemable as an attach ticket"
        );
    }

    #[test]
    fn the_attach_table_is_bounded() {
        let now = Instant::now();
        let mut sessions = SessionTable::default();
        let session = sessions.register(now).unwrap();
        let mut attaches = AttachTable::with_capacity(2);
        attaches.mint(&session, now).unwrap();
        attaches.mint(&session, now).unwrap();
        assert_eq!(attaches.mint(&session, now), Err(TableError::AtCapacity));
    }

    #[test]
    fn an_abandoned_ticket_frees_its_slot() {
        let now = Instant::now();
        let mut sessions = SessionTable::default();
        let session = sessions.register(now).unwrap();
        let mut attaches = AttachTable::with_capacity(1);
        let ticket = attaches.mint(&session, now).unwrap();
        assert_eq!(attaches.mint(&session, now), Err(TableError::AtCapacity));
        attaches.abandon(&ticket);
        assert!(
            attaches.mint(&session, now).is_ok(),
            "a client that gave up left its slot held"
        );
    }

    // ------------------------------------------------ occupancy and liveness

    /// **The defect this replaced.** `claim` succeeded at most once per session,
    /// so a phone that dropped signal for ten seconds could never come back and
    /// the operator would have to mint a fresh code for every reconnection —
    /// which is precisely what holding one persistent control connection was
    /// chosen to avoid.
    #[test]
    fn a_session_serves_one_client_at_a_time_and_many_in_succession() {
        let now = Instant::now();
        let mut t = SessionTable::default();
        let id = t.register(now).unwrap();

        assert_eq!(t.claim(&id, now), Ok(()));
        t.vacate(&id);
        assert_eq!(
            t.claim(&id, now),
            Ok(()),
            "a phone that reconnected was refused by its own host's session"
        );
        t.vacate(&id);
        assert_eq!(t.claim(&id, now), Ok(()), "and again");
    }

    #[test]
    fn two_clients_cannot_hold_one_session_at_once() {
        let now = Instant::now();
        let mut t = SessionTable::default();
        let id = t.register(now).unwrap();
        assert_eq!(t.claim(&id, now), Ok(()));
        assert_eq!(
            t.claim(&id, now),
            Err(TableError::AlreadyClaimed),
            "two phones were spliced to one host at the same time"
        );
        assert!(t.is_occupied(&id));
    }

    /// A host that keeps talking keeps its session, however long it stays up.
    #[test]
    fn a_session_survives_as_long_as_its_host_is_heard_from() {
        let t0 = Instant::now();
        let mut t = SessionTable::default();
        let id = t.register(t0).unwrap();

        // Far past the old fixed lifetime, refreshed at the keepalive interval.
        let mut at = t0;
        for _ in 0..30 {
            at += Duration::from_secs(20);
            assert!(t.touch(&id, at), "the session expired under a live host");
            t.expire(at);
        }
        assert_eq!(t.len(), 1, "a host that never went quiet lost its session");
        assert_eq!(
            t.claim(&id, at),
            Ok(()),
            "the id in the invite stopped working"
        );
    }

    #[test]
    fn a_session_whose_host_went_quiet_expires() {
        let t0 = Instant::now();
        let mut t = SessionTable::default();
        let id = t.register(t0).unwrap();
        let later = t0 + SESSION_TTL + Duration::from_secs(1);
        t.expire(later);
        assert!(t.is_empty(), "a vanished host kept its slot");
        assert_eq!(t.claim(&id, later), Err(TableError::UnknownSession));
    }

    /// `touch` reports rather than resurrects. A host whose session already
    /// expired must be told, not quietly re-created under an id the relay has
    /// forgotten and the invite still names.
    #[test]
    fn touching_an_expired_session_says_so_rather_than_recreating_it() {
        let t0 = Instant::now();
        let mut t = SessionTable::default();
        let id = t.register(t0).unwrap();
        let later = t0 + SESSION_TTL + Duration::from_secs(1);
        t.expire(later);
        assert!(!t.touch(&id, later), "an expired session answered as live");
        assert!(
            t.is_empty(),
            "touch resurrected a session the relay had dropped"
        );
    }

    #[test]
    fn vacating_a_session_the_relay_does_not_know_is_not_an_error() {
        let now = Instant::now();
        let mut t = SessionTable::default();
        let stranger = SessionId::generate();
        t.vacate(&stranger);
        assert!(t.is_empty());
        let _ = now;
    }

    /// Two identities used across these tests. Not real keys — the derivation
    /// never validates them as curve points, and using obviously fake bytes
    /// keeps a reader from thinking one matters.
    fn host_a() -> [u8; 32] {
        [0xA1; 32]
    }
    fn host_b() -> [u8; 32] {
        [0xB2; 32]
    }

    /// **The property the whole phase exists for.**
    ///
    /// A host that restarts must come back on the same session id, or the
    /// invite it minted before the restart names a session the relay no longer
    /// has, and its phone needs a fresh QR every single time.
    #[test]
    fn the_same_host_gets_the_same_session_id_every_time() {
        let key = SessionKey::generate();
        let first = key.session_id_for(&host_a());
        for _ in 0..5 {
            assert_eq!(
                key.session_id_for(&host_a()),
                first,
                "a host's session id changed between registrations"
            );
        }
        assert_ne!(
            key.session_id_for(&host_b()),
            first,
            "two different hosts were given the same session id"
        );
    }

    /// **A session id must not be computable by whoever holds the host's public
    /// key.**
    ///
    /// Every pairing QR carries that key, so an unkeyed hash would let anyone
    /// who has ever scanned one — including a device the operator has REVOKED —
    /// compute the id for ever and sit in the host's join slot. Revocation
    /// would stop it pairing but not squatting. Two relays with the same host
    /// enrolled must therefore disagree about its id.
    #[test]
    fn the_session_id_cannot_be_derived_from_the_host_key_alone() {
        let one = SessionKey::generate();
        let other = SessionKey::generate();
        assert_ne!(
            one.session_id_for(&host_a()),
            other.session_id_for(&host_a()),
            "the session id did not depend on the relay's key, so anyone holding the host's \
             public key could compute it"
        );
    }

    /// The derived id goes everywhere a random one does: invites, log lines,
    /// `parse`. A different shape would be caught far from here.
    #[test]
    fn a_derived_id_is_the_shape_parse_accepts() {
        let key = SessionKey::generate();
        let id = key.session_id_for(&host_a());
        assert!(
            SessionId::parse(id.as_str()).is_some(),
            "a derived id is not one parse accepts: {}",
            id.as_str()
        );
        assert_eq!(id.as_str().len(), SessionId::generate().as_str().len());
    }

    /// The key is the one secret this relay holds. A `Debug` that printed it
    /// would put it in the first log line that formatted relay state.
    #[test]
    fn the_session_key_is_never_rendered() {
        let key = SessionKey::generate();
        let shown = format!("{key:?}");
        // The WHOLE string, not "does it contain the bytes". Scanning the
        // rendering for hex pairs is how this test flaked: `redacted` itself
        // contains `ed` and `ac`, so any key holding 0xED or 0xAC failed it
        // about a fifth of the time. Caught by mutation testing, which failed
        // it while proving something unrelated.
        assert_eq!(
            shown, "SessionKey(<redacted>)",
            "the session key's Debug output is not the fixed redaction"
        );
    }

    /// **Reconnecting replaces, it does not accumulate.**
    ///
    /// The old entry survives until the TTL, so a host that restarts arrives at
    /// an id the table still holds. Counting that as a new session would take a
    /// second slot for a host that has one.
    #[test]
    fn re_registering_replaces_the_entry_rather_than_taking_a_second_slot() {
        let key = SessionKey::generate();
        let mut t = SessionTable::default();
        let now = Instant::now();

        let first = t.register_derived(&key, &host_a(), now).unwrap();
        t.claim(&first, now).unwrap();
        assert!(t.is_occupied(&first));

        let again = t.register_derived(&key, &host_a(), now).unwrap();
        assert_eq!(again, first, "a reconnecting host was given a different id");
        assert_eq!(t.len(), 1, "reconnecting took a second slot");
        // A splice cannot outlive the control connection that arranged it, so
        // leaving this set would lock the host's own phone out of the session it
        // has just re-made.
        assert!(
            !t.is_occupied(&again),
            "a reconnected session was still marked occupied by the connection that died"
        );
    }

    /// **A full relay must still let its own registered hosts back in.**
    ///
    /// Otherwise a host that drops and reconnects is refused while strangers
    /// that registered earlier keep their slots — and the operator's host is
    /// the one locked out of the relay it is enrolled on.
    #[test]
    fn a_full_relay_still_admits_a_host_that_is_coming_back() {
        let key = SessionKey::generate();
        let mut t = SessionTable::with_capacity(2);
        let now = Instant::now();

        let mine = t.register_derived(&key, &host_a(), now).unwrap();
        t.register_derived(&key, &host_b(), now).unwrap();
        assert_eq!(t.len(), 2);

        assert_eq!(
            t.register_derived(&key, &[0xC3; 32], now),
            Err(TableError::AtCapacity),
            "a full relay admitted a host it had never seen"
        );
        assert_eq!(
            t.register_derived(&key, &host_a(), now),
            Ok(mine),
            "a full relay refused a host that already held a slot"
        );
    }

    /// The ceiling has to be visible before it is hit. With hosts dialling in
    /// on start, the relay fills without anyone doing anything.
    #[test]
    fn the_relay_reports_how_full_it_is() {
        let key = SessionKey::generate();
        let mut t = SessionTable::with_capacity(4);
        let now = Instant::now();
        assert_eq!(t.load_percent(), 0);
        t.register_derived(&key, &host_a(), now).unwrap();
        assert_eq!(t.load_percent(), 25);
        t.register_derived(&key, &host_b(), now).unwrap();
        assert_eq!(t.load_percent(), 50, "half full was not reported as 50%");
        // Re-registering the same host does not make the relay look fuller.
        t.register_derived(&key, &host_a(), now).unwrap();
        assert_eq!(t.load_percent(), 50);
    }

    /// A bearer host has no identity to derive from and keeps the old
    /// behaviour: a fresh random id each time it registers.
    #[test]
    fn a_host_with_no_identity_still_gets_a_random_id() {
        let mut t = SessionTable::default();
        let now = Instant::now();
        let first = t.register(now).unwrap();
        let second = t.register(now).unwrap();
        assert_ne!(first, second);
        assert_eq!(t.len(), 2);
    }

    /// A real phone joins once and retries a few times on a bad network. The
    /// limit has to sit above that, or the guard breaks the thing it protects.
    #[test]
    fn an_ordinary_phone_is_never_rate_limited() {
        let mut l = JoinLimiter::default();
        let id = SessionId::generate();
        let now = Instant::now();
        for attempt in 1..=MAX_JOINS_PER_WINDOW {
            assert!(
                l.allow(&id, now),
                "a phone's join number {attempt} was refused inside one window"
            );
        }
    }

    /// **Churning one session id is refused.** Stable ids mean a leaked one
    /// stays useful for as long as the relay runs, and each attempt takes the
    /// host's only session slot for the moment it takes to fail.
    #[test]
    fn churning_one_session_id_is_refused_and_recovers_after_the_window() {
        let mut l = JoinLimiter::default();
        let id = SessionId::generate();
        let start = Instant::now();
        for _ in 0..MAX_JOINS_PER_WINDOW {
            assert!(l.allow(&id, start));
        }
        assert!(
            !l.allow(&id, start),
            "a session id was joined past its limit inside one window"
        );

        // Keep hammering it, HALFWAY THROUGH the window rather than at the same
        // instant as the rest. That spacing is the point: if a refused attempt
        // recorded itself, it would sit half a window later than the ones that
        // filled the limit and keep the window alive past them — a flood that
        // renews its own ban and locks the operator's phone out for ever.
        let midway = start + JOIN_WINDOW / 2;
        for _ in 0..20 {
            assert!(!l.allow(&id, midway));
        }

        // Still refused just before the original window closes...
        let nearly = start + JOIN_WINDOW - Duration::from_millis(1);
        assert!(!l.allow(&id, nearly));
        // ...and served again once it has, however much was thrown at it in
        // between.
        let after = start + JOIN_WINDOW + Duration::from_millis(1);
        assert!(
            l.allow(&id, after),
            "a session that waited out the window was still refused — a flood renewed its own \
             refusal and the host's own phone can never get back in"
        );
    }

    /// One session being flooded must not refuse a different one. The limit is
    /// per id on purpose: a stranger churning an id they found should not be
    /// able to lock every other host on the relay out.
    #[test]
    fn one_flooded_session_does_not_refuse_another() {
        let mut l = JoinLimiter::default();
        let flooded = SessionId::generate();
        let mine = SessionId::generate();
        let now = Instant::now();
        for _ in 0..MAX_JOINS_PER_WINDOW + 3 {
            l.allow(&flooded, now);
        }
        assert!(
            l.allow(&mine, now),
            "a flood against one session refused a join to a different one"
        );
    }

    /// The limiter must not accumulate a row per id ever seen. A relay runs for
    /// months, and an id is 22 bytes plus a map entry; "it is only small" is how
    /// unbounded growth ships.
    #[test]
    fn the_limiter_forgets_sessions_nobody_is_joining() {
        let mut l = JoinLimiter::default();
        let start = Instant::now();
        for _ in 0..500 {
            l.allow(&SessionId::generate(), start);
        }
        assert_eq!(l.tracked(), 500);
        let later = start + JOIN_WINDOW + Duration::from_millis(1);
        l.allow(&SessionId::generate(), later);
        assert_eq!(
            l.tracked(),
            1,
            "the limiter kept rows for sessions nobody had joined in a whole window"
        );
    }

    /// A rate-limited join is told exactly what an unknown session is told.
    /// "You are being rate limited" confirms the id names something real, which
    /// is the one thing a stranger churning ids wants to learn.
    #[test]
    fn a_rate_limited_join_is_indistinguishable_from_an_unknown_one() {
        assert_eq!(
            TableError::TooManyJoins.public_reason(),
            TableError::UnknownSession.public_reason()
        );
    }

    /// **A flood of joins sweeps the limiter at most once per window.**
    ///
    /// The first version swept every tracked id on every join. The deploy agent
    /// measured that at 5 ms per join with 100k ids tracked, under a lock on the
    /// async executor — a stranger slowing every real phone's join by inventing
    /// ids. The sweep count is what makes "amortised constant" a tested claim.
    #[test]
    fn a_flood_of_joins_sweeps_the_limiter_at_most_once_per_window() {
        let mut l = JoinLimiter::default();
        let start = Instant::now();
        for _ in 0..100_000 {
            l.allow(&SessionId::generate(), start);
        }
        assert_eq!(
            l.sweeps(),
            1,
            "100,000 joins inside one window swept the whole limiter {} times",
            l.sweeps()
        );
        let later = start + JOIN_WINDOW;
        l.allow(&SessionId::generate(), later);
        assert_eq!(l.sweeps(), 2, "a join a window later did not sweep");
        assert_eq!(
            l.tracked(),
            1,
            "the sweep a window later did not forget the flood"
        );
    }

    /// **An id is served again once ITS window passes, even between sweeps.**
    ///
    /// Sweeping lazily must not make the limit lazy. If only the sweep pruned
    /// old joins, an id could stay refused for up to two windows — a phone kept
    /// out twice as long as the rule says, for no reason it could see.
    #[test]
    fn an_id_is_served_again_when_its_own_window_passes_even_between_sweeps() {
        let mut l = JoinLimiter::default();
        let t0 = Instant::now();
        let other = SessionId::generate();
        let phone = SessionId::generate();

        l.allow(&other, t0); // the first sweep
        let busy = t0 + Duration::from_secs(1);
        for _ in 0..MAX_JOINS_PER_WINDOW {
            assert!(l.allow(&phone, busy));
        }
        assert!(!l.allow(&phone, busy));

        // A second sweep, while the phone's joins are still inside their window.
        l.allow(&other, t0 + JOIN_WINDOW + Duration::from_millis(500));
        assert_eq!(l.sweeps(), 2);

        // The phone's window has passed; the NEXT sweep is not due yet.
        let back = busy + JOIN_WINDOW + Duration::from_millis(1);
        assert!(
            l.allow(&phone, back),
            "the phone was still refused after its own window passed, because no sweep was due"
        );
        assert_eq!(l.sweeps(), 2, "the test did not isolate the per-id prune");
    }

    /// `is_live` is a READ: it answers without claiming, and follows the TTL.
    /// The join path relies on both — asking must not take the host's slot.
    #[test]
    fn asking_whether_a_session_is_live_claims_nothing() {
        let key = SessionKey::generate();
        let mut t = SessionTable::default();
        let now = Instant::now();
        let id = t.register_derived(&key, &host_a(), now).unwrap();

        assert!(t.is_live(&id, now));
        assert!(t.is_live(&id, now));
        assert!(
            !t.is_occupied(&id),
            "asking whether a session is live claimed it"
        );
        assert!(
            t.claim(&id, now).is_ok(),
            "a session that was only asked about could not be claimed"
        );

        assert!(
            !t.is_live(&SessionId::generate(), now),
            "an unknown id was reported live"
        );
        assert!(
            !t.is_live(&id, now + SESSION_TTL),
            "a session silent for the whole TTL was still reported live"
        );
    }
}

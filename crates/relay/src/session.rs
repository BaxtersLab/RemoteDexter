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
/// 16 bytes is 128 bits. The id is base64 of that — not a counter, not a
/// timestamp, and not derived from the host key, because anything derived tells
/// a watcher something about the host.
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

impl SessionId {
    /// Generate a fresh id from the OS random source.
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
}

impl TableError {
    /// What the peer is told. `UnknownSession` and `AlreadyClaimed` deliberately
    /// give the same words, for the reason above.
    pub fn public_reason(&self) -> &'static str {
        match self {
            TableError::UnknownSession | TableError::AlreadyClaimed | TableError::UnknownTicket => {
                "no such session"
            }
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
        self.expire(now);
        if self.entries.len() >= self.capacity {
            return Err(TableError::AtCapacity);
        }
        let id = SessionId::generate();
        self.entries.insert(
            id.clone(),
            Entry {
                last_seen: now,
                occupied: false,
            },
        );
        Ok(id)
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
}

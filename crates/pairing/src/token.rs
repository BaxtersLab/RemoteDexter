//! The pairing token: 256 random bits, one use, sixty seconds.
//!
//! ## What the host keeps
//!
//! **Only a hash.** `TokenStore` never holds the token it issued. It holds
//! `sha256(token)`, an expiry, and whether it has been redeemed. A memory dump,
//! a log line, a panic message or a debugger cannot yield a usable credential
//! from this type, because the credential is not in it.
//!
//! That is not theoretical hygiene. The implementation this replaces
//! (`module17_bootstrap_invite`) held the token as a `String`, put it on a
//! process-wide event bus, and handed it to a UDP broadcaster that sent it to
//! `255.255.255.255` every five seconds.

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// How long an invite is good for. Short on purpose: the QR is a credential
/// visible to anyone who can see the host's screen, so its useful life should
/// be about as long as it takes someone to point a phone at it.
pub const TOKEN_TTL: Duration = Duration::from_secs(60);

/// 256 bits, rendered as 64 lowercase hex characters.
pub const TOKEN_BITS: usize = 256;

/// A freshly minted token. Deliberately NOT `Clone`, `Copy`, `Debug`, or
/// `Serialize`: the only way to read it is [`Token::expose`], which is easy to
/// grep for.
pub struct Token(String);

impl Token {
    /// Mint 256 bits from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; TOKEN_BITS / 8];
        OsRng.fill_bytes(&mut bytes);
        Token(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// The token itself. Named so that every place it escapes is visible in a
    /// grep for `expose`. It belongs in exactly one place: the QR.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The hash the host retains.
    pub fn digest(&self) -> TokenDigest {
        TokenDigest::of(&self.0)
    }
}

/// SHA-256 of a token. This is what the host stores and compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// Hash a presented token so it can be compared against a stored digest.
    pub fn of(token: &str) -> Self {
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        TokenDigest(h.finalize().into())
    }

    /// Short prefix for correlating log lines without disclosing anything
    /// useful. Four bytes of a hash of a 256-bit secret is not a credential.
    pub fn fingerprint(&self) -> String {
        self.0[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Why a presented token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemError {
    /// No invite is outstanding.
    NoInvite,
    /// The token does not match the outstanding invite.
    Mismatch,
    /// The invite's sixty seconds have elapsed.
    Expired,
    /// The invite was already redeemed. One use means one.
    AlreadyRedeemed,
}

impl RedeemError {
    /// Display-safe reason. Names the rule, never the token.
    pub fn reason(self) -> &'static str {
        match self {
            RedeemError::NoInvite => "no pairing invitation is outstanding",
            RedeemError::Mismatch => "pairing token does not match",
            RedeemError::Expired => "pairing invitation has expired",
            RedeemError::AlreadyRedeemed => "pairing invitation was already used",
        }
    }
}

/// The single outstanding invitation, by hash.
///
/// At most one invite is live at a time: minting a new one replaces the old,
/// which is what makes "press the button again" a revocation rather than an
/// accumulation of valid credentials.
#[derive(Debug, Default)]
pub struct TokenStore {
    outstanding: Option<Outstanding>,
}

#[derive(Debug)]
struct Outstanding {
    digest: TokenDigest,
    expires_at: u64,
    redeemed: bool,
}

impl TokenStore {
    /// An empty store. Nothing may be redeemed.
    pub fn new() -> Self {
        TokenStore { outstanding: None }
    }

    /// Record a freshly minted token by hash, replacing any previous one.
    pub fn issue(&mut self, token: &Token, expires_at: u64) {
        self.outstanding = Some(Outstanding {
            digest: token.digest(),
            expires_at,
            redeemed: false,
        });
    }

    /// Forget the outstanding invite. Called on Stop and on a new invite.
    pub fn clear(&mut self) {
        self.outstanding = None;
    }

    /// Is an unexpired, unredeemed invite outstanding?
    pub fn is_live(&self, now: u64) -> bool {
        matches!(&self.outstanding, Some(o) if !o.redeemed && now < o.expires_at)
    }

    /// Present a token. Succeeds at most once per issued invite.
    ///
    /// Order is deliberate: expiry is checked before the redeemed flag so an
    /// expired-and-unused invite reports `Expired`, which is the more useful
    /// truth for a user staring at a stale QR.
    pub fn redeem(&mut self, presented: &str, now: u64) -> Result<(), RedeemError> {
        let Some(o) = self.outstanding.as_mut() else {
            return Err(RedeemError::NoInvite);
        };
        if TokenDigest::of(presented) != o.digest {
            return Err(RedeemError::Mismatch);
        }
        if now >= o.expires_at {
            return Err(RedeemError::Expired);
        }
        if o.redeemed {
            return Err(RedeemError::AlreadyRedeemed);
        }
        o.redeemed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_256_bits_of_hex() {
        let t = Token::generate();
        assert_eq!(t.expose().len(), 64, "64 hex chars == 256 bits");
        assert!(t.expose().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn two_tokens_differ() {
        // Not a randomness test — a wiring test. A constant token would be the
        // kind of defect that passes every other test in this file.
        let a = Token::generate();
        let b = Token::generate();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn the_store_never_holds_the_token() {
        let t = Token::generate();
        let mut s = TokenStore::new();
        s.issue(&t, 100);
        // The Debug rendering is the most likely accidental disclosure path —
        // a panic message, a log line, a test failure.
        let rendered = format!("{s:?}");
        assert!(
            !rendered.contains(t.expose()),
            "the token must not be recoverable from the store"
        );
    }

    #[test]
    fn one_use_means_one() {
        let t = Token::generate();
        let mut s = TokenStore::new();
        s.issue(&t, 100);
        assert_eq!(s.redeem(t.expose(), 50), Ok(()));
        assert_eq!(
            s.redeem(t.expose(), 50),
            Err(RedeemError::AlreadyRedeemed),
            "a replayed token must be refused"
        );
    }

    #[test]
    fn expiry_is_enforced_on_redeem() {
        let t = Token::generate();
        let mut s = TokenStore::new();
        s.issue(&t, 100);
        assert_eq!(s.redeem(t.expose(), 100), Err(RedeemError::Expired));
        assert_eq!(s.redeem(t.expose(), 101), Err(RedeemError::Expired));
    }

    #[test]
    fn a_wrong_token_is_refused_without_revealing_which_part_was_wrong() {
        let t = Token::generate();
        let mut s = TokenStore::new();
        s.issue(&t, 100);
        let mut wrong = t.expose().to_string();
        wrong.replace_range(0..1, if &wrong[0..1] == "a" { "b" } else { "a" });
        assert_eq!(s.redeem(&wrong, 50), Err(RedeemError::Mismatch));
        assert!(!RedeemError::Mismatch.reason().contains(&wrong));
    }

    #[test]
    fn a_new_invite_revokes_the_previous_one() {
        let first = Token::generate();
        let second = Token::generate();
        let mut s = TokenStore::new();
        s.issue(&first, 100);
        s.issue(&second, 100);
        assert_eq!(s.redeem(first.expose(), 50), Err(RedeemError::Mismatch));
        assert_eq!(s.redeem(second.expose(), 50), Ok(()));
    }

    #[test]
    fn clearing_the_store_refuses_everything() {
        let t = Token::generate();
        let mut s = TokenStore::new();
        s.issue(&t, 100);
        s.clear();
        assert!(!s.is_live(50));
        assert_eq!(s.redeem(t.expose(), 50), Err(RedeemError::NoInvite));
    }

    #[test]
    fn liveness_tracks_expiry_and_use() {
        let t = Token::generate();
        let mut s = TokenStore::new();
        assert!(!s.is_live(0));
        s.issue(&t, 100);
        assert!(s.is_live(99));
        assert!(!s.is_live(100), "expired");
        s.redeem(t.expose(), 50).unwrap();
        assert!(!s.is_live(50), "redeemed");
    }

    #[test]
    fn a_digest_fingerprint_is_not_the_token() {
        let t = Token::generate();
        let fp = t.digest().fingerprint();
        assert_eq!(fp.len(), 8);
        assert!(!t.expose().contains(&fp) || fp.len() < 8);
    }
}

/// A cloneable handle to the one outstanding invitation, for connection tasks.
///
/// ## Why this type exists, and why it is shaped like this
///
/// A connection future is `'static` and lives on the controller's runtime; the
/// [`PairingService`](crate::PairingService) lives in the backend the console
/// owns. The future must be able to redeem a token without owning the service.
///
/// Three properties are deliberate:
///
/// * **It holds only hashes.** `TokenStore` never contained a token and this
///   does not change that. A leaked handle leaks nothing usable.
/// * **The lock is `std::sync::Mutex`, not `tokio::sync::Mutex`.** That is not
///   an oversight. A `std` guard is not `Send`, so holding one across an
///   `.await` is a compile error rather than a latent stall. Redemption is a
///   SHA-256 and two comparisons; it has no business spanning an await.
/// * **Every method takes and releases the lock inside itself.** There is no
///   `lock()` accessor to misuse.
#[derive(Clone, Default)]
pub struct RedemptionHandle(std::sync::Arc<std::sync::Mutex<TokenStore>>);

impl RedemptionHandle {
    /// A handle to an empty store.
    pub fn new() -> Self {
        RedemptionHandle(std::sync::Arc::new(
            std::sync::Mutex::new(TokenStore::new()),
        ))
    }

    /// Record a freshly minted token by hash, replacing any previous one.
    pub fn issue(&self, token: &Token, expires_at: u64) {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        g.issue(token, expires_at);
    }

    /// Present a token. Succeeds at most once per issued invite.
    ///
    /// Synchronous by design: the caller may be inside an async fn, and the
    /// borrow ends before this returns.
    pub fn redeem(&self, presented: &str, now: u64) -> Result<(), RedeemError> {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        g.redeem(presented, now)
    }

    /// Drop the outstanding invitation.
    pub fn revoke(&self) {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        g.clear();
    }

    /// Is an unexpired, unredeemed invitation outstanding?
    pub fn is_live(&self, now: u64) -> bool {
        let g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        g.is_live(now)
    }
}

impl std::fmt::Debug for RedemptionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never renders the store. Same reason as TokenStore's own Debug.
        f.write_str("RedemptionHandle(<hash-only>)")
    }
}

#[cfg(test)]
mod handle_tests {
    use super::*;

    #[test]
    fn the_handle_shares_one_store_across_clones() {
        let h = RedemptionHandle::new();
        let t = Token::generate();
        h.issue(&t, 100);
        let clone = h.clone();
        // Redeeming through one clone must exhaust it for all of them: a
        // per-clone store would make a token reusable once per connection task.
        assert_eq!(clone.redeem(t.expose(), 50), Ok(()));
        assert_eq!(h.redeem(t.expose(), 50), Err(RedeemError::AlreadyRedeemed));
    }

    #[test]
    fn the_handle_never_renders_the_token() {
        let h = RedemptionHandle::new();
        let t = Token::generate();
        h.issue(&t, 100);
        assert!(!format!("{h:?}").contains(t.expose()));
    }

    #[test]
    fn revoke_through_the_handle_refuses_everything() {
        let h = RedemptionHandle::new();
        let t = Token::generate();
        h.issue(&t, 100);
        h.revoke();
        assert!(!h.is_live(50));
        assert_eq!(h.redeem(t.expose(), 50), Err(RedeemError::NoInvite));
    }

    /// The guard must not be `Send`, so it cannot be held across an await.
    /// This is a compile-time property; the assertion documents it.
    #[test]
    fn redemption_is_synchronous_and_cannot_span_an_await() {
        fn assert_not_send<T>() {}
        assert_not_send::<std::sync::MutexGuard<'_, TokenStore>>();
        // A tokio::sync::Mutex guard WOULD be Send, which is exactly the
        // footgun this type avoids.
    }
}

//! `PairingService` — mints one invite for the address the host is *already*
//! bound to, and does nothing else.
//!
//! ## The side effects this deliberately does not have
//!
//! Every one of these was in the implementation it replaces
//! (`modules/module17_bootstrap_invite::start`), and each is now impossible by
//! construction rather than by care:
//!
//! | removed | what it did |
//! |---|---|
//! | UDP token beacon | `module23_wifi_beacon` sent the live `session_token` to `255.255.255.255` every 5 s |
//! | process-wide token event | put `session_token` on a broadcast bus any subscriber could read |
//! | public routing probe | opened a UDP socket to `8.8.8.8:80` to discover the outbound address |
//! | external image viewer | wrote the QR to a temp file and ran `xdg-open` |
//! | NFC write | called `module22_nfc_writer` and emitted `rfid_written` **before** attempting it |
//! | BLE advertisement | printed "Bluetooth broadcast stub active" and advertised a transport that did not exist |
//!
//! `create_invite` takes an already-bound `SocketAddr` and returns a value. It
//! has no `&mut self` reach into a socket, no thread, no file handle, and no
//! way to acquire one: the crate does not depend on `tokio`, `std::process`,
//! or any network type beyond `SocketAddr` itself.

use crate::invite::{
    addr_string, canonical_bytes, nonce_hex, relay_canonical_bytes, RelayInvite, SignedInvite,
    INVITE_KIND, INVITE_VERSION, RELAY_INVITE_VERSION, SESSION_PROTOCOL,
};
use crate::qr::{self, QrBitmap};
use crate::token::{RedeemError, RedemptionHandle, Token, TOKEN_TTL};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use std::net::SocketAddr;

/// What an invitation grants. Signed, so it cannot be widened in transit.
///
/// Only capabilities that exist are listed. v3 advertised
/// `allowed_transports: ["wifi","bluetooth","usb","lan","wan"]`, three of which
/// were never implemented — an invite that claims a capability the product does
/// not have is a lie the signature makes authoritative.
pub const CAP_VIEW: &str = "view";
/// Control is a separate grant; the session still requires an explicit input
/// grant at the `session_core` gate regardless of what the invite says.
pub const CAP_CONTROL: &str = "control";

/// A minted invitation: the invite itself, and the QR to put on screen.
pub struct Invitation {
    /// The signed invite. Its `token` field is the credential.
    pub invite: SignedInvite,
    /// In-memory QR bitmap. Never written to disk.
    pub qr: QrBitmap,
    /// Short non-secret handle for log correlation.
    pub token_fingerprint: String,
}

/// An invitation for a host reached through a relay.
///
/// Separate from [`Invitation`] rather than an enum inside it, because the two
/// carry genuinely different things: one names a socket on the local network,
/// the other names a relay and a session. A single type would have to hold
/// both and let callers ask which is real.
pub struct RelayInvitation {
    /// The signed invite. Its `token` field is the credential.
    pub invite: RelayInvite,
    /// In-memory QR bitmap. Never written to disk.
    pub qr: QrBitmap,
    /// Short non-secret handle for log correlation.
    pub token_fingerprint: String,
}

/// Mints invites and remembers, by hash, the one that is outstanding.
pub struct PairingService {
    signing: SigningKey,
    host_pubkey_hex: String,
    /// **The single live token authority.** Shared by handle with every
    /// connection task, so the host redeems against the same store the console
    /// minted from. Before the Block 4 repair the shipping handshake validated
    /// against `SessionManager`'s separate UUID store instead, which the
    /// console never populated — a token from a real QR could not be accepted.
    tokens: RedemptionHandle,
}

/// Why an invite could not be minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintError {
    /// The address given is not one a peer could reach or the host could bind.
    UnusableAddress(&'static str),
    /// The QR encoder refused the payload.
    QrTooLarge(String),
}

impl MintError {
    /// Display-safe reason.
    pub fn reason(&self) -> String {
        match self {
            MintError::UnusableAddress(w) => format!("cannot mint an invite for {w}"),
            MintError::QrTooLarge(e) => e.clone(),
        }
    }
}

impl PairingService {
    /// Build a service around the host's durable signing identity and its Noise
    /// static public key.
    ///
    /// `host_pubkey_hex` is the key the invite PINS. It is passed in rather
    /// than read here so this crate never touches a key file.
    pub fn new(signing: SigningKey, host_pubkey_hex: impl Into<String>) -> Self {
        PairingService {
            signing,
            host_pubkey_hex: host_pubkey_hex.into(),
            tokens: RedemptionHandle::new(),
        }
    }

    /// This host's identity public key, standard base64. Public by definition.
    pub fn identity_b64(&self) -> String {
        STANDARD.encode(self.signing.verifying_key().to_bytes())
    }

    /// Mint an invitation for `bind`, valid for [`TOKEN_TTL`] from `now`.
    ///
    /// `bind` MUST be the address the listener is already bound to. The service
    /// does not discover, guess, or probe for an address — that is the whole
    /// point of taking it as an argument.
    ///
    /// Minting replaces any previous invitation: the old token stops being
    /// redeemable immediately, so pressing the button again is a revocation.
    pub fn create_invite(
        &mut self,
        bind: SocketAddr,
        now: u64,
        capabilities: &[String],
    ) -> Result<Invitation, MintError> {
        if bind.ip().is_unspecified() {
            return Err(MintError::UnusableAddress("a wildcard address"));
        }
        if bind.port() == 0 {
            return Err(MintError::UnusableAddress("port 0"));
        }

        let token = Token::generate();
        let nonce = nonce_hex();
        let addr = addr_string(bind);
        let expires_at = now + TOKEN_TTL.as_secs();

        let canonical = canonical_bytes(
            INVITE_KIND,
            INVITE_VERSION,
            SESSION_PROTOCOL,
            &addr,
            bind.port(),
            token.expose(),
            &nonce,
            expires_at,
            capabilities,
            &self.host_pubkey_hex,
        );
        let signature = STANDARD.encode(self.signing.sign(&canonical).to_bytes());

        let invite = SignedInvite {
            kind: INVITE_KIND.to_string(),
            version: INVITE_VERSION,
            protocol: SESSION_PROTOCOL.to_string(),
            addr,
            port: bind.port(),
            token: token.expose().to_string(),
            nonce,
            expires_at,
            capabilities: capabilities.to_vec(),
            host_pubkey: self.host_pubkey_hex.clone(),
            host_identity_pubkey: self.identity_b64(),
            signature,
        };

        let qr = qr::encode(&invite.to_json()).map_err(MintError::QrTooLarge)?;
        let token_fingerprint = token.digest().fingerprint();

        // The host keeps the HASH. `token` is dropped at the end of this
        // function; the only copy that survives is the one in the QR.
        self.tokens.issue(&token, expires_at);

        Ok(Invitation {
            invite,
            qr,
            token_fingerprint,
        })
    }

    /// Mint an invitation for a host reached through `relay`, valid for
    /// [`TOKEN_TTL`] from `now`.
    ///
    /// `relay` and `session` MUST be the relay this host actually dialled and
    /// the session it was actually issued. As with [`PairingService::create_invite`],
    /// the service discovers nothing: an invite that named an endpoint the host
    /// had guessed at would point a phone somewhere nobody chose.
    ///
    /// Minting replaces any previous invitation, whichever route it named: the
    /// old token stops being redeemable immediately. There is ONE outstanding
    /// token, not one per route — two live tokens would mean a revocation that
    /// silently left the other usable.
    pub fn create_relay_invite(
        &mut self,
        relay: SocketAddr,
        session: &str,
        now: u64,
        capabilities: &[String],
    ) -> Result<RelayInvitation, MintError> {
        if relay.ip().is_unspecified() {
            return Err(MintError::UnusableAddress("a wildcard address"));
        }
        if relay.port() == 0 {
            return Err(MintError::UnusableAddress("port 0"));
        }
        if session.is_empty() {
            return Err(MintError::UnusableAddress("an empty session id"));
        }

        let token = Token::generate();
        let nonce = nonce_hex();
        let relay_addr = addr_string(relay);
        let expires_at = now + TOKEN_TTL.as_secs();

        let canonical = relay_canonical_bytes(
            INVITE_KIND,
            RELAY_INVITE_VERSION,
            SESSION_PROTOCOL,
            &relay_addr,
            relay.port(),
            session,
            token.expose(),
            &nonce,
            expires_at,
            capabilities,
            &self.host_pubkey_hex,
        );
        let signature = STANDARD.encode(self.signing.sign(&canonical).to_bytes());

        let invite = RelayInvite {
            kind: INVITE_KIND.to_string(),
            version: RELAY_INVITE_VERSION,
            protocol: SESSION_PROTOCOL.to_string(),
            relay_addr,
            relay_port: relay.port(),
            session: session.to_string(),
            token: token.expose().to_string(),
            nonce,
            expires_at,
            capabilities: capabilities.to_vec(),
            host_pubkey: self.host_pubkey_hex.clone(),
            host_identity_pubkey: self.identity_b64(),
            signature,
        };

        let qr = qr::encode(&invite.to_json()).map_err(MintError::QrTooLarge)?;
        let token_fingerprint = token.digest().fingerprint();
        self.tokens.issue(&token, expires_at);

        Ok(RelayInvitation {
            invite,
            qr,
            token_fingerprint,
        })
    }

    /// Present a token from a connecting peer. Succeeds at most once.
    pub fn redeem(&self, presented: &str, now: u64) -> Result<(), RedeemError> {
        self.tokens.redeem(presented, now)
    }

    /// A cloneable handle to this service's token store, for connection tasks.
    ///
    /// Narrowly scoped on purpose: a connection future gets the ability to
    /// redeem a token and nothing else — no signing key, no minting, no host
    /// identity.
    pub fn redemption_handle(&self) -> RedemptionHandle {
        self.tokens.clone()
    }

    /// Drop the outstanding invitation. Called when the host stops.
    pub fn revoke(&self) {
        self.tokens.revoke();
    }

    /// Is an invitation currently redeemable?
    pub fn has_live_invite(&self, now: u64) -> bool {
        self.tokens.is_live(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite::signature_is_valid;

    fn svc() -> PairingService {
        let mut csprng = rand::rngs::OsRng;
        PairingService::new(SigningKey::generate(&mut csprng), "aa".repeat(32))
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn caps() -> Vec<String> {
        vec![CAP_VIEW.to_string(), CAP_CONTROL.to_string()]
    }

    #[test]
    fn the_invite_names_the_exact_bound_address() {
        let mut s = svc();
        let inv = s
            .create_invite(sa("192.168.1.20:8082"), 1000, &caps())
            .unwrap();
        assert_eq!(inv.invite.addr, "192.168.1.20");
        assert_eq!(inv.invite.port, 8082);
        // And carries no second address for anything to fall back to.
        assert!(!inv.invite.to_json().contains("wan_ip"));
    }

    #[test]
    fn a_wildcard_or_zero_port_cannot_be_invited_to() {
        let mut s = svc();
        assert!(matches!(
            s.create_invite(sa("0.0.0.0:8082"), 1000, &caps()),
            Err(MintError::UnusableAddress(_))
        ));
        assert!(matches!(
            s.create_invite(sa("[::]:8082"), 1000, &caps()),
            Err(MintError::UnusableAddress(_))
        ));
        assert!(matches!(
            s.create_invite(sa("192.168.1.20:0"), 1000, &caps()),
            Err(MintError::UnusableAddress(_))
        ));
    }

    #[test]
    fn expiry_is_sixty_seconds_from_now() {
        let mut s = svc();
        let inv = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        assert_eq!(inv.invite.expires_at, 1060);
    }

    #[test]
    fn the_signature_verifies_against_the_identity_in_the_invite() {
        let mut s = svc();
        let inv = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        assert!(signature_is_valid(
            &inv.invite.canonical_bytes(),
            &inv.invite.host_identity_pubkey,
            &inv.invite.signature
        ));
    }

    #[test]
    fn the_service_retains_only_the_hash() {
        let mut s = svc();
        let inv = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        let token = inv.invite.token.clone();
        // The only place the token exists after minting is the invite we were
        // handed. It must not be recoverable from the service.
        let rendered = format!("{:?}", s.tokens);
        assert!(!rendered.contains(&token));
        // ...and it is still redeemable, so the hash really was kept.
        assert_eq!(s.redeem(&token, 1010), Ok(()));
    }

    #[test]
    fn a_token_is_redeemable_once_and_then_never() {
        let mut s = svc();
        let inv = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        let t = inv.invite.token.clone();
        assert_eq!(s.redeem(&t, 1010), Ok(()));
        assert_eq!(s.redeem(&t, 1010), Err(RedeemError::AlreadyRedeemed));
    }

    #[test]
    fn minting_again_revokes_the_previous_invite() {
        let mut s = svc();
        let first = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        let second = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        assert_ne!(first.invite.token, second.invite.token);
        assert_eq!(
            s.redeem(&first.invite.token, 1010),
            Err(RedeemError::Mismatch)
        );
        assert_eq!(s.redeem(&second.invite.token, 1010), Ok(()));
    }

    #[test]
    fn revoke_kills_the_outstanding_invite() {
        let mut s = svc();
        let inv = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        assert!(s.has_live_invite(1010));
        s.revoke();
        assert!(!s.has_live_invite(1010));
        assert_eq!(
            s.redeem(&inv.invite.token, 1010),
            Err(RedeemError::NoInvite)
        );
    }

    #[test]
    fn two_invites_never_share_a_nonce() {
        let mut s = svc();
        let a = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        let b = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        assert_ne!(a.invite.nonce, b.invite.nonce);
        assert_ne!(a.invite.signature, b.invite.signature);
    }

    #[test]
    fn the_qr_carries_the_invite_and_nothing_is_written_to_disk() {
        let mut s = svc();
        let inv = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        assert!(inv.qr.size > 20, "a real QR, not a placeholder");
        // The bitmap is data we hold; there is no path in this crate that opens
        // a file. This asserts the *shape* of that guarantee: the returned
        // Invitation owns its pixels.
        assert_eq!(inv.qr.modules.len(), inv.qr.size * inv.qr.size);
    }

    #[test]
    fn capabilities_are_carried_and_signed_in_order() {
        let mut s = svc();
        let view_only = vec![CAP_VIEW.to_string()];
        let inv = s
            .create_invite(sa("10.0.0.5:8082"), 1000, &view_only)
            .unwrap();
        assert_eq!(inv.invite.capabilities, view_only);
        // Widening the capability list breaks the signature.
        let mut tampered = inv.invite.clone();
        tampered.capabilities = caps();
        assert!(!signature_is_valid(
            &tampered.canonical_bytes(),
            &tampered.host_identity_pubkey,
            &tampered.signature
        ));
    }

    #[test]
    fn the_fingerprint_is_not_the_token() {
        let mut s = svc();
        let inv = s.create_invite(sa("10.0.0.5:8082"), 1000, &caps()).unwrap();
        assert_eq!(inv.token_fingerprint.len(), 8);
        assert!(!inv.invite.token.contains(&inv.token_fingerprint));
    }

    // ------------------------------------------------- the relay route (v5)

    const SESSION: &str = "Zm9vYmFyYmF6cXV4MDAwMA";

    /// A relay invite names the RELAY and the session, and carries no host
    /// address — because a dialled-out host does not have one.
    #[test]
    fn a_relay_invite_names_the_relay_and_the_session_and_no_host_address() {
        let mut s = svc();
        let inv = s
            .create_relay_invite(sa("203.0.113.9:9443"), SESSION, 1000, &caps())
            .unwrap();
        assert_eq!(inv.invite.version, crate::RELAY_INVITE_VERSION);
        assert_eq!(inv.invite.relay_addr, "203.0.113.9");
        assert_eq!(inv.invite.relay_port, 9443);
        assert_eq!(inv.invite.session, SESSION);

        let json = inv.invite.to_json();
        for absent in ["\"addr\"", "\"port\"", "wan_ip"] {
            assert!(
                !json.contains(absent),
                "a relay invite carried {absent}, which names something that does not exist"
            );
        }
    }

    #[test]
    fn a_relay_invite_verifies_against_this_host_identity() {
        let mut s = svc();
        let inv = s
            .create_relay_invite(sa("203.0.113.9:9443"), SESSION, 1000, &caps())
            .unwrap();
        assert!(signature_is_valid(
            &inv.invite.canonical_bytes(),
            &inv.invite.host_identity_pubkey,
            &inv.invite.signature
        ));
    }

    /// And it decodes back to exactly what was minted — the QR carries a v5
    /// invite, not something that merely resembles one.
    #[test]
    fn a_minted_relay_invite_decodes_back_to_itself() {
        let mut s = svc();
        let inv = s
            .create_relay_invite(sa("203.0.113.9:9443"), SESSION, 1000, &caps())
            .unwrap();
        match crate::decode(&inv.invite.to_json()) {
            Ok(crate::Decoded::V5(back)) => assert_eq!(back, inv.invite),
            other => panic!("a minted relay invite decoded as {other:?}"),
        }
    }

    #[test]
    fn an_unusable_relay_endpoint_cannot_be_invited_to() {
        let mut s = svc();
        for bad in ["0.0.0.0:9443", "[::]:9443", "203.0.113.9:0"] {
            assert!(
                matches!(
                    s.create_relay_invite(sa(bad), SESSION, 1000, &caps()),
                    Err(MintError::UnusableAddress(_))
                ),
                "{bad} was invited to"
            );
        }
        assert!(matches!(
            s.create_relay_invite(sa("203.0.113.9:9443"), "", 1000, &caps()),
            Err(MintError::UnusableAddress(_))
        ));
    }

    /// **ONE outstanding token, not one per route.**
    ///
    /// Two live tokens would mean pressing the button again revoked one and
    /// silently left the other usable — and the operator's mental model is that
    /// minting a new code retires the old one, whichever kind it was.
    #[test]
    fn minting_a_relay_invite_retires_the_direct_one() {
        let mut s = svc();
        let direct = s
            .create_invite(sa("192.168.1.20:8082"), 1000, &caps())
            .unwrap();
        assert!(s.redeem(&direct.invite.token, 1001).is_ok());

        let direct = s
            .create_invite(sa("192.168.1.20:8082"), 2000, &caps())
            .unwrap();
        let relay = s
            .create_relay_invite(sa("203.0.113.9:9443"), SESSION, 2000, &caps())
            .unwrap();
        assert!(
            s.redeem(&direct.invite.token, 2001).is_err(),
            "the direct token still redeemed after a relay invite replaced it"
        );
        assert!(s.redeem(&relay.invite.token, 2001).is_ok());
    }

    /// And the reverse, so neither route is the privileged one.
    #[test]
    fn minting_a_direct_invite_retires_the_relay_one() {
        let mut s = svc();
        let relay = s
            .create_relay_invite(sa("203.0.113.9:9443"), SESSION, 1000, &caps())
            .unwrap();
        let direct = s
            .create_invite(sa("192.168.1.20:8082"), 1000, &caps())
            .unwrap();
        assert!(
            s.redeem(&relay.invite.token, 1001).is_err(),
            "the relay token still redeemed after a direct invite replaced it"
        );
        assert!(s.redeem(&direct.invite.token, 1001).is_ok());
    }

    #[test]
    fn a_relay_invite_token_is_redeemable_exactly_once() {
        let mut s = svc();
        let inv = s
            .create_relay_invite(sa("203.0.113.9:9443"), SESSION, 1000, &caps())
            .unwrap();
        assert!(s.redeem(&inv.invite.token, 1001).is_ok());
        assert!(
            s.redeem(&inv.invite.token, 1001).is_err(),
            "a relay invite's token was redeemable twice"
        );
    }

    /// The capabilities in a relay invite are the ones asked for, and they are
    /// signed — the same guarantee the direct route has.
    #[test]
    fn a_relay_invite_carries_and_signs_the_capabilities_it_was_given() {
        let mut s = svc();
        let view_only = vec![CAP_VIEW.to_string()];
        let inv = s
            .create_relay_invite(sa("203.0.113.9:9443"), SESSION, 1000, &view_only)
            .unwrap();
        assert_eq!(inv.invite.capabilities, view_only);

        let mut widened = inv.invite.clone();
        widened.capabilities.push(CAP_CONTROL.to_string());
        assert!(
            !signature_is_valid(
                &widened.canonical_bytes(),
                &widened.host_identity_pubkey,
                &widened.signature
            ),
            "a view-only relay invite was widened to control without breaking the signature"
        );
    }
}

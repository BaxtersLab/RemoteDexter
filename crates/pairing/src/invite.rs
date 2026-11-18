//! The signed invite: v4 for a bound host, v5 for one reached through a relay,
//! v6 for a host serving BOTH at once, with a strict decoder for v3.
//!
//! ## v5 is not "v4 but newer"
//!
//! **Both are current.** The number names the ROUTE, not a schema generation.
//! A host bound to an interface emits v4, which carries `addr` and `port`. A
//! host that dialled out to a relay emits v5, which carries `relay_addr`,
//! `relay_port` and the `session` id the relay issued, and **no host address at
//! all** — because there is none, and inventing one is how v3 ended up probing
//! a public resolver for a "public" address.
//!
//! Everything else is identical, deliberately: the token, the nonce, the
//! expiry, the capabilities and the pinned Noise key mean exactly what they
//! meant in v4, and the relay never sees any of them in the clear.
//!
//! ## v6 carries both routes, and only both
//!
//! A host listening on an interface AND dialled out to a relay can hand a phone
//! both ways to reach it in one code, and the phone races them (LAN first). v6
//! carries `addr` and `port` as v4 does and `relay_addr`, `relay_port` and
//! `session` as v5 does — **all five, always**. A host with one route still
//! mints v4 or v5, which every app can read; a one-route v6 would be a code an
//! older app cannot read, for nothing in return. An older app refuses v6 by
//! number, which is the right failure: it cannot reach a route it does not know.
//!
//! ## What the signature covers, and why each field is in it
//!
//! | field | why it must be signed |
//! |---|---|
//! | `kind` | so a QR for something else cannot be replayed as a pairing invite |
//! | `version` | so an attacker cannot downgrade a v4 invite to v3 rules |
//! | `protocol` | the session protocol the invite is for |
//! | `addr`, `port` | so the endpoint cannot be redirected to an attacker's host |
//! | `token` | so the credential cannot be swapped |
//! | `nonce` | so two invites are never byte-identical |
//! | `expires_at` | so the sixty-second life cannot be extended |
//! | `capabilities` | so "view only" cannot be quietly upgraded to control |
//! | `host_pubkey` | **the Noise key pin.** Without this signed, the pin proves nothing |
//!
//! `host_identity_pubkey` is deliberately *not* in the canonical bytes: it is
//! the key the signature is verified *with*. Substituting it invalidates the
//! signature against the identity the phone already trusts, which is
//! `InviteTrustPolicy`'s job — signature validity is not trust, and the two
//! checks are both required.
//!
//! ## What v4 removed from v3
//!
//! * `wan_ip` — v3 called `get_wan_ip()`, which opened a UDP socket to
//!   `8.8.8.8:80` to discover the outbound address. That disclosed the timing
//!   of every invitation to a third party's address space, for a field the
//!   client fell back off anyway.
//! * `security_policy` — a nested object advertising `allowed_transports:
//!   ["wifi","bluetooth","usb","lan","wan"]` and a geofence, none of which
//!   existed. Replaced by `capabilities`, which lists only what is real.

use crate::token::Token;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Marks this QR as a RemoteDexter pairing invite.
///
/// Required in v4. Its absence is how the Android side tells "you scanned the
/// installer's download URL" from "you scanned a malformed invite" and can say
/// so specifically, instead of reporting "Invalid QR" for both — which is what
/// the shipped builds did, and it cost two test rounds.
pub const INVITE_KIND: &str = "remotedexter-pair";

/// The invite schema for a host BOUND to an interface.
pub const INVITE_VERSION: u8 = 4;

/// The invite schema for a host reached THROUGH A RELAY.
///
/// Not a successor to [`INVITE_VERSION`] — see the module docs. A host emits one
/// or the other according to how it is actually reachable, and never both.
pub const RELAY_INVITE_VERSION: u8 = 5;

/// The invite schema for a host serving BOTH routes at once. See the module docs.
pub const DUAL_INVITE_VERSION: u8 = 6;

/// The byte that separates fields in the canonical encoding.
pub const CANONICAL_SEPARATOR: char = '\n';

/// Whether a field would break the canonical encoding by containing the
/// separator.
///
/// **Why this exists when nothing can currently produce such a field.** The
/// canonical form is fields joined with `\n`, which is only injective while no
/// field contains one: `("a", "b\nc")` and `("a\nb", "c")` encode identically,
/// so one signature would cover two different invites. Today every field is an
/// address, a port, hex, base64 or a fixed string, and none can hold a newline
/// — so there is no attack. This refuses them anyway, because the safety of a
/// signing format should not rest on an argument about what callers happen to
/// emit.
pub fn field_carries_separator(value: &str) -> bool {
    value.contains(CANONICAL_SEPARATOR)
}

/// The one prior version still decoded, for one migration release.
pub const LEGACY_INVITE_VERSION: u8 = 3;

/// The session protocol an invite points at. Unchanged by v4: the invite schema
/// and the session wire version are different things, and Block 10 owns the wire.
pub const SESSION_PROTOCOL: &str = "rdv3";

/// A pairing invitation, exactly as it appears in the QR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInvite {
    /// Always [`INVITE_KIND`].
    pub kind: String,
    /// Schema version.
    pub version: u8,
    /// Session protocol identifier.
    pub protocol: String,
    /// The exact IP the host is already bound to — never a guess, never a
    /// wildcard, never a second "wan" address.
    pub addr: String,
    /// The exact bound port.
    pub port: u16,
    /// The one-use 256-bit token, hex.
    pub token: String,
    /// Random per-invite nonce, hex.
    pub nonce: String,
    /// Unix seconds at which this invite stops being valid.
    pub expires_at: u64,
    /// What this invite grants. Signed, so it cannot be widened in transit.
    pub capabilities: Vec<String>,
    /// Host's Noise static X25519 public key, lowercase hex. **Pinned.**
    pub host_pubkey: String,
    /// Host's durable Ed25519 identity public key, standard base64.
    pub host_identity_pubkey: String,
    /// Ed25519 signature over [`canonical_bytes`], standard base64.
    pub signature: String,
}

/// The exact bytes signed and verified.
///
/// **Must match `InviteSignatureVerifier.canonicalBytesV4` in the Kotlin client
/// byte for byte** — same fields, same order, same `\n` separator, same UTF-8.
/// Divergence fails *silently*: every signature simply stops verifying. The
/// cross-language vectors in `contract/signed_invite_v4.json` exist to catch it
/// in CI rather than on a phone.
///
/// Field order is load-bearing and is not alphabetical. Do not tidy it.
/// Capabilities are joined with `,` in the order given; the order is part of
/// the signature, so a host must emit them deterministically.
pub fn canonical_bytes(
    kind: &str,
    version: u8,
    protocol: &str,
    addr: &str,
    port: u16,
    token: &str,
    nonce: &str,
    expires_at: u64,
    capabilities: &[String],
    host_pubkey: &str,
) -> Vec<u8> {
    format!(
        "{kind}\n{version}\n{protocol}\n{addr}\n{port}\n{token}\n{nonce}\n{expires_at}\n{}\n{host_pubkey}",
        capabilities.join(",")
    )
    .into_bytes()
}

/// A pairing invitation for a host reached through a relay.
///
/// Carries where the RELAY is and which session to ask it for. It does not
/// carry a host address, because a dialled-out host does not have one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayInvite {
    /// Always [`INVITE_KIND`]. The same kind: it is still a pairing invite.
    pub kind: String,
    /// Always [`RELAY_INVITE_VERSION`].
    pub version: u8,
    /// Session protocol identifier. Unchanged by the route.
    pub protocol: String,
    /// The relay's address, as the host reached it. Never discovered or guessed.
    pub relay_addr: String,
    /// The relay's port.
    pub relay_port: u16,
    /// The session id the relay issued to this host.
    ///
    /// Signed, so it cannot be swapped for another host's session in transit —
    /// which would splice the phone to a machine it never agreed to.
    pub session: String,
    /// The one-use 256-bit token, hex.
    pub token: String,
    /// Random per-invite nonce, hex.
    pub nonce: String,
    /// Unix seconds at which this invite stops being valid.
    pub expires_at: u64,
    /// What this invite grants. Signed, so it cannot be widened in transit.
    pub capabilities: Vec<String>,
    /// Host's Noise static X25519 public key, lowercase hex. **Pinned.**
    ///
    /// This is what makes the relay untrusted rather than trusted: the phone
    /// pins the HOST's key and runs Noise end to end through the splice, so a
    /// relay that substituted itself would fail the handshake.
    pub host_pubkey: String,
    /// Host's durable Ed25519 identity public key, standard base64.
    pub host_identity_pubkey: String,
    /// Ed25519 signature over [`relay_canonical_bytes`], standard base64.
    pub signature: String,
}

/// The exact bytes a v5 signature covers.
///
/// **Must match `InviteDecoder.canonicalBytesV5` in the Kotlin client byte for
/// byte** — same fields, same order, same `\n` separator, same UTF-8.
/// Divergence fails *silently*: every signature simply stops verifying, on a
/// phone, with both sides' own tests green. `contract/signed_invite_v5.json`
/// exists to catch it in CI instead.
///
/// Field order is load-bearing and is not alphabetical. Do not tidy it.
///
/// `session` sits with `relay_addr` and `relay_port` because the three together
/// are "where to connect and what to ask for", and they are signed as a unit.
pub fn relay_canonical_bytes(
    kind: &str,
    version: u8,
    protocol: &str,
    relay_addr: &str,
    relay_port: u16,
    session: &str,
    token: &str,
    nonce: &str,
    expires_at: u64,
    capabilities: &[String],
    host_pubkey: &str,
) -> Vec<u8> {
    format!(
        "{kind}\n{version}\n{protocol}\n{relay_addr}\n{relay_port}\n{session}\n{token}\n{nonce}\n{expires_at}\n{}\n{host_pubkey}",
        capabilities.join(",")
    )
    .into_bytes()
}

impl RelayInvite {
    /// The bytes this invite's signature covers.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        relay_canonical_bytes(
            &self.kind,
            self.version,
            &self.protocol,
            &self.relay_addr,
            self.relay_port,
            &self.session,
            &self.token,
            &self.nonce,
            self.expires_at,
            &self.capabilities,
            &self.host_pubkey,
        )
    }

    /// Render as the compact JSON that goes into the QR.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("RelayInvite is always serialisable")
    }

    /// The first field that would break the canonical encoding, if any.
    fn separator_in_field(&self) -> Option<&'static str> {
        for (name, value) in [
            ("kind", &self.kind),
            ("protocol", &self.protocol),
            ("relay_addr", &self.relay_addr),
            ("session", &self.session),
            ("token", &self.token),
            ("nonce", &self.nonce),
            ("host_pubkey", &self.host_pubkey),
        ] {
            if field_carries_separator(value) {
                return Some(name);
            }
        }
        self.capabilities
            .iter()
            .any(|c| field_carries_separator(c))
            .then_some("capabilities")
    }
}

/// A pairing invitation for a host reachable both on the LAN and through a relay.
///
/// Every field of [`SignedInvite`] and every field of [`RelayInvite`], and one
/// token: the phone races the two routes and presents the token on whichever
/// completes the pinned handshake first, and on that one only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualInvite {
    /// Always [`INVITE_KIND`].
    pub kind: String,
    /// Always [`DUAL_INVITE_VERSION`].
    pub version: u8,
    /// Session protocol identifier. Unchanged by the route.
    pub protocol: String,
    /// The exact IP the host is bound to, as in v4.
    pub addr: String,
    /// The exact bound port.
    pub port: u16,
    /// The relay's address, as the host reached it, as in v5.
    pub relay_addr: String,
    /// The relay's port.
    pub relay_port: u16,
    /// The session id the relay issued to this host. Signed, as in v5.
    pub session: String,
    /// The one-use 256-bit token, hex. ONE token for both routes.
    pub token: String,
    /// Random per-invite nonce, hex.
    pub nonce: String,
    /// Unix seconds at which this invite stops being valid.
    pub expires_at: u64,
    /// What this invite grants. Signed, so it cannot be widened in transit.
    pub capabilities: Vec<String>,
    /// Host's Noise static X25519 public key, lowercase hex. **Pinned** — on
    /// both routes, which is what keeps the relay route untrusted.
    pub host_pubkey: String,
    /// Host's durable Ed25519 identity public key, standard base64.
    pub host_identity_pubkey: String,
    /// Ed25519 signature over [`dual_canonical_bytes`], standard base64.
    pub signature: String,
}

/// The exact bytes a v6 signature covers.
///
/// **Must match `InviteDecoder.canonicalBytesV6` in the Kotlin client byte for
/// byte.** `contract/signed_invite_v6.json` catches divergence in CI.
///
/// Field order is load-bearing and is not alphabetical. The LAN route sits
/// where v4 has it and the relay route follows it in v5's order, so each route
/// is signed as a unit, exactly as it is on its own.
pub fn dual_canonical_bytes(
    kind: &str,
    version: u8,
    protocol: &str,
    addr: &str,
    port: u16,
    relay_addr: &str,
    relay_port: u16,
    session: &str,
    token: &str,
    nonce: &str,
    expires_at: u64,
    capabilities: &[String],
    host_pubkey: &str,
) -> Vec<u8> {
    format!(
        "{kind}\n{version}\n{protocol}\n{addr}\n{port}\n{relay_addr}\n{relay_port}\n{session}\n{token}\n{nonce}\n{expires_at}\n{}\n{host_pubkey}",
        capabilities.join(",")
    )
    .into_bytes()
}

impl DualInvite {
    /// The bytes this invite's signature covers.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        dual_canonical_bytes(
            &self.kind,
            self.version,
            &self.protocol,
            &self.addr,
            self.port,
            &self.relay_addr,
            self.relay_port,
            &self.session,
            &self.token,
            &self.nonce,
            self.expires_at,
            &self.capabilities,
            &self.host_pubkey,
        )
    }

    /// Render as the compact JSON that goes into the QR.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("DualInvite is always serialisable")
    }

    /// The first field that would break the canonical encoding, if any.
    fn separator_in_field(&self) -> Option<&'static str> {
        for (name, value) in [
            ("kind", &self.kind),
            ("protocol", &self.protocol),
            ("addr", &self.addr),
            ("relay_addr", &self.relay_addr),
            ("session", &self.session),
            ("token", &self.token),
            ("nonce", &self.nonce),
            ("host_pubkey", &self.host_pubkey),
        ] {
            if field_carries_separator(value) {
                return Some(name);
            }
        }
        self.capabilities
            .iter()
            .any(|c| field_carries_separator(c))
            .then_some("capabilities")
    }
}

impl SignedInvite {
    /// The bytes this invite's signature covers.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_bytes(
            &self.kind,
            self.version,
            &self.protocol,
            &self.addr,
            self.port,
            &self.token,
            &self.nonce,
            self.expires_at,
            &self.capabilities,
            &self.host_pubkey,
        )
    }

    /// Render as the compact JSON that goes into the QR.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("SignedInvite is always serialisable")
    }

    /// The first field that would break the canonical encoding, if any.
    fn separator_in_field(&self) -> Option<&'static str> {
        for (name, value) in [
            ("kind", &self.kind),
            ("protocol", &self.protocol),
            ("addr", &self.addr),
            ("token", &self.token),
            ("nonce", &self.nonce),
            ("host_pubkey", &self.host_pubkey),
        ] {
            if field_carries_separator(value) {
                return Some(name);
            }
        }
        self.capabilities
            .iter()
            .any(|c| field_carries_separator(c))
            .then_some("capabilities")
    }
}

/// Why an invite could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not JSON at all.
    NotJson,
    /// Valid JSON, but not a RemoteDexter pairing invite — most often the
    /// installer's download URL, which is a QR a user can plausibly scan by
    /// mistake. Distinguished so the UI can say which mistake was made.
    WrongKind {
        /// What the `kind` field said, if anything.
        found: String,
    },
    /// A version this build does not decode. v6, v5, v4 and v3 are accepted;
    /// anything else is refused rather than guessed at.
    UnsupportedVersion {
        /// The version encountered.
        found: u8,
    },
    /// A field contains the canonical separator, so the bytes it would be
    /// signed as are ambiguous. See [`field_carries_separator`].
    SeparatorInField {
        /// Which field.
        field: &'static str,
    },
    /// A required field was missing or the wrong type.
    Malformed {
        /// Which field.
        field: &'static str,
    },
}

impl DecodeError {
    /// Display-safe reason.
    pub fn reason(&self) -> String {
        match self {
            DecodeError::NotJson => "this QR is not a RemoteDexter pairing code".into(),
            DecodeError::WrongKind { .. } => {
                "this QR is not a pairing code — it may be the app download link".into()
            }
            DecodeError::UnsupportedVersion { found } => {
                format!("pairing code version {found} is not supported by this build")
            }
            DecodeError::Malformed { field } => format!("pairing code is missing `{field}`"),
            DecodeError::SeparatorInField { field } => {
                format!("pairing code field `{field}` is not a shape this build will verify")
            }
        }
    }
}

/// Decode an invite from QR text, accepting v6, v5 and v4, and — strictly — v3.
///
/// "Strictly" means a v3 invite is decoded into the v4 shape with its *own*
/// canonical bytes preserved for verification, not silently re-signed or
/// upgraded. A v3 invite verifies against v3 rules or not at all.
pub fn decode(text: &str) -> Result<Decoded, DecodeError> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|_| DecodeError::NotJson)?;
    let obj = v.as_object().ok_or(DecodeError::NotJson)?;

    let version = obj
        .get("version")
        .and_then(|x| x.as_u64())
        .unwrap_or(LEGACY_INVITE_VERSION as u64) as u8;

    match version {
        INVITE_VERSION => {
            let kind = obj
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            if kind != INVITE_KIND {
                return Err(DecodeError::WrongKind { found: kind });
            }
            let invite: SignedInvite =
                serde_json::from_value(v.clone()).map_err(|e| DecodeError::Malformed {
                    field: field_of(&e.to_string()),
                })?;
            if let Some(field) = invite.separator_in_field() {
                return Err(DecodeError::SeparatorInField { field });
            }
            Ok(Decoded::V4(invite))
        }
        RELAY_INVITE_VERSION => {
            let kind = obj
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            if kind != INVITE_KIND {
                return Err(DecodeError::WrongKind { found: kind });
            }
            let invite: RelayInvite =
                serde_json::from_value(v.clone()).map_err(|e| DecodeError::Malformed {
                    field: field_of(&e.to_string()),
                })?;
            if let Some(field) = invite.separator_in_field() {
                return Err(DecodeError::SeparatorInField { field });
            }
            Ok(Decoded::V5(invite))
        }
        DUAL_INVITE_VERSION => {
            let kind = obj
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            if kind != INVITE_KIND {
                return Err(DecodeError::WrongKind { found: kind });
            }
            // Every route field is required by the type: a v6 missing either
            // route is Malformed, never quietly read as the route it kept.
            let invite: DualInvite =
                serde_json::from_value(v.clone()).map_err(|e| DecodeError::Malformed {
                    field: field_of(&e.to_string()),
                })?;
            if let Some(field) = invite.separator_in_field() {
                return Err(DecodeError::SeparatorInField { field });
            }
            Ok(Decoded::V6(invite))
        }
        LEGACY_INVITE_VERSION => {
            // v3 has no `kind`. Requiring one would refuse every invite from the
            // release this migration exists to support.
            let get = |k: &'static str| -> Result<String, DecodeError> {
                obj.get(k)
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .ok_or(DecodeError::Malformed { field: k })
            };
            let port = obj
                .get("port")
                .and_then(|x| x.as_u64())
                .ok_or(DecodeError::Malformed { field: "port" })?;
            // v3 emitted the address as `lan_ip`, and builds before March 2026
            // as `host_ip`. Both are read; dropping either silently breaks
            // pairing against a host the user already owns.
            let addr = obj
                .get("lan_ip")
                .or_else(|| obj.get("host_ip"))
                .and_then(|x| x.as_str())
                .ok_or(DecodeError::Malformed { field: "lan_ip" })?
                .to_string();
            Ok(Decoded::V3(LegacyInvite {
                addr,
                port: port as u16,
                token: get("session_token")?,
                nonce: obj
                    .get("nonce")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                protocol: obj
                    .get("protocol")
                    .and_then(|x| x.as_str())
                    .unwrap_or(SESSION_PROTOCOL)
                    .to_string(),
                wan_ip: obj
                    .get("wan_ip")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                host_pubkey: get("host_pubkey")?,
                host_identity_pubkey: get("host_identity_pubkey")?,
                signature: get("signature")?,
            }))
        }
        other => Err(DecodeError::UnsupportedVersion { found: other }),
    }
}

fn field_of(msg: &str) -> &'static str {
    for f in [
        "kind",
        "version",
        "protocol",
        "relay_addr",
        "relay_port",
        "session",
        "addr",
        "port",
        "token",
        "nonce",
        "expires_at",
        "capabilities",
        "host_pubkey",
        "host_identity_pubkey",
        "signature",
    ] {
        if msg.contains(f) {
            return f;
        }
    }
    "invite"
}

/// A decoded invite, tagged by the schema it arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// A host reachable both on the LAN and through a relay.
    V6(DualInvite),
    /// A host reached through a relay.
    V5(RelayInvite),
    /// A host bound to an interface.
    V4(SignedInvite),
    /// One version back, kept for a single migration release.
    V3(LegacyInvite),
}

/// A v3 invite. Retained only so a host that has not been updated still pairs;
/// it is verified against v3's canonical bytes, never re-signed as v4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyInvite {
    /// `lan_ip` (or `host_ip` on builds before March 2026).
    pub addr: String,
    /// Port.
    pub port: u16,
    /// Token.
    pub token: String,
    /// Nonce.
    pub nonce: String,
    /// Session protocol.
    pub protocol: String,
    /// The public-probe field v4 removed. Read only to reconstruct v3's
    /// canonical bytes; never used as an address.
    pub wan_ip: String,
    /// Pinned Noise key.
    pub host_pubkey: String,
    /// Identity key.
    pub host_identity_pubkey: String,
    /// Signature.
    pub signature: String,
}

impl LegacyInvite {
    /// v3's canonical bytes, reproduced exactly as
    /// `module17_bootstrap_invite::canonical_signing_bytes` produced them.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.nonce,
            self.token,
            self.addr,
            self.wan_ip,
            self.port,
            self.protocol,
            LEGACY_INVITE_VERSION,
            self.host_pubkey
        )
        .into_bytes()
    }
}

/// Verify an invite's signature against the identity key it names.
///
/// Answers only "is this signature valid for the key *in the invite*". It says
/// nothing about whether that identity should be trusted — an attacker can sign
/// their own invite with their own key perfectly well. Trust is a separate
/// decision, made against a remembered identity.
pub fn signature_is_valid(canonical: &[u8], identity_b64: &str, signature_b64: &str) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Ok(key_bytes) = STANDARD.decode(identity_b64) else {
        return false;
    };
    let Ok(sig_bytes) = STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(key_arr): Result<[u8; 32], _> = key_bytes.try_into() else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_arr) else {
        return false;
    };
    key.verify_strict(canonical, &Signature::from_bytes(&sig_arr))
        .is_ok()
}

/// Build the address string a v4 invite carries from an already-bound socket.
pub(crate) fn addr_string(bind: SocketAddr) -> String {
    bind.ip().to_string()
}

/// Random hex nonce.
pub(crate) fn nonce_hex() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Unused-in-product helper kept for the token type's sake.
#[allow(dead_code)]
fn _assert_token_is_used(_t: &Token) {}

#[cfg(test)]
mod v5_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn signed_v5() -> RelayInvite {
        let k = key();
        let caps = vec!["view".to_string(), "control".to_string()];
        let canonical = relay_canonical_bytes(
            INVITE_KIND,
            RELAY_INVITE_VERSION,
            SESSION_PROTOCOL,
            "203.0.113.9",
            9443,
            "AAAAAAAAAAAAAAAAAAAAAA",
            &"1f".repeat(32),
            &"9c".repeat(16),
            1_787_000_060,
            &caps,
            &"ab".repeat(32),
        );
        RelayInvite {
            kind: INVITE_KIND.into(),
            version: RELAY_INVITE_VERSION,
            protocol: SESSION_PROTOCOL.into(),
            relay_addr: "203.0.113.9".into(),
            relay_port: 9443,
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            token: "1f".repeat(32),
            nonce: "9c".repeat(16),
            expires_at: 1_787_000_060,
            capabilities: caps,
            host_pubkey: "ab".repeat(32),
            host_identity_pubkey: STANDARD.encode(k.verifying_key().to_bytes()),
            signature: STANDARD.encode(k.sign(&canonical).to_bytes()),
        }
    }

    fn verifies(i: &RelayInvite) -> bool {
        signature_is_valid(&i.canonical_bytes(), &i.host_identity_pubkey, &i.signature)
    }

    #[test]
    fn a_v5_invite_round_trips_through_decode_and_verifies() {
        let invite = signed_v5();
        assert!(
            verifies(&invite),
            "a freshly signed v5 invite did not verify"
        );
        match decode(&invite.to_json()) {
            Ok(Decoded::V5(back)) => assert_eq!(back, invite),
            other => panic!("a v5 invite decoded as {other:?}"),
        }
    }

    /// **The cross-version substitution.** A v5 invite must not be verifiable
    /// under v4's rules, and a v4 invite must not be verifiable under v5's.
    /// `version` is inside the signed bytes, and the two encodings have
    /// different shapes, so neither can be read as the other.
    #[test]
    fn a_v5_invite_cannot_be_read_as_v4_or_the_reverse() {
        let five = signed_v5();

        // The same values, encoded as v4 would encode them.
        let as_v4 = canonical_bytes(
            &five.kind,
            INVITE_VERSION,
            &five.protocol,
            &five.relay_addr,
            five.relay_port,
            &five.token,
            &five.nonce,
            five.expires_at,
            &five.capabilities,
            &five.host_pubkey,
        );
        assert!(
            !signature_is_valid(&as_v4, &five.host_identity_pubkey, &five.signature),
            "a v5 signature verified against v4 canonical bytes — a relay invite could be replayed as a direct one"
        );
        assert_ne!(
            as_v4,
            five.canonical_bytes(),
            "the two encodings produced identical bytes"
        );
    }

    /// The session id is what decides WHICH HOST the relay splices to. Unsigned,
    /// it could be swapped for another host's session and the phone would be
    /// connected to a machine it never agreed to.
    #[test]
    fn the_session_id_is_signed() {
        let mut tampered = signed_v5();
        tampered.session = "BBBBBBBBBBBBBBBBBBBBBB".into();
        assert!(
            !verifies(&tampered),
            "the session id could be swapped without breaking the signature"
        );
    }

    #[test]
    fn the_relay_endpoint_is_signed() {
        for mutate in [
            (|i: &mut RelayInvite| i.relay_addr = "198.51.100.4".into()) as fn(&mut RelayInvite),
            |i: &mut RelayInvite| i.relay_port = 1234,
        ] {
            let mut tampered = signed_v5();
            mutate(&mut tampered);
            assert!(
                !verifies(&tampered),
                "the relay endpoint could be redirected without breaking the signature"
            );
        }
    }

    #[test]
    fn capabilities_cannot_be_widened_in_transit() {
        let mut tampered = signed_v5();
        tampered.capabilities.push("admin".into());
        assert!(!verifies(&tampered), "a grant was widened in transit");
    }

    /// **Why the separator guard exists.** Joining fields with `\n` is only
    /// injective while no field contains one. Two ADJACENT free-form fields can
    /// be re-split: these two invites differ in where the boundary falls, and
    /// encode to exactly the same bytes — so one signature covers both, and the
    /// phone would connect to a different relay than the one that was signed.
    ///
    /// No host emits an address containing a newline, so this is not a live
    /// attack. It is a property of the format, and the guard makes the safety
    /// structural instead of a claim about what callers happen to produce.
    #[test]
    fn two_different_invites_can_encode_identically_without_the_guard() {
        let caps = vec!["view".to_string()];
        let encode = |protocol: &str, relay_addr: &str| {
            relay_canonical_bytes(
                INVITE_KIND,
                RELAY_INVITE_VERSION,
                protocol,
                relay_addr,
                9443,
                "AAAAAAAAAAAAAAAAAAAAAA",
                "t",
                "n",
                1,
                &caps,
                "k",
            )
        };
        // The boundary between `protocol` and `relay_addr` moves; the bytes do
        // not.
        let signed_for = encode("rdv3", "evil.example\n198.51.100.4");
        let read_as = encode("rdv3\nevil.example", "198.51.100.4");
        assert_eq!(
            signed_for, read_as,
            "the collision this guard exists for is not reproducible — check the reasoning before trusting the guard"
        );

        // `session` and `token` are adjacent free-form fields too.
        let a = relay_canonical_bytes(
            INVITE_KIND,
            RELAY_INVITE_VERSION,
            "rdv3",
            "198.51.100.4",
            9443,
            "S",
            "T\nU",
            "n",
            1,
            &caps,
            "k",
        );
        let b = relay_canonical_bytes(
            INVITE_KIND,
            RELAY_INVITE_VERSION,
            "rdv3",
            "198.51.100.4",
            9443,
            "S\nT",
            "U",
            "n",
            1,
            &caps,
            "k",
        );
        assert_eq!(
            a, b,
            "session and token can be re-split across their boundary"
        );
    }

    /// And the guard refuses them, in both schemas, before a signature is ever
    /// checked.
    #[test]
    fn a_field_carrying_the_separator_is_refused_in_both_schemas() {
        let mut five = signed_v5();
        five.relay_addr = "203.0.113.9\n9443".into();
        assert_eq!(
            decode(&five.to_json()),
            Err(DecodeError::SeparatorInField {
                field: "relay_addr"
            }),
            "a v5 invite with an ambiguous field was decoded"
        );

        let mut four = SignedInvite {
            kind: INVITE_KIND.into(),
            version: INVITE_VERSION,
            protocol: SESSION_PROTOCOL.into(),
            addr: "192.168.1.20".into(),
            port: 8082,
            token: "1f".repeat(32),
            nonce: "9c".repeat(16),
            expires_at: 1,
            capabilities: vec!["view".into()],
            host_pubkey: "ab".repeat(32),
            host_identity_pubkey: String::new(),
            signature: String::new(),
        };
        four.addr = "192.168.1.20\n8082".into();
        assert_eq!(
            decode(&four.to_json()),
            Err(DecodeError::SeparatorInField { field: "addr" }),
            "a v4 invite with an ambiguous field was decoded"
        );
    }

    /// A capability is a free-form string too, and it is joined with `,` into a
    /// field that is then joined with `\n`.
    #[test]
    fn a_capability_carrying_the_separator_is_refused() {
        let mut five = signed_v5();
        five.capabilities = vec!["view\ncontrol".into()];
        assert_eq!(
            decode(&five.to_json()),
            Err(DecodeError::SeparatorInField {
                field: "capabilities"
            })
        );
    }

    fn signed_v6() -> DualInvite {
        let k = key();
        let caps = vec!["view".to_string(), "control".to_string()];
        let canonical = dual_canonical_bytes(
            INVITE_KIND,
            DUAL_INVITE_VERSION,
            SESSION_PROTOCOL,
            "192.168.1.20",
            8082,
            "203.0.113.9",
            9443,
            "AAAAAAAAAAAAAAAAAAAAAA",
            &"1f".repeat(32),
            &"9c".repeat(16),
            1_787_000_060,
            &caps,
            &"ab".repeat(32),
        );
        DualInvite {
            kind: INVITE_KIND.into(),
            version: DUAL_INVITE_VERSION,
            protocol: SESSION_PROTOCOL.into(),
            addr: "192.168.1.20".into(),
            port: 8082,
            relay_addr: "203.0.113.9".into(),
            relay_port: 9443,
            session: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            token: "1f".repeat(32),
            nonce: "9c".repeat(16),
            expires_at: 1_787_000_060,
            capabilities: caps,
            host_pubkey: "ab".repeat(32),
            host_identity_pubkey: STANDARD.encode(k.verifying_key().to_bytes()),
            signature: STANDARD.encode(k.sign(&canonical).to_bytes()),
        }
    }

    #[test]
    fn a_v6_invite_decodes_as_v6_and_verifies() {
        let six = signed_v6();
        match decode(&six.to_json()) {
            Ok(Decoded::V6(d)) => {
                assert_eq!(d, six);
                assert!(signature_is_valid(
                    &d.canonical_bytes(),
                    &d.host_identity_pubkey,
                    &d.signature
                ));
            }
            other => panic!("a v6 invite decoded as {other:?}"),
        }
    }

    /// **A v6 that lost a route is refused, not read as the route it kept.**
    /// Including a v5 relabelled as v6: it has no LAN route.
    #[test]
    fn a_v6_missing_either_route_is_malformed() {
        for field in ["addr", "port", "relay_addr", "relay_port", "session"] {
            let mut v: serde_json::Value = serde_json::from_str(&signed_v6().to_json()).unwrap();
            v.as_object_mut().unwrap().remove(field);
            match decode(&v.to_string()) {
                Err(DecodeError::Malformed { field: f }) => {
                    assert_eq!(f, field, "removing {field} was reported as {f}")
                }
                other => panic!("a v6 without {field} decoded as {other:?}"),
            }
        }
        let mut five = signed_v5();
        five.version = DUAL_INVITE_VERSION;
        assert!(
            matches!(decode(&five.to_json()), Err(DecodeError::Malformed { .. })),
            "a v5 relabelled as v6 was accepted"
        );
    }

    #[test]
    fn a_v6_route_field_carrying_the_separator_is_refused() {
        for (field, bad) in [
            (
                "addr",
                DualInvite {
                    addr: "192.168.1.20\n8082".into(),
                    ..signed_v6()
                },
            ),
            (
                "relay_addr",
                DualInvite {
                    relay_addr: "203.0.113.9\n9443".into(),
                    ..signed_v6()
                },
            ),
            (
                "session",
                DualInvite {
                    session: "AAAA\nBBBB".into(),
                    ..signed_v6()
                },
            ),
        ] {
            assert_eq!(
                decode(&bad.to_json()),
                Err(DecodeError::SeparatorInField { field }),
                "{field}"
            );
        }
    }

    #[test]
    fn an_unknown_version_is_still_refused_by_name() {
        // 7, not 6: v6 is the both-routes invite now, and a v5 relabelled as
        // v6 is refused as Malformed (it has no LAN route), which is tested
        // with the v6 decoder.
        let mut five = signed_v5();
        five.version = 7;
        assert_eq!(
            decode(&five.to_json()),
            Err(DecodeError::UnsupportedVersion { found: 7 })
        );
    }

    #[test]
    fn a_v5_qr_that_is_not_a_pairing_invite_is_named_as_such() {
        let mut five = signed_v5();
        five.kind = "something-else".into();
        assert!(matches!(
            decode(&five.to_json()),
            Err(DecodeError::WrongKind { .. })
        ));
    }

    /// Red-proof gap closed 2026-09-17: nothing failed when the v6 arm stopped
    /// checking `kind`. The signature would still refuse such a code later, but
    /// the operator would be told "bad signature" about a QR that was never a
    /// pairing invite at all.
    #[test]
    fn a_v6_qr_that_is_not_a_pairing_invite_is_named_as_such() {
        let six = DualInvite {
            kind: "something-else".into(),
            ..signed_v6()
        };
        assert_eq!(
            decode(&six.to_json()),
            Err(DecodeError::WrongKind {
                found: "something-else".into()
            })
        );
    }
}

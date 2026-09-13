//! The ten tamper cases the architecture plan names, plus the cases worth
//! keeping from the three crates this one replaces.
//!
//! Every tamper test follows one shape: take a validly signed invite, change
//! **one** field, and assert the signature no longer verifies. That shape is
//! the point — it proves the field is inside the canonical bytes. A field that
//! can be edited without breaking the signature is a field an attacker can
//! choose, and the QR would still scan.

use pairing::{
    invite::{canonical_bytes, LegacyInvite},
    service::{CAP_CONTROL, CAP_VIEW},
    signature_is_valid, DecodeError, Decoded, PairingService, RedeemError, SignedInvite,
    INVITE_KIND, INVITE_VERSION,
};
use std::net::SocketAddr;

fn svc() -> PairingService {
    let mut csprng = rand::rngs::OsRng;
    PairingService::new(
        ed25519_dalek::SigningKey::generate(&mut csprng),
        "bb".repeat(32),
    )
}
fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn caps() -> Vec<String> {
    vec![CAP_VIEW.to_string(), CAP_CONTROL.to_string()]
}

fn valid_invite() -> SignedInvite {
    svc()
        .create_invite(sa("192.168.1.20:8082"), 1000, &caps())
        .unwrap()
        .invite
}

fn verifies(i: &SignedInvite) -> bool {
    signature_is_valid(&i.canonical_bytes(), &i.host_identity_pubkey, &i.signature)
}

/// The control for all nine tamper tests below. If this ever fails they are all
/// vacuous — they would "pass" by rejecting an invite that was already invalid.
#[test]
fn control_an_untampered_invite_verifies() {
    assert!(verifies(&valid_invite()));
}

// ── the ten security cases ───────────────────────────────────────────────

#[test]
fn tampered_address_breaks_the_signature() {
    let mut i = valid_invite();
    i.addr = "10.66.66.66".into();
    assert!(!verifies(&i), "redirecting the endpoint must invalidate it");
}

#[test]
fn tampered_port_breaks_the_signature() {
    let mut i = valid_invite();
    i.port = 9999;
    assert!(!verifies(&i));
}

#[test]
fn tampered_expiry_breaks_the_signature() {
    let mut i = valid_invite();
    i.expires_at += 86_400;
    assert!(!verifies(&i), "the sixty seconds must not be extendable");
}

#[test]
fn tampered_capability_breaks_the_signature() {
    let mut i = svc()
        .create_invite(sa("192.168.1.20:8082"), 1000, &[CAP_VIEW.to_string()])
        .unwrap()
        .invite;
    i.capabilities.push(CAP_CONTROL.to_string());
    assert!(!verifies(&i), "view-only must not be upgradable to control");
}

#[test]
fn tampered_noise_key_breaks_the_signature() {
    let mut i = valid_invite();
    i.host_pubkey = "cc".repeat(32);
    assert!(
        !verifies(&i),
        "the pinned key is the whole point; it must be signed"
    );
}

/// Swapping the identity key alone breaks the signature. Swapping identity AND
/// signature together produces a *valid* signature by a *different* key — which
/// is exactly why signature validity is not trust, and why the client must
/// compare against a remembered identity.
#[test]
fn tampered_identity_key_breaks_the_signature_and_reveals_the_trust_boundary() {
    let mut i = valid_invite();
    let mut csprng = rand::rngs::OsRng;
    let attacker = ed25519_dalek::SigningKey::generate(&mut csprng);
    let attacker_b64 = pairing::identity_b64(&attacker);

    i.host_identity_pubkey = attacker_b64.clone();
    assert!(!verifies(&i), "identity alone swapped");

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::Signer;
    i.signature = STANDARD.encode(attacker.sign(&i.canonical_bytes()).to_bytes());
    assert!(
        verifies(&i),
        "re-signed by the attacker's key it DOES verify — this is the point"
    );
    assert_ne!(
        i.host_identity_pubkey,
        valid_invite().host_identity_pubkey,
        "and the identity differs, which is what the client must refuse on"
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let mut i = valid_invite();
    let mut bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        i.signature.as_bytes(),
    )
    .unwrap();
    bytes[0] ^= 0x01;
    i.signature = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
    assert!(!verifies(&i));
}

#[test]
fn a_qr_of_the_wrong_kind_is_named_as_such() {
    // The installer download URL is the QR a user will plausibly scan by
    // mistake. It must produce a specific refusal, not "invalid".
    let installer =
        r#"{"kind":"remotedexter-install","version":4,"url":"https://example.invalid/app.apk"}"#;
    match pairing::decode(installer) {
        Err(DecodeError::WrongKind { found }) => assert_eq!(found, "remotedexter-install"),
        other => panic!("expected WrongKind, got {other:?}"),
    }
    // And a plain non-JSON QR is distinguished from both.
    assert_eq!(
        pairing::decode("https://example.invalid/app.apk"),
        Err(DecodeError::NotJson)
    );
}

#[test]
fn a_replayed_token_is_refused() {
    let mut s = svc();
    let inv = s
        .create_invite(sa("192.168.1.20:8082"), 1000, &caps())
        .unwrap();
    assert_eq!(s.redeem(&inv.invite.token, 1010), Ok(()));
    assert_eq!(
        s.redeem(&inv.invite.token, 1010),
        Err(RedeemError::AlreadyRedeemed)
    );
}

#[test]
fn an_expired_token_is_refused_even_though_the_signature_is_still_valid() {
    let mut s = svc();
    let inv = s
        .create_invite(sa("192.168.1.20:8082"), 1000, &caps())
        .unwrap();
    // The signature never expires; the invite does. Both checks are required.
    assert!(verifies(&inv.invite));
    assert_eq!(
        s.redeem(&inv.invite.token, inv.invite.expires_at),
        Err(RedeemError::Expired)
    );
}

// ── migrated from qr_bootstrap ───────────────────────────────────────────

/// Was `encode_payload_is_deterministic` / `encode_payload_string_is_deterministic`.
#[test]
fn canonical_bytes_are_deterministic() {
    let caps = caps();
    let a = canonical_bytes(
        INVITE_KIND,
        INVITE_VERSION,
        "rdv3",
        "10.0.0.1",
        8082,
        "tok",
        "non",
        42,
        &caps,
        "pk",
    );
    let b = canonical_bytes(
        INVITE_KIND,
        INVITE_VERSION,
        "rdv3",
        "10.0.0.1",
        8082,
        "tok",
        "non",
        42,
        &caps,
        "pk",
    );
    assert_eq!(a, b);
}

/// Was `version_bump_changes_output`. A downgrade to v3 rules must not be
/// possible under a v4 signature.
#[test]
fn version_is_inside_the_signature() {
    let caps = caps();
    let v4 = canonical_bytes(
        INVITE_KIND,
        4,
        "rdv3",
        "10.0.0.1",
        8082,
        "t",
        "n",
        42,
        &caps,
        "pk",
    );
    let v3 = canonical_bytes(
        INVITE_KIND,
        3,
        "rdv3",
        "10.0.0.1",
        8082,
        "t",
        "n",
        42,
        &caps,
        "pk",
    );
    assert_ne!(v4, v3);

    let mut i = valid_invite();
    i.version = 3;
    assert!(!verifies(&i));
}

/// Was `qr_matrix_dimensions_match`.
#[test]
fn the_qr_matrix_is_square_and_sized_to_its_modules() {
    let inv = svc()
        .create_invite(sa("192.168.1.20:8082"), 1000, &caps())
        .unwrap();
    assert_eq!(inv.qr.modules.len(), inv.qr.size * inv.qr.size);
    assert!(
        inv.qr.size >= 21 + 8,
        "at least a version-1 QR plus quiet zone"
    );
}

/// Was `from_session_roundtrip`.
#[test]
fn an_invite_round_trips_through_json() {
    let original = valid_invite();
    match pairing::decode(&original.to_json()) {
        Ok(Decoded::V4(back)) => {
            assert_eq!(back, original);
            assert!(verifies(&back), "and still verifies after the round trip");
        }
        other => panic!("expected V4, got {other:?}"),
    }
}

// ── migrated from qr_handshake ───────────────────────────────────────────

/// Was `corrupted_signature_returns_error` / `test_vector_corrupted_signature`.
#[test]
fn a_corrupted_signature_field_does_not_panic_and_does_not_verify() {
    for bad in ["", "!!!not base64!!!", "AAAA", &"A".repeat(200)] {
        let mut i = valid_invite();
        i.signature = bad.to_string();
        assert!(!verifies(&i), "signature {bad:?} must not verify");
    }
}

/// Was `invalid_fields_reserved_nonzero` — malformed structure is refused by
/// field name rather than collapsing into one opaque error.
#[test]
fn a_missing_required_field_names_the_field() {
    let full = valid_invite().to_json();
    let v: serde_json::Value = serde_json::from_str(&full).unwrap();
    for field in ["token", "host_pubkey", "signature", "expires_at"] {
        let mut o = v.as_object().unwrap().clone();
        o.remove(field);
        let text = serde_json::to_string(&o).unwrap();
        match pairing::decode(&text) {
            Err(DecodeError::Malformed { field: f }) => assert_eq!(f, field),
            other => panic!("removing {field} gave {other:?}"),
        }
    }
}

/// Was `fuzz_smoke`. The decoder is the first thing an attacker reaches, before
/// any signature check. It must refuse, never panic.
#[test]
fn the_decoder_never_panics_on_hostile_input() {
    let cases: Vec<String> = vec![
        String::new(),
        "null".into(),
        "[]".into(),
        "{}".into(),
        "{\"version\":999}".into(),
        "{\"version\":4}".into(),
        "{\"kind\":\"remotedexter-pair\",\"version\":4}".into(),
        "\u{0}\u{1}\u{2}".into(),
        "{\"version\":4,\"kind\":".into(),
        format!("{{\"kind\":\"{}\"}}", "A".repeat(10_000)),
        format!(
            "{{\"version\":4,\"kind\":\"remotedexter-pair\",\"port\":{}}}",
            u64::MAX
        ),
    ];
    for c in cases {
        let _ = pairing::decode(&c); // must return, not unwind
    }
}

// ── one-version-back decoding ────────────────────────────────────────────

/// A v3 invite still decodes, and verifies against **v3's** canonical bytes —
/// not re-signed, not upgraded.
#[test]
fn a_v3_invite_decodes_and_verifies_under_v3_rules() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::Signer;
    let mut csprng = rand::rngs::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut csprng);

    let legacy = LegacyInvite {
        addr: "192.168.1.20".into(),
        port: 8082,
        token: "deadbeef".into(),
        nonce: "abc123".into(),
        protocol: "rdv3".into(),
        wan_ip: "203.0.113.7".into(),
        host_pubkey: "dd".repeat(32),
        host_identity_pubkey: pairing::identity_b64(&key),
        signature: String::new(),
    };
    let sig = STANDARD.encode(key.sign(&legacy.canonical_bytes()).to_bytes());

    let json = format!(
        r#"{{"version":3,"lan_ip":"{}","wan_ip":"{}","port":{},"session_token":"{}","nonce":"{}","protocol":"rdv3","host_pubkey":"{}","host_identity_pubkey":"{}","signature":"{}"}}"#,
        legacy.addr,
        legacy.wan_ip,
        legacy.port,
        legacy.token,
        legacy.nonce,
        legacy.host_pubkey,
        legacy.host_identity_pubkey,
        sig
    );

    match pairing::decode(&json) {
        Ok(Decoded::V3(got)) => {
            assert_eq!(got.addr, "192.168.1.20");
            assert!(signature_is_valid(
                &got.canonical_bytes(),
                &got.host_identity_pubkey,
                &sig
            ));
        }
        other => panic!("expected V3, got {other:?}"),
    }
}

/// v3 read the address from `host_ip` before March 2026. Dropping that fallback
/// silently breaks pairing against a host the user already owns — it is the
/// exact rename that produced the "Invalid QR" failure two test rounds were
/// lost to.
#[test]
fn a_v3_invite_still_accepts_the_pre_rename_host_ip_key() {
    let json = r#"{"version":3,"host_ip":"192.168.1.20","port":8082,"session_token":"t","host_pubkey":"x","host_identity_pubkey":"y","signature":"z"}"#;
    match pairing::decode(json) {
        Ok(Decoded::V3(got)) => assert_eq!(got.addr, "192.168.1.20"),
        other => panic!("expected V3, got {other:?}"),
    }
}

/// Anything outside the supported set is refused rather than guessed at, in
/// BOTH directions — older than the migration window, and newer than this build.
///
/// 2026-09-12: `5` moved out of this test because v5 is now decoded. It is the
/// RELAY route, not a successor to v4; both are current, and a host emits one or
/// the other according to how it is actually reachable. `6` takes its place as
/// the "newer than this build" case.
#[test]
fn an_unsupported_version_is_refused_by_number() {
    match pairing::decode(r#"{"version":2,"port":1}"#) {
        Err(DecodeError::UnsupportedVersion { found }) => assert_eq!(found, 2),
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
    match pairing::decode(r#"{"version":6,"port":1}"#) {
        Err(DecodeError::UnsupportedVersion { found }) => assert_eq!(found, 6),
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

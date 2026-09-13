//! P7 — no private key bytes in anything the host can emit.
//!
//! The threat model listed P7's proof as "log scan": a person reading output and
//! not seeing a key. That is not a check. It passes whenever nobody looks, it
//! cannot fail a build, and it says nothing about the paths that were not
//! exercised on the day somebody looked.
//!
//! This is the same claim as an executed assertion. It builds a service from a
//! KNOWN secret, drives every public method that produces a string, and asserts
//! those bytes appear in none of them — as raw bytes, as hex, and as base64,
//! because a leak is a leak in whatever encoding it escapes in.
//!
//! ## It never prints the secret
//!
//! Every assertion is an absence. On failure the message names the encoding and
//! the surface, never the value — a test that dumps the key to prove the key
//! leaked has itself leaked it, into CI logs that live longer than the run.
//! Key material has reached a terminal in this project before; a test written to
//! prevent that must not be the thing that does it.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use pairing::{
    service::{CAP_CONTROL, CAP_VIEW},
    PairingService,
};
use std::net::SocketAddr;

/// A fixed, obviously-fake secret. Fixed so the test is deterministic; fake so
/// this file never contains anything real.
const FAKE_SECRET: [u8; 32] = [
    0xA5, 0x5A, 0xC3, 0x3C, 0x0F, 0xF0, 0x11, 0xEE, 0x22, 0xDD, 0x33, 0xCC, 0x44, 0xBB, 0x55, 0xAA,
    0x66, 0x99, 0x77, 0x88, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x0D, 0xEF, 0xAC, 0xED,
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Assert the secret is absent, in every encoding it could escape in.
///
/// Named `surface` rather than dumping the haystack: the haystack is exactly
/// what must not reach a log.
fn assert_no_secret(surface: &str, haystack: &str) {
    let lower = haystack.to_lowercase();
    assert!(
        !lower.contains(&hex(&FAKE_SECRET)),
        "{surface} leaked the private key as HEX"
    );
    assert!(
        !lower.contains(&hex(&FAKE_SECRET).to_uppercase().to_lowercase()),
        "{surface} leaked the private key as upper-case hex"
    );
    assert!(
        !haystack.contains(&STANDARD.encode(FAKE_SECRET)),
        "{surface} leaked the private key as BASE64"
    );
    // Raw bytes, in case something wrote them straight through.
    let raw = String::from_utf8_lossy(&FAKE_SECRET).to_string();
    if raw.chars().any(|c| !c.is_control()) {
        assert!(
            !haystack.contains(&raw),
            "{surface} leaked the private key as RAW BYTES"
        );
    }
}

fn service() -> PairingService {
    let signing = SigningKey::from_bytes(&FAKE_SECRET);
    // The host pubkey the service advertises is public by definition.
    let pubkey_hex = hex(signing.verifying_key().as_bytes());
    PairingService::new(signing, pubkey_hex)
}

#[test]
fn nothing_the_pairing_service_emits_contains_the_private_key() {
    let mut svc = service();
    let bind: SocketAddr = "192.168.1.50:8082".parse().unwrap();
    let caps = vec![CAP_VIEW.to_string(), CAP_CONTROL.to_string()];

    // The identity it advertises. This one is SUPPOSED to be public, which is
    // exactly why it is checked: the public key is derived from the private one,
    // and a mistake here emits the wrong half.
    assert_no_secret("identity_b64()", &svc.identity_b64());

    // The invite — the single largest thing this crate emits, and the one that
    // goes on a screen as a QR code for anyone to photograph.
    let Ok(invitation) = svc.create_invite(bind, 1_800_000_000, &caps) else {
        panic!("a valid invite could not be minted");
    };
    // `Invitation` does not derive Debug and neither does PairingService --
    // both deliberate, and both worth keeping: a type holding a credential
    // should not be one careless `{:?}` from a log line. So the fields are
    // rendered individually rather than the struct as a whole.
    assert_no_secret(
        "the signed invite",
        &serde_json::to_string(&invitation.invite).expect("invite serialises"),
    );
    assert_no_secret("the token fingerprint", &invitation.token_fingerprint);

    // Every error path. Errors are the surfaces most likely to be formatted
    // carelessly, because they are written when something has already gone
    // wrong and attention is elsewhere.
    for (label, addr) in [
        ("wildcard address", "0.0.0.0:8082"),
        ("port 0", "192.168.1.50:0"),
    ] {
        let addr: SocketAddr = addr.parse().unwrap();
        match svc.create_invite(addr, 1_800_000_000, &caps) {
            Err(e) => assert_no_secret(&format!("MintError Debug ({label})"), &format!("{e:?}")),
            Ok(_) => panic!("{label} should not have produced an invite"),
        }
    }

    if let Err(e) = svc.redeem("not-a-real-token", 1_800_000_000) {
        assert_no_secret("RedeemError Debug", &format!("{e:?}"));
    }
}

/// The public key must actually be present somewhere — otherwise a service that
/// emitted the empty string would pass every assertion above.
///
/// An absence test that cannot distinguish "nothing leaked" from "nothing
/// happened" is not a test.
#[test]
fn the_absence_check_is_looking_at_something() {
    let svc = service();
    let signing = SigningKey::from_bytes(&FAKE_SECRET);
    let public_b64 = STANDARD.encode(signing.verifying_key().to_bytes());
    assert_eq!(
        svc.identity_b64(),
        public_b64,
        "identity_b64 does not advertise the public key, so the P7 assertions \
         above were reading an empty or unrelated surface"
    );
}

/// Proof the detector works: it must find the secret when the secret is really
/// there. Without this, every assertion above could be a no-op.
#[test]
#[should_panic(expected = "leaked the private key as HEX")]
fn the_detector_catches_a_real_leak() {
    assert_no_secret("a deliberately leaking surface", &hex(&FAKE_SECRET));
}

#[test]
#[should_panic(expected = "leaked the private key as BASE64")]
fn the_detector_catches_a_base64_leak() {
    assert_no_secret(
        "a deliberately leaking surface",
        &STANDARD.encode(FAKE_SECRET),
    );
}

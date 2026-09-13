//! Cross-language canonical-byte vectors for the v5 (relay) invite.
//!
//! The same discipline as `vectors.rs`, for the other route: the Rust host
//! signs, the Kotlin client verifies, and a one-character divergence makes
//! every signature fail silently on a phone with both sides' own tests green.
//!
//! `contract/signed_invite_v5.json` is the shared fixture. This file asserts
//! Rust produces the Rust half and VERIFIES the Kotlin half;
//! `InviteV5Test.kt` does the mirror image. Neither side imports the other.

use pairing::invite::relay_canonical_bytes;
use pairing::{signature_is_valid, INVITE_KIND, RELAY_INVITE_VERSION};

const FIXTURE: &str = include_str!("../../../contract/signed_invite_v5.json");

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("contract/signed_invite_v5.json is valid JSON")
}

fn caps_of(v: &serde_json::Value) -> Vec<String> {
    v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect()
}

fn encode(v: &serde_json::Value) -> Vec<u8> {
    relay_canonical_bytes(
        v["kind"].as_str().unwrap(),
        v["version"].as_u64().unwrap() as u8,
        v["protocol"].as_str().unwrap(),
        v["relay_addr"].as_str().unwrap(),
        v["relay_port"].as_u64().unwrap() as u16,
        v["session"].as_str().unwrap(),
        v["token"].as_str().unwrap(),
        v["nonce"].as_str().unwrap(),
        v["expires_at"].as_u64().unwrap(),
        &caps_of(v),
        v["host_pubkey"].as_str().unwrap(),
    )
}

#[test]
fn rust_reproduces_the_shared_canonical_bytes() {
    let f = fixture();
    let v = &f["rust_generated"];
    let produced = encode(v);
    assert_eq!(
        String::from_utf8(produced.clone()).unwrap(),
        v["canonical_utf8"].as_str().unwrap(),
        "v5 canonical bytes drifted from the checked-in vector"
    );
    assert!(
        signature_is_valid(
            &produced,
            v["host_identity_pubkey"].as_str().unwrap(),
            v["signature"].as_str().unwrap()
        ),
        "the recorded signature must verify over the recorded bytes"
    );
}

/// The direction that catches "Rust is self-consistently wrong".
#[test]
fn rust_verifies_the_kotlin_generated_vector() {
    let f = fixture();
    let v = &f["kotlin_generated"];
    let produced = encode(v);
    assert_eq!(
        String::from_utf8(produced.clone()).unwrap(),
        v["canonical_utf8"].as_str().unwrap(),
        "Rust and Kotlin disagree on the v5 canonical encoding"
    );
    assert!(
        signature_is_valid(
            &produced,
            v["host_identity_pubkey"].as_str().unwrap(),
            v["signature"].as_str().unwrap()
        ),
        "the signature Kotlin produced must verify here"
    );
}

/// Every negative control must fail here too, for the same reason it fails on
/// the phone: the signature covers the field that was changed.
#[test]
fn rust_rejects_every_negative_control() {
    let f = fixture();
    let negatives = f["negative"].as_array().expect("negative controls");
    assert!(
        !negatives.is_empty(),
        "the fixture carries no negative controls"
    );
    for c in negatives {
        let name = c["name"].as_str().unwrap();
        assert!(
            !signature_is_valid(
                &encode(c),
                c["host_identity_pubkey"].as_str().unwrap(),
                c["signature"].as_str().unwrap()
            ),
            "negative control {name} VERIFIED — it must not"
        );
    }
}

/// The fixture describes the schema it claims to.
#[test]
fn the_fixture_is_the_v5_schema() {
    let f = fixture();
    assert_eq!(
        f["schema_version"].as_u64().unwrap() as u8,
        RELAY_INVITE_VERSION
    );
    assert_eq!(f["kind"].as_str().unwrap(), INVITE_KIND);
    for half in ["rust_generated", "kotlin_generated"] {
        assert_eq!(
            f[half]["version"].as_u64().unwrap() as u8,
            RELAY_INVITE_VERSION,
            "{half} is not a v5 vector"
        );
    }
}

/// **The two routes must not be confusable.** The v4 and v5 fixtures describe
/// different schemas, and a vector from one must not encode to the other's
/// bytes. This is the cross-language half of the same property the unit tests
/// prove in Rust alone.
#[test]
fn the_v4_and_v5_vectors_do_not_encode_to_the_same_bytes() {
    let five = fixture();
    let four: serde_json::Value =
        serde_json::from_str(include_str!("../../../contract/signed_invite_v4.json")).unwrap();
    assert_ne!(
        five["rust_generated"]["canonical_utf8"].as_str().unwrap(),
        four["rust_generated"]["canonical_utf8"].as_str().unwrap()
    );
    // And neither signature verifies over the other's bytes.
    assert!(!signature_is_valid(
        five["rust_generated"]["canonical_utf8"]
            .as_str()
            .unwrap()
            .as_bytes(),
        four["rust_generated"]["host_identity_pubkey"]
            .as_str()
            .unwrap(),
        four["rust_generated"]["signature"].as_str().unwrap()
    ));
}

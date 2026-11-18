//! Cross-language canonical-byte vectors for the v6 (both-routes) invite.
//!
//! The same discipline as `vectors.rs` and `relay_vectors.rs`: the Rust host
//! signs, the Kotlin client verifies, and a one-character divergence makes every
//! signature fail silently on a phone with both sides' own tests green.
//!
//! `contract/signed_invite_v6.json` is the shared fixture. This file asserts
//! Rust produces the Rust half and VERIFIES the Kotlin half; `InviteV6Test.kt`
//! does the mirror image. Neither side imports the other.

use pairing::invite::dual_canonical_bytes;
use pairing::{signature_is_valid, DUAL_INVITE_VERSION, INVITE_KIND};

const FIXTURE: &str = include_str!("../../../contract/signed_invite_v6.json");

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("contract/signed_invite_v6.json is valid JSON")
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
    dual_canonical_bytes(
        v["kind"].as_str().unwrap(),
        v["version"].as_u64().unwrap() as u8,
        v["protocol"].as_str().unwrap(),
        v["addr"].as_str().unwrap(),
        v["port"].as_u64().unwrap() as u16,
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

fn verifies(v: &serde_json::Value, bytes: &[u8]) -> bool {
    signature_is_valid(
        bytes,
        v["host_identity_pubkey"].as_str().unwrap(),
        v["signature"].as_str().unwrap(),
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
        "v6 canonical bytes drifted from the checked-in vector"
    );
    assert!(
        verifies(v, &produced),
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
        "Rust and Kotlin disagree on the v6 canonical encoding"
    );
    assert!(
        verifies(v, &produced),
        "the signature Kotlin produced must verify here"
    );
}

/// Every negative control must fail here too — including `swapped_routes`,
/// the one only v6 has: the same five values with the two routes exchanged.
#[test]
fn rust_rejects_every_negative_control() {
    let f = fixture();
    let negatives = f["negative"].as_array().expect("negative controls");
    let names: Vec<&str> = negatives
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"swapped_routes"),
        "the fixture lost the control that only v6 needs: {names:?}"
    );
    for c in negatives {
        let name = c["name"].as_str().unwrap();
        assert!(
            !verifies(c, &encode(c)),
            "negative control {name} VERIFIED — it must not"
        );
    }
}

/// The fixture describes the schema it claims to.
#[test]
fn the_fixture_is_the_v6_schema() {
    let f = fixture();
    assert_eq!(
        f["schema_version"].as_u64().unwrap() as u8,
        DUAL_INVITE_VERSION
    );
    assert_eq!(f["kind"].as_str().unwrap(), INVITE_KIND);
    for half in ["rust_generated", "kotlin_generated"] {
        assert_eq!(
            f[half]["version"].as_u64().unwrap() as u8,
            DUAL_INVITE_VERSION,
            "{half} is not a v6 vector"
        );
    }
}

/// **A v6 signature must not verify as a v4 or a v5.** Otherwise one route
/// could be lifted out of a v6 code and presented as a code naming that route
/// alone. The v6 vector is built from the SAME inputs as the v4 and v5 vectors,
/// so this compares like with like.
#[test]
fn a_v6_signature_does_not_cover_the_v4_or_v5_encoding() {
    let six = fixture();
    let r = &six["rust_generated"];
    let token = r["token"].as_str().unwrap();
    let nonce = r["nonce"].as_str().unwrap();
    let caps = caps_of(r);
    let pin = r["host_pubkey"].as_str().unwrap();
    let expires = r["expires_at"].as_u64().unwrap();

    let as_v4 = pairing::invite::canonical_bytes(
        INVITE_KIND,
        DUAL_INVITE_VERSION,
        "rdv3",
        r["addr"].as_str().unwrap(),
        r["port"].as_u64().unwrap() as u16,
        token,
        nonce,
        expires,
        &caps,
        pin,
    );
    let as_v5 = pairing::invite::relay_canonical_bytes(
        INVITE_KIND,
        DUAL_INVITE_VERSION,
        "rdv3",
        r["relay_addr"].as_str().unwrap(),
        r["relay_port"].as_u64().unwrap() as u16,
        r["session"].as_str().unwrap(),
        token,
        nonce,
        expires,
        &caps,
        pin,
    );
    assert!(
        !verifies(r, &as_v4),
        "a v6 signature verified as a v4 encoding"
    );
    assert!(
        !verifies(r, &as_v5),
        "a v6 signature verified as a v5 encoding"
    );

    for other in [
        include_str!("../../../contract/signed_invite_v4.json"),
        include_str!("../../../contract/signed_invite_v5.json"),
    ] {
        let o: serde_json::Value = serde_json::from_str(other).unwrap();
        assert_ne!(
            r["canonical_utf8"].as_str().unwrap(),
            o["rust_generated"]["canonical_utf8"].as_str().unwrap()
        );
    }
}

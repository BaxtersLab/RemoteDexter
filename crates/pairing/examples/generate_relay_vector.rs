//! Regenerates the Rust half of `contract/signed_invite_v5.json`.
//!
//! `cargo run -p pairing --example generate_relay_vector`. Deterministic: the
//! signing key, token, nonce, session and timestamp are fixed, so a re-run
//! either reproduces the checked-in file exactly or shows a real change. A
//! vector generated from random input could not be checked in at all.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use pairing::invite::relay_canonical_bytes;
use pairing::{INVITE_KIND, RELAY_INVITE_VERSION, SESSION_PROTOCOL};

fn main() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let caps = vec!["view".to_string(), "control".to_string()];
    let (relay_addr, relay_port) = ("203.0.113.9", 9443u16);
    let session = "Zm9vYmFyYmF6cXV4MDAwMA";
    let token = "1f".repeat(32);
    let nonce = "9c".repeat(16);
    let expires_at = 1_787_000_060u64;
    let host_pubkey = "ab".repeat(32);

    let canonical = relay_canonical_bytes(
        INVITE_KIND,
        RELAY_INVITE_VERSION,
        SESSION_PROTOCOL,
        relay_addr,
        relay_port,
        session,
        &token,
        &nonce,
        expires_at,
        &caps,
        &host_pubkey,
    );
    println!(
        "{}",
        serde_json::json!({
            "canonical_utf8": String::from_utf8(canonical.clone()).unwrap(),
            "host_identity_pubkey": STANDARD.encode(key.verifying_key().to_bytes()),
            "signature": STANDARD.encode(key.sign(&canonical).to_bytes()),
        })
    );
}

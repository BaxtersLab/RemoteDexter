//! Regenerates the Rust half of `contract/signed_invite_v4.json`.
//!
//! `cargo run -p pairing --example generate_vector`. Deterministic: the signing
//! key, token, nonce and timestamp are fixed, so a re-run either reproduces the
//! checked-in file exactly or shows a real change. A vector generated from
//! random input could not be checked in at all.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use pairing::invite::canonical_bytes;
use pairing::{INVITE_KIND, INVITE_VERSION, SESSION_PROTOCOL};

fn main() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let caps = vec!["view".to_string(), "control".to_string()];
    let (addr, port) = ("192.168.1.20", 8082u16);
    let token = "1f".repeat(32);
    let nonce = "9c".repeat(16);
    let expires_at = 1_787_000_060u64;
    let host_pubkey = "ab".repeat(32);

    let canonical = canonical_bytes(
        INVITE_KIND,
        INVITE_VERSION,
        SESSION_PROTOCOL,
        addr,
        port,
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

//! Regenerates the Rust half of `contract/signed_invite_v6.json`.
//!
//! `cargo run -p pairing --example generate_dual_vector`. Deterministic, like
//! the v4 and v5 generators, and built from the same fixed inputs: the v4
//! vector's LAN route and the v5 vector's relay route, under the same key. So
//! a v6 vector is recognisably "both of those, signed as one", and a re-run
//! either reproduces the checked-in file exactly or shows a real change.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use pairing::invite::dual_canonical_bytes;
use pairing::{DUAL_INVITE_VERSION, INVITE_KIND, SESSION_PROTOCOL};

fn main() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let caps = vec!["view".to_string(), "control".to_string()];
    let (addr, port) = ("192.168.1.20", 8082u16);
    let (relay_addr, relay_port) = ("203.0.113.9", 9443u16);
    let session = "Zm9vYmFyYmF6cXV4MDAwMA";
    let token = "1f".repeat(32);
    let nonce = "9c".repeat(16);
    let expires_at = 1_787_000_060u64;
    let host_pubkey = "ab".repeat(32);

    let canonical = dual_canonical_bytes(
        INVITE_KIND,
        DUAL_INVITE_VERSION,
        SESSION_PROTOCOL,
        addr,
        port,
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

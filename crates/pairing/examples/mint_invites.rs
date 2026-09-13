//! Exercise the real invite-minting path for the VM packet-capture proof.
//!
//! The generated invites stay in memory and are immediately revoked. Output is
//! deliberately limited to a count; credentials never reach stdout or logs.

use ed25519_dalek::SigningKey;
use pairing::{PairingService, CAP_VIEW};
use rand::rngs::OsRng;

fn main() {
    let signing = SigningKey::generate(&mut OsRng);
    let mut service = PairingService::new(signing, "aa".repeat(32));
    let capabilities = [CAP_VIEW.to_string()];
    let bind = "127.0.0.1:8082".parse().expect("fixed proof address");

    for now in 1_000..1_005 {
        let invitation = service
            .create_invite(bind, now, &capabilities)
            .expect("mint invite through the real pairing service");
        assert!(invitation.qr.size > 20, "invite must contain a real QR");
        service.revoke();
    }

    println!("minted 5 invites");
}

use scp_consumer::{build_metadata_v1, Ed25519MetadataVerifier, parse_and_verify, NoopTrust};
use connection_package_generator::ConnectionPackage;
use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signer};

fn main() {
    // Deterministic keypair from a fixed secret (avoids RNG/version mismatches in deps).
    let secret_bytes = [42u8; 32];
    let secret = SecretKey::from_bytes(&secret_bytes).expect("secret key bytes");
    let public = PublicKey::from(&secret);
    let keypair = Keypair { secret, public };

    // Example claims that we want to sign and transport in metadata.
    let claims: &[u8] = b"example:scp:claims";

    // Build a ConnectionPackage with the metadata set to the claims initially.
    let mut pkg = ConnectionPackage {
        topic_id: [0u8; 32],
        pc_x25519_pk: [1u8; 32],
        android_x25519_pk: [2u8; 32],
        nat_hint: 0,
        port_hints: vec![443u16],
        metadata: claims.to_vec(),
    };

    // Canonical bytes to sign: serialize the package where metadata == claims only.
    let mut tmp = pkg.clone();
    tmp.metadata = claims.to_vec();
    let signed_bytes = connection_package_generator::serialize::serialize_without_signature(&tmp);

    // Sign the canonical bytes with ed25519 keypair.
    let signature = keypair.sign(&signed_bytes);
    let sig_bytes = signature.to_bytes();
    let pk_bytes = keypair.public.to_bytes();

    // Build metadata v1 (version + claims + pubkey + sig) and attach to the package.
    let meta_v1 = build_metadata_v1(claims, &pk_bytes, &sig_bytes);
    pkg.metadata = meta_v1;

    // Serialize the full package to bytes (the same serializer is used for wire format).
    let raw = connection_package_generator::serialize::serialize_without_signature(&pkg);

    // Parse and verify using the Ed25519MetadataVerifier and a NoopTrust chain.
    let verifier = Ed25519MetadataVerifier;
    let trust = NoopTrust;
    match parse_and_verify(&raw, &verifier, &trust) {
        Ok(msg) => {
            #[cfg(feature = "debug-logs")]
            println!("Signature verified; parsed message: {:?}", msg);
        }
        Err(e) => {
            #[cfg(feature = "debug-logs")]
            eprintln!("verify failed: {:?}", e);
            std::process::exit(1);
        }
    }
}

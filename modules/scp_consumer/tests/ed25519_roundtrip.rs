#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use scp_consumer::{parse_and_verify, Ed25519MetadataVerifier, NoopTrust};
    use connection_package_generator::types::ConnectionPackage;
    use connection_package_generator::serialize::serialize_without_signature;

    #[test]
    fn ed25519_metadata_roundtrip() {
        // deterministic keypair from fixed secret (avoid RNG version mismatches in deps)
        let secret_bytes = [42u8; 32];
        let keypair = SigningKey::from_bytes(&secret_bytes);

        // base claims
        let claims = b"claims-v1".to_vec();

        // build package with claims only
        let mut pkg = ConnectionPackage {
            topic_id: [1u8; 32],
            pc_x25519_pk: [2u8; 32],
            android_x25519_pk: [3u8; 32],
            nat_hint: 0,
            port_hints: vec![9000u16],
            metadata: claims.clone(),
        };

        // compute signed bytes (metadata = claims)
        let signed = serialize_without_signature(&pkg);

        // sign
        let sig = keypair.sign(&signed);

        // build versioned metadata: [version][claims][pk][sig]
        let full_meta = scp_consumer::build_metadata_v1(&claims, &keypair.verifying_key().to_bytes(), &sig.to_bytes());
        pkg.metadata = full_meta.clone();

        // serialize full package (includes metadata with pk+sig appended)
        let full_serial = serialize_without_signature(&pkg);

        // run parse_and_verify with Ed25519MetadataVerifier and noop trust chain
        let res = parse_and_verify(&full_serial, &Ed25519MetadataVerifier, &NoopTrust);
        assert!(res.is_ok());
    }
}

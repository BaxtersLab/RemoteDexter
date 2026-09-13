#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use scp_consumer::{parse_and_verify, Ed25519MetadataVerifier, NoopTrust};
    use connection_package_generator::types::ConnectionPackage;
    use connection_package_generator::serialize::serialize_without_signature;

    fn make_keypair() -> SigningKey {
        let secret_bytes = [42u8; 32];
        SigningKey::from_bytes(&secret_bytes)
    }

    #[test]
    fn malformed_signature_is_rejected() {
        let keypair = make_keypair();
        let claims = b"claims".to_vec();

        let mut pkg = ConnectionPackage {
            topic_id: [9u8; 32],
            pc_x25519_pk: [8u8; 32],
            android_x25519_pk: [7u8; 32],
            nat_hint: 0,
            port_hints: vec![100u16],
            metadata: claims.clone(),
        };

        let signed = serialize_without_signature(&pkg);
        let sig = keypair.sign(&signed);
        let mut bad_sig = sig.to_bytes();
        // flip a bit in signature
        bad_sig[10] ^= 0xFF;

        // use versioned metadata builder but with a bad signature
        let mut bad_sig_arr = [0u8; 64];
        bad_sig_arr.copy_from_slice(&bad_sig);
        let meta = scp_consumer::build_metadata_v1(&claims, &keypair.verifying_key().to_bytes(), &bad_sig_arr);
        pkg.metadata = meta;

        let full = serialize_without_signature(&pkg);
        let res = parse_and_verify(&full, &Ed25519MetadataVerifier, &NoopTrust);
        assert!(res.is_err());
    }

    #[test]
    fn bad_public_key_is_rejected() {
        let keypair = make_keypair();
        let claims = b"claims".to_vec();

        let mut pkg = ConnectionPackage {
            topic_id: [1u8; 32],
            pc_x25519_pk: [2u8; 32],
            android_x25519_pk: [3u8; 32],
            nat_hint: 0,
            port_hints: vec![],
            metadata: claims.clone(),
        };

        let signed = serialize_without_signature(&pkg);
        let sig = keypair.sign(&signed);

        // create bad public key (flip a byte)
        let mut bad_pk = keypair.verifying_key().to_bytes();
        bad_pk[0] ^= 0xFF;

        let mut bad_pk_arr = [0u8; 32];
        bad_pk_arr.copy_from_slice(&bad_pk);
        let meta = scp_consumer::build_metadata_v1(&claims, &bad_pk_arr, &sig.to_bytes());
        pkg.metadata = meta;

        let full = serialize_without_signature(&pkg);
        let res = parse_and_verify(&full, &Ed25519MetadataVerifier, &NoopTrust);
        assert!(res.is_err());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let keypair = make_keypair();
        let claims = b"claims-tamper".to_vec();

        let mut pkg = ConnectionPackage {
            topic_id: [5u8; 32],
            pc_x25519_pk: [6u8; 32],
            android_x25519_pk: [7u8; 32],
            nat_hint: 0,
            port_hints: vec![8080u16],
            metadata: claims.clone(),
        };

        let signed = serialize_without_signature(&pkg);
        let sig = keypair.sign(&signed);

        // append correct pk+sig
        let meta = scp_consumer::build_metadata_v1(&claims, &keypair.verifying_key().to_bytes(), &sig.to_bytes());
        pkg.metadata = meta;

        // serialize and then tamper with the serialized bytes (change one topic byte)
        let mut full = serialize_without_signature(&pkg);
        // flip a byte in topic_id
        full[0] ^= 0x01;

        let res = parse_and_verify(&full, &Ed25519MetadataVerifier, &NoopTrust);
        assert!(res.is_err());
    }
}

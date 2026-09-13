#[cfg(test)]
mod tests {
    use scp_consumer::{parse_and_verify, ScpError};
    use connection_package_generator::serialize::serialize_without_signature;
    use connection_package_generator::types::ConnectionPackage;

    struct FailVerifier;
    impl scp_consumer::Verifier for FailVerifier {
        fn verify(&self, _msg: &scp_consumer::ScpMessage) -> Result<(), scp_consumer::ScpError> {
            Err(ScpError::InvalidPackage)
        }
    }

    struct PassTrust;
    impl scp_consumer::TrustChain for PassTrust {
        fn check_trust_chain(&self, _msg: &scp_consumer::ScpMessage) -> Result<(), scp_consumer::ScpError> {
            Ok(())
        }
    }

    #[test]
    fn parse_and_verify_fails_when_verifier_fails() {
        let pkg = ConnectionPackage {
            topic_id: [3u8; 32],
            pc_x25519_pk: [4u8; 32],
            android_x25519_pk: [5u8; 32],
            nat_hint: 2,
            port_hints: vec![1000u16],
            metadata: b"meta".to_vec(),
        };
        let s = serialize_without_signature(&pkg);
        let res = parse_and_verify(&s, &FailVerifier, &PassTrust);
        assert_eq!(res, Err(ScpError::InvalidPackage));
    }
}

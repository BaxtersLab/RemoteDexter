#[cfg(test)]
mod tests {
    use scp_consumer::parse_scp;
    use connection_package_generator::serialize::serialize_without_signature;
    use connection_package_generator::types::ConnectionPackage;

    #[test]
    fn roundtrip_parse() {
        let pkg = ConnectionPackage {
            topic_id: [3u8; 32],
            pc_x25519_pk: [4u8; 32],
            android_x25519_pk: [5u8; 32],
            nat_hint: 2,
            port_hints: vec![1000u16],
            metadata: b"scp-test".to_vec(),
        };

        let s = serialize_without_signature(&pkg);
        let parsed = parse_scp(&s).expect("should parse");
        assert_eq!(parsed.pkg, pkg);
    }
}

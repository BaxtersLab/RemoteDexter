#[cfg(test)]
mod tests {
    use connection_package_generator::types::ConnectionPackage;
    use connection_package_generator::serialize::serialize_without_signature;
    use connection_package_generator::deserialize::parse_connection_package;
    use connection_package_generator::ConnectionError;

    #[test]
    fn roundtrip_serialize_parse() {
        let pkg = ConnectionPackage {
            topic_id: [3u8; 32],
            pc_x25519_pk: [4u8; 32],
            android_x25519_pk: [5u8; 32],
            nat_hint: 2,
            port_hints: vec![1000u16, 2000u16],
            metadata: b"roundtrip-metadata".to_vec(),
        };

        let serialized = serialize_without_signature(&pkg);
        let parsed = parse_connection_package(&serialized).expect("should parse");
        assert_eq!(pkg, parsed);
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let pkg = ConnectionPackage {
            topic_id: [1u8; 32],
            pc_x25519_pk: [2u8; 32],
            android_x25519_pk: [3u8; 32],
            nat_hint: 0,
            port_hints: vec![8080u16],
            metadata: b"x".to_vec(),
        };

        let mut s = serialize_without_signature(&pkg);
        // append trailing byte
        s.push(0xFF);
        let res = parse_connection_package(&s);
        assert_eq!(res, Err(ConnectionError::InvalidInput));
    }

    #[test]
    fn parse_rejects_zero_port() {
        let pkg = ConnectionPackage {
            topic_id: [7u8; 32],
            pc_x25519_pk: [8u8; 32],
            android_x25519_pk: [9u8; 32],
            nat_hint: 1,
            port_hints: vec![0u16],
            metadata: vec![],
        };

        let s = serialize_without_signature(&pkg);
        let res = parse_connection_package(&s);
        assert_eq!(res, Err(ConnectionError::InvalidInput));
    }

    #[test]
    fn parse_rejects_port_count_too_large() {
        let pkg = ConnectionPackage {
            topic_id: [11u8; 32],
            pc_x25519_pk: [12u8; 32],
            android_x25519_pk: [13u8; 32],
            nat_hint: 0,
            port_hints: vec![],
            metadata: vec![],
        };

        let mut s = serialize_without_signature(&pkg);
        // force port count to 17 (>16)
        let count_pos = 32 + 32 + 32 + 1; // index of count
        s[count_pos] = 17u8;
        let res = parse_connection_package(&s);
        assert_eq!(res, Err(ConnectionError::InvalidInput));
    }

    #[test]
    fn parse_rejects_oversized_metadata() {
        let pkg = ConnectionPackage {
            topic_id: [21u8; 32],
            pc_x25519_pk: [22u8; 32],
            android_x25519_pk: [23u8; 32],
            nat_hint: 1,
            port_hints: vec![80u16],
            metadata: vec![0u8; 10],
        };

        let mut s = serialize_without_signature(&pkg);
        // compute metadata length position
        let meta_len_pos = 32 + 32 + 32 + 1 + 1 + (2 * pkg.port_hints.len());
        // set to 5000 (0x1388) which exceeds 4096
        let large_len: u16 = 5000;
        let bytes = large_len.to_be_bytes();
        s[meta_len_pos] = bytes[0];
        s[meta_len_pos + 1] = bytes[1];

        let res = parse_connection_package(&s);
        assert_eq!(res, Err(ConnectionError::InvalidInput));
    }
}

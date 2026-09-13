#[cfg(test)]
mod tests {
    use scp_consumer::{parse_scp, ScpError};
    use connection_package_generator::serialize::serialize_without_signature;
    use connection_package_generator::types::ConnectionPackage;

    #[test]
    fn parse_empty_fails() {
        let res = parse_scp(&[]);
        assert_eq!(res, Err(ScpError::InvalidPackage));
    }

    #[test]
    fn parse_truncated_fails() {
        // Build a minimal valid package then truncate
        let pkg = ConnectionPackage {
            topic_id: [0u8; 32],
            pc_x25519_pk: [1u8; 32],
            android_x25519_pk: [2u8; 32],
            nat_hint: 0,
            port_hints: vec![8080u16],
            metadata: b"abc".to_vec(),
        };
        let mut s = serialize_without_signature(&pkg);
        s.truncate(50);
        let res = parse_scp(&s);
        assert_eq!(res, Err(ScpError::InvalidPackage));
    }

    #[test]
    fn parse_port_count_too_large_maps_to_invalid_package() {
        let pkg = ConnectionPackage {
            topic_id: [7u8; 32],
            pc_x25519_pk: [8u8; 32],
            android_x25519_pk: [9u8; 32],
            nat_hint: 1,
            port_hints: vec![],
            metadata: vec![],
        };
        let mut s = serialize_without_signature(&pkg);
        // set port count byte to 17 (>16)
        let count_pos = 32 + 32 + 32 + 1;
        s[count_pos] = 17u8;
        let res = parse_scp(&s);
        assert_eq!(res, Err(ScpError::InvalidPackage));
    }

    #[test]
    fn parse_zero_port_maps_to_invalid_package() {
        let pkg = ConnectionPackage {
            topic_id: [21u8; 32],
            pc_x25519_pk: [22u8; 32],
            android_x25519_pk: [23u8; 32],
            nat_hint: 1,
            port_hints: vec![0u16],
            metadata: vec![],
        };
        let s = serialize_without_signature(&pkg);
        let res = parse_scp(&s);
        assert_eq!(res, Err(ScpError::InvalidPackage));
    }

    #[test]
    fn parse_oversized_declared_metadata_maps_to_invalid_package() {
        let pkg = ConnectionPackage {
            topic_id: [3u8; 32],
            pc_x25519_pk: [4u8; 32],
            android_x25519_pk: [5u8; 32],
            nat_hint: 0,
            port_hints: vec![],
            metadata: vec![],
        };
        let mut s = serialize_without_signature(&pkg);
        // set declared metadata length to 5000 (> MAX_METADATA_LEN)
        let meta_len_pos = 32 + 32 + 32 + 1 + 1 + (2 * pkg.port_hints.len());
        let bytes = (5000u16).to_be_bytes();
        s[meta_len_pos] = bytes[0];
        s[meta_len_pos + 1] = bytes[1];
        let res = parse_scp(&s);
        assert_eq!(res, Err(ScpError::InvalidPackage));
    }
}

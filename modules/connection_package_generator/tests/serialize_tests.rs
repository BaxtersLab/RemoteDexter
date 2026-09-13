#[cfg(test)]
mod tests {
    use connection_package_generator::types::ConnectionPackage;
    use connection_package_generator::serialize::serialize_without_signature;

    #[test]
    fn serialize_deterministic() {
        let pkg = ConnectionPackage {
            topic_id: [3u8; 32],
            pc_x25519_pk: [4u8; 32],
            android_x25519_pk: [5u8; 32],
            nat_hint: 2,
            port_hints: vec![1000u16, 2000u16],
            metadata: vec![0xAA, 0xBB, 0xCC],
        };

        let a = serialize_without_signature(&pkg);
        let b = serialize_without_signature(&pkg);
        assert_eq!(a, b);
        // Check metadata length encoded correctly at the end before metadata
        let meta_len_pos = 32 + 32 + 32 + 1 + 1 + (2 * pkg.port_hints.len());
        let encoded_len = u16::from_be_bytes([a[meta_len_pos], a[meta_len_pos + 1]]);
        assert_eq!(encoded_len as usize, pkg.metadata.len());
    }

    #[test]
    fn serialize_no_trailing_bytes() {
        let pkg = ConnectionPackage {
            topic_id: [0u8; 32],
            pc_x25519_pk: [0u8; 32],
            android_x25519_pk: [0u8; 32],
            nat_hint: 0,
            port_hints: vec![],
            metadata: vec![],
        };
        let s = serialize_without_signature(&pkg);
        // expected length: 32+32+32 +1 +1 + 0 + 2 + 0 = 100
        assert_eq!(s.len(), 32 + 32 + 32 + 1 + 1 + 0 + 2 + 0);
    }
}

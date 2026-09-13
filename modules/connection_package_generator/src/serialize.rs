use crate::types::ConnectionPackage;

// Canonical binary framing for ConnectionPackage
// Layout (in order):
// topic_id (32)
// pc_x25519_pk (32)
// android_x25519_pk (32)
// nat_hint (u8)
// port_hint_count (u8)
// port_hints (port_hint_count * u16 BE)
// metadata_length (u16 BE)
// metadata (L bytes)

pub fn serialize_without_signature(pkg: &ConnectionPackage) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&pkg.topic_id);
    buf.extend_from_slice(&pkg.pc_x25519_pk);
    buf.extend_from_slice(&pkg.android_x25519_pk);

    buf.push(pkg.nat_hint);
    let count = pkg.port_hints.len();
    buf.push(count as u8);

    for port in &pkg.port_hints {
        buf.extend_from_slice(&port.to_be_bytes());
    }

    let meta_len = pkg.metadata.len() as u16;
    buf.extend_from_slice(&meta_len.to_be_bytes());
    buf.extend_from_slice(&pkg.metadata);

    buf
}

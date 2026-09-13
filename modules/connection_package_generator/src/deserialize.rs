use crate::types::{ConnectionError, ConnectionPackage};

pub fn parse_connection_package(raw: &[u8]) -> Result<ConnectionPackage, ConnectionError> {
    let total = raw.len();
    // Minimum length: 32(topic) +32 +32 +1 +1 +2(meta_len) = 100
    if total < 100 {
        return Err(ConnectionError::InvalidInput);
    }

    let mut cursor: usize = 0;

    // topic_id
    let topic = raw.get(cursor..cursor + 32).ok_or(ConnectionError::InvalidInput)?;
    let mut topic_id = [0u8; 32];
    topic_id.copy_from_slice(topic);
    cursor += 32;

    // pc_x25519_pk
    let pc = raw.get(cursor..cursor + 32).ok_or(ConnectionError::InvalidInput)?;
    let mut pc_x25519_pk = [0u8; 32];
    pc_x25519_pk.copy_from_slice(pc);
    cursor += 32;

    // android_x25519_pk
    let and = raw.get(cursor..cursor + 32).ok_or(ConnectionError::InvalidInput)?;
    let mut android_x25519_pk = [0u8; 32];
    android_x25519_pk.copy_from_slice(and);
    cursor += 32;

    // nat_hint
    let nat_hint = *raw.get(cursor).ok_or(ConnectionError::InvalidInput)?;
    cursor += 1;

    // port_hint_count
    let port_hint_count = *raw.get(cursor).ok_or(ConnectionError::InvalidInput)? as usize;
    cursor += 1;
    if port_hint_count > 16 {
        return Err(ConnectionError::InvalidInput);
    }

    // port_hints
    let mut port_hints = Vec::with_capacity(port_hint_count);
    for _ in 0..port_hint_count {
        let b = raw.get(cursor..cursor + 2).ok_or(ConnectionError::InvalidInput)?;
        let port = u16::from_be_bytes([b[0], b[1]]);
        if port == 0 {
            return Err(ConnectionError::InvalidInput);
        }
        port_hints.push(port);
        cursor += 2;
    }

    // metadata length
    let ml = raw.get(cursor..cursor + 2).ok_or(ConnectionError::InvalidInput)?;
    let meta_len = u16::from_be_bytes([ml[0], ml[1]]) as usize;
    cursor += 2;

    const MAX_METADATA_LEN: usize = 4096;
    if meta_len > MAX_METADATA_LEN {
        return Err(ConnectionError::InvalidInput);
    }

    // metadata
    if cursor + meta_len != total {
        // either not enough bytes or trailing bytes
        return Err(ConnectionError::InvalidInput);
    }
    let meta = raw.get(cursor..cursor + meta_len).ok_or(ConnectionError::InvalidInput)?;
    let mut metadata = vec![0u8; meta_len];
    metadata.copy_from_slice(meta);
    cursor += meta_len;

    // ensure we've consumed exactly all bytes
    if cursor != total {
        return Err(ConnectionError::InvalidInput);
    }

    Ok(ConnectionPackage {
        topic_id,
        pc_x25519_pk,
        android_x25519_pk,
        nat_hint,
        port_hints,
        metadata,
    })
}

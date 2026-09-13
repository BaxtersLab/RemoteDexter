

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionPackage {
    pub topic_id: [u8; 32],
    pub pc_x25519_pk: [u8; 32],
    pub android_x25519_pk: [u8; 32],
    pub nat_hint: u8,
    pub port_hints: Vec<u16>,
    pub metadata: Vec<u8>, // opaque metadata for signaling
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionError {
    InvalidInput,
}


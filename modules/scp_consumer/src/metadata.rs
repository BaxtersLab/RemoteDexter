use crate::types::ScpError;

// Metadata format versioning
pub const METADATA_V1: u8 = 1;

pub struct MetadataV1<'a> {
    pub claims: &'a [u8],
    pub pk: &'a [u8; 32],
    pub sig: &'a [u8; 64],
}

pub fn parse_metadata(bytes: &[u8]) -> Result<MetadataV1<'_>, ScpError> {
    // require at least: 1 byte version + 32 pk + 64 sig
    if bytes.len() < 1 + 96 {
        return Err(ScpError::InvalidPackage);
    }
    let version = bytes[0];
    match version {
        METADATA_V1 => {
            let len = bytes.len();
            let split = len - 96;
            let claims = &bytes[1..split];
            let tail = &bytes[split..];
            let pk_slice: &[u8] = &tail[0..32];
            let sig_slice: &[u8] = &tail[32..96];
            let pk_ref: &[u8; 32] = pk_slice.try_into().map_err(|_| ScpError::InvalidPackage)?;
            let sig_ref: &[u8; 64] = sig_slice.try_into().map_err(|_| ScpError::InvalidPackage)?;
            Ok(MetadataV1 { claims, pk: pk_ref, sig: sig_ref })
        }
        _ => Err(ScpError::InvalidPackage),
    }
}

pub fn build_metadata_v1(claims: &[u8], pk: &[u8;32], sig: &[u8;64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + claims.len() + 96);
    v.push(METADATA_V1);
    v.extend_from_slice(claims);
    v.extend_from_slice(pk);
    v.extend_from_slice(sig);
    v
}

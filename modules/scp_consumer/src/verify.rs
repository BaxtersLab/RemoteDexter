use crate::types::{ScpMessage, ScpError};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use crate::metadata::parse_metadata;

/// Verifier hook: implement to validate message signatures or contents.
pub trait Verifier {
    fn verify(&self, msg: &ScpMessage) -> Result<(), ScpError>;
}

/// Trust chain hook: implement to validate the origin/trust relationship.
pub trait TrustChain {
    fn check_trust_chain(&self, msg: &ScpMessage) -> Result<(), ScpError>;
}

/// No-op verifier that always returns Ok.
pub struct NoopVerifier;
impl Verifier for NoopVerifier {
    fn verify(&self, _msg: &ScpMessage) -> Result<(), ScpError> { Ok(()) }
}

/// No-op trust chain checker.
pub struct NoopTrust;
impl TrustChain for NoopTrust {
    fn check_trust_chain(&self, _msg: &ScpMessage) -> Result<(), ScpError> { Ok(()) }
}

/// Helper: verify an ed25519 signature given raw key and signature bytes.
pub fn verify_ed25519(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), ScpError> {
    let pk = VerifyingKey::from_bytes(pk).map_err(|_| ScpError::InvalidInput)?;
    // ed25519-dalek 2.x: Signature::from_bytes is infallible over a fixed
    // 64-byte array — any 64 bytes are a syntactically valid signature, and
    // whether they verify is `pk.verify`'s answer, not the parser's.
    let signature = Signature::from_bytes(sig);
    pk.verify(msg, &signature).map_err(|_| ScpError::InvalidPackage)
}

/// Concrete verifier that expects `metadata` to end with 32-byte public key + 64-byte signature,
/// and verifies an ed25519 signature over the canonical serialization where `metadata` is only
/// the leading claim bytes (i.e. metadata_without_sig).
pub struct Ed25519MetadataVerifier;
impl Verifier for Ed25519MetadataVerifier {
    fn verify(&self, msg: &ScpMessage) -> Result<(), ScpError> {
        let meta = &msg.pkg.metadata;
            // parse versioned metadata
            let parsed = parse_metadata(meta)?;
            // rebuild a temporary ConnectionPackage with metadata=claims only
            let mut tmp = msg.pkg.clone();
            tmp.metadata = parsed.claims.to_vec();
            let signed_bytes = connection_package_generator::serialize::serialize_without_signature(&tmp);
            verify_ed25519(parsed.pk, &signed_bytes, parsed.sig)
    }
}

/// Parse and then run verifier and trust-chain checks.
pub fn parse_and_verify<V: Verifier, T: TrustChain>(
    raw: &[u8],
    verifier: &V,
    trust: &T,
) -> Result<ScpMessage, ScpError> {
    let msg = crate::parse::parse_scp(raw)?;
    verifier.verify(&msg)?;
    trust.check_trust_chain(&msg)?;
    Ok(msg)
}

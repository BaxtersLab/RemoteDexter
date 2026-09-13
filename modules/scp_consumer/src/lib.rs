pub mod types;
pub mod parse;
pub mod verify;
pub mod metadata;

pub use types::{ScpError, ScpMessage};
pub use parse::parse_scp;
pub use verify::{Verifier, TrustChain, NoopVerifier, NoopTrust, parse_and_verify, verify_ed25519, Ed25519MetadataVerifier};
pub use metadata::{build_metadata_v1, METADATA_V1};

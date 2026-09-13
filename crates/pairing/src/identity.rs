//! The host's durable Ed25519 invite-signing identity.
//!
//! Migrated from `module17_bootstrap_invite::signing` and moved to
//! **ed25519-dalek 2.x**. The 1.x API it used (`Keypair`, `PublicKey`,
//! `Keypair::from_bytes`) carries RUSTSEC-2022-0093 and, through
//! `curve25519-dalek 3`, pinned `zeroize` below 1.4 — which is what blocked the
//! `snow` upgrade for two blocks. See `docs/DEPENDENCIES.md` §3.0.
//!
//! Deliberately a **separate** keypair from the Noise static key: a compromise
//! of one must not compromise the other. This key says "this invite really came
//! from the host you already trust"; the Noise key is what the session pins.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use std::io;
use std::path::Path;

/// Raw serialised form: 32 bytes secret ‖ 32 bytes public.
const KEYPAIR_BYTES: usize = 64;

/// Why an identity could not be loaded.
#[derive(Debug)]
pub enum IdentityError {
    /// The file exists but is not a 64-byte keypair.
    ///
    /// **Never silently replaced.** A malformed key file is far more likely to
    /// be a truncated write, a wrong file, or a restored backup than a reason
    /// to mint a brand-new identity — and minting one would invalidate every
    /// phone already paired with this host, presenting as "identity changed"
    /// on every device at once.
    Malformed {
        /// How many bytes were actually there.
        found: usize,
    },
    /// The file could not be read or written.
    Io(io::Error),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Malformed { found } => write!(
                f,
                "host signing identity is malformed ({found} bytes, expected {KEYPAIR_BYTES}); \
                 refusing to replace it — move it aside deliberately if it is genuinely lost"
            ),
            IdentityError::Io(e) => write!(f, "host signing identity I/O error: {}", e.kind()),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Load the persistent signing key at `path`, or create and persist one on
/// first run.
///
/// Returns [`IdentityError::Malformed`] rather than regenerating when the file
/// exists but is the wrong size.
pub fn load_or_create(path: &Path) -> Result<SigningKey, IdentityError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let arr: [u8; KEYPAIR_BYTES] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::Malformed { found: bytes.len() })?;
            Ok(SigningKey::from_keypair_bytes(&arr)
                .map_err(|_| IdentityError::Malformed { found: bytes.len() })?)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut csprng = rand::rngs::OsRng;
            let key = SigningKey::generate(&mut csprng);
            write_owner_only(path, &key.to_keypair_bytes()).map_err(IdentityError::Io)?;
            Ok(key)
        }
        Err(e) => Err(IdentityError::Io(e)),
    }
}

/// Write a key file readable only by its owner.
fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Standard-alphabet base64 of the 32-byte public key — the
/// `host_identity_pubkey` every invite carries.
pub fn identity_b64(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rd-pairing-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    /// Migrated from `module17_bootstrap_invite::signing`.
    #[test]
    fn sign_and_verify_roundtrip() {
        let mut csprng = rand::rngs::OsRng;
        let key = SigningKey::generate(&mut csprng);
        let sig = key.sign(b"hello invite");
        assert!(key.verifying_key().verify(b"hello invite", &sig).is_ok());
    }

    /// Migrated from `module17_bootstrap_invite::signing`.
    #[test]
    fn tampered_message_fails_verification() {
        let mut csprng = rand::rngs::OsRng;
        let key = SigningKey::generate(&mut csprng);
        let sig = key.sign(b"hello invite");
        assert!(key.verifying_key().verify(b"hello invit3", &sig).is_err());
    }

    /// Migrated from `module17_bootstrap_invite::signing`.
    #[test]
    fn load_or_create_persists_and_reuses_identity() {
        let p = tmp("persist");
        let first = load_or_create(&p).unwrap();
        let second = load_or_create(&p).unwrap();
        assert_eq!(
            identity_b64(&first),
            identity_b64(&second),
            "a second load must reuse the stored key, not mint a new one"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// Migrated from `module17_bootstrap_invite::signing`.
    #[test]
    fn different_identities_produce_different_keys() {
        let a = tmp("a");
        let b = tmp("b");
        let ka = load_or_create(&a).unwrap();
        let kb = load_or_create(&b).unwrap();
        assert_ne!(identity_b64(&ka), identity_b64(&kb));
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    /// NEW, and the reason this module exists rather than a one-line helper.
    /// The 1.x implementation regenerated silently on any read failure —
    /// including a short read — which would re-key the host and break every
    /// paired phone at once.
    #[test]
    fn a_malformed_key_file_is_refused_not_replaced() {
        let p = tmp("malformed");
        std::fs::write(&p, b"not a keypair").unwrap();
        let before = std::fs::read(&p).unwrap();
        match load_or_create(&p) {
            Err(IdentityError::Malformed { found }) => assert_eq!(found, 13),
            other => panic!("expected Malformed, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&p).unwrap(),
            before,
            "the existing file must be left exactly as it was"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn a_created_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp("perms");
        let _ = load_or_create(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "0o{mode:o} — a signing key must not be group or world readable"
        );
        let _ = std::fs::remove_file(&p);
    }
}

//! The Android client's own Noise static key.
//!
//! Block 9. Until now the client called `generate_keypair()` on **every
//! connection**, so from the host's point of view each reconnect was a
//! different device. Durable pairing is impossible against a peer with no
//! stable identity: the host can record a device all it likes, but the key it
//! recorded never comes back.
//!
//! ## The same rules the host learned the hard way
//!
//! * **Only an absent file may be generated into.** A file of the wrong size is
//!   a malformed key and is an error, never something to overwrite. On the host
//!   the equivalent code silently replaced a key it failed to parse, which
//!   would have stranded every paired device; the same mistake here would
//!   silently un-pair the phone and leave the operator wondering why.
//! * **Owner-only at creation**, not patched afterwards, so there is no window
//!   in which the file exists readable.
//! * **Atomic**: written to a temporary file and renamed into place, so a
//!   process killed mid-write never leaves a half-key that would parse.
//!
//! ## What is stored
//!
//! The 32-byte X25519 private key, and nothing else. The public half is derived
//! by `snow` during the handshake, so storing it would only create a second
//! copy that could disagree with the first.

use std::io;
use std::path::{Path, PathBuf};

/// Bytes in a stored client private key.
pub const CLIENT_KEY_LEN: u64 = 32;

/// Why a client identity could not be established.
#[derive(Debug)]
pub enum IdentityError {
    /// The file exists but is not `CLIENT_KEY_LEN` bytes. Never overwritten.
    Malformed {
        /// Size actually found.
        found: u64,
    },
    /// Filesystem trouble.
    Io(io::Error),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Malformed { found } => write!(
                f,
                "client identity is {found} bytes, expected {CLIENT_KEY_LEN}; \
                 refusing to replace it"
            ),
            IdentityError::Io(e) => write!(f, "client identity i/o: {e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// The file inside the app-private directory.
pub fn identity_file(app_private_dir: &Path) -> PathBuf {
    app_private_dir.join("client_identity.key")
}

/// Load this device's private key, creating one on first run.
///
/// Never logs, returns, or otherwise exposes the key material — the caller gets
/// bytes to hand straight to `snow`, and nothing else.
pub fn load_or_create(path: &Path) -> Result<Vec<u8>, IdentityError> {
    match std::fs::metadata(path) {
        Ok(m) if m.len() == CLIENT_KEY_LEN => {
            return std::fs::read(path).map_err(IdentityError::Io);
        }
        Ok(m) => return Err(IdentityError::Malformed { found: m.len() }),
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(IdentityError::Io(e));
        }
        Err(_) => {}
    }

    let keypair = snow::Builder::new(
        crate::NOISE_PATTERN
            .parse()
            .map_err(|_| IdentityError::Io(io::Error::other("bad noise pattern")))?,
    )
    .generate_keypair()
    .map_err(|_| IdentityError::Io(io::Error::other("keypair generation failed")))?;

    write_new_owner_only(path, &keypair.private).map_err(IdentityError::Io)?;
    Ok(keypair.private)
}

/// Forget this device's identity.
///
/// The Android half of "fully prevent future reconnects": the host can revoke a
/// device, and the device can renounce itself. After this the next connection
/// generates a **new** key, so the host sees an unknown device and refuses it
/// until the owner pairs again with a fresh QR.
///
/// Idempotent — forgetting twice, or forgetting when nothing was stored, is
/// success. Removes exactly one file and never touches anything beside it.
///
/// A session already running keeps the key it handshaked with; this governs the
/// next connection, not the current one.
pub fn forget(path: &Path) -> Result<(), IdentityError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(IdentityError::Io(e)),
    }
}

/// Create the file owner-only and atomically.
fn write_new_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A sibling temp, so the rename below is within one directory and therefore
    // atomic rather than a copy.
    let tmp = path.with_extension("key.tmp");
    // `create_new` so a leftover temp is never silently reused.
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rd-client-id-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The whole point: the same device, twice.
    #[test]
    fn the_same_key_comes_back_on_the_next_run() {
        let p = identity_file(&scratch("stable"));
        let first = load_or_create(&p).expect("created");
        let second = load_or_create(&p).expect("loaded");
        assert_eq!(
            first, second,
            "a client that generates a new key per run can never be a paired device"
        );
        assert_eq!(first.len(), CLIENT_KEY_LEN as usize);
    }

    #[test]
    fn two_devices_do_not_share_a_key() {
        let a = load_or_create(&identity_file(&scratch("a"))).unwrap();
        let b = load_or_create(&identity_file(&scratch("b"))).unwrap();
        assert_ne!(a, b, "separate installs must be separate identities");
    }

    /// The host made this exact mistake and it would have stranded every paired
    /// device. Here it would silently un-pair the phone instead.
    #[test]
    fn a_malformed_key_is_an_error_not_a_replacement() {
        let p = identity_file(&scratch("malformed"));
        std::fs::write(&p, vec![0u8; 7]).unwrap();

        let err = load_or_create(&p).expect_err("must refuse");
        assert!(matches!(err, IdentityError::Malformed { found: 7 }));
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            7,
            "the malformed file must be left exactly as it was"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_new_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let p = identity_file(&scratch("perms"));
        load_or_create(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn no_temporary_file_survives_creation() {
        let d = scratch("tmp");
        load_or_create(&identity_file(&d)).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    /// A temp left by a killed process must not be mistaken for the real key.
    #[test]
    fn a_stale_temporary_does_not_block_creation() {
        let d = scratch("stale");
        let p = identity_file(&d);
        std::fs::write(p.with_extension("key.tmp"), b"junk").unwrap();
        let key = load_or_create(&p).expect("a stale temp must not stop a first run");
        assert_eq!(key.len(), CLIENT_KEY_LEN as usize);
    }

    /// Forgetting has to actually change who this device is. If the same key
    /// came back afterwards, "Forget" would be a button that does nothing while
    /// telling the owner their phone is no longer paired.
    #[test]
    fn forgetting_yields_a_different_identity_next_time() {
        let p = identity_file(&scratch("forget"));
        let before = load_or_create(&p).unwrap();
        forget(&p).expect("forget must succeed");
        assert!(!p.exists(), "the stored key must be gone");
        let after = load_or_create(&p).unwrap();
        assert_ne!(
            before, after,
            "a forgotten device must not be recognisable as the old one"
        );
    }

    #[test]
    fn forgetting_is_idempotent_and_safe_when_nothing_is_stored() {
        let p = identity_file(&scratch("forget-twice"));
        forget(&p).expect("forgetting nothing is success");
        load_or_create(&p).unwrap();
        forget(&p).unwrap();
        forget(&p).expect("forgetting twice is success");
    }

    #[test]
    fn forgetting_touches_nothing_beside_the_key() {
        let d = scratch("forget-neighbours");
        let neighbour = d.join("something_else.dat");
        std::fs::write(&neighbour, b"keep me").unwrap();
        let p = identity_file(&d);
        load_or_create(&p).unwrap();

        forget(&p).unwrap();
        assert!(neighbour.exists(), "only the identity may be removed");
        assert_eq!(std::fs::read(&neighbour).unwrap(), b"keep me");
    }

    #[test]
    fn the_key_lives_inside_the_app_private_directory() {
        let d = scratch("path");
        let p = identity_file(&d);
        assert!(
            p.starts_with(&d),
            "the key must not escape the app's own directory"
        );
        assert_eq!(p.file_name().unwrap(), "client_identity.key");
    }
}

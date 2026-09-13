//! Where the host's identity files live, and the one-time move that puts them
//! there.
//!
//! Block 9. Until now `identity_path()` placed the host's private keys **beside
//! the executable**, under `target/release/`. On this box that left them
//! `mode 664` — world-readable — and inside a build directory that a `cargo
//! clean` would happily delete. They belong in the platform's data directory,
//! owner-only.
//!
//! ## Nothing here ever reads a key
//!
//! The move is `std::fs::rename`, which operates on directory entries: it never
//! opens the file, so no byte of a private key passes through this process, a
//! log, or anyone's terminal. Verification is by size and metadata only. Where
//! a caller wants proof the move was faithful, the honest tool is a hash
//! computed outside this module — a digest is not the key.
//!
//! ## It refuses far more than it does
//!
//! The block's Risk section is explicit: migration "can strand existing test
//! pairings", so this must never guess. Every ambiguous situation is a refusal
//! that leaves both sides untouched, because the failure mode is not a leak —
//! it is **availability**. A host that loses its identity generates a new one,
//! and then every paired phone sees a changed host key and refuses to connect.
//! That is host pinning working correctly, and it would look like everything
//! broke at once.
//!
//! In particular: a malformed key is **never** silently replaced with a fresh
//! one. That is the single worst thing this code could do.

use std::path::{Path, PathBuf};

/// Bytes in a Noise/Ed25519 keypair file as this host writes them.
pub const IDENTITY_FILE_LEN: u64 = 64;

/// What happened, or why nothing did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migration {
    /// No legacy file. A fresh install, or already cleaned up.
    NothingToDo,
    /// The destination already holds it and the legacy path is gone.
    AlreadyMigrated,
    /// Moved, and the destination verified as a 64-byte regular file.
    Moved,
    /// Deliberately declined. Both paths are left exactly as they were.
    Refused(Refusal),
}

/// Why a migration declined to act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A key exists at BOTH paths. Which one is current cannot be known from
    /// here, and picking wrong strands every paired device.
    BothPresent,
    /// The legacy path is a symlink, directory, or something else. Following it
    /// would move a file this host does not own.
    LegacyNotRegularFile,
    /// The legacy file is not `IDENTITY_FILE_LEN` bytes. Malformed — moved
    /// nowhere, and above all NOT regenerated.
    LegacyWrongSize(u64),
    /// Source and destination are on different filesystems, so `rename` cannot
    /// be atomic and a copy would have to read the key. Refused rather than
    /// read: the operator can move it deliberately.
    CrossDevice,
    /// The destination directory could not be created.
    DestinationUnusable(String),
    /// `rename` itself failed.
    MoveFailed(String),
}

impl Refusal {
    /// A line safe to print. Names the rule and the paths, never a byte of key.
    pub fn explain(&self) -> String {
        match self {
            Refusal::BothPresent => "a key exists at both the old and new paths; \
                 refusing to guess which is current"
                .to_string(),
            Refusal::LegacyNotRegularFile => {
                "the old path is not a regular file; refusing to follow it".to_string()
            }
            Refusal::LegacyWrongSize(n) => format!(
                "the old key is {n} bytes, expected {IDENTITY_FILE_LEN}; \
                 refusing to move it and refusing to replace it"
            ),
            Refusal::CrossDevice => "the old and new paths are on different filesystems; \
                 refusing to copy, because copying would read the key"
                .to_string(),
            Refusal::DestinationUnusable(e) => format!("the destination is unusable: {e}"),
            Refusal::MoveFailed(e) => format!("the move failed: {e}"),
        }
    }
}

/// The directory identity files belong in.
///
/// `$XDG_DATA_HOME/remotedexter/identity/`, or `~/.local/share/...` when unset,
/// per the XDG basedir spec. On Windows, `%LOCALAPPDATA%\RemoteDexter\identity`.
pub fn identity_dir() -> PathBuf {
    data_dir().join("identity")
}

/// The application's data directory: everything persistent the host owns.
///
/// `$XDG_DATA_HOME/remotedexter/` or `~/.local/share/remotedexter/`, and
/// `%LOCALAPPDATA%\RemoteDexter` on Windows.
pub fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("RemoteDexter")
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && !is_snap_path(p))
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("remotedexter")
    }
}

/// Does this path point inside a snap's private tree?
///
/// **This box's documented number-one time sink.** A terminal launched from the
/// VS Code snap exports `XDG_DATA_HOME=$HOME/snap/code/<rev>/.local/share`, so
/// trusting it would file the host's private keys inside a snap revision
/// directory — invisible to the real host, which `run.sh` starts with the snap
/// variables scrubbed, and silently discarded when that revision is cleaned up.
/// The identity would appear to vanish and every paired device would be
/// stranded by a host that had quietly generated a new one.
///
/// Observed on 2026-08-27: `XDG_DATA_HOME` in this box's editor terminal was
/// `$HOME/snap/code/<revision>/.local/share`.
///
/// Gated to where it is reachable. `data_dir` only consults it under
/// `#[cfg(not(windows))]` — Windows takes `%LOCALAPPDATA%` and snaps do not
/// exist there — so in a non-test Windows build it is dead code and warns. The
/// `test` arm keeps it compiled on Windows for
/// `a_snap_contaminated_data_home_is_not_trusted`, because the function is pure
/// and this tree tests pure decisions on every platform rather than only where
/// they run.
#[cfg(any(not(windows), test))]
fn is_snap_path(p: &Path) -> bool {
    p.components().any(|c| c.as_os_str() == "snap")
}

/// Owner-only on the destination. `0700` for the directory, `0600` for the key.
#[cfg(unix)]
fn tighten(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn tighten(_path: &Path, _mode: u32) -> std::io::Result<()> {
    // Windows ACLs are not mode bits; the data directory is already per-user.
    Ok(())
}

/// May the host generate a fresh key at this path?
///
/// The rule that stops a bad day becoming an unrecoverable one. Only an
/// **absent** file may be generated into. A file of the wrong size is a
/// malformed key: it must stop startup so the operator can look at it, and it
/// must never be overwritten with a fresh identity — that would strand every
/// paired device behind a host key they correctly refuse.
///
/// Returns `Ok(true)` to generate, `Ok(false)` to load what is there, and
/// `Err(len)` when the file is the wrong size.
///
/// `host_app`'s Noise loader did exactly the forbidden thing until 2026-08-27:
/// `if bytes.len() == 64 { use it }` and otherwise fell through to generate and
/// overwrite. The invite-signing loader in `pairing::identity` already got this
/// right, which is why only one of the two needed repairing.
pub fn may_generate(existing_len: Option<u64>) -> Result<bool, u64> {
    match existing_len {
        None => Ok(true),
        Some(n) if n == IDENTITY_FILE_LEN => Ok(false),
        Some(n) => Err(n),
    }
}

/// May the host proceed to load or create at the destination?
///
/// A refusal must stop startup. Proceeding past one would land in
/// [`may_generate`] with an absent destination and quietly mint a new identity
/// — the very outcome the refusal existed to prevent.
pub fn may_proceed(m: &Migration) -> Result<(), &Refusal> {
    match m {
        Migration::Moved | Migration::AlreadyMigrated | Migration::NothingToDo => Ok(()),
        Migration::Refused(r) => Err(r),
    }
}

/// What a migration *would* do, decided from metadata alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Nothing to move.
    NothingToDo,
    /// Already at the destination.
    AlreadyMigrated,
    /// A well-formed key is ready to be moved.
    Ready,
    /// Would decline, for this reason.
    Refused(Refusal),
}

/// Decide what would happen, **without touching anything**.
///
/// This is what makes the migration inspectable before it runs: it opens no
/// file, moves nothing, and creates nothing. `migrate_one` is exactly this
/// decision followed by the act, so a dry run cannot disagree with the real
/// thing — there is one decision procedure, not two.
pub fn assess(legacy: &Path, dest: &Path) -> Plan {
    let legacy_meta = std::fs::symlink_metadata(legacy).ok();
    let dest_exists = dest.exists();

    let meta = match (&legacy_meta, dest_exists) {
        (None, true) => return Plan::AlreadyMigrated,
        (None, false) => return Plan::NothingToDo,
        (Some(_), true) => return Plan::Refused(Refusal::BothPresent),
        (Some(m), false) => m,
    };

    if !meta.is_file() {
        return Plan::Refused(Refusal::LegacyNotRegularFile);
    }
    if meta.len() != IDENTITY_FILE_LEN {
        return Plan::Refused(Refusal::LegacyWrongSize(meta.len()));
    }
    Plan::Ready
}

/// Create a key file readable only by its owner.
///
/// `std::fs::write` obeys the umask, which is how both of this box's key files
/// ended up `mode 664` — world-readable private keys. The mode is set at
/// creation, not patched afterwards, so there is no window in which the file
/// exists readable.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let _ = tighten(parent, 0o700);
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
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

/// Move one identity file from `legacy` to `dest`, or explain why not.
///
/// Never reads either file's contents. Both paths are left untouched on every
/// refusal.
pub fn migrate_one(legacy: &Path, dest: &Path) -> Migration {
    match assess(legacy, dest) {
        Plan::NothingToDo => return Migration::NothingToDo,
        Plan::AlreadyMigrated => return Migration::AlreadyMigrated,
        Plan::Refused(r) => return Migration::Refused(r),
        Plan::Ready => {}
    }

    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Migration::Refused(Refusal::DestinationUnusable(e.to_string()));
        }
        let _ = tighten(parent, 0o700);
    }

    // The move itself. `rename` never opens the file.
    if let Err(e) = std::fs::rename(legacy, dest) {
        // EXDEV: a copy would be required, and a copy reads the key.
        if e.raw_os_error() == Some(18) {
            return Migration::Refused(Refusal::CrossDevice);
        }
        return Migration::Refused(Refusal::MoveFailed(e.to_string()));
    }
    let _ = tighten(dest, 0o600);

    // Verified by metadata only — never by content.
    match std::fs::metadata(dest) {
        Ok(m) if m.is_file() && m.len() == IDENTITY_FILE_LEN => Migration::Moved,
        Ok(m) => Migration::Refused(Refusal::LegacyWrongSize(m.len())),
        Err(e) => Migration::Refused(Refusal::MoveFailed(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    /// A private scratch directory. No `tempfile` dependency is added for this.
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rd-identity-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A stand-in for a key. **Never a real one** — these tests must be
    /// runnable by anyone, on any box, without a host identity existing.
    fn fake_key(path: &Path, len: usize) {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, vec![0xAB; len]).unwrap();
    }

    #[test]
    fn a_fresh_install_has_nothing_to_move() {
        let d = scratch("fresh");
        assert_eq!(
            migrate_one(&d.join("old.key"), &d.join("new/old.key")),
            Migration::NothingToDo
        );
    }

    #[test]
    fn a_key_already_in_place_is_left_alone() {
        let d = scratch("already");
        let dest = d.join("new/id.key");
        fake_key(&dest, 64);
        assert_eq!(
            migrate_one(&d.join("id.key"), &dest),
            Migration::AlreadyMigrated
        );
        assert!(dest.exists(), "the destination must not be disturbed");
    }

    #[test]
    fn a_well_formed_key_moves_and_the_old_path_is_gone() {
        let d = scratch("move");
        let legacy = d.join("id.key");
        let dest = d.join("new/id.key");
        fake_key(&legacy, 64);

        assert_eq!(migrate_one(&legacy, &dest), Migration::Moved);
        assert!(!legacy.exists(), "the old path must not be left behind");
        assert_eq!(std::fs::metadata(&dest).unwrap().len(), 64);
    }

    #[cfg(unix)]
    #[test]
    fn the_moved_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("perms");
        let legacy = d.join("id.key");
        let dest = d.join("new/id.key");
        fake_key(&legacy, 64);
        // The state this box was actually found in: world-readable.
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o664)).unwrap();

        assert_eq!(migrate_one(&legacy, &dest), Migration::Moved);
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a private key must not stay world-readable");
        let dir_mode = std::fs::metadata(dest.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "and neither may the directory holding it");
    }

    /// The worst thing this code could do is replace a key it did not
    /// understand. It must refuse, and leave the file exactly where it is.
    #[test]
    fn a_malformed_key_is_neither_moved_nor_replaced() {
        let d = scratch("malformed");
        let legacy = d.join("id.key");
        let dest = d.join("new/id.key");
        fake_key(&legacy, 31);

        assert_eq!(
            migrate_one(&legacy, &dest),
            Migration::Refused(Refusal::LegacyWrongSize(31))
        );
        assert!(
            legacy.exists(),
            "the malformed key must be left where it is"
        );
        assert_eq!(std::fs::metadata(&legacy).unwrap().len(), 31);
        assert!(!dest.exists(), "and nothing may be created in its place");
    }

    /// Two keys, no way to know which the host is using. Guessing wrong strands
    /// every paired device.
    #[test]
    fn a_key_at_both_paths_is_a_refusal_not_a_choice() {
        let d = scratch("both");
        let legacy = d.join("id.key");
        let dest = d.join("new/id.key");
        fake_key(&legacy, 64);
        fake_key(&dest, 64);

        assert_eq!(
            migrate_one(&legacy, &dest),
            Migration::Refused(Refusal::BothPresent)
        );
        assert!(
            legacy.exists() && dest.exists(),
            "both must survive untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_where_a_key_should_be_is_refused() {
        let d = scratch("symlink");
        let real = d.join("elsewhere.key");
        fake_key(&real, 64);
        let legacy = d.join("id.key");
        std::os::unix::fs::symlink(&real, &legacy).unwrap();
        let dest = d.join("new/id.key");

        assert_eq!(
            migrate_one(&legacy, &dest),
            Migration::Refused(Refusal::LegacyNotRegularFile)
        );
        assert!(real.exists(), "the symlink target must not be moved");
        assert!(!dest.exists());
    }

    #[test]
    fn a_directory_where_a_key_should_be_is_refused() {
        let d = scratch("dir");
        let legacy = d.join("id.key");
        std::fs::create_dir_all(&legacy).unwrap();
        assert_eq!(
            migrate_one(&legacy, &d.join("new/id.key")),
            Migration::Refused(Refusal::LegacyNotRegularFile)
        );
    }

    /// Running it twice must be safe: the second pass sees the destination and
    /// reports that, rather than doing anything.
    #[test]
    fn migration_is_idempotent() {
        let d = scratch("twice");
        let legacy = d.join("id.key");
        let dest = d.join("new/id.key");
        fake_key(&legacy, 64);

        assert_eq!(migrate_one(&legacy, &dest), Migration::Moved);
        assert_eq!(migrate_one(&legacy, &dest), Migration::AlreadyMigrated);
        assert_eq!(std::fs::metadata(&dest).unwrap().len(), 64);
    }

    /// A dry run must touch nothing at all — that is its whole value.
    #[test]
    fn assessing_moves_nothing_and_creates_nothing() {
        let d = scratch("assess");
        let legacy = d.join("id.key");
        let dest = d.join("new/id.key");
        fake_key(&legacy, 64);

        assert_eq!(assess(&legacy, &dest), Plan::Ready);
        assert!(legacy.exists(), "a dry run must not move the key");
        assert!(!dest.exists(), "a dry run must not create the destination");
        assert!(
            !dest.parent().unwrap().exists(),
            "nor the directory that would hold it"
        );
    }

    /// One decision procedure, not two: a dry run that could disagree with the
    /// real thing would be worse than no dry run.
    #[test]
    fn the_dry_run_agrees_with_what_actually_happens() {
        for (tag, len) in [("ok", 64usize), ("bad", 31)] {
            let d = scratch(tag);
            let legacy = d.join("id.key");
            let dest = d.join("new/id.key");
            fake_key(&legacy, len);

            let planned = assess(&legacy, &dest);
            let done = migrate_one(&legacy, &dest);
            match (planned, done) {
                (Plan::Ready, Migration::Moved) => {}
                (Plan::Refused(a), Migration::Refused(b)) => assert_eq!(a, b),
                (p, m) => panic!("dry run said {p:?} but the migration did {m:?}"),
            }
        }
    }

    #[test]
    fn every_refusal_explains_itself_without_naming_a_byte() {
        for r in [
            Refusal::BothPresent,
            Refusal::LegacyNotRegularFile,
            Refusal::LegacyWrongSize(31),
            Refusal::CrossDevice,
            Refusal::DestinationUnusable("x".into()),
            Refusal::MoveFailed("y".into()),
        ] {
            let msg = r.explain();
            assert!(
                !msg.is_empty(),
                "a refusal the operator cannot read is not a refusal"
            );
            assert!(
                !msg.contains("\u{0}") && msg.is_ascii() || msg.chars().all(|c| !c.is_control()),
                "an explanation must be printable text, not file content: {msg}"
            );
        }
    }

    #[test]
    fn only_an_absent_key_may_be_generated() {
        assert_eq!(may_generate(None), Ok(true), "a fresh install generates");
        assert_eq!(
            may_generate(Some(IDENTITY_FILE_LEN)),
            Ok(false),
            "a well-formed key is loaded, not replaced"
        );
        assert_eq!(
            may_generate(Some(31)),
            Err(31),
            "a malformed key must stop startup, never be overwritten"
        );
        assert_eq!(
            may_generate(Some(0)),
            Err(0),
            "an empty file is malformed, not absent"
        );
    }

    /// Proceeding past a refusal would generate a new identity at an empty
    /// destination — the exact outcome the refusal exists to prevent.
    #[test]
    fn a_refusal_stops_startup() {
        assert!(may_proceed(&Migration::Moved).is_ok());
        assert!(may_proceed(&Migration::AlreadyMigrated).is_ok());
        assert!(may_proceed(&Migration::NothingToDo).is_ok());
        for r in [
            Refusal::BothPresent,
            Refusal::LegacyWrongSize(31),
            Refusal::LegacyNotRegularFile,
            Refusal::CrossDevice,
        ] {
            assert!(
                may_proceed(&Migration::Refused(r.clone())).is_err(),
                "refusal {r:?} must not be walked past"
            );
        }
    }

    /// The box hazard, as a test.
    #[test]
    fn a_snap_contaminated_data_home_is_not_trusted() {
        // Roots are irrelevant here — only a `snap` path COMPONENT matters — so
        // these are deliberately not real home directories.
        assert!(is_snap_path(Path::new("/u/snap/code/258/.local/share")));
        assert!(is_snap_path(Path::new("/snap/code/current/.local/share")));
        assert!(
            !is_snap_path(Path::new("/u/.local/share")),
            "a legitimate data home must still be used"
        );
        assert!(
            !is_snap_path(Path::new("/u/snapper/.local/share")),
            "a substring match would wrongly reject a user called snapper"
        );
    }

    #[test]
    fn the_identity_directory_is_under_the_platform_data_home() {
        let dir = identity_dir();
        let s = dir.to_string_lossy();
        assert!(
            s.contains("remotedexter") || s.contains("RemoteDexter"),
            "identity must live in an app-owned directory, got {s}"
        );
        assert!(s.ends_with("identity"), "got {s}");
    }
}

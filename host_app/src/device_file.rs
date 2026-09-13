//! Where the enrolled-device list is kept, and how it is written.
//!
//! Block 9. The store itself is pure — `pairing::devices` knows nothing about
//! files. This is the only place it touches a disk.
//!
//! ## Why the write is atomic
//!
//! A device list half-written by a host that lost power is worse than no list:
//! it could parse, and it could parse as **fewer devices than were revoked**.
//! So a save writes a temporary file in the same directory, flushes it, and
//! renames it over the target. `rename` within a directory is atomic, so a
//! reader sees either the whole old file or the whole new one, never a splice.
//!
//! ## Why a corrupt file is never overwritten
//!
//! Silently starting from empty and then saving would destroy the operator's
//! record of what they had revoked. Instead the corrupt file is **moved aside**
//! with a timestamp and the host starts with an empty list, which fails closed:
//! an unknown key and a revoked key are both refused, so nothing is let in that
//! was not let in before. What is lost is convenience — every device must
//! re-enrol with a fresh QR — and that is the right thing to lose.

use pairing::devices::DeviceStore;
use std::path::{Path, PathBuf};

/// The device list's path.
pub fn devices_path() -> PathBuf {
    crate::identity_store::data_dir().join("devices.json")
}

/// What happened when the list was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// No file yet — a host that has enrolled nobody.
    Fresh,
    /// Read, with this many devices.
    Restored(usize),
    /// Unreadable. The file was preserved at this path and the host starts
    /// empty; every device must re-enrol.
    Quarantined(PathBuf),
}

/// Read the device list, quarantining it if it cannot be understood.
pub fn load_from(path: &Path) -> (DeviceStore, Loaded) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return (DeviceStore::new(), Loaded::Fresh),
    };
    match DeviceStore::from_json(&text) {
        Ok(store) => {
            let n = store.len();
            (store, Loaded::Restored(n))
        }
        Err(_) => {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let kept = path.with_extension(format!("json.corrupt-{stamp}"));
            // Preserve, never delete. If even the rename fails there is nothing
            // more this can safely do, and starting empty still fails closed.
            let _ = std::fs::rename(path, &kept);
            (DeviceStore::new(), Loaded::Quarantined(kept))
        }
    }
}

/// Write the device list atomically, owner-only, and DURABLY.
///
/// `write_owner_only` already `sync_all()`s the temporary file, so its CONTENTS
/// reach the disk. Until 2026-09-07 the rename that publishes it did not: on
/// POSIX a rename is not durable until the containing DIRECTORY is synced, so a
/// power loss could leave the directory entry pointing at the previous file.
///
/// For this store that is not a lost setting. The previous file is the one
/// WITHOUT the revocation, so the failure mode is a revoked device coming back
/// — the operator having been told it was withdrawn. Found by an outside
/// security review.
///
/// The directory sync is Unix-only: opening a directory as a file to `fsync` it
/// is a POSIX idiom that Windows does not share.
pub fn save_to(path: &Path, store: &DeviceStore) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    crate::identity_store::write_owner_only(&tmp, store.to_json().as_bytes())?;
    // Same directory, so this is a rename and not a copy.
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        // Failing here means the rename may not survive a power cut, which the
        // caller must be able to report — so it is an error, not a `let _`.
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rd-devices-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const A: [u8; 32] = [7u8; 32];

    #[test]
    fn a_host_with_no_file_starts_fresh() {
        let p = scratch("fresh").join("devices.json");
        let (store, how) = load_from(&p);
        assert_eq!(how, Loaded::Fresh);
        assert!(store.is_empty());
    }

    /// The point of the whole slice: enrolments outlive the host process.
    #[test]
    fn enrolments_survive_a_restart() {
        let p = scratch("restart").join("devices.json");
        let mut store = DeviceStore::new();
        store.enroll(A, "Baxter's S10", 100);
        save_to(&p, &store).unwrap();

        let (back, how) = load_from(&p);
        assert_eq!(how, Loaded::Restored(1));
        assert_eq!(back.get(&A).unwrap().display_name, "Baxter's S10");
    }

    /// And so do revocations — a revocation that forgets itself on restart
    /// would let the withdrawn device straight back in.
    #[test]
    fn revocations_survive_a_restart() {
        let p = scratch("revoked").join("devices.json");
        let mut store = DeviceStore::new();
        store.enroll(A, "stolen", 100);
        store.revoke(&A, 150);
        save_to(&p, &store).unwrap();

        let (mut back, _) = load_from(&p);
        assert!(back.get(&A).unwrap().is_revoked());
        assert!(
            back.authorize_paired(&A, 200).is_err(),
            "a restart must not un-revoke a device"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_device_list_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let p = scratch("perms").join("devices.json");
        save_to(&p, &DeviceStore::new()).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "another account able to edit this file could un-revoke a device"
        );
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        let d = scratch("tmp");
        let p = d.join("devices.json");
        save_to(&p, &DeviceStore::new()).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    /// A corrupt list must not be silently reset — that would destroy the
    /// record of what the operator had revoked.
    #[test]
    fn a_corrupt_list_is_preserved_and_the_host_starts_empty() {
        let d = scratch("corrupt");
        let p = d.join("devices.json");
        std::fs::write(&p, "{ this is not json").unwrap();

        let (store, how) = load_from(&p);
        assert!(store.is_empty(), "starting empty fails closed");
        let Loaded::Quarantined(kept) = how else {
            panic!("a corrupt list must be quarantined, got {how:?}");
        };
        assert!(
            kept.exists(),
            "the corrupt file must be preserved, not deleted"
        );
        assert!(!p.exists(), "and moved out of the way");
        assert_eq!(
            std::fs::read_to_string(&kept).unwrap(),
            "{ this is not json"
        );
    }

    /// Fails closed: after quarantine, a previously-revoked device is unknown,
    /// and unknown is refused just as revoked was.
    #[test]
    fn quarantining_never_lets_a_device_in_that_was_refused_before() {
        let d = scratch("failclosed");
        let p = d.join("devices.json");
        std::fs::write(&p, "garbage").unwrap();
        let (mut store, _) = load_from(&p);
        assert!(
            store.authorize_paired(&A, 100).is_err(),
            "an empty store must refuse everyone"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_save_that_cannot_write_reports_an_error_rather_than_claiming_success() {
        // The caller shows the operator a revocation as soon as the in-memory
        // store changes. If the write fails and `save_to` said Ok, that
        // revocation would silently not survive a restart — so the error has to
        // reach the caller. Here the parent is a FILE, so no directory can be
        // made under it.
        // Block the WRITE specifically. Two earlier attempts did not:
        // pointing at a path under a regular file failed at `create_dir_all`,
        // so the test passed even with the write and rename ignored; and making
        // the parent read-only does not work either, because
        // `write_owner_only` calls `tighten(parent, 0o700)` and hands the
        // permission straight back.
        //
        // A DIRECTORY sitting where the temporary file must be written cannot
        // be undone by any of that: opening it for writing fails.
        let dir = scratch("blocked-write");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("devices.json");
        std::fs::create_dir_all(dir.join("devices.json.tmp")).unwrap();

        let outcome = save_to(&target, &DeviceStore::new());
        assert!(
            outcome.is_err(),
            "a save that cannot write must not report success"
        );
    }

    #[test]
    fn a_saved_list_can_be_saved_again_over_itself() {
        let p = scratch("twice").join("devices.json");
        let mut store = DeviceStore::new();
        store.enroll(A, "phone", 100);
        save_to(&p, &store).unwrap();
        save_to(&p, &store).unwrap();
        let (back, how) = load_from(&p);
        assert_eq!(how, Loaded::Restored(1));
        assert_eq!(back.len(), 1);
    }
}

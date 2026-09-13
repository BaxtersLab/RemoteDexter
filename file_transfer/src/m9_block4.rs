//! Super-Block 4: Filesystem integration (design + minimal helpers)
//!
//! Scope (document-only and minimal helpers):
//! - Temp-file strategy (create stable temporary files in the target
//!   directory to hold in-progress transfers).
//! - Atomic completion (documented only here; no implementation).
//! - Resume integration with the filesystem (design notes, no logic).
//! - Overwrite policy hooks (trait surface only; no policy logic).
//! - Path sanitization rules (provided via `sanitize_filename`).
//! - Large-file safety constraints (documented as comments).
//!
//! This module intentionally provides no atomic rename or completion
//! semantics yet; it offers a `TempFileManager` helper and a trait
//! surface for overwrite policies so higher layers can be implemented
//! in Super-Block 4 without leaking policy decisions into Super-Block 3.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Minimal temp-file manager.
pub struct TempFileManager;

impl TempFileManager {
    /// Create a new temporary file in `target_dir` suitable for writing
    /// an incoming transfer. The function ensures `target_dir` exists
    /// and attempts to create a stable temp filename derived from
    /// `final_name` (".<final_name>.part"). If that name is taken,
    /// it falls back to a randomized temporary name.
    pub fn create_temp(target_dir: &Path, final_name: &str) -> io::Result<(PathBuf, std::fs::File)> {
        std::fs::create_dir_all(target_dir)?;

        let mut attempt = 0u32;
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);

        // First attempt: deterministic ".<final_name>.part"
        let dot_name = format!(".{}.part", final_name);
        let candidate = target_dir.join(&dot_name);
        match opts.open(&candidate) {
            Ok(f) => return Ok((candidate, f)),
            Err(e) => {
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e);
                }
            }
        }

        // Fallback attempts with timestamp + pid + counter
        loop {
            attempt = attempt.wrapping_add(1);
            let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
            let name = format!(".rdx_tmp_{}_{}_{}", std::process::id(), ts, attempt);
            let p = target_dir.join(&name);
            match opts.open(&p) {
                Ok(f) => return Ok((p, f)),
                Err(e) => {
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        if attempt > 16 { break; }
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not create temp file"))
    }

    /// Sanitize a candidate filename. Rejects "..", path separators,
    /// null bytes and control characters. Returns a safe filename on
    /// success or an error otherwise.
    pub fn sanitize_filename(name: &str) -> Result<String, crate::m9_block3::FileTransferError> {
        if name.contains("..") { return Err(crate::m9_block3::FileTransferError::Placeholder); }
        if name.contains('/') || name.contains('\\') { return Err(crate::m9_block3::FileTransferError::Placeholder); }
        if name.as_bytes().iter().any(|&b| b == 0) { return Err(crate::m9_block3::FileTransferError::Placeholder); }
        if name.chars().any(|c| c.is_control()) { return Err(crate::m9_block3::FileTransferError::Placeholder); }
        let s = name.trim();
        if s.is_empty() { return Err(crate::m9_block3::FileTransferError::Placeholder); }
        Ok(s.to_string())
    }
}

/// Overwrite policy hooks for deciding how to save incoming files.
pub trait FileTransferPolicy {
    fn choose_save_path(&self, offer_name: &str) -> Result<PathBuf, crate::m9_block3::FileTransferError>;

    fn handle_overwrite(&self, existing: &Path) -> OverwriteDecision;
}

/// Decision returned by overwrite policy hooks.
pub enum OverwriteDecision {
    Allow,
    Deny,
    Rename(PathBuf),
}

/// File completion metadata produced when a temp file is moved into place.
pub struct FileCompletion {
    pub final_path: PathBuf,
    pub size: u64,
    pub hash: Option<crate::m9_block3::FileHash>,
}

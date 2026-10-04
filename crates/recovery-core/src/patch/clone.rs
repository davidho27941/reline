//! Directory hashing, destination-space preflight, APFS clone with verified copy fallback.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash::{sha256_file, Sha256Hex};
use crate::progress::{ProgressSink, Stage};
use crate::{ErrorCode, RecoveryError, Result};

/// Relative path → (size, sha256) for every regular file under a root. Deterministic order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DirManifest {
    pub files: BTreeMap<PathBuf, (u64, Sha256Hex)>,
}

impl DirManifest {
    pub fn total_bytes(&self) -> u64 {
        self.files.values().map(|(s, _)| *s).sum()
    }

    /// Paths whose size or hash differ, plus paths present in only one side.
    pub fn diff(&self, other: &DirManifest) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for (p, v) in &self.files {
            match other.files.get(p) {
                Some(o) if o == v => {}
                _ => out.push(p.clone()),
            }
        }
        for p in other.files.keys() {
            if !self.files.contains_key(p) {
                out.push(p.clone());
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// SHA-256 over the sorted listing (for evidence).
    pub fn digest(&self) -> Sha256Hex {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        for (p, (s, hash)) in &self.files {
            h.update(p.as_os_str().as_bytes());
            h.update(b"\0");
            h.update(s.to_le_bytes());
            h.update(hash.0.as_bytes());
            h.update(b"\n");
        }
        Sha256Hex(hex::encode(h.finalize()))
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| RecoveryError::io(e, dir))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| RecoveryError::io(e, dir))?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let meta = std::fs::symlink_metadata(&p).map_err(|err| RecoveryError::io(err, &p))?;
        if meta.file_type().is_symlink() {
            return Err(RecoveryError::new(
                ErrorCode::UnsupportedBackup,
                "backup contains a symbolic link; refusing to follow it",
            )
            .with_path(p));
        }
        if meta.is_dir() {
            walk(root, &p, out)?;
        } else {
            out.push(p.strip_prefix(root).expect("under root").to_path_buf());
        }
    }
    Ok(())
}

/// Hash every regular file under `root`.
pub fn hash_dir(root: &Path, progress: &dyn ProgressSink, stage: Stage) -> Result<DirManifest> {
    let mut rels = Vec::new();
    walk(root, root, &mut rels)?;
    let mut files = BTreeMap::new();
    let total = rels.len() as u64;
    for (i, rel) in rels.iter().enumerate() {
        progress.check_cancelled()?;
        let p = root.join(rel);
        let size = std::fs::metadata(&p)
            .map_err(|e| RecoveryError::io(e, &p))?
            .len();
        let h = sha256_file(&p, &crate::progress::NoProgress, stage)?;
        files.insert(rel.clone(), (size, h));
        progress.report(stage, i as u64 + 1, total);
    }
    Ok(DirManifest { files })
}

/// Free bytes available to the user on the volume holding `path`.
pub fn available_bytes(path: &Path) -> Result<u64> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| RecoveryError::new(ErrorCode::InvalidArgument, "path contains NUL"))?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a valid out-pointer.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(RecoveryError::io(std::io::Error::last_os_error(), path));
    }
    Ok(u64::from(st.f_bavail) * st.f_frsize)
}

fn same_device(a: &Path, b: &Path) -> Result<bool> {
    let ma = std::fs::metadata(a).map_err(|e| RecoveryError::io(e, a))?;
    let mb = std::fs::metadata(b).map_err(|e| RecoveryError::io(e, b))?;
    Ok(ma.dev() == mb.dev())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneReport {
    pub files: u64,
    pub bytes: u64,
    pub cloned_with_clonefile: u64,
    pub copied: u64,
    pub same_volume: bool,
    pub available_bytes_before: u64,
    pub required_bytes_estimate: u64,
}

fn clonefile(src: &Path, dst: &Path) -> std::io::Result<()> {
    let s = CString::new(src.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("NUL in path"))?;
    let d = CString::new(dst.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("NUL in path"))?;
    // SAFETY: both strings are valid NUL-terminated paths; flags 0 = default (no follow).
    let rc = unsafe { libc::clonefile(s.as_ptr(), d.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn copy_verified(src: &Path, dst: &Path) -> Result<()> {
    let mut s = std::fs::File::open(src).map_err(|e| RecoveryError::io(e, src))?;
    let mut d = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| RecoveryError::io(e, dst))?;
    std::io::copy(&mut s, &mut d).map_err(|e| RecoveryError::io(e, dst))?;
    d.sync_all().map_err(|e| RecoveryError::io(e, dst))?;
    Ok(())
}

/// Clone `src` to `dst` (which must not exist). Tries APFS `clonefile` per file, falls back to a
/// verified byte copy. Returns a report; the caller verifies with `hash_dir`.
pub fn clone_tree(
    src: &Path,
    dst: &Path,
    src_manifest: &DirManifest,
    progress: &dyn ProgressSink,
    stage: Stage,
) -> Result<CloneReport> {
    clone_tree_with(src, dst, src_manifest, progress, stage, false)
}

/// `force_copy` skips `clonefile` so the byte-copy fallback can be exercised on one volume.
pub fn clone_tree_with(
    src: &Path,
    dst: &Path,
    src_manifest: &DirManifest,
    progress: &dyn ProgressSink,
    stage: Stage,
    force_copy: bool,
) -> Result<CloneReport> {
    if dst.exists() {
        return Err(
            RecoveryError::new(ErrorCode::CloneFailed, "clone destination already exists")
                .with_path(dst),
        );
    }
    let parent = dst.parent().ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::InvalidArgument,
            "clone destination has no parent",
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|e| RecoveryError::io(e, parent))?;
    let same_volume = same_device(src, parent)?;
    let available = available_bytes(parent)?;
    let total = src_manifest.total_bytes();
    // Even a clonefile needs metadata space; demand the full size when the volume differs, and a
    // generous margin otherwise so a clonefile→copy fallback cannot run out midway.
    let required = if same_volume {
        total / 10 + 64 * 1024 * 1024
    } else {
        total + 64 * 1024 * 1024
    };
    if available < required {
        return Err(RecoveryError::new(
            ErrorCode::CloneFailed,
            format!("destination has {available} bytes free; at least {required} bytes are needed"),
        )
        .with_path(parent)
        .with_remedy("Free space or choose a destination on a volume with enough room."));
    }
    let mut report = CloneReport {
        files: 0,
        bytes: 0,
        cloned_with_clonefile: 0,
        copied: 0,
        same_volume,
        available_bytes_before: available,
        required_bytes_estimate: required,
    };
    std::fs::create_dir(dst).map_err(|e| RecoveryError::io(e, dst))?;
    let n = src_manifest.files.len() as u64;
    for (i, (rel, (size, _))) in src_manifest.files.iter().enumerate() {
        progress.check_cancelled()?;
        let s = src.join(rel);
        let d = dst.join(rel);
        if let Some(p) = d.parent() {
            std::fs::create_dir_all(p).map_err(|e| RecoveryError::io(e, p))?;
        }
        let cloned = if force_copy {
            Err(std::io::Error::other("forced copy"))
        } else {
            clonefile(&s, &d)
        };
        match cloned {
            Ok(()) => report.cloned_with_clonefile += 1,
            Err(_) => {
                copy_verified(&s, &d)?;
                report.copied += 1;
            }
        }
        report.files += 1;
        report.bytes += size;
        progress.report(stage, i as u64 + 1, n);
    }
    // Mirror directory permissions loosely: everything the user can read/write.
    fn fix_dirs(p: &Path) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                if e.path().is_dir() {
                    let _ =
                        std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o700));
                    fix_dirs(&e.path());
                }
            }
        }
    }
    fix_dirs(dst);
    Ok(report)
}

/// Atomically replace `target` with the bytes of `new_file` (same directory temp + rename).
pub fn replace_file(target: &Path, new_file: &Path) -> Result<()> {
    let dir = target
        .parent()
        .ok_or_else(|| RecoveryError::new(ErrorCode::InvalidArgument, "target has no parent"))?;
    let tmp = dir.join(format!(
        ".{}.recovery-tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("payload")
    ));
    let mode = std::fs::metadata(target)
        .map(|m| m.permissions().mode())
        .unwrap_or(0o644);
    {
        let mut s = std::fs::File::open(new_file).map_err(|e| RecoveryError::io(e, new_file))?;
        let mut d = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| RecoveryError::io(e, &tmp))?;
        std::io::copy(&mut s, &mut d).map_err(|e| RecoveryError::io(e, &tmp))?;
        d.sync_all().map_err(|e| RecoveryError::io(e, &tmp))?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode & 0o777))
        .map_err(|e| RecoveryError::io(e, &tmp))?;
    std::fs::rename(&tmp, target).map_err(|e| RecoveryError::io(e, target))?;
    crate::session::workspace::fsync_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::NoProgress;

    fn tree(root: &Path) {
        std::fs::create_dir_all(root.join("ab")).unwrap();
        std::fs::write(root.join("Manifest.db"), vec![1u8; 70_000]).unwrap();
        std::fs::write(root.join("ab/abcdef"), vec![2u8; 123]).unwrap();
        std::fs::write(root.join("empty"), b"").unwrap();
    }

    #[test]
    fn clonefile_and_copy_fallback_produce_identical_trees() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        tree(&src);
        let manifest = hash_dir(&src, &NoProgress, Stage::Patching).unwrap();
        assert_eq!(manifest.files.len(), 3);
        let a = clone_tree_with(
            &src,
            &tmp.path().join("a"),
            &manifest,
            &NoProgress,
            Stage::Patching,
            false,
        )
        .unwrap();
        let b = clone_tree_with(
            &src,
            &tmp.path().join("b"),
            &manifest,
            &NoProgress,
            Stage::Patching,
            true,
        )
        .unwrap();
        assert_eq!(b.copied, 3);
        assert_eq!(b.cloned_with_clonefile, 0);
        assert_eq!(a.files + b.files, 6);
        for d in ["a", "b"] {
            let m = hash_dir(&tmp.path().join(d), &NoProgress, Stage::Patching).unwrap();
            assert!(manifest.diff(&m).is_empty(), "{d} differs");
        }
        // Source untouched.
        assert_eq!(
            hash_dir(&src, &NoProgress, Stage::Patching).unwrap(),
            manifest
        );
    }

    #[test]
    fn existing_destination_and_symlinks_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        tree(&src);
        let manifest = hash_dir(&src, &NoProgress, Stage::Patching).unwrap();
        std::fs::create_dir_all(tmp.path().join("exists")).unwrap();
        let err = clone_tree(
            &src,
            &tmp.path().join("exists"),
            &manifest,
            &NoProgress,
            Stage::Patching,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::CloneFailed);
        std::os::unix::fs::symlink("/etc/hosts", src.join("link")).unwrap();
        let err = hash_dir(&src, &NoProgress, Stage::Patching).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedBackup);
    }

    #[test]
    fn replace_file_is_atomic_and_keeps_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("payload");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let new = tmp.path().join("new");
        std::fs::write(&new, b"new-bytes").unwrap();
        replace_file(&target, &new).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new-bytes");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().contains("recovery-tmp")));
    }
}

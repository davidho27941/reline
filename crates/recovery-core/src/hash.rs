//! Streaming hashes with cooperative cancellation.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::progress::{ProgressSink, Stage};
use crate::{RecoveryError, Result};

/// Chunk size for all streaming operations (8 MiB keeps memory bounded on multi-GB files).
pub const CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// Lowercase hex SHA-256 digest.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Sha256Hex(pub String);

impl Sha256Hex {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Sha256Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.0)
    }
}

impl std::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// SHA-256 of a file read in bounded chunks. Reports progress and honours cancellation.
pub fn sha256_file(path: &Path, progress: &dyn ProgressSink, stage: Stage) -> Result<Sha256Hex> {
    let mut file = File::open(path).map_err(|e| RecoveryError::io(e, path))?;
    let total = file
        .metadata()
        .map_err(|e| RecoveryError::io(e, path))?
        .len();
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut done = 0u64;
    loop {
        progress.check_cancelled()?;
        let n = file
            .read(&mut buf)
            .map_err(|e| RecoveryError::io(e, path))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        done += n as u64;
        progress.report(stage, done, total);
    }
    Ok(Sha256Hex(hex::encode(hasher.finalize())))
}

/// SHA-1 lowercase hex (used only for Finder `fileID` derivation and `Digest` comparison).
pub fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::Sha1;
    hex::encode(Sha1::digest(bytes))
}

/// Finder backup file identifier: SHA-1 of `"<domain>-<relativePath>"`.
pub fn backup_file_id(domain: &str, relative_path: &str) -> String {
    sha1_hex(format!("{domain}-{relative_path}").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::NoProgress;

    #[test]
    fn file_id_matches_proven_case() {
        // From the proven case report: this domain + path yields this fileID.
        let id = backup_file_id(
            "AppDomainGroup-group.com.linecorp.line",
            "Library/Application Support/PrivateStore/P_ud1a36fb6aa96feb1303f7c2f0631b837/Messages/Line.sqlite",
        );
        assert_eq!(id, "d58dda5fd87caf774b139f9df5e8dc9914f0a12a");
    }

    #[test]
    fn sha256_of_file_matches_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.bin");
        let data: Vec<u8> = (0..(CHUNK_SIZE + 123)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        let h = sha256_file(&p, &NoProgress, Stage::Intake).unwrap();
        assert_eq!(h, Sha256Hex::of_bytes(&data));
    }
}

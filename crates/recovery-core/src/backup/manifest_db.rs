//! `Manifest.db` decryption, validation, and `MBFile` record decoding. See `docs/backup-format.md` §3–4.

use std::path::{Path, PathBuf};

use plist::Value;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::backup::keybag::UnlockedKeybag;
use crate::backup::payload;
use crate::progress::{ProgressSink, Stage};
use crate::secret::{Key256, SecretBytes};
use crate::{ErrorCode, RecoveryError, Result};

pub const FLAG_FILE: i64 = 1;
pub const FLAG_DIRECTORY: i64 = 2;
pub const FLAG_SYMLINK: i64 = 4;

/// Non-secret, reportable file metadata. `encryption_key` is kept separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    pub file_id: String,
    pub domain: String,
    pub relative_path: String,
    pub flags: i64,
    pub size: Option<u64>,
    pub protection_class: Option<u32>,
    pub has_encryption_key: bool,
    pub has_digest: bool,
    pub mode: Option<u32>,
    pub last_modified: Option<i64>,
}

impl FileRecord {
    pub fn is_regular_file(&self) -> bool {
        self.flags & FLAG_FILE != 0 && self.mode.map(|m| m & 0o170000 == 0o100000).unwrap_or(true)
    }

    pub fn payload_relative_path(&self) -> PathBuf {
        PathBuf::from(&self.file_id[..2]).join(&self.file_id)
    }
}

/// Decoded `MBFile` with its wrapped key.
pub struct FileEntry {
    pub record: FileRecord,
    pub encryption_key: Option<SecretBytes>,
    pub digest: Option<Vec<u8>>,
}

impl std::fmt::Debug for FileEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileEntry")
            .field("record", &self.record)
            .field("has_key", &self.encryption_key.is_some())
            .finish()
    }
}

/// Read-only handle over a decrypted `Manifest.db` living in the session workspace.
pub struct ManifestDb {
    conn: Connection,
    path: PathBuf,
}

impl std::fmt::Debug for ManifestDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestDb")
            .field("path", &self.path)
            .finish()
    }
}

/// Decrypt the source `Manifest.db` into `dst` using the unlocked keybag and `ManifestKey`.
pub fn decrypt_manifest_db(
    src: &Path,
    dst: &Path,
    keybag: &UnlockedKeybag,
    manifest_key: &[u8],
    progress: &dyn ProgressSink,
) -> Result<payload::StreamResult> {
    let key: Key256 = keybag.unwrap_manifest_key(manifest_key)?;
    let res = payload::decrypt_file(src, dst, &key, progress, Stage::Intake).map_err(|e| {
        if e.code == ErrorCode::CryptoFailure {
            RecoveryError::new(
                ErrorCode::MalformedMetadata,
                "Manifest.db could not be decrypted with the unlocked ManifestKey",
            )
            .with_path(src)
        } else {
            e
        }
    })?;
    Ok(res)
}

impl ManifestDb {
    /// Open a decrypted Manifest.db read-only and validate the `Files` schema.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| {
            RecoveryError::new(
                ErrorCode::MalformedMetadata,
                format!("Manifest.db cannot be opened: {e}"),
            )
            .with_path(path)
        })?;
        let header: String = conn
            .query_row("SELECT quick_check", [], |_r| Ok(String::new()))
            .or_else(|_| conn.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0)))
            .map_err(|e| {
                RecoveryError::new(
                    ErrorCode::MalformedMetadata,
                    format!("Manifest.db quick_check failed: {e}"),
                )
                .with_path(path)
            })?;
        if header != "ok" {
            return Err(RecoveryError::new(
                ErrorCode::MalformedMetadata,
                format!("Manifest.db quick_check: {header}"),
            )
            .with_path(path));
        }
        let mut cols: Vec<String> = Vec::new();
        {
            let mut stmt = conn.prepare("PRAGMA table_info(Files)")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
            for c in rows {
                cols.push(c?);
            }
        }
        for required in ["fileID", "domain", "relativePath", "flags", "file"] {
            if !cols.iter().any(|c| c == required) {
                return Err(RecoveryError::new(
                    ErrorCode::MalformedMetadata,
                    format!("Manifest.db Files table lacks column {required}"),
                )
                .with_path(path));
            }
        }
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_count(&self) -> Result<u64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM Files", [], |r| r.get::<_, i64>(0))? as u64)
    }

    /// Entries whose domain is in `domains`, ordered by domain then path (deterministic).
    pub fn entries_in_domains(&self, domains: &[&str]) -> Result<Vec<FileEntry>> {
        let mut out = Vec::new();
        let mut stmt = self.conn.prepare("SELECT fileID, domain, relativePath, flags, file FROM Files WHERE domain = ?1 ORDER BY relativePath")?;
        for d in domains {
            let rows = stmt.query_map([d], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?;
            for row in rows {
                let (file_id, domain, relative_path, flags, blob) = row?;
                out.push(decode_entry(
                    file_id,
                    domain,
                    relative_path,
                    flags,
                    blob.as_deref(),
                )?);
            }
        }
        Ok(out)
    }

    /// Single entry by exact domain + relativePath.
    pub fn entry(&self, domain: &str, relative_path: &str) -> Result<Option<FileEntry>> {
        let mut stmt = self.conn.prepare("SELECT fileID, domain, relativePath, flags, file FROM Files WHERE domain = ?1 AND relativePath = ?2")?;
        let mut rows = stmt.query_map([domain, relative_path], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })?;
        match rows.next() {
            None => Ok(None),
            Some(row) => {
                let (file_id, domain, relative_path, flags, blob) = row?;
                Ok(Some(decode_entry(
                    file_id,
                    domain,
                    relative_path,
                    flags,
                    blob.as_deref(),
                )?))
            }
        }
    }
}

fn decode_entry(
    file_id: String,
    domain: String,
    relative_path: String,
    flags: i64,
    blob: Option<&[u8]>,
) -> Result<FileEntry> {
    let expected = crate::hash::backup_file_id(&domain, &relative_path);
    if expected != file_id {
        return Err(RecoveryError::new(
            ErrorCode::MalformedMetadata,
            format!("fileID does not match SHA-1(domain-relativePath) for {relative_path}"),
        ));
    }
    let mut record = FileRecord {
        file_id,
        domain,
        relative_path,
        flags,
        size: None,
        protection_class: None,
        has_encryption_key: false,
        has_digest: false,
        mode: None,
        last_modified: None,
    };
    let mut encryption_key = None;
    let mut digest = None;
    if let Some(blob) = blob {
        let mb = MbFile::decode(blob)?;
        record.size = mb.size;
        record.protection_class = mb.protection_class;
        record.has_encryption_key = mb.encryption_key.is_some();
        record.has_digest = mb.digest.is_some();
        record.mode = mb.mode;
        record.last_modified = mb.last_modified;
        encryption_key = mb.encryption_key;
        digest = mb.digest;
    }
    Ok(FileEntry {
        record,
        encryption_key,
        digest,
    })
}

/// Decoded fields of an `MBFile` NSKeyedArchiver plist.
pub struct MbFile {
    pub size: Option<u64>,
    pub protection_class: Option<u32>,
    pub encryption_key: Option<SecretBytes>,
    pub digest: Option<Vec<u8>>,
    pub mode: Option<u32>,
    pub last_modified: Option<i64>,
    pub relative_path: Option<String>,
}

impl std::fmt::Debug for MbFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MbFile")
            .field("size", &self.size)
            .field("protection_class", &self.protection_class)
            .finish()
    }
}

impl MbFile {
    pub fn decode(blob: &[u8]) -> Result<Self> {
        let bad =
            |m: &str| RecoveryError::new(ErrorCode::MalformedMetadata, format!("MBFile: {m}"));
        let v = Value::from_reader(std::io::Cursor::new(blob))
            .map_err(|e| bad(&format!("plist: {e}")))?;
        let top = v.as_dictionary().ok_or_else(|| bad("not a dictionary"))?;
        let objects = top
            .get("$objects")
            .and_then(|o| o.as_array())
            .ok_or_else(|| bad("missing $objects"))?;
        let root_uid = top
            .get("$top")
            .and_then(|t| t.as_dictionary())
            .and_then(|t| t.get("root"))
            .and_then(|r| r.as_uid())
            .map(|u| u.get() as usize)
            .ok_or_else(|| bad("missing $top.root"))?;
        let root = objects
            .get(root_uid)
            .and_then(|o| o.as_dictionary())
            .ok_or_else(|| bad("root is not a dictionary"))?;
        let deref = |v: &Value| -> Option<Value> {
            match v {
                Value::Uid(u) => objects.get(u.get() as usize).cloned(),
                other => Some(other.clone()),
            }
        };
        let int = |k: &str| root.get(k).and_then(|v| v.as_unsigned_integer());
        let encryption_key = root
            .get("EncryptionKey")
            .and_then(deref)
            .and_then(|v| match v {
                Value::Data(d) => Some(d),
                Value::Dictionary(d) => d
                    .get("NS.data")
                    .and_then(|x| x.as_data())
                    .map(|x| x.to_vec()),
                _ => None,
            });
        let digest = root.get("Digest").and_then(deref).and_then(|v| match v {
            Value::Data(d) => Some(d),
            Value::Dictionary(d) => d
                .get("NS.data")
                .and_then(|x| x.as_data())
                .map(|x| x.to_vec()),
            _ => None,
        });
        let relative_path = root
            .get("RelativePath")
            .and_then(deref)
            .and_then(|v| v.as_string().map(|s| s.to_owned()));
        Ok(Self {
            size: int("Size"),
            protection_class: int("ProtectionClass").map(|c| c as u32),
            encryption_key: encryption_key.map(SecretBytes::new),
            digest,
            mode: int("Mode").map(|m| m as u32),
            last_modified: root.get("LastModified").and_then(|v| v.as_signed_integer()),
            relative_path,
        })
    }
}

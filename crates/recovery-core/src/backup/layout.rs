//! Directory layout, `Info.plist`, `Status.plist`, `Manifest.plist` validation (pre-password).

use std::path::{Path, PathBuf};

use plist::Value;
use serde::{Deserialize, Serialize};

use crate::report::time::format_rfc3339_utc;
use crate::{ErrorCode, RecoveryError, Result};

pub const INFO_PLIST: &str = "Info.plist";
pub const STATUS_PLIST: &str = "Status.plist";
pub const MANIFEST_PLIST: &str = "Manifest.plist";
pub const MANIFEST_DB: &str = "Manifest.db";

/// Non-secret backup metadata safe to display and to persist in the session manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInfo {
    pub backup_dir: PathBuf,
    pub udid: Option<String>,
    pub device_name: Option<String>,
    pub product_version: Option<String>,
    pub product_type: Option<String>,
    /// From `Status.plist` `Date`, RFC 3339 UTC.
    pub backup_date: Option<String>,
    pub snapshot_state: String,
    pub backup_state: Option<String>,
    pub is_full_backup: Option<bool>,
    pub status_version: Option<String>,
    pub status_uuid: Option<String>,
    pub is_encrypted: bool,
    pub manifest_version: Option<String>,
    /// Whether the keybag and ManifestKey are present (needed for decryption).
    pub has_keybag: bool,
    /// Number of payload shard directories (`00`..`ff`) present.
    pub payload_dirs: u32,
}

/// Raw encryption inputs from `Manifest.plist`. Not secrets by themselves (they are useless
/// without the password) but kept out of reports.
pub struct ManifestPlistCrypto {
    pub keybag: Vec<u8>,
    pub manifest_key: Vec<u8>,
}

impl std::fmt::Debug for ManifestPlistCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestPlistCrypto")
            .field("keybag_len", &self.keybag.len())
            .field("manifest_key_len", &self.manifest_key.len())
            .finish()
    }
}

fn read_plist(path: &Path) -> Result<Value> {
    match Value::from_file(path) {
        Ok(v) => Ok(v),
        Err(e) => {
            if !path.exists() {
                return Err(RecoveryError::new(
                    ErrorCode::InvalidBackupStructure,
                    format!("{} is missing", path.file_name().and_then(|n| n.to_str()).unwrap_or("file")),
                )
                .with_path(path)
                .with_remedy("Select the backup folder itself (the one named after the device UDID) and make sure the backup finished."));
            }
            if let Some(io) = e.as_io() {
                if io.kind() == std::io::ErrorKind::PermissionDenied {
                    return Err(RecoveryError::io(std::io::Error::from(io.kind()), path));
                }
            }
            Err(RecoveryError::new(
                ErrorCode::MalformedMetadata,
                format!("{}: {e}", path.display()),
            )
            .with_path(path))
        }
    }
}

fn str_key(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key)
        .and_then(|v| v.as_string())
        .map(|s| s.to_owned())
}

fn date_key(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key).and_then(|v| v.as_date()).map(|d| {
        let st: std::time::SystemTime = d.into();
        let secs = match st.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        };
        format_rfc3339_utc(secs)
    })
}

/// Validate the directory and read the three metadata plists. Does not need the password.
pub fn inspect(backup_dir: &Path) -> Result<(BackupInfo, ManifestPlistCrypto)> {
    let meta = std::fs::metadata(backup_dir).map_err(|e| RecoveryError::io(e, backup_dir))?;
    if !meta.is_dir() {
        return Err(RecoveryError::new(
            ErrorCode::InvalidBackupStructure,
            "selected path is not a directory",
        )
        .with_path(backup_dir));
    }
    // Probe readability of the directory listing first so TCC denials surface clearly.
    let rd = std::fs::read_dir(backup_dir).map_err(|e| RecoveryError::io(e, backup_dir))?;
    let mut payload_dirs = 0u32;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.len() == 2 && name.chars().all(|c| c.is_ascii_hexdigit()) && entry.path().is_dir() {
            payload_dirs += 1;
        }
    }

    let status = read_plist(&backup_dir.join(STATUS_PLIST))?;
    let status = status.as_dictionary().ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::MalformedMetadata,
            "Status.plist is not a dictionary",
        )
    })?;
    let manifest = read_plist(&backup_dir.join(MANIFEST_PLIST))?;
    let manifest = manifest.as_dictionary().ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::MalformedMetadata,
            "Manifest.plist is not a dictionary",
        )
    })?;
    let info = read_plist(&backup_dir.join(INFO_PLIST))?;
    let info = info.as_dictionary().ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::MalformedMetadata,
            "Info.plist is not a dictionary",
        )
    })?;
    let manifest_db = backup_dir.join(MANIFEST_DB);
    if !manifest_db.is_file() {
        return Err(RecoveryError::new(
            ErrorCode::InvalidBackupStructure,
            "Manifest.db is missing",
        )
        .with_path(&manifest_db));
    }

    let snapshot_state = str_key(status, "SnapshotState").unwrap_or_default();
    let is_encrypted = manifest
        .get("IsEncrypted")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);
    let lockdown = manifest.get("Lockdown").and_then(|v| v.as_dictionary());
    let keybag = manifest
        .get("BackupKeyBag")
        .and_then(|v| v.as_data())
        .map(|d| d.to_vec());
    let manifest_key = manifest
        .get("ManifestKey")
        .and_then(|v| v.as_data())
        .map(|d| d.to_vec());

    let backup_info = BackupInfo {
        backup_dir: backup_dir.to_path_buf(),
        udid: str_key(info, "Unique Identifier")
            .or_else(|| lockdown.and_then(|l| str_key(l, "UniqueDeviceID"))),
        device_name: str_key(info, "Device Name")
            .or_else(|| lockdown.and_then(|l| str_key(l, "DeviceName"))),
        product_version: str_key(info, "Product Version")
            .or_else(|| lockdown.and_then(|l| str_key(l, "ProductVersion"))),
        product_type: str_key(info, "Product Type"),
        backup_date: date_key(status, "Date").or_else(|| date_key(manifest, "Date")),
        snapshot_state: snapshot_state.clone(),
        backup_state: str_key(status, "BackupState"),
        is_full_backup: status.get("IsFullBackup").and_then(|v| v.as_boolean()),
        status_version: str_key(status, "Version"),
        status_uuid: str_key(status, "UUID"),
        is_encrypted,
        manifest_version: str_key(manifest, "Version"),
        has_keybag: keybag.is_some() && manifest_key.is_some(),
        payload_dirs,
    };

    if snapshot_state != "finished" {
        return Err(RecoveryError::new(
            ErrorCode::UnsupportedBackup,
            format!("backup snapshot state is '{snapshot_state}', expected 'finished'"),
        )
        .with_path(backup_dir)
        .with_remedy("The backup did not finish. Create a new encrypted backup and select it."));
    }
    if !is_encrypted {
        return Err(RecoveryError::new(
            ErrorCode::UnsupportedBackup,
            "backup is not encrypted; only encrypted backups carry the keybag this tool needs",
        )
        .with_path(backup_dir)
        .with_remedy("Enable 'Encrypt local backup' in Finder and create a new backup."));
    }
    let (Some(keybag), Some(manifest_key)) = (keybag, manifest_key) else {
        return Err(RecoveryError::new(
            ErrorCode::MalformedMetadata,
            "Manifest.plist lacks BackupKeyBag or ManifestKey",
        )
        .with_path(backup_dir));
    };
    if manifest_key.len() != 44 {
        return Err(RecoveryError::new(
            ErrorCode::MalformedMetadata,
            format!("ManifestKey has {} bytes, expected 44", manifest_key.len()),
        )
        .with_path(backup_dir));
    }
    Ok((
        backup_info,
        ManifestPlistCrypto {
            keybag,
            manifest_key,
        },
    ))
}

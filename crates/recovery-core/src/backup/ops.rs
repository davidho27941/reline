//! Intake orchestration: inspect (no password) and intake (authenticate, index, discover, extract).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::backup::discovery::{self, LineStore};
use crate::backup::keybag::Keybag;
use crate::backup::layout::{self, BackupInfo, MANIFEST_DB, MANIFEST_PLIST, STATUS_PLIST};
use crate::backup::manifest_db::{self, ManifestDb};
use crate::backup::payload;
use crate::hash::{sha256_file, Sha256Hex};
use crate::progress::{ProgressSink, Stage};
use crate::secret::Password;
use crate::session::driver::{BackupRole, Driver};
use crate::session::workspace::create_private_dir;
use crate::{ErrorCode, RecoveryError, Result};

pub const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Hashes of the source files the intake read. Recomputed after extraction to prove immutability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceHashes {
    pub manifest_db: Sha256Hex,
    pub manifest_plist: Sha256Hex,
    pub status_plist: Sha256Hex,
    pub line_payload: Option<Sha256Hex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedDatabase {
    /// Path inside the session workspace (plaintext area).
    pub plaintext_path: std::path::PathBuf,
    pub size: u64,
    pub sha256: Sha256Hex,
    pub payload_size: u64,
    pub sqlite_header_ok: bool,
    /// Manifest `Size` field, which may legitimately differ for live databases.
    pub manifest_declared_size: Option<u64>,
}

/// Non-secret intake evidence persisted in the session manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeEvidence {
    pub role: BackupRole,
    pub backup: BackupInfo,
    pub manifest_file_count: u64,
    pub source_hashes: SourceHashes,
    pub stores_found: Vec<StoreSummary>,
    pub selected_store: StoreSummary,
    pub line_db: ExtractedDatabase,
    /// Whether this backup's store may be patched (current role) — false when a WAL/journal is
    /// pending or metadata is outside the supported policy.
    pub patchable: bool,
    pub patchability_issues: Vec<String>,
    /// True when the source hashes were identical before and after extraction.
    pub source_unchanged: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSummary {
    pub domain: String,
    pub account_dir: String,
    pub relative_path: String,
    pub file_id: String,
    pub manifest_size: Option<u64>,
    pub protection_class: Option<u32>,
    pub has_digest: bool,
    pub siblings: Vec<String>,
    pub pending_journals: Vec<String>,
}

impl From<&LineStore> for StoreSummary {
    fn from(s: &LineStore) -> Self {
        Self {
            domain: s.domain.clone(),
            account_dir: s.account_dir.clone(),
            relative_path: s.relative_path.clone(),
            file_id: s.record.file_id.clone(),
            manifest_size: s.record.size,
            protection_class: s.record.protection_class,
            has_digest: s.record.has_digest,
            siblings: s.siblings.iter().map(|x| x.name.clone()).collect(),
            pending_journals: s
                .pending_journals()
                .iter()
                .map(|x| x.name.clone())
                .collect(),
        }
    }
}

pub fn inspect(_driver: &mut Driver, backup_dir: &Path) -> Result<serde_json::Value> {
    let (info, _crypto) = layout::inspect(backup_dir)?;
    Ok(serde_json::to_value(info)?)
}

/// Evaluate the metadata policy for the selected store (fail closed).
pub fn patchability_issues(
    store: &LineStore,
    keybag_has_class: impl Fn(u32) -> bool,
) -> Vec<String> {
    let mut issues = Vec::new();
    let rec = &store.record;
    match rec.protection_class {
        Some(c) if crate::backup::keybag::SUPPORTED_CLASSES.contains(&c) => {
            if !keybag_has_class(c) {
                issues.push(format!("keybag has no usable key for protection class {c}"));
            }
        }
        Some(c) => issues.push(format!(
            "protection class {c} is outside the supported set {{1, 3, 4}}"
        )),
        None => issues.push("MBFile lacks ProtectionClass".into()),
    }
    if !rec.has_encryption_key {
        issues.push("MBFile lacks EncryptionKey".into());
    }
    if rec.has_digest {
        issues.push("MBFile carries a Digest; updating digests is not supported".into());
    }
    if !rec.is_regular_file() {
        issues.push("Line.sqlite Manifest entry is not a regular file".into());
    }
    for j in store.pending_journals() {
        issues.push(format!(
            "sibling {} has non-zero size and could be replayed over the repaired database",
            j.name
        ));
    }
    issues
}

pub fn intake(
    driver: &mut Driver,
    role: BackupRole,
    backup_dir: &Path,
    account_dir: Option<&str>,
    password: Option<Password>,
    progress: &dyn ProgressSink,
) -> Result<serde_json::Value> {
    // Preserve the other role's evidence across this stage restart.
    let previous = driver
        .workspace
        .manifest()
        .stage(Stage::Intake)
        .evidence
        .clone();
    let staging = driver.workspace.begin_stage(Stage::Intake)?;
    driver.state.secure_plan = None;
    let result = intake_inner(
        driver,
        role,
        backup_dir,
        account_dir,
        password,
        progress,
        &staging,
        previous,
    );
    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            driver.state.keybags.remove(&role);
            let _ = remove_role_plaintext(driver, role);
            driver.workspace.fail_stage(Stage::Intake, &e)?;
            Err(e)
        }
    }
}

fn remove_role_plaintext(driver: &Driver, role: BackupRole) -> Result<()> {
    let dir = driver.workspace.plaintext_dir().join(role.as_str());
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| RecoveryError::io(e, &dir))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn intake_inner(
    driver: &mut Driver,
    role: BackupRole,
    backup_dir: &Path,
    account_dir: Option<&str>,
    password: Option<Password>,
    progress: &dyn ProgressSink,
    staging: &Path,
    previous_evidence: serde_json::Value,
) -> Result<serde_json::Value> {
    let (info, crypto) = layout::inspect(backup_dir)?;
    let password = password.ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::InvalidArgument,
            "backup password is required for intake",
        )
        .with_remedy("Enter the encrypted-backup password.")
    })?;
    progress.report(Stage::Intake, 0, 0);

    // Source hashes before any work.
    let before = SourceHashes {
        manifest_db: sha256_file(&backup_dir.join(MANIFEST_DB), progress, Stage::Intake)?,
        manifest_plist: sha256_file(&backup_dir.join(MANIFEST_PLIST), progress, Stage::Intake)?,
        status_plist: sha256_file(&backup_dir.join(STATUS_PLIST), progress, Stage::Intake)?,
        line_payload: None,
    };

    // Authenticate.
    let keybag = Keybag::parse(&crypto.keybag)?;
    let unlocked = keybag.unlock(&password)?;
    drop(password);

    // Decrypt the index into plaintext/<role>/.
    remove_role_plaintext(driver, role)?;
    let role_dir = driver.workspace.plaintext_dir().join(role.as_str());
    create_private_dir(&role_dir)?;
    let manifest_plain = role_dir.join(MANIFEST_DB);
    manifest_db::decrypt_manifest_db(
        &backup_dir.join(MANIFEST_DB),
        &manifest_plain,
        &unlocked,
        &crypto.manifest_key,
        progress,
    )?;
    let manifest = ManifestDb::open(&manifest_plain)?;
    let manifest_file_count = manifest.file_count()?;

    // Discover.
    let stores = discovery::discover(&manifest)?;
    let summaries: Vec<StoreSummary> = stores.iter().map(StoreSummary::from).collect();
    if stores.is_empty() {
        return Err(RecoveryError::new(ErrorCode::PayloadNotFound, "no LINE message database found in this backup")
            .with_path(backup_dir)
            .with_remedy("Make sure LINE was installed on the device when this backup was created, and that the backup is complete."));
    }
    let selected = match (stores.len(), account_dir) {
        (1, None) => &stores[0],
        (_, Some(acct)) => stores
            .iter()
            .find(|s| s.account_dir == acct)
            .ok_or_else(|| {
                RecoveryError::new(
                    ErrorCode::PayloadNotFound,
                    format!("no LINE store with account directory {acct}"),
                )
            })?,
        (_, None) => {
            let err = RecoveryError::new(
                ErrorCode::AmbiguousAccount,
                format!("{} LINE accounts found; select one", stores.len()),
            )
            .with_remedy("Choose the account directory to recover and run intake again.");
            driver.workspace.fail_stage(Stage::Intake, &err)?;
            return Ok(serde_json::json!({
                "status": "ambiguous_account",
                "role": role,
                "backup": info,
                "candidates": summaries,
            }));
        }
    };

    // Metadata policy and journal check.
    let mut warnings = Vec::new();
    let issues = patchability_issues(selected, |c| unlocked.has_class(c));
    let patchable = issues.is_empty();
    if !selected.pending_journals().is_empty() {
        warnings.push("A SQLite write-ahead log or journal is pending beside Line.sqlite; the extracted copy may lack the newest commits.".into());
    }

    // Extract the database (read-only source).
    let payload_path = backup_dir.join(selected.record.payload_relative_path());
    let payload_hash_before = sha256_file(&payload_path, progress, Stage::Intake)?;
    let enc_key = selected.encryption_key_for(&manifest)?;
    let class = selected.record.protection_class.ok_or_else(|| {
        RecoveryError::new(ErrorCode::UnsupportedMetadata, "missing ProtectionClass")
    })?;
    let file_key = unlocked.unwrap_file_key(class, &enc_key)?;
    let db_plain = role_dir.join(discovery::LINE_DB_NAME);
    let stream =
        payload::decrypt_file(&payload_path, &db_plain, &file_key, progress, Stage::Intake)?;
    drop(file_key);
    let mut header = [0u8; 16];
    {
        use std::io::Read;
        let mut f = std::fs::File::open(&db_plain).map_err(|e| RecoveryError::io(e, &db_plain))?;
        let _ = f
            .read(&mut header)
            .map_err(|e| RecoveryError::io(e, &db_plain))?;
    }
    let sqlite_header_ok = &header == SQLITE_MAGIC;
    if !sqlite_header_ok {
        return Err(RecoveryError::new(
            ErrorCode::DatabaseUnsupported,
            "decrypted Line.sqlite does not start with the SQLite header",
        )
        .with_path(&payload_path));
    }

    // Prove the source is unchanged.
    let after = SourceHashes {
        manifest_db: sha256_file(&backup_dir.join(MANIFEST_DB), progress, Stage::Intake)?,
        manifest_plist: sha256_file(&backup_dir.join(MANIFEST_PLIST), progress, Stage::Intake)?,
        status_plist: sha256_file(&backup_dir.join(STATUS_PLIST), progress, Stage::Intake)?,
        line_payload: Some(sha256_file(&payload_path, progress, Stage::Intake)?),
    };
    let source_unchanged = after.manifest_db == before.manifest_db
        && after.manifest_plist == before.manifest_plist
        && after.status_plist == before.status_plist
        && after.line_payload.as_ref() == Some(&payload_hash_before);
    if !source_unchanged {
        return Err(RecoveryError::new(ErrorCode::VerificationFailed, "source backup changed during intake; is Finder writing to it?")
            .with_path(backup_dir)
            .with_remedy("Disconnect the iPhone, make sure no backup is running, and select a preserved copy of the backup."));
    }

    let evidence = IntakeEvidence {
        role,
        backup: info,
        manifest_file_count,
        source_hashes: SourceHashes {
            line_payload: Some(payload_hash_before),
            ..before
        },
        stores_found: summaries,
        selected_store: StoreSummary::from(selected),
        line_db: ExtractedDatabase {
            plaintext_path: db_plain.clone(),
            size: stream.output_size,
            sha256: stream.output_sha256.clone(),
            payload_size: stream.input_size,
            sqlite_header_ok,
            manifest_declared_size: selected.record.size,
        },
        patchable,
        patchability_issues: issues,
        source_unchanged,
        warnings,
    };

    // Merge with the other role and commit.
    let mut merged = match previous_evidence {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    merged.insert(role.as_str().to_owned(), serde_json::to_value(&evidence)?);
    let mut outputs = Vec::new();
    for (k, v) in &merged {
        let p = staging.join(format!("intake-{k}.json"));
        let mut f = crate::session::workspace::create_private_file(&p)?;
        use std::io::Write;
        f.write_all(&serde_json::to_vec_pretty(v)?)
            .map_err(|e| RecoveryError::io(e, &p))?;
        outputs.push((p, false));
    }
    driver.state.keybags.insert(role, unlocked);
    driver.workspace.commit_stage(
        Stage::Intake,
        &outputs,
        serde_json::Value::Object(merged),
        progress,
    )?;
    let mut inputs = match driver.workspace.manifest().inputs.clone() {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    inputs.insert(
        format!("{}_backup_dir", role.as_str()),
        serde_json::json!(backup_dir),
    );
    driver.workspace.manifest_mut().inputs = serde_json::Value::Object(inputs);
    driver.workspace.write_manifest()?;
    Ok(serde_json::json!({ "status": "ok", "intake": evidence }))
}

impl LineStore {
    /// Fetch the wrapped file key for this store from the manifest.
    pub fn encryption_key_for(&self, manifest: &ManifestDb) -> Result<crate::secret::SecretBytes> {
        let entry = manifest
            .entry(&self.domain, &self.relative_path)?
            .ok_or_else(|| {
                RecoveryError::new(
                    ErrorCode::PayloadNotFound,
                    "LINE store vanished from Manifest.db",
                )
            })?;
        entry.encryption_key.ok_or_else(|| {
            RecoveryError::new(ErrorCode::UnsupportedMetadata, "MBFile lacks EncryptionKey")
        })
    }
}

/// Load committed intake evidence for a role, if present.
pub fn load_evidence(driver: &Driver, role: BackupRole) -> Result<IntakeEvidence> {
    let stage = driver.workspace.manifest().stage(Stage::Intake);
    if stage.state != crate::session::StageState::Committed {
        return Err(
            RecoveryError::new(ErrorCode::SessionState, "intake has not been committed")
                .with_remedy("Run intake for both backups first."),
        );
    }
    let v = stage.evidence.get(role.as_str()).cloned().ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::SessionState,
            format!("intake for the {} backup has not been run", role.as_str()),
        )
    })?;
    Ok(serde_json::from_value(v)?)
}

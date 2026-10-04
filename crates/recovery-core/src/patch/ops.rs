//! Patch and export orchestration.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::backup::keybag::{Keybag, UnlockedKeybag};
use crate::backup::layout;
use crate::backup::manifest_db::ManifestDb;
use crate::backup::ops::{load_evidence, IntakeEvidence};
use crate::backup::payload;
use crate::hash::{sha256_file, Sha256Hex};
use crate::patch::clone::{clone_tree, hash_dir, replace_file, CloneReport, DirManifest};
use crate::progress::{ProgressSink, Stage};
use crate::repair::{post_repair, repair_working_copy, RepairResult, RepairValidation};
use crate::secret::Password;
use crate::session::driver::{BackupRole, Driver, PatchConfirmation};
use crate::session::workspace::create_private_dir;
use crate::session::StageState;
use crate::{ErrorCode, RecoveryError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionEvidence {
    pub plaintext_size: u64,
    pub plaintext_sha256: Sha256Hex,
    pub payload_size: u64,
    pub payload_sha256: Sha256Hex,
    pub protection_class: u32,
    pub round_trip_sha256: Sha256Hex,
    pub round_trip_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchEvidence {
    pub plan_id: String,
    pub repair: RepairResult,
    pub validation: RepairValidation,
    pub encryption: EncryptionEvidence,
    pub clone: CloneReport,
    pub clone_dir: PathBuf,
    pub rollback_source_dir: PathBuf,
    pub source_manifest_digest: Sha256Hex,
    pub source_unchanged_after_clone: bool,
    pub replaced_relative_path: PathBuf,
    pub clone_differs_only_at: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub clone_dir: PathBuf,
    pub structure_ok: bool,
    pub snapshot_state: String,
    pub manifest_db_unchanged: bool,
    pub manifest_plist_unchanged: bool,
    pub reread_plaintext_size: u64,
    pub reread_sha256: Sha256Hex,
    pub expected_sha256: Sha256Hex,
    pub hash_matches: bool,
    pub integrity_ok: bool,
    pub integrity_detail: Vec<String>,
    pub gates: Vec<(String, bool)>,
    pub all_gates_passed: bool,
}

fn staging_clone_root(destination_dir: &Path, session_id: &str) -> PathBuf {
    destination_dir.join(format!(".reline-staging-{session_id}"))
}

fn keybag_for_current(
    driver: &mut Driver,
    cur_ev: &IntakeEvidence,
    password: Option<Password>,
) -> Result<()> {
    if driver.state.keybags.contains_key(&BackupRole::Current) {
        return Ok(());
    }
    let pw = password.ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::InvalidArgument,
            "the current backup password is required to patch",
        )
        .with_remedy("Enter the encrypted-backup password.")
    })?;
    let (_info, crypto) = layout::inspect(&cur_ev.backup.backup_dir)?;
    let unlocked = Keybag::parse(&crypto.keybag)?.unlock(&pw)?;
    driver.state.keybags.insert(BackupRole::Current, unlocked);
    Ok(())
}

pub fn patch(
    driver: &mut Driver,
    destination_dir: &Path,
    confirm: &PatchConfirmation,
    password: Option<Password>,
    progress: &dyn ProgressSink,
) -> Result<serde_json::Value> {
    // --- Gates before any stage begins ---
    let plan = crate::analysis::ops::load_plan(driver)?;
    if !plan.actionable {
        return Err(RecoveryError::new(
            ErrorCode::AnalysisUnsupported,
            "the repair plan is diagnostic-only; patching is disabled",
        ));
    }
    let secure = driver.state.secure_plan.clone().ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::SessionState,
            "the in-memory repair plan is not available (session was resumed)",
        )
        .with_remedy("Run analysis again in this session before patching.")
    })?;
    if secure.plan.plan_id != plan.plan_id {
        return Err(RecoveryError::new(
            ErrorCode::PlanInvalidated,
            "in-memory plan does not match the committed plan",
        ));
    }
    let cur_ev = load_evidence(driver, BackupRole::Current)?;
    if !cur_ev.patchable {
        return Err(RecoveryError::new(
            ErrorCode::UnsupportedMetadata,
            format!(
                "current backup cannot be patched: {}",
                cur_ev.patchability_issues.join("; ")
            ),
        ));
    }
    if confirm.predicted_update_count != plan.predicted_update_count
        || confirm.plan_id != plan.plan_id
        || confirm.destination_dir != destination_dir
        || confirm.rollback_source_dir != cur_ev.backup.backup_dir
    {
        return Err(RecoveryError::new(
            ErrorCode::InvalidArgument,
            "mutation confirmation does not match the plan, destination, or rollback source",
        )
        .with_remedy("Review the plan summary again and confirm the exact values shown."));
    }
    if !destination_dir.is_dir() {
        return Err(RecoveryError::new(
            ErrorCode::InvalidArgument,
            "destination is not an existing directory",
        )
        .with_path(destination_dir));
    }
    let src_dir = cur_ev.backup.backup_dir.clone();
    let dest_canon = std::fs::canonicalize(destination_dir)
        .map_err(|e| RecoveryError::io(e, destination_dir))?;
    let src_canon = std::fs::canonicalize(&src_dir).map_err(|e| RecoveryError::io(e, &src_dir))?;
    if dest_canon.starts_with(&src_canon) || src_canon.starts_with(&dest_canon) {
        return Err(RecoveryError::new(
            ErrorCode::InvalidArgument,
            "destination must not be inside the source backup (or contain it)",
        )
        .with_path(destination_dir));
    }
    keybag_for_current(driver, &cur_ev, password)?;

    let staging = driver.workspace.begin_stage(Stage::Patching)?;
    let session_id = driver.workspace.manifest().session_id.clone();
    let clone_root = staging_clone_root(destination_dir, &session_id);
    let clone_dir = clone_root.join(
        cur_ev
            .backup
            .udid
            .clone()
            .unwrap_or_else(|| "backup".into()),
    );
    let result = patch_inner(
        driver,
        &secure,
        &cur_ev,
        &staging,
        &clone_root,
        &clone_dir,
        progress,
    );
    match result {
        Ok(ev) => {
            let verification = verify_inner(driver, &cur_ev, &ev, progress);
            match verification {
                Ok(v) => {
                    Ok(serde_json::json!({ "status": "verified", "patch": ev, "verification": v }))
                }
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&clone_root);
                    driver.workspace.fail_stage(Stage::Verification, &e)?;
                    Err(e)
                }
            }
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&clone_root);
            driver.workspace.fail_stage(Stage::Patching, &e)?;
            Err(e)
        }
    }
}

fn patch_inner(
    driver: &mut Driver,
    secure: &crate::analysis::plan::SecurePlan,
    cur_ev: &IntakeEvidence,
    staging: &Path,
    clone_root: &Path,
    clone_dir: &Path,
    progress: &dyn ProgressSink,
) -> Result<PatchEvidence> {
    // 1. Transactional repair of a fresh working copy.
    let repaired = staging.join(crate::repair::ops::REPAIRED_NAME);
    let repair = repair_working_copy(secure, &repaired, progress)?;
    progress.check_cancelled()?;

    // 2. Post-repair gates.
    let validation = post_repair(secure, &repaired, progress)?;
    if !validation.all_passed {
        // Retain for expert inspection, explicitly unverified.
        let keep = driver
            .workspace
            .plaintext_path(crate::repair::ops::UNVERIFIED_NAME);
        let _ = std::fs::rename(&repaired, &keep);
        return Err(RecoveryError::new(ErrorCode::VerificationFailed, format!("post-repair validation failed: {}", validation.failed_gates.join("; ")))
            .with_remedy("The repaired database was kept as 'unverified' for expert inspection. No payload was encrypted and no clone was created."));
    }

    // 3. Encrypt with the original per-file key.
    let unlocked: &UnlockedKeybag = driver
        .state
        .keybags
        .get(&BackupRole::Current)
        .expect("ensured");
    let manifest = ManifestDb::open(
        &driver
            .workspace
            .plaintext_dir()
            .join(BackupRole::Current.as_str())
            .join(layout::MANIFEST_DB),
    )?;
    let entry = manifest
        .entry(
            &cur_ev.selected_store.domain,
            &cur_ev.selected_store.relative_path,
        )?
        .ok_or_else(|| {
            RecoveryError::new(
                ErrorCode::PayloadNotFound,
                "LINE store missing from Manifest.db",
            )
        })?;
    let class = entry.record.protection_class.ok_or_else(|| {
        RecoveryError::new(ErrorCode::UnsupportedMetadata, "missing ProtectionClass")
    })?;
    if entry.record.has_digest {
        return Err(RecoveryError::new(
            ErrorCode::UnsupportedMetadata,
            "MBFile carries a Digest; not supported",
        ));
    }
    let ek = entry.encryption_key.as_ref().ok_or_else(|| {
        RecoveryError::new(ErrorCode::UnsupportedMetadata, "missing EncryptionKey")
    })?;
    let file_key = unlocked.unwrap_file_key(class, ek)?;
    let payload_path = staging.join("payload.enc");
    let enc = payload::encrypt_file(
        &repaired,
        &payload_path,
        &file_key,
        progress,
        Stage::Patching,
    )?;
    if enc.output_size != payload::ciphertext_len(validation.pages_after.file_size) {
        return Err(RecoveryError::new(
            ErrorCode::CryptoFailure,
            "ciphertext size does not match PKCS#7 expectation",
        ));
    }
    // 4. Mandatory round trip.
    let roundtrip = staging.join("roundtrip.sqlite");
    let dec = payload::decrypt_file(
        &payload_path,
        &roundtrip,
        &file_key,
        progress,
        Stage::Patching,
    )?;
    drop(file_key);
    let round_trip_ok = dec.output_sha256 == validation.repaired_sha256
        && dec.output_size == validation.pages_after.file_size;
    let _ = std::fs::remove_file(&roundtrip);
    if !round_trip_ok {
        return Err(RecoveryError::new(
            ErrorCode::CryptoFailure,
            "decrypting the generated payload did not reproduce the repaired database",
        ));
    }
    let encryption = EncryptionEvidence {
        plaintext_size: validation.pages_after.file_size,
        plaintext_sha256: validation.repaired_sha256.clone(),
        payload_size: enc.output_size,
        payload_sha256: enc.output_sha256.clone(),
        protection_class: class,
        round_trip_sha256: dec.output_sha256,
        round_trip_ok,
    };
    progress.check_cancelled()?;

    // 5. Clone the source backup (read-only source, hashed before and after).
    let src_dir = &cur_ev.backup.backup_dir;
    let source_manifest: DirManifest = hash_dir(src_dir, progress, Stage::Patching)?;
    if clone_root.exists() {
        std::fs::remove_dir_all(clone_root).map_err(|e| RecoveryError::io(e, clone_root))?;
    }
    create_private_dir(clone_root)?;
    let clone = clone_tree(
        src_dir,
        clone_dir,
        &source_manifest,
        progress,
        Stage::Patching,
    )?;
    let clone_manifest = hash_dir(clone_dir, progress, Stage::Patching)?;
    let diff = source_manifest.diff(&clone_manifest);
    if !diff.is_empty() {
        return Err(RecoveryError::new(
            ErrorCode::CloneFailed,
            format!(
                "clone differs from source at {} paths before patching",
                diff.len()
            ),
        ));
    }

    // 6. Replace the payload only inside the clone.
    let rel =
        PathBuf::from(&cur_ev.selected_store.file_id[..2]).join(&cur_ev.selected_store.file_id);
    replace_file(&clone_dir.join(&rel), &payload_path)?;
    let after_manifest = hash_dir(clone_dir, progress, Stage::Patching)?;
    let differs = source_manifest.diff(&after_manifest);
    if differs != vec![rel.clone()] {
        return Err(RecoveryError::new(
            ErrorCode::VerificationFailed,
            format!("clone differs from source at unexpected paths: {differs:?}"),
        ));
    }
    if after_manifest.files.get(&rel).map(|(_, h)| h) != Some(&enc.output_sha256) {
        return Err(RecoveryError::new(
            ErrorCode::VerificationFailed,
            "replaced payload hash mismatch",
        ));
    }
    let source_after = hash_dir(src_dir, progress, Stage::Patching)?;
    let source_unchanged = source_after == source_manifest;
    if !source_unchanged {
        return Err(RecoveryError::new(
            ErrorCode::VerificationFailed,
            "source backup changed during patching",
        )
        .with_path(src_dir));
    }

    let evidence = PatchEvidence {
        plan_id: secure.plan.plan_id.clone(),
        repair,
        validation,
        encryption,
        clone,
        clone_dir: clone_dir.to_path_buf(),
        rollback_source_dir: src_dir.clone(),
        source_manifest_digest: source_manifest.digest(),
        source_unchanged_after_clone: source_unchanged,
        replaced_relative_path: rel,
        clone_differs_only_at: differs,
    };
    let ev_json = serde_json::to_value(&evidence)?;
    driver.workspace.commit_stage(
        Stage::Patching,
        &[(repaired, true), (payload_path, false)],
        ev_json,
        progress,
    )?;
    Ok(evidence)
}

/// Re-read the clone through the normal backup-reading path.
fn verify_inner(
    driver: &mut Driver,
    cur_ev: &IntakeEvidence,
    patch: &PatchEvidence,
    progress: &dyn ProgressSink,
) -> Result<VerificationEvidence> {
    let staging = driver.workspace.begin_stage(Stage::Verification)?;
    let clone_dir = &patch.clone_dir;
    let (info, crypto) = layout::inspect(clone_dir)?;
    let unlocked = driver
        .state
        .keybags
        .get(&BackupRole::Current)
        .expect("ensured");
    // The keybag inside the clone must still unlock the same class keys: re-parse and compare by
    // unwrapping the ManifestKey with the in-memory keybag.
    let _ = Keybag::parse(&crypto.keybag)?;
    let manifest_plain = staging.join(layout::MANIFEST_DB);
    crate::backup::manifest_db::decrypt_manifest_db(
        &clone_dir.join(layout::MANIFEST_DB),
        &manifest_plain,
        unlocked,
        &crypto.manifest_key,
        progress,
    )?;
    let manifest = ManifestDb::open(&manifest_plain)?;
    let stores = crate::backup::discovery::discover(&manifest)?;
    let store = stores
        .iter()
        .find(|s| s.account_dir == cur_ev.selected_store.account_dir)
        .ok_or_else(|| {
            RecoveryError::new(ErrorCode::PayloadNotFound, "LINE store not found in clone")
        })?;
    let ek = store.encryption_key_for(&manifest)?;
    let class = store.record.protection_class.ok_or_else(|| {
        RecoveryError::new(ErrorCode::UnsupportedMetadata, "missing ProtectionClass")
    })?;
    let key = unlocked.unwrap_file_key(class, &ek)?;
    let reread = staging.join("reread.sqlite");
    let dec = payload::decrypt_file(
        &clone_dir.join(store.record.payload_relative_path()),
        &reread,
        &key,
        progress,
        Stage::Verification,
    )?;
    drop(key);
    let (integrity_detail, integrity_ok) = {
        let c = crate::analysis::schema::open_read_only(&reread)?;
        let d = crate::analysis::schema::integrity_check(&c)?;
        let ok = d.len() == 1 && d[0] == "ok";
        (d, ok)
    };
    let manifest_db_unchanged = sha256_file(
        &clone_dir.join(layout::MANIFEST_DB),
        progress,
        Stage::Verification,
    )? == cur_ev.source_hashes.manifest_db;
    let manifest_plist_unchanged = sha256_file(
        &clone_dir.join(layout::MANIFEST_PLIST),
        progress,
        Stage::Verification,
    )? == cur_ev.source_hashes.manifest_plist;
    let hash_matches = dec.output_sha256 == patch.encryption.plaintext_sha256
        && dec.output_size == patch.encryption.plaintext_size;
    let gates = vec![
        (
            "clone has a valid, finished backup structure".to_string(),
            info.snapshot_state == "finished",
        ),
        (
            "Manifest.db byte-identical to source".to_string(),
            manifest_db_unchanged,
        ),
        (
            "Manifest.plist byte-identical to source".to_string(),
            manifest_plist_unchanged,
        ),
        (
            "re-read plaintext hash equals repaired database hash".to_string(),
            hash_matches,
        ),
        (
            "re-read database passes integrity_check".to_string(),
            integrity_ok,
        ),
        (
            "clone differs from source only at the approved payload".to_string(),
            patch.clone_differs_only_at == vec![patch.replaced_relative_path.clone()],
        ),
    ];
    let all = gates.iter().all(|(_, ok)| *ok);
    let _ = std::fs::remove_file(&reread);
    let ev = VerificationEvidence {
        clone_dir: clone_dir.clone(),
        structure_ok: true,
        snapshot_state: info.snapshot_state.clone(),
        manifest_db_unchanged,
        manifest_plist_unchanged,
        reread_plaintext_size: dec.output_size,
        reread_sha256: dec.output_sha256,
        expected_sha256: patch.encryption.plaintext_sha256.clone(),
        hash_matches,
        integrity_ok,
        integrity_detail,
        gates: gates.clone(),
        all_gates_passed: all,
    };
    if !all {
        let failed: Vec<&str> = gates
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(g, _)| g.as_str())
            .collect();
        return Err(RecoveryError::new(
            ErrorCode::VerificationFailed,
            format!("clone re-read failed: {}", failed.join("; ")),
        )
        .with_remedy("The clone was discarded. The source backup is unchanged."));
    }
    let ev_json = serde_json::to_value(&ev)?;
    driver
        .workspace
        .commit_stage(Stage::Verification, &[], ev_json, progress)?;
    Ok(ev)
}

/// Load committed patch/verification evidence.
pub fn load_patch_evidence(driver: &Driver) -> Result<(PatchEvidence, VerificationEvidence)> {
    let m = driver.workspace.manifest();
    let p = m.stage(Stage::Patching);
    let v = m.stage(Stage::Verification);
    if p.state != StageState::Committed || v.state != StageState::Committed {
        return Err(RecoveryError::new(
            ErrorCode::SessionState,
            "patching and verification must both be committed before export",
        )
        .with_remedy("Run patching first."));
    }
    Ok((
        serde_json::from_value(p.evidence.clone())?,
        serde_json::from_value(v.evidence.clone())?,
    ))
}

/// Export the verified clone under a new name next to it, plus reports and instructions.
pub fn export(
    driver: &mut Driver,
    destination_dir: &Path,
    overwrite_confirmed: bool,
    progress: &dyn ProgressSink,
) -> Result<serde_json::Value> {
    let (patch_ev, ver_ev) = load_patch_evidence(driver)?;
    if !ver_ev.all_gates_passed {
        return Err(RecoveryError::new(
            ErrorCode::VerificationFailed,
            "clone is not verified; export is disabled",
        ));
    }
    if !patch_ev.clone_dir.exists() {
        return Err(RecoveryError::new(
            ErrorCode::SessionState,
            "the verified clone is no longer present",
        )
        .with_path(&patch_ev.clone_dir));
    }
    let cur_ev = load_evidence(driver, BackupRole::Current)?;
    let udid = cur_ev
        .backup
        .udid
        .clone()
        .unwrap_or_else(|| "backup".into());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let stamp = crate::report::time::format_rfc3339_utc(now)
        .replace([':', '-'], "")
        .replace("T", "-")
        .trim_end_matches("+0000")
        .to_owned();
    let final_dir = destination_dir.join(format!("{udid}_PATCHED_{stamp}"));
    if final_dir.exists() {
        if !overwrite_confirmed {
            return Err(RecoveryError::new(
                ErrorCode::ExportConflict,
                "an export with this name already exists",
            )
            .with_path(&final_dir)
            .with_remedy("Choose another destination, or confirm overwrite explicitly."));
        }
        std::fs::remove_dir_all(&final_dir).map_err(|e| RecoveryError::io(e, &final_dir))?;
    }
    let staging = driver.workspace.begin_stage(Stage::Export)?;
    let res = (|| -> Result<serde_json::Value> {
        std::fs::rename(&patch_ev.clone_dir, &final_dir)
            .map_err(|e| RecoveryError::io(e, &final_dir))?;
        let _ = std::fs::remove_dir(patch_ev.clone_dir.parent().unwrap_or(destination_dir));
        let bundle = crate::report::ops::build(driver, false, Some(&final_dir))?;
        let base = final_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("export")
            .to_owned();
        let md = destination_dir.join(format!("{base}.report.md"));
        let js = destination_dir.join(format!("{base}.report.json"));
        let ins = destination_dir.join(format!("{base}.RESTORE-INSTRUCTIONS.md"));
        for (p, body) in [
            (&md, bundle.markdown.as_bytes()),
            (&js, serde_json::to_vec_pretty(&bundle.json)?.as_slice()),
            (&ins, bundle.instructions.as_bytes()),
        ] {
            if p.exists() && !overwrite_confirmed {
                return Err(RecoveryError::new(
                    ErrorCode::ExportConflict,
                    "report file already exists",
                )
                .with_path(p));
            }
            std::fs::write(p, body).map_err(|e| RecoveryError::io(e, p))?;
        }
        let ev_copy = staging.join("export.json");
        let ev = serde_json::json!({ "exported_backup_dir": final_dir, "report_markdown": md, "report_json": js, "instructions": ins, "rollback_source_dir": patch_ev.rollback_source_dir });
        std::fs::write(&ev_copy, serde_json::to_vec_pretty(&ev)?)
            .map_err(|e| RecoveryError::io(e, &ev_copy))?;
        driver
            .workspace
            .commit_stage(Stage::Export, &[(ev_copy, false)], ev.clone(), progress)?;
        Ok(serde_json::json!({ "status": "exported", "export": ev }))
    })();
    match res {
        Ok(v) => Ok(v),
        Err(e) => {
            driver.workspace.fail_stage(Stage::Export, &e)?;
            Err(e)
        }
    }
}

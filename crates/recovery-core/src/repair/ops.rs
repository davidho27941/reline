//! Repaired-database export for expert inspection (task 5.4).

use std::path::Path;

use crate::progress::{ProgressSink, Stage};
use crate::session::driver::Driver;
use crate::session::StageState;
use crate::{ErrorCode, RecoveryError, Result};

pub const UNVERIFIED_NAME: &str = "repaired-unverified.sqlite";
pub const REPAIRED_NAME: &str = "repaired.sqlite";

/// Export the repaired plaintext database with an explicit verification state sidecar.
/// Default never overwrites; `overwrite_confirmed` is a separate explicit consent.
pub fn export_repaired_database(
    driver: &mut Driver,
    destination_file: &Path,
    overwrite_confirmed: bool,
    progress: &dyn ProgressSink,
) -> Result<serde_json::Value> {
    let manifest = driver.workspace.manifest();
    let patching = manifest.stage(Stage::Patching);
    let verification = manifest.stage(Stage::Verification);
    // Verified only when every post-repair gate passed AND the clone re-read passed.
    let (source, state, failed_gates) = if patching.state == StageState::Committed
        && verification.state == StageState::Committed
        && verification.evidence.get("all_gates_passed") == Some(&serde_json::Value::Bool(true))
    {
        let rec = patching
            .outputs
            .iter()
            .find(|o| o.path.file_name().and_then(|n| n.to_str()) == Some(REPAIRED_NAME))
            .ok_or_else(|| {
                RecoveryError::new(
                    ErrorCode::SessionState,
                    "repaired database is no longer retained in the session",
                )
                .with_remedy("Run patching again.")
            })?;
        (
            driver.workspace.root().join(&rec.path),
            "verified",
            Vec::new(),
        )
    } else {
        let p = driver.workspace.plaintext_path(UNVERIFIED_NAME);
        if !p.exists() {
            return Err(RecoveryError::new(
                ErrorCode::SessionState,
                "no repaired database is available",
            )
            .with_remedy("Run patching first."));
        }
        let gates: Vec<String> = patching
            .error
            .iter()
            .map(|e| e.message.clone())
            .chain(verification.error.iter().map(|e| e.message.clone()))
            .collect();
        (p, "unverified", gates)
    };
    if destination_file.exists() && !overwrite_confirmed {
        return Err(RecoveryError::new(
            ErrorCode::ExportConflict,
            "destination file already exists",
        )
        .with_path(destination_file)
        .with_remedy("Choose a new name, or confirm overwrite explicitly."));
    }
    let sidecar = {
        let mut s = destination_file.as_os_str().to_owned();
        s.push(".recovery.json");
        std::path::PathBuf::from(s)
    };
    std::fs::copy(&source, destination_file).map_err(|e| RecoveryError::io(e, destination_file))?;
    let sha = crate::hash::sha256_file(destination_file, progress, Stage::Export)?;
    let plan_id = manifest
        .stage(Stage::Analysis)
        .evidence
        .get("plan")
        .and_then(|p| p.get("plan_id"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let meta = serde_json::json!({
        "state": state,
        "sha256": sha,
        "plan_id": plan_id,
        "failed_gates": failed_gates,
        "warning": "This file contains decrypted private chat data. It is not a backup payload and must not be copied into a Finder backup.",
    });
    std::fs::write(&sidecar, serde_json::to_vec_pretty(&meta)?)
        .map_err(|e| RecoveryError::io(e, &sidecar))?;
    Ok(
        serde_json::json!({ "status": "ok", "destination": destination_file, "sidecar": sidecar, "state": state, "sha256": sha }),
    )
}

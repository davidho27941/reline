//! Audit report: Markdown + JSON built from the session manifest. Never reads plaintext.

use std::path::Path;

use crate::progress::Stage;
use crate::session::driver::Driver;
use crate::{RecoveryError, Result};

#[derive(Debug, Clone)]
pub struct ReportBundle {
    pub markdown: String,
    pub json: serde_json::Value,
    pub instructions: String,
}

fn redact_value(salt: &str, v: &str) -> String {
    format!(
        "redacted:{}",
        crate::analysis::plan::public_id(salt, v)[..12].to_owned()
    )
}

fn collect_sensitive_identifiers(m: &crate::session::SessionManifest) -> Vec<String> {
    let mut out = Vec::new();
    let intake = &m.stage(Stage::Intake).evidence;
    for role in ["old", "current"] {
        if let Some(ev) = intake.get(role) {
            if let Some(u) = ev.pointer("/backup/udid").and_then(|v| v.as_str()) {
                out.push(u.to_owned());
            }
            if let Some(a) = ev
                .pointer("/selected_store/account_dir")
                .and_then(|v| v.as_str())
            {
                out.push(a.to_owned());
            }
            if let Some(arr) = ev.get("stores_found").and_then(|v| v.as_array()) {
                for s in arr {
                    if let Some(a) = s.get("account_dir").and_then(|v| v.as_str()) {
                        out.push(a.to_owned());
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out.retain(|s| s.len() >= 8);
    out
}

fn redact_json(v: &mut serde_json::Value, salt: &str, ids: &[String]) {
    match v {
        serde_json::Value::String(s) => {
            for id in ids {
                if s.contains(id.as_str()) {
                    *s = s.replace(id.as_str(), &redact_value(salt, id));
                }
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| redact_json(x, salt, ids)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| redact_json(x, salt, ids)),
        _ => {}
    }
}

fn s(v: &serde_json::Value, ptr: &str) -> String {
    match v.pointer(ptr) {
        Some(serde_json::Value::String(x)) => x.clone(),
        Some(serde_json::Value::Null) | None => "—".into(),
        Some(x) => x.to_string(),
    }
}

pub fn build(driver: &Driver, redacted: bool, exported_dir: Option<&Path>) -> Result<ReportBundle> {
    let m = driver.workspace.manifest().clone();
    let salt = m.session_id.clone();
    let mut json = serde_json::json!({
        "report_version": 1,
        "generated_at": crate::report::time::format_rfc3339_utc(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)),
        "core_version": m.core_version,
        "session_id": m.session_id,
        "redacted": redacted,
        "stages": m.stages,
        "inputs": m.inputs,
        "warnings": m.warnings,
        "partial_artifacts": driver.workspace.partial_artifacts(),
        "exported_backup_dir": exported_dir,
    });
    if redacted {
        let ids = collect_sensitive_identifiers(&m);
        redact_json(&mut json, &salt, &ids);
    }
    let intake = &json["stages"]["intake"]["evidence"];
    let plan = &json["stages"]["analysis"]["evidence"]["plan"];
    let patch = &json["stages"]["patching"]["evidence"];
    let ver = &json["stages"]["verification"]["evidence"];
    let exp = &json["stages"]["export"]["evidence"];

    let mut md = String::new();
    md.push_str("# Reline Report\n\n");
    md.push_str(&format!(
        "- Generated: {}\n- Core version: {}\n- Session: {}\n- Redacted identifiers: {}\n\n",
        s(&json, "/generated_at"),
        s(&json, "/core_version"),
        s(&json, "/session_id"),
        redacted
    ));
    md.push_str("All timestamps carry an explicit UTC offset. This report contains no passwords, keys, or message text.\n\n");

    md.push_str(
        "## Stages\n\n| Stage | State | Started | Finished | Error |\n|---|---|---|---|---|\n",
    );
    for st in Stage::ALL {
        let rec = &json["stages"][st.as_str()];
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            st.as_str(),
            s(rec, "/state"),
            s(rec, "/started_at"),
            s(rec, "/finished_at"),
            s(rec, "/error/message")
        ));
    }
    md.push('\n');

    md.push_str("## Inputs\n\n| | Old backup | Current backup |\n|---|---|---|\n");
    for (label, ptr) in [
        ("Device", "/backup/device_name"),
        ("iOS", "/backup/product_version"),
        ("UDID", "/backup/udid"),
        ("Backup date", "/backup/backup_date"),
        ("Snapshot state", "/backup/snapshot_state"),
        ("Manifest.db SHA-256", "/source_hashes/manifest_db"),
        ("LINE payload SHA-256", "/source_hashes/line_payload"),
        ("Line.sqlite SHA-256 (plaintext)", "/line_db/sha256"),
        ("Line.sqlite size", "/line_db/size"),
        ("Manifest declared size", "/line_db/manifest_declared_size"),
        ("Account directory", "/selected_store/account_dir"),
        ("Protection class", "/selected_store/protection_class"),
        ("Pending journals", "/selected_store/pending_journals"),
        ("Patchable", "/patchable"),
        ("Source unchanged after intake", "/source_unchanged"),
    ] {
        md.push_str(&format!(
            "| {label} | {} | {} |\n",
            s(&intake["old"], ptr),
            s(&intake["current"], ptr)
        ));
    }
    md.push('\n');

    md.push_str("## Analysis\n\n");
    if plan.is_object() {
        md.push_str(&format!("- Plan id: `{}`\n- Adapter: {}\n- Rule: {}\n- Actionable: {}\n- Predicted updates: {}\n- Predicate: `{}`\n- Authorized fields: {}\n- Protected fields: {}\n\n", s(plan, "/plan_id"), s(plan, "/adapter_id"), s(plan, "/rule_version"), s(plan, "/actionable"), s(plan, "/predicted_update_count"), s(plan, "/candidate_predicate"), s(plan, "/authorized_fields"), s(plan, "/protected_fields")));
        md.push_str("| Count | Value |\n|---|---|\n");
        for k in [
            "old_messages",
            "current_messages",
            "matched",
            "old_only",
            "current_only",
            "candidates",
            "preserved_placeholders",
            "chat_conflicts",
            "timestamp_conflicts",
            "sender_conflicts",
            "unknown_differences",
            "text_differences",
            "metadata_differences",
            "null_identity_rows_old",
            "null_identity_rows_current",
            "duplicate_identity_values",
        ] {
            md.push_str(&format!("| {k} | {} |\n", s(plan, &format!("/counts/{k}"))));
        }
        md.push_str(&format!(
            "| candidates by old type | {} |\n\n",
            s(plan, "/counts/candidates_by_old_type")
        ));
        if let Some(ex) = plan.get("exclusions").and_then(|v| v.as_array()) {
            md.push_str("Exclusions:\n\n");
            for e in ex {
                md.push_str(&format!("- {}: {}\n", s(e, "/reason"), s(e, "/count")));
            }
            md.push('\n');
        }
        for (title, key) in [("Warnings", "warnings"), ("Blockers", "blockers")] {
            if let Some(arr) = plan.get(key).and_then(|v| v.as_array()) {
                if !arr.is_empty() {
                    md.push_str(&format!("{title}:\n\n"));
                    for w in arr {
                        md.push_str(&format!("- {}\n", w.as_str().unwrap_or("")));
                    }
                    md.push('\n');
                }
            }
        }
    } else {
        md.push_str(&format!(
            "No repair plan. Supported: {}. Reasons: {}\n\n",
            s(&json["stages"]["analysis"]["evidence"], "/supported"),
            s(&json["stages"]["analysis"]["evidence"], "/reasons")
        ));
    }

    md.push_str("## Patching\n\n");
    if patch.is_object() {
        md.push_str(&format!("- Updates applied: {} (predicted {})\n- Repaired DB SHA-256: `{}`\n- Repaired DB size: {} bytes\n- Pages before/after: {} / {} (page size {})\n- Payload SHA-256: `{}` ({} bytes, protection class {})\n- Round trip OK: {}\n- Clone: {} files, {} bytes, clonefile {} / copied {}\n- Clone differs from source only at: {}\n- Source unchanged after clone: {}\n- Rollback source: `{}`\n\n",
            s(patch, "/repair/actual_update_count"), s(patch, "/repair/predicted_update_count"), s(patch, "/validation/repaired_sha256"), s(patch, "/encryption/plaintext_size"),
            s(patch, "/validation/pages_before/page_count"), s(patch, "/validation/pages_after/page_count"), s(patch, "/validation/pages_after/page_size"),
            s(patch, "/encryption/payload_sha256"), s(patch, "/encryption/payload_size"), s(patch, "/encryption/protection_class"), s(patch, "/encryption/round_trip_ok"),
            s(patch, "/clone/files"), s(patch, "/clone/bytes"), s(patch, "/clone/cloned_with_clonefile"), s(patch, "/clone/copied"), s(patch, "/clone_differs_only_at"), s(patch, "/source_unchanged_after_clone"), s(patch, "/rollback_source_dir")));
        md.push_str("Post-repair gates:\n\n");
        md.push_str(&format!("- integrity_check ok: {}\n- authorized-field mismatches: {}\n- remaining candidates: {}\n- protected-field mismatches: {}\n- rows before/after: {} / {}\n- unrelated tables checked/changed: {} / {}\n- failed gates: {}\n\n",
            s(patch, "/validation/integrity_ok"), s(patch, "/validation/repaired_field_mismatches"), s(patch, "/validation/remaining_candidates"), s(patch, "/validation/protected_field_mismatches"), s(patch, "/validation/rows_before"), s(patch, "/validation/rows_after"), s(patch, "/validation/unrelated_tables_checked"), s(patch, "/validation/unrelated_tables_changed"), s(patch, "/validation/failed_gates")));
    } else {
        md.push_str(&format!(
            "Not performed. {}\n\n",
            s(&json["stages"]["patching"], "/error/message")
        ));
    }

    md.push_str("## Verification (clone re-read)\n\n");
    if let Some(g) = ver.get("gates").and_then(|v| v.as_array()) {
        for gate in g {
            md.push_str(&format!(
                "- [{}] {}\n",
                if gate[1].as_bool().unwrap_or(false) {
                    "x"
                } else {
                    " "
                },
                gate[0].as_str().unwrap_or("")
            ));
        }
        md.push_str(&format!(
            "\n- Re-read SHA-256: `{}`\n- Expected SHA-256: `{}`\n- All gates passed: {}\n\n",
            s(ver, "/reread_sha256"),
            s(ver, "/expected_sha256"),
            s(ver, "/all_gates_passed")
        ));
    } else {
        md.push_str(&format!(
            "Not performed. {}\n\n",
            s(&json["stages"]["verification"], "/error/message")
        ));
    }

    md.push_str("## Export\n\n");
    if exp.is_object() {
        md.push_str(&format!(
            "- Patched backup: `{}`\n- Preserved original (rollback source): `{}`\n\n",
            s(exp, "/exported_backup_dir"),
            s(exp, "/rollback_source_dir")
        ));
    } else if let Some(d) = exported_dir {
        md.push_str(&format!("- Patched backup: `{}`\n\n", d.display()));
    } else {
        md.push_str("Not exported.\n\n");
    }

    if let Some(w) = json.get("warnings").and_then(|v| v.as_array()) {
        if !w.is_empty() {
            md.push_str("## Warnings\n\n");
            for x in w {
                md.push_str(&format!("- {}\n", x.as_str().unwrap_or("")));
            }
            md.push('\n');
        }
    }

    let instructions = restore_instructions(
        &s(&intake["current"], "/backup/udid"),
        &s(&intake["current"], "/backup/device_name"),
        &s(&intake["current"], "/backup/backup_date"),
        exported_dir
            .map(|d| d.display().to_string())
            .or_else(|| {
                exp.get("exported_backup_dir")
                    .and_then(|v| v.as_str())
                    .map(|x| x.to_owned())
            })
            .unwrap_or_else(|| "<exported patched backup>".into())
            .as_str(),
        &s(patch, "/rollback_source_dir"),
        &s(patch, "/encryption/payload_size"),
        &s(patch, "/replaced_relative_path"),
    );
    md.push_str("## Manual Finder restore and rollback\n\n");
    md.push_str(&instructions);
    Ok(ReportBundle {
        markdown: md,
        json,
        instructions,
    })
}

/// Task 8.2: manual restore checklist, offline first launch, checkpoint, rollback.
pub fn restore_instructions(
    udid: &str,
    device_name: &str,
    backup_date: &str,
    patched_dir: &str,
    rollback_source: &str,
    payload_size: &str,
    payload_rel: &str,
) -> String {
    format!(
"# Manual restore checklist

This application never touches Finder, MobileSync, or the iPhone. Every step below is yours.

Identify the backups:

- Patched backup (verified): `{patched_dir}`
- Preserved original current-device backup (rollback source): `{rollback_source}`
- Device: {device_name} — UDID `{udid}` — original backup date {backup_date}
- Patched LINE payload: `{payload_rel}` must be {payload_size} bytes inside the patched backup

Before touching MobileSync:

1. Unplug the iPhone. Quit Finder windows that show the device. Make sure no backup or restore is running.
2. Open `~/Library/Application Support/MobileSync/Backup/`.
3. If a folder named `{udid}` exists there, move it out (for example to `FINDER_ORIGINAL_{udid}` next to your preserved copies). Never delete it.
4. Copy the patched backup folder into `MobileSync/Backup/` so that it is named exactly `{udid}`.
5. Confirm the payload size: `stat -f \"%z\" \"~/Library/Application Support/MobileSync/Backup/{udid}/{payload_rel}\"` should print {payload_size}.

Restore:

6. Connect the iPhone and open Finder. Do not click \"Back Up Now\". If a backup starts automatically, cancel it.
7. Choose \"Restore Backup…\" and pick the entry for {device_name} whose date matches {backup_date}. Do not pick an older backup.
8. Enter the encrypted-backup password and wait. Do not disconnect during the restore. Apps re-download from the App Store afterwards; this is normal.

First launch:

9. Before opening LINE, enable Airplane Mode and turn off Wi-Fi and cellular data.
10. Open LINE and check the previously unreadable messages while offline. Only then reconnect.

Checkpoint:

11. Once satisfied, create a fresh encrypted Finder backup as a checkpoint. Do not delete the preserved original, the patched backup, or the exported report until that checkpoint exists.

Rollback:

- Unplug the iPhone. Remove `MobileSync/Backup/{udid}` (the patched copy) and move `FINDER_ORIGINAL_{udid}` back to `MobileSync/Backup/{udid}`.
- Alternatively restore from the preserved original at `{rollback_source}` using the same steps.
- Never swap directories while Finder is backing up or restoring.
"
    )
}

pub fn report(driver: &mut Driver, redacted: bool) -> Result<serde_json::Value> {
    let bundle = build(driver, redacted, None)?;
    let dir = driver.workspace.export_dir();
    let suffix = if redacted { "-redacted" } else { "" };
    let md = dir.join(format!("report{suffix}.md"));
    let js = dir.join(format!("report{suffix}.json"));
    let ins = dir.join("RESTORE-INSTRUCTIONS.md");
    std::fs::write(&md, bundle.markdown.as_bytes()).map_err(|e| RecoveryError::io(e, &md))?;
    std::fs::write(&js, serde_json::to_vec_pretty(&bundle.json)?)
        .map_err(|e| RecoveryError::io(e, &js))?;
    std::fs::write(&ins, bundle.instructions.as_bytes()).map_err(|e| RecoveryError::io(e, &ins))?;
    Ok(
        serde_json::json!({ "status": "ok", "markdown_path": md, "json_path": js, "instructions_path": ins, "markdown": bundle.markdown, "json": bundle.json }),
    )
}

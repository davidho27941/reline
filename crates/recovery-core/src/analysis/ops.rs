//! Analysis orchestration: verify inputs, preflight, select adapter, run, persist plan.

use std::path::Path;

use crate::analysis::adapters;
use crate::analysis::plan::{public_id, Exclusion, InputHashes, RepairPlan, SecurePlan};
use crate::analysis::schema::{self, Preflight};
use crate::backup::ops::{load_evidence, IntakeEvidence};
use crate::hash::sha256_file;
use crate::progress::{ProgressSink, Stage};
use crate::session::driver::{BackupRole, Driver};
use crate::{ErrorCode, RecoveryError, Result};

/// Everything the diagnostics file records when analysis is unsupported or finds nothing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Diagnostics {
    pub old_preflight: Preflight,
    pub current_preflight: Preflight,
    pub adapter_gaps: Vec<(String, Vec<String>)>,
    pub supported: bool,
    pub reasons: Vec<String>,
}

pub fn analyze(driver: &mut Driver, progress: &dyn ProgressSink) -> Result<serde_json::Value> {
    let old_ev = load_evidence(driver, BackupRole::Old)?;
    let cur_ev = load_evidence(driver, BackupRole::Current)?;
    let staging = driver.workspace.begin_stage(Stage::Analysis)?;
    driver.state.secure_plan = None;
    match analyze_inner(driver, &old_ev, &cur_ev, &staging, progress) {
        Ok(v) => Ok(v),
        Err(e) => {
            driver.workspace.fail_stage(Stage::Analysis, &e)?;
            Err(e)
        }
    }
}

fn verify_input(ev: &IntakeEvidence, progress: &dyn ProgressSink) -> Result<()> {
    let p: &Path = &ev.line_db.plaintext_path;
    let h = sha256_file(p, progress, Stage::Analysis)?;
    if h != ev.line_db.sha256 {
        return Err(RecoveryError::new(
            ErrorCode::SessionState,
            format!(
                "extracted {} database no longer matches its intake hash",
                ev.role.as_str()
            ),
        )
        .with_path(p)
        .with_remedy("Run intake again."));
    }
    Ok(())
}

fn analyze_inner(
    driver: &mut Driver,
    old_ev: &IntakeEvidence,
    cur_ev: &IntakeEvidence,
    staging: &Path,
    progress: &dyn ProgressSink,
) -> Result<serde_json::Value> {
    verify_input(old_ev, progress)?;
    verify_input(cur_ev, progress)?;
    progress.check_cancelled()?;

    let old_path = &old_ev.line_db.plaintext_path;
    let cur_path = &cur_ev.line_db.plaintext_path;
    let conn = schema::open_read_only(cur_path)?;
    conn.execute(
        "ATTACH DATABASE ?1 AS olddb",
        [format!("file:{}?mode=ro", old_path.display())],
    )?;
    let old_pre = {
        let oc = schema::open_read_only(old_path)?;
        schema::preflight(&oc, old_path)?
    };
    let cur_pre = schema::preflight(&conn, cur_path)?;
    progress.check_cancelled()?;

    let mut reasons = Vec::new();
    if !old_pre.integrity_ok {
        reasons.push(format!(
            "old database failed integrity_check: {}",
            old_pre.integrity_detail.join("; ")
        ));
    }
    if !cur_pre.integrity_ok {
        reasons.push(format!(
            "current database failed integrity_check: {}",
            cur_pre.integrity_detail.join("; ")
        ));
    }
    let registry = adapters::registry();
    let selection = adapters::select(&registry, &old_pre.schema, &cur_pre.schema);
    let adapter_gaps = match &selection {
        Ok(_) => Vec::new(),
        Err(g) => g.clone(),
    };
    if selection.is_err() {
        reasons.push("no compatibility adapter accepts both schemas".into());
    }

    let input_hashes = InputHashes {
        old_database: old_ev.line_db.sha256.clone(),
        current_database: cur_ev.line_db.sha256.clone(),
        old_database_size: old_ev.line_db.size,
        current_database_size: cur_ev.line_db.size,
    };
    let mut schema_fingerprints = std::collections::BTreeMap::new();
    schema_fingerprints.insert("old".to_owned(), old_pre.schema.sha256.clone());
    schema_fingerprints.insert("current".to_owned(), cur_pre.schema.sha256.clone());

    let diagnostics_path = staging.join("analysis-diagnostics.json");
    let plan_path = staging.join("repair-plan.json");

    if !reasons.is_empty() {
        let diag = Diagnostics {
            old_preflight: old_pre,
            current_preflight: cur_pre,
            adapter_gaps,
            supported: false,
            reasons: reasons.clone(),
        };
        write_json(&diagnostics_path, &diag)?;
        driver.workspace.commit_stage(
            Stage::Analysis,
            &[(diagnostics_path, false)],
            serde_json::json!({ "supported": false, "actionable": false, "reasons": reasons, "input_hashes": input_hashes }),
            progress,
        )?;
        return Ok(serde_json::json!({ "status": "unsupported", "diagnostics": diag }));
    }
    let adapter = selection.expect("checked");
    let outcome = adapter.analyze(&conn, progress)?;
    progress.check_cancelled()?;

    let salt = driver.workspace.manifest().session_id.clone();
    let mut public_ids: Vec<String> = outcome
        .candidates
        .iter()
        .map(|c| public_id(&salt, &c.identifier))
        .collect();
    public_ids.sort();
    let mut exclusions = vec![
        Exclusion {
            reason: "old-only messages (never inserted)".into(),
            count: outcome.counts.old_only,
        },
        Exclusion {
            reason: "current-only messages (left unchanged)".into(),
            count: outcome.counts.current_only,
        },
        Exclusion {
            reason: "placeholders already present in the old database (preserved)".into(),
            count: outcome.counts.preserved_placeholders,
        },
        Exclusion {
            reason: "chat relationship conflicts".into(),
            count: outcome.counts.chat_conflicts,
        },
        Exclusion {
            reason: "timestamp conflicts".into(),
            count: outcome.counts.timestamp_conflicts,
        },
        Exclusion {
            reason: "sender relationship conflicts".into(),
            count: outcome.counts.sender_conflicts,
        },
        Exclusion {
            reason: "differences matching no supported rule (diagnostic only)".into(),
            count: outcome.counts.unknown_differences,
        },
        Exclusion {
            reason: "old rows without a message identifier (NULL ZID; never matched)".into(),
            count: outcome.counts.null_identity_rows_old,
        },
        Exclusion {
            reason: "current rows without a message identifier (NULL ZID; never matched)".into(),
            count: outcome.counts.null_identity_rows_current,
        },
        Exclusion {
            reason: "identifier values duplicated in either database (all carrying rows excluded)"
                .into(),
            count: outcome.counts.duplicate_identity_values,
        },
    ];
    exclusions.retain(|e| e.count > 0);
    let actionable = outcome.blockers.is_empty() && !outcome.candidates.is_empty();
    let mut plan = RepairPlan {
        plan_id: String::new(),
        adapter_id: adapter.id().to_owned(),
        rule_version: adapter.rule_version().to_owned(),
        core_version: crate::CORE_VERSION.to_owned(),
        input_hashes,
        candidate_predicate: adapter.candidate_predicate().to_owned(),
        authorized_fields: adapter
            .authorized_fields()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        protected_fields: adapter
            .protected_fields()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        predicted_update_count: outcome.counts.candidates,
        counts: outcome.counts.clone(),
        exclusions,
        warnings: outcome.warnings.clone(),
        blockers: outcome.blockers.clone(),
        actionable,
        public_candidate_ids: public_ids,
        validation_predicates: vec![
            "PRAGMA integrity_check returns exactly 'ok'".into(),
            "every candidate's authorized fields equal the old database values".into(),
            "every row's protected fields equal the current database values".into(),
            "message row count unchanged; every other table byte-identical".into(),
            "page_size unchanged; page_count >= original; no VACUUM, truncation or page rewrite"
                .into(),
            "update count equals predicted_update_count or the transaction is rolled back".into(),
        ],
        schema_fingerprints,
    };
    plan.plan_id = plan.compute_id();

    let diag = Diagnostics {
        old_preflight: old_pre,
        current_preflight: cur_pre,
        adapter_gaps,
        supported: true,
        reasons: outcome.blockers.clone(),
    };
    write_json(&diagnostics_path, &diag)?;
    write_json(&plan_path, &plan)?;
    let evidence = serde_json::json!({
        "supported": true,
        "actionable": actionable,
        "plan": plan,
    });
    driver.workspace.commit_stage(
        Stage::Analysis,
        &[(diagnostics_path, false), (plan_path, false)],
        evidence,
        progress,
    )?;
    if actionable {
        driver.state.secure_plan = Some(SecurePlan {
            plan: plan.clone(),
            candidates: outcome.candidates,
            old_db_path: old_path.clone(),
            current_db_path: cur_path.clone(),
        });
    }
    Ok(
        serde_json::json!({ "status": if actionable { "actionable" } else { "diagnostic_only" }, "plan": plan, "diagnostics": diag }),
    )
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    let mut f = crate::session::workspace::create_private_file(path)?;
    f.write_all(&serde_json::to_vec_pretty(value)?)
        .map_err(|e| RecoveryError::io(e, path))?;
    Ok(())
}

/// Load the committed plan from the manifest (persisted form, no identifiers).
pub fn load_plan(driver: &Driver) -> Result<RepairPlan> {
    let stage = driver.workspace.manifest().stage(Stage::Analysis);
    if stage.state != crate::session::StageState::Committed {
        return Err(
            RecoveryError::new(ErrorCode::SessionState, "analysis has not been committed")
                .with_remedy("Run analysis first."),
        );
    }
    let plan = stage.evidence.get("plan").cloned().ok_or_else(|| {
        RecoveryError::new(
            ErrorCode::AnalysisUnsupported,
            "analysis produced no repair plan",
        )
    })?;
    Ok(serde_json::from_value(plan)?)
}

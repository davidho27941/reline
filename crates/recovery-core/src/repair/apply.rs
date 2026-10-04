//! Revalidate the plan, then apply it inside one transaction.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::analysis::adapters;
use crate::analysis::plan::SecurePlan;
use crate::analysis::schema;
use crate::hash::{sha256_file, Sha256Hex};
use crate::progress::{ProgressSink, Stage};
use crate::{ErrorCode, RecoveryError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairResult {
    pub predicted_update_count: u64,
    pub actual_update_count: u64,
    pub committed: bool,
    pub working_copy_sha256_before: Sha256Hex,
    pub working_copy_sha256_after: Sha256Hex,
    pub pages_before: schema::PageStats,
    pub pages_after: schema::PageStats,
}

fn attach_old(conn: &Connection, old: &Path) -> Result<()> {
    conn.execute(
        "ATTACH DATABASE ?1 AS olddb",
        [format!("file:{}?mode=ro", old.display())],
    )?;
    Ok(())
}

/// Re-check input hashes and re-derive the candidate set. Any drift invalidates the plan.
pub fn revalidate(secure: &SecurePlan, progress: &dyn ProgressSink) -> Result<()> {
    let old_h = sha256_file(&secure.old_db_path, progress, Stage::Patching)?;
    let cur_h = sha256_file(&secure.current_db_path, progress, Stage::Patching)?;
    if old_h != secure.plan.input_hashes.old_database
        || cur_h != secure.plan.input_hashes.current_database
    {
        return Err(RecoveryError::new(
            ErrorCode::PlanInvalidated,
            "input database hashes no longer match the repair plan",
        )
        .with_remedy("Run intake and analysis again."));
    }
    let registry = adapters::registry();
    let adapter = registry
        .iter()
        .find(|a| a.id() == secure.plan.adapter_id)
        .ok_or_else(|| {
            RecoveryError::new(
                ErrorCode::PlanInvalidated,
                format!(
                    "adapter {} is not available in this build",
                    secure.plan.adapter_id
                ),
            )
        })?;
    if adapter.rule_version() != secure.plan.rule_version {
        return Err(RecoveryError::new(
            ErrorCode::PlanInvalidated,
            "rule version changed since the plan was produced",
        ));
    }
    let conn = schema::open_read_only(&secure.current_db_path)?;
    attach_old(&conn, &secure.old_db_path)?;
    let outcome = adapter.analyze(&conn, progress)?;
    if !outcome.blockers.is_empty() {
        return Err(RecoveryError::new(
            ErrorCode::PlanInvalidated,
            format!("inputs now have blockers: {}", outcome.blockers.join("; ")),
        ));
    }
    let mut now: Vec<&str> = outcome
        .candidates
        .iter()
        .map(|c| c.identifier.as_str())
        .collect();
    let mut planned: Vec<&str> = secure
        .candidates
        .iter()
        .map(|c| c.identifier.as_str())
        .collect();
    now.sort_unstable();
    planned.sort_unstable();
    if now != planned || outcome.counts.candidates != secure.plan.predicted_update_count {
        return Err(RecoveryError::new(
            ErrorCode::PlanInvalidated,
            "the candidate set derived from the inputs differs from the plan",
        ));
    }
    Ok(())
}

/// Copy the current database to `working_copy` and apply the plan transactionally.
pub fn repair_working_copy(
    secure: &SecurePlan,
    working_copy: &Path,
    progress: &dyn ProgressSink,
) -> Result<RepairResult> {
    revalidate(secure, progress)?;
    progress.check_cancelled()?;

    // Fresh private copy of the current database.
    {
        let mut src = std::fs::File::open(&secure.current_db_path)
            .map_err(|e| RecoveryError::io(e, &secure.current_db_path))?;
        let mut dst = crate::session::workspace::create_private_file(working_copy)?;
        std::io::copy(&mut src, &mut dst).map_err(|e| RecoveryError::io(e, working_copy))?;
        dst.sync_all()
            .map_err(|e| RecoveryError::io(e, working_copy))?;
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let p = sidecar(working_copy, suffix);
        if p.exists() {
            std::fs::remove_file(&p).map_err(|e| RecoveryError::io(e, &p))?;
        }
    }
    let before = sha256_file(working_copy, progress, Stage::Patching)?;
    if before != secure.plan.input_hashes.current_database {
        return Err(RecoveryError::new(
            ErrorCode::PlanInvalidated,
            "working copy does not match the current database hash",
        )
        .with_path(working_copy));
    }

    let registry = adapters::registry();
    let adapter = registry
        .iter()
        .find(|a| a.id() == secure.plan.adapter_id)
        .expect("validated above");
    let predicted = secure.plan.predicted_update_count;
    let pages_before;
    let actual;
    {
        let mut conn = Connection::open_with_flags(
            working_copy,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| {
            RecoveryError::new(
                ErrorCode::DatabaseUnsupported,
                format!("cannot open working copy: {e}"),
            )
            .with_path(working_copy)
        })?;
        pages_before = schema::page_stats(&conn, working_copy)?;
        attach_old(&conn, &secure.old_db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut count = 0u64;
        for (i, c) in secure.candidates.iter().enumerate() {
            if progress.is_cancelled() {
                tx.rollback()?;
                return Err(RecoveryError::cancelled());
            }
            let n = adapter.repair_one(&tx, &c.identifier)?;
            if n != 1 {
                tx.rollback()?;
                return Err(RecoveryError::new(
                    ErrorCode::RepairMismatch,
                    format!("a planned update changed {n} rows instead of 1; transaction rolled back, database unchanged"),
                ));
            }
            count += 1;
            if i % 64 == 0 {
                progress.report(Stage::Patching, count, predicted);
            }
        }
        if count != predicted {
            tx.rollback()?;
            return Err(RecoveryError::new(
                ErrorCode::RepairMismatch,
                format!("update count {count} differs from predicted {predicted}; transaction rolled back, database unchanged"),
            ));
        }
        tx.commit()?;
        actual = count;
        // Fold any WAL back into the main file without changing journal_mode.
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if mode.eq_ignore_ascii_case("wal") {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        }
        conn.execute("DETACH DATABASE olddb", [])?;
    }
    for suffix in ["-wal", "-journal"] {
        let p = sidecar(working_copy, suffix);
        if p.exists() && std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0) > 0 {
            return Err(RecoveryError::new(
                ErrorCode::VerificationFailed,
                format!("a non-empty {suffix} file remained beside the repaired database"),
            )
            .with_path(p));
        }
        let _ = std::fs::remove_file(&p);
    }
    let _ = std::fs::remove_file(sidecar(working_copy, "-shm"));
    let pages_after = {
        let conn = schema::open_read_only(working_copy)?;
        schema::page_stats(&conn, working_copy)?
    };
    let after = sha256_file(working_copy, progress, Stage::Patching)?;
    Ok(RepairResult {
        predicted_update_count: predicted,
        actual_update_count: actual,
        committed: true,
        working_copy_sha256_before: before,
        working_copy_sha256_after: after,
        pages_before,
        pages_after,
    })
}

pub(crate) fn sidecar(db: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = db.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

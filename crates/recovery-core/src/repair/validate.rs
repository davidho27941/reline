//! Post-repair gates. All must pass before the repaired bytes may be encrypted.

use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::analysis::adapters;
use crate::analysis::plan::SecurePlan;
use crate::analysis::schema::{self, PageStats};
use crate::hash::{sha256_file, Sha256Hex};
use crate::progress::{ProgressSink, Stage};
use crate::{ErrorCode, RecoveryError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairValidation {
    pub integrity_ok: bool,
    pub repaired_field_mismatches: u64,
    pub remaining_candidates: u64,
    pub protected_field_mismatches: u64,
    pub rows_before: u64,
    pub rows_after: u64,
    pub unrelated_tables_checked: u64,
    pub unrelated_tables_changed: Vec<String>,
    pub pages_before: PageStats,
    pub pages_after: PageStats,
    pub repaired_sha256: Sha256Hex,
    pub failed_gates: Vec<String>,
    pub all_passed: bool,
}

fn q(conn: &Connection, sql: &str) -> Result<u64> {
    Ok(conn.query_row(sql, [], |r| r.get::<_, i64>(0))? as u64)
}

/// Validate `repaired` against the plan, the old database, and the untouched current database.
pub fn post_repair(
    secure: &SecurePlan,
    repaired: &Path,
    progress: &dyn ProgressSink,
) -> Result<RepairValidation> {
    let registry = adapters::registry();
    let adapter = registry
        .iter()
        .find(|a| a.id() == secure.plan.adapter_id)
        .ok_or_else(|| RecoveryError::new(ErrorCode::PlanInvalidated, "adapter unavailable"))?;
    let table = adapter.message_table();
    let id_col = adapter.identity_column();
    let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));

    let conn = schema::open_read_only(repaired)?;
    conn.execute(
        "ATTACH DATABASE ?1 AS olddb",
        [format!("file:{}?mode=ro", secure.old_db_path.display())],
    )?;
    conn.execute(
        "ATTACH DATABASE ?1 AS curdb",
        [format!("file:{}?mode=ro", secure.current_db_path.display())],
    )?;
    progress.report(Stage::Verification, 1, 6);

    let mut failed = Vec::new();
    let integrity = schema::integrity_check(&conn)?;
    let integrity_ok = integrity.len() == 1 && integrity[0] == "ok";
    if !integrity_ok {
        failed.push(format!("integrity_check: {}", integrity.join("; ")));
    }
    progress.check_cancelled()?;
    progress.report(Stage::Verification, 2, 6);

    let ids = secure.identifiers();
    let repaired_field_mismatches = adapter.count_repaired_mismatches(&conn, &ids)?;
    if repaired_field_mismatches != 0 {
        failed.push(format!(
            "{repaired_field_mismatches} authorized field values differ from the old database"
        ));
    }
    // Re-running the analysis on (repaired, old) must find zero candidates.
    let outcome = adapter.analyze(&conn, progress)?;
    let remaining_candidates = outcome.counts.candidates;
    if remaining_candidates != 0 {
        failed.push(format!(
            "{remaining_candidates} candidates remain after repair"
        ));
    }
    progress.report(Stage::Verification, 3, 6);

    // Protected fields identical for every row and the row set unchanged. The working copy is a
    // byte copy of the current database and the repair only UPDATEs, so rows are paired by
    // rowid: this covers rows whose identity column is NULL or duplicated (real stores have
    // both), which an identity join would skip or cross-match.
    let protected: Vec<String> = adapter
        .protected_fields()
        .iter()
        .map(|f| format!("r.{0} IS NOT n.{0}", quote(f)))
        .collect();
    let protected_field_mismatches = q(
        &conn,
        &format!(
            "SELECT COUNT(*) FROM main.{t} r JOIN curdb.{t} n ON n.rowid = r.rowid WHERE {cond}",
            t = quote(table),
            cond = protected.join(" OR ")
        ),
    )?;
    if protected_field_mismatches != 0 {
        failed.push(format!(
            "{protected_field_mismatches} rows changed a protected field"
        ));
    }
    let rows_before = q(
        &conn,
        &format!("SELECT COUNT(*) FROM curdb.{}", quote(table)),
    )?;
    let rows_after = q(
        &conn,
        &format!("SELECT COUNT(*) FROM main.{}", quote(table)),
    )?;
    // Every rowid present after must have existed before with the same identity, and vice versa.
    let unmatched = q(&conn, &format!("SELECT (SELECT COUNT(*) FROM main.{t} r WHERE NOT EXISTS (SELECT 1 FROM curdb.{t} n WHERE n.rowid = r.rowid AND n.{id} IS r.{id})) + (SELECT COUNT(*) FROM curdb.{t} n WHERE NOT EXISTS (SELECT 1 FROM main.{t} r WHERE r.rowid = n.rowid))", t = quote(table), id = quote(id_col)))?;
    if rows_before != rows_after || unmatched != 0 {
        failed.push(format!(
            "row set changed: before {rows_before}, after {rows_after}, unmatched {unmatched}"
        ));
    }
    progress.check_cancelled()?;
    progress.report(Stage::Verification, 4, 6);

    // Every other table byte-identical.
    let mut tables: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        for n in stmt.query_map([], |r| r.get::<_, String>(0))? {
            tables.push(n?);
        }
    }
    let mut cur_tables: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT name FROM curdb.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        for n in stmt.query_map([], |r| r.get::<_, String>(0))? {
            cur_tables.push(n?);
        }
    }
    if tables != cur_tables {
        failed.push("table set changed".into());
    }
    let mut unrelated_tables_changed = Vec::new();
    let mut unrelated_tables_checked = 0u64;
    for t in &tables {
        if t == table {
            continue;
        }
        unrelated_tables_checked += 1;
        let a = table_digest_in(&conn, "main", t)?;
        let b = table_digest_in(&conn, "curdb", t)?;
        if a != b {
            unrelated_tables_changed.push(t.clone());
        }
    }
    if !unrelated_tables_changed.is_empty() {
        failed.push(format!(
            "unrelated tables changed: {}",
            unrelated_tables_changed.join(", ")
        ));
    }
    progress.report(Stage::Verification, 5, 6);

    // Page statistics: same page size and journal mode, no shrink, no truncation.
    let pages_after = schema::page_stats(&conn, repaired)?;
    let pages_before = {
        let c = schema::open_read_only(&secure.current_db_path)?;
        schema::page_stats(&c, &secure.current_db_path)?
    };
    if pages_after.page_size != pages_before.page_size {
        failed.push("page_size changed".into());
    }
    if pages_after.page_count < pages_before.page_count {
        failed.push("page_count decreased (VACUUM or truncation?)".into());
    }
    if pages_after.file_size != pages_after.page_size * pages_after.page_count {
        failed.push("file size is not page_size * page_count".into());
    }
    if !pages_after
        .journal_mode
        .eq_ignore_ascii_case(&pages_before.journal_mode)
    {
        failed.push(format!(
            "journal_mode changed from {} to {}",
            pages_before.journal_mode, pages_after.journal_mode
        ));
    }
    drop(conn);
    let repaired_sha256 = sha256_file(repaired, progress, Stage::Verification)?;
    progress.report(Stage::Verification, 6, 6);
    Ok(RepairValidation {
        integrity_ok,
        repaired_field_mismatches,
        remaining_candidates,
        protected_field_mismatches,
        rows_before,
        rows_after,
        unrelated_tables_checked,
        unrelated_tables_changed,
        pages_before,
        pages_after,
        repaired_sha256,
        all_passed: failed.is_empty(),
        failed_gates: failed,
    })
}

fn table_digest_in(conn: &Connection, schema_name: &str, table: &str) -> Result<Sha256Hex> {
    use sha2::Digest;
    let quoted = format!("{schema_name}.\"{}\"", table.replace('"', "\"\""));
    let mut stmt = conn.prepare(&format!("SELECT * FROM {quoted} ORDER BY rowid"))?;
    let ncols = stmt.column_count();
    let mut h = sha2::Sha256::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        for i in 0..ncols {
            let v: rusqlite::types::Value = row.get(i)?;
            schema::hash_value(&mut h, &v);
        }
        h.update(b"\n");
    }
    Ok(Sha256Hex(hex::encode(h.finalize())))
}

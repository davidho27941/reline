//! SQLite preflight: integrity, schema fingerprint, page statistics, identifier checks.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::hash::Sha256Hex;
use crate::{ErrorCode, RecoveryError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageStats {
    pub page_size: u64,
    pub page_count: u64,
    pub freelist_count: u64,
    pub journal_mode: String,
    pub file_size: u64,
}

/// Table → ordered column names, plus a digest of the whole `sqlite_master` text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaFingerprint {
    pub tables: BTreeMap<String, Vec<String>>,
    /// SHA-256 over `CREATE` statements of tables and indexes, sorted.
    pub sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preflight {
    pub integrity_ok: bool,
    pub integrity_detail: Vec<String>,
    pub schema: SchemaFingerprint,
    pub pages: PageStats,
}

pub fn open_read_only(path: &Path) -> Result<Connection> {
    let uri = format!("file:{}?mode=ro&immutable=0", path.display());
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| {
        RecoveryError::new(
            ErrorCode::DatabaseUnsupported,
            format!("cannot open database read-only: {e}"),
        )
        .with_path(path)
    })
}

pub fn integrity_check(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("PRAGMA integrity_check")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn page_stats(conn: &Connection, path: &Path) -> Result<PageStats> {
    let page_size: u64 = conn.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))? as u64;
    let page_count: u64 = conn.query_row("PRAGMA page_count", [], |r| r.get::<_, i64>(0))? as u64;
    let freelist_count: u64 =
        conn.query_row("PRAGMA freelist_count", [], |r| r.get::<_, i64>(0))? as u64;
    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    let file_size = std::fs::metadata(path)
        .map_err(|e| RecoveryError::io(e, path))?
        .len();
    Ok(PageStats {
        page_size,
        page_count,
        freelist_count,
        journal_mode,
        file_size,
    })
}

pub fn fingerprint(conn: &Connection) -> Result<SchemaFingerprint> {
    use sha2::Digest;
    let mut tables = BTreeMap::new();
    let mut names: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        for n in stmt.query_map([], |r| r.get::<_, String>(0))? {
            names.push(n?);
        }
    }
    for name in &names {
        let mut cols = Vec::new();
        let mut stmt = conn.prepare(&format!(
            "PRAGMA table_info(\"{}\")",
            name.replace('"', "\"\"")
        ))?;
        for c in stmt.query_map([], |r| r.get::<_, String>(1))? {
            cols.push(c?);
        }
        tables.insert(name.clone(), cols);
    }
    let mut ddl: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT COALESCE(sql, '') FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type, name")?;
        for s in stmt.query_map([], |r| r.get::<_, String>(0))? {
            ddl.push(s?);
        }
    }
    let mut h = sha2::Sha256::new();
    for d in &ddl {
        h.update(d.as_bytes());
        h.update(b"\n");
    }
    Ok(SchemaFingerprint {
        tables,
        sha256: Sha256Hex(hex::encode(h.finalize())),
    })
}

pub fn preflight(conn: &Connection, path: &Path) -> Result<Preflight> {
    let integrity_detail = integrity_check(conn)?;
    let integrity_ok = integrity_detail.len() == 1 && integrity_detail[0] == "ok";
    Ok(Preflight {
        integrity_ok,
        integrity_detail,
        schema: fingerprint(conn)?,
        pages: page_stats(conn, path)?,
    })
}

/// Does the schema contain every required table/column?
pub fn missing_columns(schema: &SchemaFingerprint, required: &[(&str, &[&str])]) -> Vec<String> {
    let mut missing = Vec::new();
    for (table, cols) in required {
        match schema.tables.get(*table) {
            None => missing.push(format!("{table} (table)")),
            Some(have) => {
                for c in *cols {
                    if !have.iter().any(|h| h == c) {
                        missing.push(format!("{table}.{c}"));
                    }
                }
            }
        }
    }
    missing
}

/// Digest over all rows of a table in rowid order (used for "unrelated tables unchanged").
pub fn table_digest(conn: &Connection, table: &str) -> Result<Sha256Hex> {
    use sha2::Digest;
    let quoted = format!("\"{}\"", table.replace('"', "\"\""));
    let has_rowid: bool = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM pragma_table_info({quoted}) WHERE pk > 0"),
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|_| true)
        .unwrap_or(true);
    let order = if has_rowid { "ORDER BY rowid" } else { "" };
    let mut stmt = conn.prepare(&format!("SELECT * FROM {quoted} {order}"))?;
    let ncols = stmt.column_count();
    let mut h = sha2::Sha256::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        for i in 0..ncols {
            let v: rusqlite::types::Value = row.get(i)?;
            hash_value(&mut h, &v);
        }
        h.update(b"\n");
    }
    Ok(Sha256Hex(hex::encode(h.finalize())))
}

pub(crate) fn hash_value(h: &mut sha2::Sha256, v: &rusqlite::types::Value) {
    use rusqlite::types::Value;
    use sha2::Digest;
    match v {
        Value::Null => h.update(b"\x00N"),
        Value::Integer(i) => {
            h.update(b"\x00I");
            h.update(i.to_le_bytes());
        }
        Value::Real(f) => {
            h.update(b"\x00R");
            h.update(f.to_le_bytes());
        }
        Value::Text(t) => {
            h.update(b"\x00T");
            h.update((t.len() as u64).to_le_bytes());
            h.update(t.as_bytes());
        }
        Value::Blob(b) => {
            h.update(b"\x00B");
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        }
    }
}

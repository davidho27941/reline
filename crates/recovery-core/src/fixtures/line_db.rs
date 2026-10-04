//! Synthetic old/current `Line.sqlite` pairs reproducing the proven corruption distribution.
//!
//! Report §7.3/§7.4: 248 current type-106 rows that exist in the old DB; 21 were already 106
//! (preserved); 227 need repair, split by old type 0/1/112/2/3/14 = 211/6/4/3/2/1, with
//! 221 text differences and 145 metadata differences. One old-only message exists (§7.2).
//!
//! Core Data primary keys are deliberately offset between the two databases so that any code
//! comparing `Z_PK` values across databases fails the fixture.

use std::path::Path;

use rusqlite::{params, Connection};

use crate::fixtures::prng::Prng;
use crate::Result;

/// Distribution of repair candidates by old content type: (old_type, count, text_differs, metadata_differs).
pub const PROVEN_DISTRIBUTION: [(i64, u32, u32, u32); 6] = [
    (0, 211, 211, 129),
    (1, 6, 5, 6),
    (112, 4, 0, 4),
    (2, 3, 3, 3),
    (3, 2, 2, 2),
    (14, 1, 0, 1),
];
pub const PRESERVED_PLACEHOLDERS: u32 = 21;
pub const EXPECTED_CANDIDATES: u32 = 227;
pub const OLD_ONLY_MESSAGES: u32 = 1;
pub const PLACEHOLDER_TYPE: i64 = 106;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LineDbSpec {
    /// Total messages in the old database (>= 1000 recommended so candidates are sparse).
    pub message_count: u32,
    pub chat_count: u32,
    /// Messages that exist only in the current database (post-migration traffic).
    pub current_only_messages: u32,
    /// Inject a duplicate ZID (a non-candidate row) into the current database; the rows carrying
    /// it must be excluded from matching while the 227 candidates stay actionable.
    pub duplicate_zid_in_current: bool,
    /// Inject a NULL ZID into the old database (a non-candidate row); it must be excluded and
    /// counted, never matched.
    pub null_zid_in_old: bool,
    /// Number of candidates whose chat MID differs between databases (relationship conflict).
    pub chat_conflicts: u32,
    /// Number of candidates whose timestamp differs (relationship conflict).
    pub timestamp_conflicts: u32,
    /// Drop a required column from the current schema (unsupported schema).
    pub break_schema: bool,
    /// Introduce a row that differs in a way no rule covers (ZTEXT differs but current type != 106).
    pub unknown_differences: u32,
    pub seed: u64,
}

impl Default for LineDbSpec {
    fn default() -> Self {
        Self {
            message_count: 3000,
            chat_count: 12,
            current_only_messages: 40,
            duplicate_zid_in_current: false,
            null_zid_in_old: false,
            chat_conflicts: 0,
            timestamp_conflicts: 0,
            break_schema: false,
            unknown_differences: 0,
            seed: 7,
        }
    }
}

/// Ground truth the generator knows, for tests.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LineDbTruth {
    pub old_message_count: u32,
    pub current_message_count: u32,
    pub expected_candidates: u32,
    pub preserved_placeholders: u32,
    pub old_only: u32,
    pub current_only: u32,
    pub chat_conflicts: u32,
    pub timestamp_conflicts: u32,
    pub unknown_differences: u32,
    pub text_differences: u32,
    pub metadata_differences: u32,
    /// ZIDs that must be repaired (sorted). Test-only; real plans never persist these.
    pub candidate_zids: Vec<String>,
    /// SHA-256 over the canonical row listing of the *expected* repaired current database.
    pub expected_repaired_logical_digest: String,
}

const SCHEMA: &str = "
PRAGMA journal_mode=DELETE;
PRAGMA page_size=4096;
CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER PRIMARY KEY, Z_NAME VARCHAR, Z_SUPER INTEGER, Z_MAX INTEGER);
CREATE TABLE Z_METADATA (Z_VERSION INTEGER PRIMARY KEY, Z_UUID VARCHAR(255), Z_PLIST BLOB);
CREATE TABLE ZUSER (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZMID VARCHAR, ZNAME VARCHAR);
CREATE TABLE ZCHAT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZTYPE INTEGER, ZUNREAD INTEGER, ZLASTUPDATED TIMESTAMP, ZMID VARCHAR, ZLASTMESSAGE VARCHAR, ZE2EECONTENTTYPES VARCHAR);
CREATE TABLE ZCHATMETADATA (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZCHAT INTEGER);
CREATE TABLE ZCONTACT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZMID VARCHAR);
CREATE TABLE ZGROUP (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZMID VARCHAR);
CREATE TABLE ZMESSAGE (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZCONTENTTYPE INTEGER, ZMESSAGETYPE INTEGER, ZREADCOUNT INTEGER, ZSENDSTATUS INTEGER, ZCHAT INTEGER, ZSENDER INTEGER, ZTIMESTAMP INTEGER, ZID VARCHAR, ZTEXT VARCHAR, ZCONTENTMETADATA BLOB, ZTHUMBNAIL BLOB);
CREATE TABLE ZMESSAGEMETADATA (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZMESSAGE INTEGER);
CREATE INDEX ZMESSAGE_ZCHAT_INDEX ON ZMESSAGE (ZCHAT);
CREATE INDEX ZMESSAGE_ZSENDER_INDEX ON ZMESSAGE (ZSENDER);
CREATE INDEX ZMESSAGE_ZTIMESTAMP_INDEX ON ZMESSAGE (ZTIMESTAMP);
CREATE INDEX ZMESSAGE_ZID_INDEX ON ZMESSAGE (ZID);
CREATE INDEX ZCHAT_ZMID_INDEX ON ZCHAT (ZMID);
INSERT INTO Z_PRIMARYKEY VALUES (1,'Chat',0,0),(2,'ChatMetadata',0,0),(3,'Contact',0,0),(4,'Group',0,0),(5,'Message',0,0),(6,'MessageMetadata',0,0),(7,'User',0,0);
INSERT INTO Z_METADATA VALUES (1,'FIXTURE-UUID',NULL);
";

#[derive(Clone)]
struct Msg {
    zid: Option<String>,
    chat_idx: u32,
    sender_idx: u32,
    ts: i64,
    content_type: i64,
    message_type: i64,
    text: Option<String>,
    metadata: Option<Vec<u8>>,
    thumbnail: Option<Vec<u8>>,
    send_status: i64,
    read_count: i64,
}

fn write_db(
    path: &Path,
    msgs: &[Msg],
    chats: &[String],
    users: &[String],
    pk_offset: i64,
    break_schema: bool,
) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    conn.execute_batch("BEGIN")?;
    if break_schema {
        conn.execute_batch("ALTER TABLE ZMESSAGE DROP COLUMN ZCONTENTMETADATA;")?;
    }
    for (i, mid) in users.iter().enumerate() {
        conn.execute(
            "INSERT INTO ZUSER (Z_PK, Z_ENT, Z_OPT, ZMID, ZNAME) VALUES (?1, 7, 1, ?2, ?3)",
            params![i as i64 + 1 + pk_offset, mid, format!("User {i}")],
        )?;
    }
    for (i, mid) in chats.iter().enumerate() {
        conn.execute(
            "INSERT INTO ZCHAT (Z_PK, Z_ENT, Z_OPT, ZTYPE, ZUNREAD, ZLASTUPDATED, ZMID, ZLASTMESSAGE, ZE2EECONTENTTYPES) VALUES (?1, 1, 1, ?2, 0, 0, ?3, NULL, NULL)",
            params![i as i64 + 1 + pk_offset, if i % 3 == 0 { 2 } else { 0 }, mid],
        )?;
    }
    let mut stmt = if break_schema {
        conn.prepare("INSERT INTO ZMESSAGE (Z_PK, Z_ENT, Z_OPT, ZCONTENTTYPE, ZMESSAGETYPE, ZREADCOUNT, ZSENDSTATUS, ZCHAT, ZSENDER, ZTIMESTAMP, ZID, ZTEXT, ZTHUMBNAIL) VALUES (?1, 5, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?12)")?
    } else {
        conn.prepare("INSERT INTO ZMESSAGE (Z_PK, Z_ENT, Z_OPT, ZCONTENTTYPE, ZMESSAGETYPE, ZREADCOUNT, ZSENDSTATUS, ZCHAT, ZSENDER, ZTIMESTAMP, ZID, ZTEXT, ZCONTENTMETADATA, ZTHUMBNAIL) VALUES (?1, 5, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)")?
    };
    for (i, m) in msgs.iter().enumerate() {
        stmt.execute(params![
            i as i64 + 1 + pk_offset,
            m.content_type,
            m.message_type,
            m.read_count,
            m.send_status,
            m.chat_idx as i64 + 1 + pk_offset,
            m.sender_idx as i64 + 1 + pk_offset,
            m.ts,
            m.zid,
            m.text,
            m.metadata,
            m.thumbnail,
        ])?;
    }
    drop(stmt);
    conn.execute_batch("COMMIT; PRAGMA wal_checkpoint(TRUNCATE);")?;
    Ok(())
}

/// Canonical digest of a message table: sha256 over rows ordered by ZID with chat/sender MIDs
/// resolved, so two databases with different Z_PK layouts but equal content agree.
pub fn logical_digest(conn: &Connection) -> Result<String> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    let mut stmt = conn.prepare(
        "SELECT m.ZID, c.ZMID, u.ZMID, m.ZTIMESTAMP, m.ZCONTENTTYPE, m.ZMESSAGETYPE, m.ZTEXT, m.ZCONTENTMETADATA, m.ZTHUMBNAIL, m.ZSENDSTATUS, m.ZREADCOUNT
         FROM ZMESSAGE m LEFT JOIN ZCHAT c ON c.Z_PK = m.ZCHAT LEFT JOIN ZUSER u ON u.Z_PK = m.ZSENDER
         ORDER BY m.ZID IS NULL, m.ZID, m.ZTIMESTAMP",
    )?;
    let rows = stmt.query_map([], |r| {
        let mut row = Vec::new();
        for i in 0..11 {
            let v: rusqlite::types::Value = r.get(i)?;
            row.push(v);
        }
        Ok(row)
    })?;
    for row in rows {
        for v in row? {
            match v {
                rusqlite::types::Value::Null => h.update(b"\x00N"),
                rusqlite::types::Value::Integer(i) => {
                    h.update(b"\x00I");
                    h.update(i.to_le_bytes());
                }
                rusqlite::types::Value::Real(f) => {
                    h.update(b"\x00R");
                    h.update(f.to_le_bytes());
                }
                rusqlite::types::Value::Text(t) => {
                    h.update(b"\x00T");
                    h.update((t.len() as u64).to_le_bytes());
                    h.update(t.as_bytes());
                }
                rusqlite::types::Value::Blob(b) => {
                    h.update(b"\x00B");
                    h.update((b.len() as u64).to_le_bytes());
                    h.update(&b);
                }
            }
        }
        h.update(b"\n");
    }
    Ok(hex::encode(h.finalize()))
}

/// Build `old.sqlite`, `current.sqlite`, and `expected_repaired.sqlite` in `dir`.
pub fn build(dir: &Path, spec: &LineDbSpec) -> Result<LineDbTruth> {
    std::fs::create_dir_all(dir).map_err(|e| crate::RecoveryError::io(e, dir))?;
    let mut rng = Prng::seeded(spec.seed);
    let total_special: u32 = PROVEN_DISTRIBUTION.iter().map(|d| d.1).sum::<u32>()
        + PRESERVED_PLACEHOLDERS
        + OLD_ONLY_MESSAGES
        + spec.chat_conflicts
        + spec.timestamp_conflicts
        + spec.unknown_differences
        + 2;
    assert!(
        spec.message_count > total_special,
        "message_count too small for the distribution"
    );
    assert_eq!(
        PROVEN_DISTRIBUTION.iter().map(|d| d.1).sum::<u32>(),
        EXPECTED_CANDIDATES
    );

    let chats: Vec<String> = (0..spec.chat_count)
        .map(|_| format!("u{}", rng.hex(16)))
        .collect();
    let users: Vec<String> = (0..(spec.chat_count * 2))
        .map(|_| format!("u{}", rng.hex(16)))
        .collect();

    // Old database: realistic mix of normal messages.
    let base_ts: i64 = 1_501_323_951_046;
    let mut old: Vec<Msg> = Vec::with_capacity(spec.message_count as usize);
    for i in 0..spec.message_count {
        let content_type = match rng.below(100) {
            0..=79 => 0,
            80..=89 => 1,
            90..=93 => 2,
            94..=95 => 3,
            96..=97 => 14,
            _ => 112,
        };
        let text = match content_type {
            0 => Some(format!("message {} {}", i, rng.hex(8))),
            2 | 3 => Some(format!("media caption {}", rng.hex(4))),
            _ => None,
        };
        let metadata = if content_type != 0 || rng.below(100) < 60 {
            let n = 24 + rng.below(40) as usize;
            Some(rng.bytes(n))
        } else {
            None
        };
        let thumbnail = if matches!(content_type, 1 | 2) {
            Some(rng.bytes(64))
        } else {
            None
        };
        old.push(Msg {
            zid: Some(format!(
                "{}",
                1_000_000_000_000u64 + u64::from(i) * 7 + rng.below(5)
            )),
            chat_idx: rng.below(u64::from(spec.chat_count)) as u32,
            sender_idx: rng.below(u64::from(spec.chat_count) * 2) as u32,
            ts: base_ts + i64::from(i) * 60_000 + rng.below(50_000) as i64,
            content_type,
            message_type: 0,
            text,
            metadata,
            thumbnail,
            send_status: 2,
            read_count: rng.below(3) as i64,
        });
    }
    // Ensure ZIDs unique in old.
    {
        let mut seen = std::collections::HashSet::new();
        for m in &mut old {
            let mut z = m.zid.clone().expect("set");
            while !seen.insert(z.clone()) {
                z.push('1');
            }
            m.zid = Some(z);
        }
    }

    // Choose special indices without overlap. Deterministic shuffle.
    let mut idx: Vec<u32> = (0..spec.message_count).collect();
    for i in (1..idx.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        idx.swap(i, j);
    }
    let mut cursor = 0usize;
    let mut take = |n: u32| -> Vec<u32> {
        let v = idx[cursor..cursor + n as usize].to_vec();
        cursor += n as usize;
        v
    };

    // 227 candidates: set old types to match distribution, then mutate in current.
    let mut candidates: Vec<(u32, i64, bool, bool)> = Vec::new(); // (index, old_type, text_differs, metadata_differs)
    for (old_type, count, text_diff, meta_diff) in PROVEN_DISTRIBUTION {
        let picks = take(count);
        for (k, &i) in picks.iter().enumerate() {
            let m = &mut old[i as usize];
            m.content_type = old_type;
            let td = (k as u32) < text_diff;
            let md = (k as u32) < meta_diff;
            // Text: present in old when it must differ (current will NULL it); otherwise NULL in both.
            m.text = if td {
                Some(format!("original text {} {}", i, rng.hex(6)))
            } else {
                None
            };
            m.metadata = if md { Some(rng.bytes(32)) } else { None };
            candidates.push((i, old_type, td, md));
        }
    }
    let preserved = take(PRESERVED_PLACEHOLDERS);
    for &i in &preserved {
        let m = &mut old[i as usize];
        m.content_type = PLACEHOLDER_TYPE;
        m.text = None;
        m.metadata = None;
    }
    let old_only = take(OLD_ONLY_MESSAGES);
    let chat_conf = take(spec.chat_conflicts);
    let ts_conf = take(spec.timestamp_conflicts);
    let unknown = take(spec.unknown_differences);
    let dup_source = take(1);
    let null_target = take(1);
    if spec.null_zid_in_old {
        old[null_target[0] as usize].zid = None;
    }

    // Current database = old minus old-only, with 106 placeholders, conflicts, extra messages.
    let mut current: Vec<Msg> =
        Vec::with_capacity(old.len() + spec.current_only_messages as usize + 1);
    let mut candidate_zids = Vec::new();
    for (i, m) in old.iter().enumerate() {
        let i = i as u32;
        if old_only.contains(&i) {
            continue;
        }
        let mut c = m.clone();
        if let Some(&(_, _, _td, _md)) = candidates.iter().find(|c| c.0 == i) {
            c.content_type = PLACEHOLDER_TYPE;
            c.text = None; // text differs iff old had text
            c.metadata = None; // metadata differs iff old had metadata
            candidate_zids.push(m.zid.clone().expect("zid"));
        }
        if chat_conf.contains(&i) {
            // Looks like a candidate but points to a different chat: must be excluded.
            c.content_type = PLACEHOLDER_TYPE;
            c.text = None;
            c.chat_idx = (c.chat_idx + 1) % spec.chat_count;
        }
        if ts_conf.contains(&i) {
            c.content_type = PLACEHOLDER_TYPE;
            c.text = None;
            c.ts += 1;
        }
        if unknown.contains(&i) {
            // Differs, but current type is not the placeholder: no rule covers it.
            c.text = Some(format!("edited {}", rng.hex(4)));
        }
        current.push(c);
    }
    if spec.null_zid_in_old {
        // the null-ZID row exists in current with a real ZID so only old is defective
        if let Some(c) = current.iter_mut().find(|c| c.zid.is_none()) {
            c.zid = Some("9999999999999".into());
        }
    }
    let last_ts = old.last().map(|m| m.ts).unwrap_or(base_ts);
    for j in 0..spec.current_only_messages {
        current.push(Msg {
            zid: Some(format!("{}", 2_000_000_000_000u64 + u64::from(j))),
            chat_idx: rng.below(u64::from(spec.chat_count)) as u32,
            sender_idx: rng.below(u64::from(spec.chat_count) * 2) as u32,
            ts: last_ts + 60_000 * (i64::from(j) + 1),
            content_type: 0,
            message_type: 0,
            text: Some(format!("new device message {j}")),
            metadata: None,
            thumbnail: None,
            send_status: 2,
            read_count: 0,
        });
    }
    if spec.duplicate_zid_in_current {
        let mut dup = current
            .iter()
            .find(|c| c.zid == old[dup_source[0] as usize].zid)
            .cloned()
            .expect("source present");
        dup.ts += 5;
        current.push(dup);
    }

    // Expected repaired = current with candidate rows restored from old (only three fields).
    let mut repaired = current.clone();
    for c in &mut repaired {
        if let Some(o) = candidate_zids
            .iter()
            .position(|z| Some(z) == c.zid.as_ref())
        {
            let src = old
                .iter()
                .find(|m| m.zid.as_deref() == Some(candidate_zids[o].as_str()))
                .expect("old");
            c.content_type = src.content_type;
            c.text = src.text.clone();
            c.metadata = src.metadata.clone();
        }
    }

    // Offsets prove Z_PK is never compared across databases.
    write_db(&dir.join("old.sqlite"), &old, &chats, &users, 0, false)?;
    write_db(
        &dir.join("current.sqlite"),
        &current,
        &chats,
        &users,
        1000,
        spec.break_schema,
    )?;
    write_db(
        &dir.join("expected_repaired.sqlite"),
        &repaired,
        &chats,
        &users,
        1000,
        spec.break_schema,
    )?;
    let digest = if spec.break_schema {
        String::new()
    } else {
        let conn = Connection::open_with_flags(
            dir.join("expected_repaired.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        logical_digest(&conn)?
    };
    candidate_zids.sort();
    Ok(LineDbTruth {
        old_message_count: old.len() as u32,
        current_message_count: current.len() as u32,
        expected_candidates: EXPECTED_CANDIDATES,
        preserved_placeholders: PRESERVED_PLACEHOLDERS,
        old_only: OLD_ONLY_MESSAGES,
        current_only: spec.current_only_messages,
        chat_conflicts: spec.chat_conflicts,
        timestamp_conflicts: spec.timestamp_conflicts,
        unknown_differences: spec.unknown_differences,
        text_differences: PROVEN_DISTRIBUTION.iter().map(|d| d.2).sum(),
        metadata_differences: PROVEN_DISTRIBUTION.iter().map(|d| d.3).sum(),
        candidate_zids,
        expected_repaired_logical_digest: digest,
    })
}

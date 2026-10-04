//! Adapter for the LINE iOS Core Data store proven in October 2026.
//!
//! Rule `type106-placeholder-restore/2` (report §7.3, §8.1):
//!
//! ```text
//! identity   :=  ZID, non-NULL and unique in BOTH databases
//!                (NULL-ZID rows and every row carrying a duplicated ZID are excluded and counted)
//! candidate  :=  current.ZCONTENTTYPE = 106
//!            AND old.ZID = current.ZID
//!            AND old.ZCONTENTTYPE IS NOT NULL AND old.ZCONTENTTYPE != 106
//!            AND chat MID equal AND ZTIMESTAMP equal
//! authorized :=  ZCONTENTTYPE, ZTEXT, ZCONTENTMETADATA   (restored from old)
//! ```
//!
//! Version 2 differs from version 1 only in the identity rule: version 1 treated any NULL or
//! duplicated `ZID` as a blocker for the whole analysis. Real LINE stores carry local rows with
//! `ZID IS NULL` (content type 0) and occasional byte-identical duplicate rows, so version 2
//! excludes exactly those rows and reports the counts; the repair statement additionally refuses
//! to touch an identifier that is not unique in both databases.

use rusqlite::{params, Connection, Transaction};

use crate::analysis::adapter::{AnalysisOutcome, Candidate, LineAdapter};
use crate::progress::{ProgressSink, Stage};
use crate::Result;

pub const PLACEHOLDER_TYPE: i64 = 106;

#[derive(Debug, Default, Clone, Copy)]
pub struct LineIosCoreDataV1;

const REQUIRED: &[(&str, &[&str])] = &[
    (
        "ZMESSAGE",
        &[
            "Z_PK",
            "ZID",
            "ZCHAT",
            "ZSENDER",
            "ZTIMESTAMP",
            "ZCONTENTTYPE",
            "ZTEXT",
            "ZCONTENTMETADATA",
            "ZTHUMBNAIL",
            "ZSENDSTATUS",
            "ZREADCOUNT",
        ],
    ),
    ("ZCHAT", &["Z_PK", "ZMID", "ZTYPE"]),
];
const AUTHORIZED: &[&str] = &["ZCONTENTTYPE", "ZTEXT", "ZCONTENTMETADATA"];
const PROTECTED: &[&str] = &[
    "Z_PK",
    "ZID",
    "ZCHAT",
    "ZSENDER",
    "ZTIMESTAMP",
    "ZSENDSTATUS",
    "ZREADCOUNT",
    "ZTHUMBNAIL",
];

/// Identifiers that occur more than once in either database. Rows carrying them never match.
const DUPS_CTE: &str = "
dups AS (
    SELECT ZID FROM main.ZMESSAGE WHERE ZID IS NOT NULL GROUP BY ZID HAVING COUNT(*) > 1
    UNION
    SELECT ZID FROM olddb.ZMESSAGE WHERE ZID IS NOT NULL GROUP BY ZID HAVING COUNT(*) > 1
)";

/// Matched pairs with chat MIDs resolved inside each database. `olddb` must be attached.
/// NULL identifiers never join; duplicated identifiers are removed on both sides.
const MATCHED_CTE: &str = "
WITH dups AS (
    SELECT ZID FROM main.ZMESSAGE WHERE ZID IS NOT NULL GROUP BY ZID HAVING COUNT(*) > 1
    UNION
    SELECT ZID FROM olddb.ZMESSAGE WHERE ZID IS NOT NULL GROUP BY ZID HAVING COUNT(*) > 1
),
cur AS (
    SELECT m.ZID AS zid, c.ZMID AS chat_mid, m.ZTIMESTAMP AS ts, m.ZSENDER AS sender_pk,
           m.ZCONTENTTYPE AS ct, m.ZTEXT AS txt, m.ZCONTENTMETADATA AS meta, m.ZTHUMBNAIL AS thumb
    FROM main.ZMESSAGE m LEFT JOIN main.ZCHAT c ON c.Z_PK = m.ZCHAT
    WHERE m.ZID IS NOT NULL AND m.ZID NOT IN (SELECT ZID FROM dups)
),
old AS (
    SELECT m.ZID AS zid, c.ZMID AS chat_mid, m.ZTIMESTAMP AS ts, m.ZSENDER AS sender_pk,
           m.ZCONTENTTYPE AS ct, m.ZTEXT AS txt, m.ZCONTENTMETADATA AS meta, m.ZTHUMBNAIL AS thumb
    FROM olddb.ZMESSAGE m LEFT JOIN olddb.ZCHAT c ON c.Z_PK = m.ZCHAT
    WHERE m.ZID IS NOT NULL AND m.ZID NOT IN (SELECT ZID FROM dups)
),
matched AS (
    SELECT cur.zid AS zid,
           cur.chat_mid IS NOT old.chat_mid AS chat_conflict,
           cur.ts IS NOT old.ts AS ts_conflict,
           cur.ct AS cur_ct, old.ct AS old_ct,
           cur.txt IS NOT old.txt AS txt_diff,
           cur.meta IS NOT old.meta AS meta_diff,
           cur.thumb IS NOT old.thumb AS thumb_diff
    FROM cur JOIN old ON old.zid = cur.zid
)";

fn has_user_mid(conn: &Connection, schema: &str) -> bool {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {schema}.pragma_table_info('ZUSER') WHERE name = 'ZMID'"),
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

impl LineAdapter for LineIosCoreDataV1 {
    fn id(&self) -> &'static str {
        "line-ios-coredata-v1"
    }
    fn rule_version(&self) -> &'static str {
        "type106-placeholder-restore/2"
    }
    fn message_table(&self) -> &'static str {
        "ZMESSAGE"
    }
    fn identity_column(&self) -> &'static str {
        "ZID"
    }
    fn required_schema(&self) -> &'static [(&'static str, &'static [&'static str])] {
        REQUIRED
    }
    fn authorized_fields(&self) -> &'static [&'static str] {
        AUTHORIZED
    }
    fn protected_fields(&self) -> &'static [&'static str] {
        PROTECTED
    }
    fn candidate_predicate(&self) -> &'static str {
        "ZID IS NOT NULL AND ZID unique in both databases AND current.ZCONTENTTYPE = 106 AND old.ZID = current.ZID AND old.ZCONTENTTYPE IS NOT NULL AND old.ZCONTENTTYPE != 106 AND chat_mid(old) = chat_mid(current) AND old.ZTIMESTAMP = current.ZTIMESTAMP"
    }

    fn analyze(&self, conn: &Connection, progress: &dyn ProgressSink) -> Result<AnalysisOutcome> {
        let mut out = AnalysisOutcome::default();
        let q = |sql: &str| -> Result<u64> {
            Ok(conn.query_row(sql, [], |r| r.get::<_, i64>(0))? as u64)
        };
        progress.report(Stage::Analysis, 1, 10);
        out.counts.old_messages = q("SELECT COUNT(*) FROM olddb.ZMESSAGE")?;
        out.counts.current_messages = q("SELECT COUNT(*) FROM main.ZMESSAGE")?;

        // Identity preflight. NULL and duplicated identifiers are excluded from matching and
        // counted (rule version 2); duplicated chat MIDs still block because relationship
        // validation would be ambiguous.
        for (label, schema) in [("old", "olddb"), ("current", "main")] {
            let nulls = q(&format!(
                "SELECT COUNT(*) FROM {schema}.ZMESSAGE WHERE ZID IS NULL"
            ))?;
            if nulls > 0 {
                out.warnings.push(format!(
                    "{label} database has {nulls} message rows with NULL ZID; they are never matched or written"
                ));
            }
            if label == "old" {
                out.counts.null_identity_rows_old = nulls;
            } else {
                out.counts.null_identity_rows_current = nulls;
            }
            let dup_chats = q(&format!("SELECT COUNT(*) FROM (SELECT ZMID FROM {schema}.ZCHAT WHERE ZMID IS NOT NULL GROUP BY ZMID HAVING COUNT(*) > 1)"))?;
            if dup_chats > 0 {
                out.blockers.push(format!(
                    "{label} database has {dup_chats} duplicated chat MIDs"
                ));
            }
        }
        out.counts.duplicate_identity_values =
            q(&format!("WITH {DUPS_CTE} SELECT COUNT(*) FROM dups"))?;
        if out.counts.duplicate_identity_values > 0 {
            out.warnings.push(format!(
                "{} ZID values occur on more than one row in the old or current database; every row carrying them is excluded from matching and repair",
                out.counts.duplicate_identity_values
            ));
        }
        progress.check_cancelled()?;
        progress.report(Stage::Analysis, 2, 10);
        if !out.blockers.is_empty() {
            return Ok(out);
        }

        out.counts.old_only = q(&format!("WITH {DUPS_CTE} SELECT COUNT(*) FROM olddb.ZMESSAGE o WHERE o.ZID IS NOT NULL AND o.ZID NOT IN (SELECT ZID FROM dups) AND NOT EXISTS (SELECT 1 FROM main.ZMESSAGE n WHERE n.ZID = o.ZID)"))?;
        out.counts.current_only = q(&format!("WITH {DUPS_CTE} SELECT COUNT(*) FROM main.ZMESSAGE n WHERE n.ZID IS NOT NULL AND n.ZID NOT IN (SELECT ZID FROM dups) AND NOT EXISTS (SELECT 1 FROM olddb.ZMESSAGE o WHERE o.ZID = n.ZID)"))?;
        out.counts.matched = q(&format!("{MATCHED_CTE} SELECT COUNT(*) FROM matched"))?;
        out.counts.chat_conflicts = q(&format!(
            "{MATCHED_CTE} SELECT COUNT(*) FROM matched WHERE chat_conflict"
        ))?;
        out.counts.timestamp_conflicts = q(&format!(
            "{MATCHED_CTE} SELECT COUNT(*) FROM matched WHERE ts_conflict AND NOT chat_conflict"
        ))?;
        progress.report(Stage::Analysis, 4, 10);

        // Sender check via MID when both schemas expose ZUSER.ZMID.
        if has_user_mid(conn, "main") && has_user_mid(conn, "olddb") {
            out.counts.sender_conflicts = q(
                "SELECT COUNT(*) FROM main.ZMESSAGE n JOIN olddb.ZMESSAGE o ON o.ZID = n.ZID
                 LEFT JOIN main.ZUSER nu ON nu.Z_PK = n.ZSENDER LEFT JOIN olddb.ZUSER ou ON ou.Z_PK = o.ZSENDER
                 WHERE nu.ZMID IS NOT ou.ZMID",
            )?;
        } else {
            out.warnings.push("sender_check: unavailable (ZUSER.ZMID not present in both schemas); ZSENDER is protected and never written".into());
        }
        progress.check_cancelled()?;

        // Candidates.
        let cand_where = "cur_ct = 106 AND old_ct IS NOT NULL AND old_ct != 106 AND NOT chat_conflict AND NOT ts_conflict";
        {
            let mut stmt = conn.prepare(&format!("{MATCHED_CTE} SELECT zid, old_ct, txt_diff, meta_diff FROM matched WHERE {cand_where} ORDER BY zid"))?;
            let rows = stmt.query_map([], |r| {
                Ok(Candidate {
                    identifier: r.get(0)?,
                    old_content_type: r.get(1)?,
                    text_differs: r.get::<_, i64>(2)? != 0,
                    metadata_differs: r.get::<_, i64>(3)? != 0,
                })
            })?;
            for c in rows {
                let c = c?;
                out.counts.text_differences += u64::from(c.text_differs);
                out.counts.metadata_differences += u64::from(c.metadata_differs);
                *out.counts
                    .candidates_by_old_type
                    .entry(c.old_content_type.to_string())
                    .or_insert(0) += 1;
                out.candidates.push(c);
            }
        }
        out.counts.candidates = out.candidates.len() as u64;
        progress.report(Stage::Analysis, 7, 10);
        out.counts.preserved_placeholders = q(&format!(
            "{MATCHED_CTE} SELECT COUNT(*) FROM matched WHERE cur_ct = 106 AND old_ct = 106"
        ))?;
        // Rows that differ in compared content fields but match no rule (diagnostic only).
        out.counts.unknown_differences = q(&format!(
            "{MATCHED_CTE} SELECT COUNT(*) FROM matched WHERE NOT chat_conflict AND NOT ts_conflict
             AND NOT ({cand_where}) AND NOT (cur_ct = 106 AND old_ct = 106)
             AND (txt_diff OR meta_diff OR thumb_diff OR cur_ct IS NOT old_ct)"
        ))?;
        // Placeholder rows whose old counterpart is also unusable (NULL type) are unsupported.
        let null_old = q(&format!(
            "{MATCHED_CTE} SELECT COUNT(*) FROM matched WHERE cur_ct = 106 AND old_ct IS NULL"
        ))?;
        if null_old > 0 {
            out.warnings.push(format!(
                "{null_old} placeholder rows have a NULL old content type and are left untouched"
            ));
        }
        progress.report(Stage::Analysis, 10, 10);
        Ok(out)
    }

    fn repair_one(&self, tx: &Transaction<'_>, identifier: &str) -> Result<usize> {
        // The predicate is repeated in full for every row; identity uniqueness, chat MID and
        // timestamp agreement are re-checked here so a drifted input cannot be repaired and the
        // scalar subqueries can never pick an arbitrary row.
        let n = tx.execute(
            "UPDATE main.ZMESSAGE
             SET ZCONTENTTYPE = (SELECT o.ZCONTENTTYPE FROM olddb.ZMESSAGE o WHERE o.ZID = ?1),
                 ZTEXT = (SELECT o.ZTEXT FROM olddb.ZMESSAGE o WHERE o.ZID = ?1),
                 ZCONTENTMETADATA = (SELECT o.ZCONTENTMETADATA FROM olddb.ZMESSAGE o WHERE o.ZID = ?1)
             WHERE ZID = ?1 AND ZCONTENTTYPE = 106
               AND (SELECT COUNT(*) FROM main.ZMESSAGE d WHERE d.ZID = ?1) = 1
               AND (SELECT COUNT(*) FROM olddb.ZMESSAGE d WHERE d.ZID = ?1) = 1
               AND EXISTS (
                   SELECT 1 FROM olddb.ZMESSAGE o
                   LEFT JOIN olddb.ZCHAT oc ON oc.Z_PK = o.ZCHAT
                   LEFT JOIN main.ZCHAT nc ON nc.Z_PK = main.ZMESSAGE.ZCHAT
                   WHERE o.ZID = ?1 AND o.ZCONTENTTYPE IS NOT NULL AND o.ZCONTENTTYPE != 106
                     AND oc.ZMID IS nc.ZMID AND o.ZTIMESTAMP IS main.ZMESSAGE.ZTIMESTAMP
               )",
            params![identifier],
        )?;
        Ok(n)
    }

    fn count_repaired_mismatches(&self, conn: &Connection, identifiers: &[String]) -> Result<u64> {
        let mut stmt = conn.prepare(
            "SELECT (r.ZCONTENTTYPE IS NOT o.ZCONTENTTYPE) + (r.ZTEXT IS NOT o.ZTEXT) + (r.ZCONTENTMETADATA IS NOT o.ZCONTENTMETADATA)
             FROM main.ZMESSAGE r JOIN olddb.ZMESSAGE o ON o.ZID = r.ZID WHERE r.ZID = ?1",
        )?;
        let mut mismatches = 0u64;
        for id in identifiers {
            let n: Option<i64> = stmt.query_row([id], |r| r.get(0)).ok();
            match n {
                Some(0) => {}
                Some(k) => mismatches += k as u64,
                None => mismatches += 3, // row vanished
            }
        }
        Ok(mismatches)
    }
}

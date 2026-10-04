//! The compatibility-adapter contract. Generic modules never reference a concrete adapter.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::analysis::schema::SchemaFingerprint;
use crate::progress::ProgressSink;
use crate::Result;

/// Counts that explain an analysis. Every number can be recomputed from the two inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisCounts {
    pub old_messages: u64,
    pub current_messages: u64,
    pub matched: u64,
    pub old_only: u64,
    pub current_only: u64,
    pub chat_conflicts: u64,
    pub timestamp_conflicts: u64,
    pub sender_conflicts: u64,
    pub candidates: u64,
    pub preserved_placeholders: u64,
    pub unknown_differences: u64,
    pub text_differences: u64,
    pub metadata_differences: u64,
    /// `old_type → count` for candidates.
    pub candidates_by_old_type: std::collections::BTreeMap<String, u64>,
    /// Rows whose identity column is NULL (system/local rows). Never matched, never written.
    #[serde(default)]
    pub null_identity_rows_old: u64,
    #[serde(default)]
    pub null_identity_rows_current: u64,
    /// Identity values that occur on more than one row in either database. Every row carrying
    /// such a value is excluded from matching so a repair can never pick an arbitrary row.
    #[serde(default)]
    pub duplicate_identity_values: u64,
}

/// One candidate as the adapter sees it. The identifier is real and must stay in memory only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub identifier: String,
    pub old_content_type: i64,
    pub text_differs: bool,
    pub metadata_differs: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisOutcome {
    pub counts: AnalysisCounts,
    pub candidates: Vec<Candidate>,
    /// Human-readable, secret-free notes (e.g. "sender check unavailable").
    pub warnings: Vec<String>,
    /// Reasons the plan is not actionable even if candidates exist (fail closed).
    pub blockers: Vec<String>,
}

/// A versioned LINE compatibility adapter.
pub trait LineAdapter: Send + Sync {
    /// Stable adapter identifier, e.g. `line-ios-coredata-v1`.
    fn id(&self) -> &'static str;
    /// Stable rule identifier and version, e.g. `type106-placeholder-restore/2`.
    fn rule_version(&self) -> &'static str;
    /// Table holding messages and the column carrying the stable identity.
    fn message_table(&self) -> &'static str;
    fn identity_column(&self) -> &'static str;
    /// Tables and columns both databases must expose.
    fn required_schema(&self) -> &'static [(&'static str, &'static [&'static str])];
    /// Fields the repair may write.
    fn authorized_fields(&self) -> &'static [&'static str];
    /// Fields that must be byte-identical before and after repair for every row.
    fn protected_fields(&self) -> &'static [&'static str];
    /// Textual predicate (for the plan and the report) describing a candidate row.
    fn candidate_predicate(&self) -> &'static str;
    /// Does this adapter accept both schemas? Returns missing requirements otherwise.
    fn schema_gaps(&self, old: &SchemaFingerprint, current: &SchemaFingerprint) -> Vec<String> {
        let mut gaps = crate::analysis::schema::missing_columns(old, self.required_schema())
            .into_iter()
            .map(|m| format!("old: {m}"))
            .collect::<Vec<_>>();
        gaps.extend(
            crate::analysis::schema::missing_columns(current, self.required_schema())
                .into_iter()
                .map(|m| format!("current: {m}")),
        );
        gaps
    }
    /// Compare the two databases. `conn` is a read-only connection to the current database with
    /// the old database attached as `olddb`.
    fn analyze(&self, conn: &Connection, progress: &dyn ProgressSink) -> Result<AnalysisOutcome>;
    /// Repair one candidate inside an open transaction on the working copy (old attached as
    /// `olddb`). Must repeat the full predicate and return the number of rows changed.
    fn repair_one(&self, tx: &rusqlite::Transaction<'_>, identifier: &str) -> Result<usize>;
    /// Count rows where the repaired authorized fields differ from the old values for the given
    /// identifiers (`repaired` is the main database, old attached as `olddb`).
    fn count_repaired_mismatches(&self, conn: &Connection, identifiers: &[String]) -> Result<u64>;
}

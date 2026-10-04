//! Versioned session manifest.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::hash::Sha256Hex;
use crate::progress::Stage;

/// Bump when the on-disk layout changes incompatibly. Older manifests are rejected, never
/// migrated silently.
pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageState {
    /// Never started.
    Pending,
    /// Started; outputs (if any) live in `staging/` and are partial.
    Running,
    /// Outputs fsynced, hashed and registered.
    Committed,
    /// Stopped on an error; diagnostic detail retained, outputs partial.
    Failed,
    /// Cancelled cooperatively; sensitive partial outputs removed.
    Cancelled,
    /// A later input change invalidated this stage's evidence.
    Invalidated,
}

/// One committed output file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputEntry {
    /// Path relative to the workspace root.
    pub path: PathBuf,
    pub size: u64,
    pub sha256: Sha256Hex,
    /// True when the file holds decrypted user data and must be removed on cleanup.
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageRecord {
    pub state: StageState,
    #[serde(default)]
    pub outputs: Vec<OutputEntry>,
    /// RFC 3339 with explicit offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// Secret-free structured error when `state == Failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::RecoveryError>,
    /// Free-form, secret-free evidence (counts, hashes, rule versions) carried forward.
    #[serde(default)]
    pub evidence: serde_json::Value,
}

impl Default for StageRecord {
    fn default() -> Self {
        Self {
            state: StageState::Pending,
            outputs: Vec::new(),
            started_at: None,
            finished_at: None,
            error: None,
            evidence: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionManifest {
    pub manifest_version: u32,
    pub core_version: String,
    /// Random per-session identifier; also used to salt public identifiers in reports.
    pub session_id: String,
    pub created_at: String,
    pub stages: BTreeMap<Stage, StageRecord>,
    /// Non-secret inputs: selected directories, device metadata, hashes.
    #[serde(default)]
    pub inputs: serde_json::Value,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl SessionManifest {
    pub fn new(session_id: String, created_at: String) -> Self {
        let mut stages = BTreeMap::new();
        for s in Stage::ALL {
            stages.insert(s, StageRecord::default());
        }
        Self {
            manifest_version: MANIFEST_VERSION,
            core_version: crate::CORE_VERSION.to_owned(),
            session_id,
            created_at,
            stages,
            inputs: serde_json::Value::Null,
            warnings: Vec::new(),
        }
    }

    pub fn stage(&self, stage: Stage) -> &StageRecord {
        self.stages.get(&stage).expect("all stages present")
    }

    pub fn stage_mut(&mut self, stage: Stage) -> &mut StageRecord {
        self.stages.get_mut(&stage).expect("all stages present")
    }

    pub fn is_committed(&self, stage: Stage) -> bool {
        self.stage(stage).state == StageState::Committed
    }

    /// Mark `from` and every later stage as invalidated (inputs changed).
    pub fn invalidate_from(&mut self, from: Stage) {
        let mut hit = false;
        for s in Stage::ALL {
            if s == from {
                hit = true;
            }
            if hit {
                let rec = self.stage_mut(s);
                if rec.state != StageState::Pending {
                    rec.state = StageState::Invalidated;
                }
            }
        }
    }
}

impl std::cmp::PartialOrd for Stage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Stage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let idx = |s: &Stage| {
            Stage::ALL
                .iter()
                .position(|x| x == s)
                .expect("stage in ALL")
        };
        idx(self).cmp(&idx(other))
    }
}

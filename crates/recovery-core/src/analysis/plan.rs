//! The RepairPlan: immutable mutation contract.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::analysis::adapter::{AnalysisCounts, Candidate};
use crate::hash::Sha256Hex;

/// Serializable plan. Contains no message text and no raw message identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPlan {
    /// SHA-256 over the deterministic content of this plan (excludes salted identifiers and
    /// timestamps), so identical inputs and rules yield the same id in every session.
    pub plan_id: String,
    pub adapter_id: String,
    pub rule_version: String,
    pub core_version: String,
    pub input_hashes: InputHashes,
    pub candidate_predicate: String,
    pub authorized_fields: Vec<String>,
    pub protected_fields: Vec<String>,
    pub predicted_update_count: u64,
    pub counts: AnalysisCounts,
    pub exclusions: Vec<Exclusion>,
    pub warnings: Vec<String>,
    pub blockers: Vec<String>,
    /// `actionable == true` means the Patch stage may be offered to the user.
    pub actionable: bool,
    /// Salted public identifiers of the candidates (sha256(session_salt || id)), sorted.
    pub public_candidate_ids: Vec<String>,
    /// Validation predicates re-run after repair, in plain words.
    pub validation_predicates: Vec<String>,
    pub schema_fingerprints: BTreeMap<String, Sha256Hex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputHashes {
    pub old_database: Sha256Hex,
    pub current_database: Sha256Hex,
    pub old_database_size: u64,
    pub current_database_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusion {
    pub reason: String,
    pub count: u64,
}

impl RepairPlan {
    /// Deterministic id over everything except `public_candidate_ids` and `plan_id`.
    pub fn compute_id(&self) -> String {
        use sha2::Digest;
        let mut clone = self.clone();
        clone.plan_id = String::new();
        clone.public_candidate_ids = Vec::new();
        let bytes = serde_json::to_vec(&clone).expect("plan serializes");
        hex::encode(sha2::Sha256::digest(bytes))
    }
}

/// In-memory plan with the real identifiers needed to repair. Never serialized.
#[derive(Clone)]
pub struct SecurePlan {
    pub plan: RepairPlan,
    pub candidates: Vec<Candidate>,
    pub old_db_path: PathBuf,
    pub current_db_path: PathBuf,
}

impl std::fmt::Debug for SecurePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurePlan")
            .field("plan_id", &self.plan.plan_id)
            .field("candidates", &self.candidates.len())
            .finish()
    }
}

impl SecurePlan {
    pub fn identifiers(&self) -> Vec<String> {
        self.candidates
            .iter()
            .map(|c| c.identifier.clone())
            .collect()
    }
}

/// Salted public identifier for reports.
pub fn public_id(salt: &str, identifier: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(salt.as_bytes());
    h.update(b"|");
    h.update(identifier.as_bytes());
    hex::encode(h.finalize())[..16].to_owned()
}

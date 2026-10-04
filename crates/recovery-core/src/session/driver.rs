//! Request-driven orchestration shared by the FFI and the CLI.
//!
//! The `Request` enum *is* the FFI contract: one JSON object with an `op` tag. Results are
//! `serde_json::Value` so the host can render them without a second schema. Operations are
//! added here as layers land; each one begins a stage, runs, and either commits or fails it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::progress::ProgressSink;
use crate::secret::Password;
use crate::session::Workspace;
use crate::Result;

/// Which of the two selected backups a request refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRole {
    /// Backup of the old device: the source of original message content.
    Old,
    /// Backup of the current device: the repair base and the clone source.
    Current,
}

impl BackupRole {
    pub fn as_str(self) -> &'static str {
        match self {
            BackupRole::Old => "old",
            BackupRole::Current => "current",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness check; returns core version.
    Ping,
    /// Session status: stage states, partial artifacts, warnings.
    Status,
    /// Remove plaintext and partial material.
    Cleanup,
    /// Read-only structural inspection of a backup directory. No password required.
    Inspect { backup_dir: PathBuf },
    /// Authenticate, decrypt the index, discover LINE stores, extract the working copy.
    /// `account_dir` disambiguates multiple LINE accounts (the `P_u…` directory name).
    Intake {
        role: BackupRole,
        backup_dir: PathBuf,
        #[serde(default)]
        account_dir: Option<String>,
    },
    /// Compare the two extracted databases and produce a RepairPlan.
    Analyze,
    /// Apply the plan to a working copy, encrypt, clone, replace, re-read. Requires the current
    /// backup password and an explicit confirmation matching the plan.
    Patch {
        destination_dir: PathBuf,
        confirm: PatchConfirmation,
    },
    /// Analyze and, when the resulting plan matches `confirm`, patch in the same process. Used
    /// by the CLI, whose in-memory plan does not survive between invocations.
    AnalyzeAndPatch {
        destination_dir: PathBuf,
        confirm: PatchConfirmation,
    },
    /// Export the verified clone and reports. Default never overwrites.
    Export {
        destination_dir: PathBuf,
        #[serde(default)]
        overwrite_confirmed: bool,
    },
    /// Produce the audit report (Markdown + JSON) for the current state.
    Report {
        #[serde(default)]
        redacted: bool,
    },
    /// Export the repaired plaintext database for expert inspection.
    ExportRepairedDatabase {
        destination_file: PathBuf,
        #[serde(default)]
        overwrite_confirmed: bool,
    },
    /// Generate synthetic fixtures (feature `fixtures`).
    #[cfg(feature = "fixtures")]
    GenerateFixture {
        output_dir: PathBuf,
        #[serde(default)]
        spec: crate::fixtures::FixtureSpec,
    },
}

/// Explicit mutation consent: every field must match the plan on file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchConfirmation {
    pub predicted_update_count: u64,
    pub plan_id: String,
    pub destination_dir: PathBuf,
    pub rollback_source_dir: PathBuf,
}

/// Owns the workspace and in-memory session state (unlocked keys live here, never on disk).
pub struct Driver {
    pub(crate) workspace: Workspace,
    pub(crate) state: crate::session::state::SessionState,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("workspace", &self.workspace.root())
            .finish()
    }
}

impl Driver {
    pub fn open(workspace_dir: &Path) -> Result<Self> {
        let workspace = Workspace::open(workspace_dir)?;
        Ok(Self {
            workspace,
            state: crate::session::state::SessionState::default(),
        })
    }

    pub fn workspace(&self) -> &Workspace {
        &self.workspace
    }

    /// The in-memory plan with real identifiers, present only after an actionable analysis in
    /// this process. Never persisted.
    pub fn secure_plan(&self) -> Option<&crate::analysis::plan::SecurePlan> {
        self.state.secure_plan.as_ref()
    }

    pub fn execute(
        &mut self,
        request: Request,
        password: Option<Password>,
        progress: &dyn ProgressSink,
    ) -> Result<serde_json::Value> {
        match request {
            Request::Ping => Ok(serde_json::json!({ "core_version": crate::CORE_VERSION })),
            Request::Status => Ok(self.status()),
            Request::Cleanup => {
                self.state = Default::default();
                self.workspace.cleanup_plaintext()?;
                Ok(self.status())
            }
            Request::Inspect { backup_dir } => crate::backup::ops::inspect(self, &backup_dir),
            Request::Intake {
                role,
                backup_dir,
                account_dir,
            } => crate::backup::ops::intake(
                self,
                role,
                &backup_dir,
                account_dir.as_deref(),
                password,
                progress,
            ),
            Request::Analyze => crate::analysis::ops::analyze(self, progress),
            Request::Patch {
                destination_dir,
                confirm,
            } => crate::patch::ops::patch(self, &destination_dir, &confirm, password, progress),
            Request::AnalyzeAndPatch {
                destination_dir,
                confirm,
            } => {
                let analysis = crate::analysis::ops::analyze(self, progress)?;
                let patch =
                    crate::patch::ops::patch(self, &destination_dir, &confirm, password, progress)?;
                Ok(serde_json::json!({
                    "analysis": analysis,
                    "patch": patch["patch"],
                    "verification": patch["verification"],
                    "status": patch["status"],
                }))
            }
            Request::Export {
                destination_dir,
                overwrite_confirmed,
            } => crate::patch::ops::export(self, &destination_dir, overwrite_confirmed, progress),
            Request::Report { redacted } => crate::report::ops::report(self, redacted),
            Request::ExportRepairedDatabase {
                destination_file,
                overwrite_confirmed,
            } => crate::repair::ops::export_repaired_database(
                self,
                &destination_file,
                overwrite_confirmed,
                progress,
            ),
            #[cfg(feature = "fixtures")]
            Request::GenerateFixture { output_dir, spec } => {
                let summary = crate::fixtures::generate(&output_dir, &spec, progress)?;
                Ok(serde_json::to_value(summary)?)
            }
        }
    }

    pub fn status(&self) -> serde_json::Value {
        let m = self.workspace.manifest();
        serde_json::json!({
            "session_id": m.session_id,
            "core_version": m.core_version,
            "stages": m.stages,
            "partial_artifacts": self.workspace.partial_artifacts(),
            "warnings": m.warnings,
            "inputs": m.inputs,
        })
    }
}

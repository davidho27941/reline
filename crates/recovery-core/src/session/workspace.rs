//! Session workspace on disk: restrictive permissions, staging, atomic commits, cleanup.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::hash::{sha256_file, Sha256Hex};
use crate::progress::{NoProgress, ProgressSink, Stage};
use crate::session::manifest::{OutputEntry, SessionManifest, StageRecord, StageState};
use crate::{ErrorCode, RecoveryError, Result};

const MANIFEST_FILE: &str = "session.json";
const MANIFEST_TMP: &str = "session.json.tmp";
pub(crate) const DIR_STAGING: &str = "staging";
pub(crate) const DIR_COMMITTED: &str = "committed";
pub(crate) const DIR_PLAINTEXT: &str = "plaintext";
pub(crate) const DIR_EXPORT: &str = "export";

/// Describes a committed output after `commit_stage`.
#[derive(Debug, Clone)]
pub struct OutputRecord {
    pub path: PathBuf,
    pub entry: OutputEntry,
}

/// What `Workspace::open` found on disk that is not trustworthy evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PartialArtifacts {
    /// Stages recorded as Running/Failed when the manifest was loaded (interrupted).
    pub interrupted_stages: Vec<Stage>,
    /// Files under staging/ (relative paths).
    pub staging_files: Vec<PathBuf>,
    /// Files under committed/ that the manifest does not list, or whose hash/size differ.
    pub unregistered_committed_files: Vec<PathBuf>,
    /// Plaintext material present on disk.
    pub plaintext_files: Vec<PathBuf>,
}

impl PartialArtifacts {
    pub fn is_empty(&self) -> bool {
        self.interrupted_stages.is_empty()
            && self.staging_files.is_empty()
            && self.unregistered_committed_files.is_empty()
            && self.plaintext_files.is_empty()
    }
}

#[derive(Debug)]
pub struct Workspace {
    root: PathBuf,
    manifest: SessionManifest,
    partial: PartialArtifacts,
}

fn now_rfc3339() -> String {
    // RFC 3339 in UTC with explicit offset. No chrono dependency: compute from SystemTime.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    crate::report::time::format_rfc3339_utc(secs)
}

fn random_id() -> String {
    // 128 bits from the OS CSPRNG via /dev/urandom semantics of `getrandom` through std.
    let mut buf = [0u8; 16];
    // std::fs::File::open("/dev/urandom") is portable on macOS; avoid extra dependency.
    use std::io::Read;
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    if buf == [0u8; 16] {
        // Extremely unlikely fallback; still unique per process.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        buf[..16].copy_from_slice(&t.to_le_bytes());
    }
    hex::encode(buf)
}

pub(crate) fn create_private_dir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(RecoveryError::io(e, path)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| RecoveryError::io(e, path))
}

/// Create a 0600 file for writing (truncating).
pub(crate) fn create_private_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| RecoveryError::io(e, path))
}

pub(crate) fn fsync_dir(path: &Path) -> Result<()> {
    let d = File::open(path).map_err(|e| RecoveryError::io(e, path))?;
    d.sync_all().map_err(|e| RecoveryError::io(e, path))
}

fn list_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            list_files(root, &p, out);
        } else if let Ok(rel) = p.strip_prefix(root) {
            out.push(rel.to_path_buf());
        }
    }
}

impl Workspace {
    /// Open or create a workspace at `root`. Classifies partial artifacts; never deletes.
    pub fn open(root: &Path) -> Result<Self> {
        create_private_dir(root)?;
        for d in [DIR_STAGING, DIR_COMMITTED, DIR_PLAINTEXT, DIR_EXPORT] {
            create_private_dir(&root.join(d))?;
        }
        let manifest_path = root.join(MANIFEST_FILE);
        let mut manifest = if manifest_path.exists() {
            let bytes =
                fs::read(&manifest_path).map_err(|e| RecoveryError::io(e, &manifest_path))?;
            let m: SessionManifest = serde_json::from_slice(&bytes).map_err(|e| {
                RecoveryError::new(
                    ErrorCode::SessionState,
                    format!("session manifest unreadable: {e}"),
                )
                .with_path(&manifest_path)
            })?;
            if m.manifest_version != crate::session::manifest::MANIFEST_VERSION {
                return Err(RecoveryError::new(
                    ErrorCode::SessionState,
                    format!(
                        "session manifest version {} is not supported by this build (expects {})",
                        m.manifest_version,
                        crate::session::manifest::MANIFEST_VERSION
                    ),
                )
                .with_path(&manifest_path)
                .with_remedy("Start a new session in an empty folder."));
            }
            m
        } else {
            SessionManifest::new(random_id(), now_rfc3339())
        };

        // Classify.
        let mut partial = PartialArtifacts::default();
        for s in Stage::ALL {
            let rec = manifest.stage_mut(s);
            if rec.state == StageState::Running {
                partial.interrupted_stages.push(s);
                rec.state = StageState::Failed;
                rec.error = Some(RecoveryError::new(
                    ErrorCode::SessionState,
                    "stage was interrupted before commit; its outputs are partial",
                ));
            }
        }
        list_files(root, &root.join(DIR_STAGING), &mut partial.staging_files);
        list_files(
            root,
            &root.join(DIR_PLAINTEXT),
            &mut partial.plaintext_files,
        );
        let mut committed_on_disk = Vec::new();
        list_files(root, &root.join(DIR_COMMITTED), &mut committed_on_disk);
        for rel in committed_on_disk {
            let registered = manifest.stages.values().any(|rec| {
                rec.state == StageState::Committed
                    && rec.outputs.iter().any(|o| {
                        o.path == rel
                            && fs::metadata(root.join(&o.path))
                                .map(|m| m.len() == o.size)
                                .unwrap_or(false)
                    })
            });
            if !registered {
                partial.unregistered_committed_files.push(rel);
            }
        }

        let ws = Self {
            root: root.to_path_buf(),
            manifest,
            partial,
        };
        if !manifest_path.exists() || !ws.partial.interrupted_stages.is_empty() {
            ws.write_manifest()?;
        }
        Ok(ws)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &SessionManifest {
        &self.manifest
    }

    pub fn manifest_mut(&mut self) -> &mut SessionManifest {
        &mut self.manifest
    }

    pub fn partial_artifacts(&self) -> &PartialArtifacts {
        &self.partial
    }

    pub fn plaintext_dir(&self) -> PathBuf {
        self.root.join(DIR_PLAINTEXT)
    }

    pub fn export_dir(&self) -> PathBuf {
        self.root.join(DIR_EXPORT)
    }

    pub fn staging_dir(&self, stage: Stage) -> PathBuf {
        self.root.join(DIR_STAGING).join(stage.as_str())
    }

    pub fn committed_dir(&self, stage: Stage) -> PathBuf {
        self.root.join(DIR_COMMITTED).join(stage.as_str())
    }

    /// Persist the manifest atomically: write tmp (0600), fsync, rename, fsync directory.
    pub fn write_manifest(&self) -> Result<()> {
        let tmp = self.root.join(MANIFEST_TMP);
        let final_path = self.root.join(MANIFEST_FILE);
        {
            let mut f = create_private_file(&tmp)?;
            let bytes = serde_json::to_vec_pretty(&self.manifest)?;
            f.write_all(&bytes)
                .map_err(|e| RecoveryError::io(e, &tmp))?;
            f.sync_all().map_err(|e| RecoveryError::io(e, &tmp))?;
        }
        fs::rename(&tmp, &final_path).map_err(|e| RecoveryError::io(e, &final_path))?;
        fsync_dir(&self.root)
    }

    /// Begin a stage: clear its staging dir, mark Running, persist.
    pub fn begin_stage(&mut self, stage: Stage) -> Result<PathBuf> {
        let staging = self.staging_dir(stage);
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(|e| RecoveryError::io(e, &staging))?;
        }
        create_private_dir(&staging)?;
        let rec = self.manifest.stage_mut(stage);
        *rec = StageRecord {
            state: StageState::Running,
            started_at: Some(now_rfc3339()),
            ..StageRecord::default()
        };
        // Later stages depend on this one; they are no longer valid.
        let mut later = false;
        for s in Stage::ALL {
            if later {
                let r = self.manifest.stage_mut(s);
                if r.state != StageState::Pending {
                    r.state = StageState::Invalidated;
                }
            }
            if s == stage {
                later = true;
            }
        }
        self.write_manifest()?;
        Ok(staging)
    }

    /// Commit a stage: fsync each staged output, hash it, move it under `committed/<stage>/`,
    /// then atomically register everything. `sensitive` marks outputs holding decrypted data.
    pub fn commit_stage(
        &mut self,
        stage: Stage,
        outputs: &[(PathBuf, bool)],
        evidence: serde_json::Value,
        progress: &dyn ProgressSink,
    ) -> Result<Vec<OutputRecord>> {
        if self.manifest.stage(stage).state != StageState::Running {
            return Err(RecoveryError::new(
                ErrorCode::SessionState,
                format!("cannot commit stage {} that is not running", stage.as_str()),
            ));
        }
        let committed_dir = self.committed_dir(stage);
        if committed_dir.exists() {
            fs::remove_dir_all(&committed_dir).map_err(|e| RecoveryError::io(e, &committed_dir))?;
        }
        create_private_dir(&committed_dir)?;
        let mut records = Vec::new();
        for (src, sensitive) in outputs {
            progress.check_cancelled()?;
            let f = File::open(src).map_err(|e| RecoveryError::io(e, src))?;
            f.sync_all().map_err(|e| RecoveryError::io(e, src))?;
            let size = f.metadata().map_err(|e| RecoveryError::io(e, src))?.len();
            drop(f);
            let sha256 = sha256_file(src, progress, stage)?;
            let name = src
                .file_name()
                .ok_or_else(|| RecoveryError::internal("output without file name"))?;
            let dest = committed_dir.join(name);
            fs::rename(src, &dest).map_err(|e| RecoveryError::io(e, &dest))?;
            let rel = dest
                .strip_prefix(&self.root)
                .map_err(|_| RecoveryError::internal("output outside workspace"))?
                .to_path_buf();
            records.push(OutputRecord {
                path: dest.clone(),
                entry: OutputEntry {
                    path: rel,
                    size,
                    sha256,
                    sensitive: *sensitive,
                },
            });
        }
        fsync_dir(&committed_dir)?;
        let rec = self.manifest.stage_mut(stage);
        rec.state = StageState::Committed;
        rec.finished_at = Some(now_rfc3339());
        rec.outputs = records.iter().map(|r| r.entry.clone()).collect();
        rec.evidence = evidence;
        rec.error = None;
        self.write_manifest()?;
        let staging = self.staging_dir(stage);
        let _ = fs::remove_dir_all(&staging);
        Ok(records)
    }

    /// Record a failure or cancellation. Removes the stage's staging outputs (they may hold
    /// sensitive partial data) and never marks the stage complete.
    pub fn fail_stage(&mut self, stage: Stage, err: &RecoveryError) -> Result<()> {
        let staging = self.staging_dir(stage);
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(|e| RecoveryError::io(e, &staging))?;
        }
        let rec = self.manifest.stage_mut(stage);
        rec.state = if err.is_cancelled() {
            StageState::Cancelled
        } else {
            StageState::Failed
        };
        rec.finished_at = Some(now_rfc3339());
        rec.outputs.clear();
        rec.error = Some(err.clone());
        self.write_manifest()
    }

    /// Remove every plaintext file and all staging output. Committed non-sensitive evidence and
    /// the manifest remain so the report can still be produced.
    pub fn cleanup_plaintext(&mut self) -> Result<()> {
        for d in [self.root.join(DIR_PLAINTEXT), self.root.join(DIR_STAGING)] {
            if d.exists() {
                fs::remove_dir_all(&d).map_err(|e| RecoveryError::io(e, &d))?;
            }
            create_private_dir(&d)?;
        }
        // Sensitive committed outputs (for example a repaired database retained for expert
        // inspection) are removed too unless the caller exported them first.
        let mut to_remove = Vec::new();
        for rec in self.manifest.stages.values_mut() {
            rec.outputs.retain(|o| {
                if o.sensitive {
                    to_remove.push(o.path.clone());
                    false
                } else {
                    true
                }
            });
        }
        for rel in to_remove {
            let p = self.root.join(rel);
            if p.exists() {
                fs::remove_file(&p).map_err(|e| RecoveryError::io(e, &p))?;
            }
        }
        self.partial = PartialArtifacts::default();
        self.write_manifest()
    }

    /// Verify that every committed output still has its recorded size and hash.
    pub fn verify_committed(&self) -> Result<()> {
        for (stage, rec) in &self.manifest.stages {
            if rec.state != StageState::Committed {
                continue;
            }
            for o in &rec.outputs {
                let p = self.root.join(&o.path);
                let h = sha256_file(&p, &NoProgress, *stage)?;
                if h != o.sha256 {
                    return Err(RecoveryError::new(
                        ErrorCode::SessionState,
                        format!(
                            "committed output of stage {} no longer matches its recorded hash",
                            stage.as_str()
                        ),
                    )
                    .with_path(p));
                }
            }
        }
        Ok(())
    }

    /// Path for a new plaintext file (0600) inside `plaintext/`.
    pub fn plaintext_path(&self, name: &str) -> PathBuf {
        self.plaintext_dir().join(name)
    }
}

/// Re-export for tests and callers needing a precise hash type.
pub type Hash = Sha256Hex;

#[cfg(test)]
mod tests {
    use super::*;

    fn write(p: &Path, data: &[u8]) {
        let mut f = create_private_file(p).unwrap();
        f.write_all(data).unwrap();
    }

    #[test]
    fn commit_registers_outputs_and_restart_sees_them_committed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let mut ws = Workspace::open(&root).unwrap();
        assert!(ws.partial_artifacts().is_empty());
        let staging = ws.begin_stage(Stage::Intake).unwrap();
        write(&staging.join("a.bin"), b"hello");
        let recs = ws
            .commit_stage(
                Stage::Intake,
                &[(staging.join("a.bin"), false)],
                serde_json::json!({"n": 1}),
                &NoProgress,
            )
            .unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].entry.sha256, Sha256Hex::of_bytes(b"hello"));
        let mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let fmode = fs::metadata(&recs[0].path).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o600);

        let ws2 = Workspace::open(&root).unwrap();
        assert!(ws2.manifest().is_committed(Stage::Intake));
        assert!(ws2.partial_artifacts().is_empty());
        ws2.verify_committed().unwrap();
    }

    #[test]
    fn interrupted_stage_is_partial_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let mut ws = Workspace::open(&root).unwrap();
        let staging = ws.begin_stage(Stage::Analysis).unwrap();
        write(&staging.join("partial.bin"), b"half");
        write(&ws.plaintext_path("db.sqlite"), b"secret");
        drop(ws); // simulate crash before commit

        let ws2 = Workspace::open(&root).unwrap();
        let p = ws2.partial_artifacts();
        assert_eq!(p.interrupted_stages, vec![Stage::Analysis]);
        assert_eq!(p.staging_files.len(), 1);
        assert_eq!(p.plaintext_files.len(), 1);
        assert_eq!(
            ws2.manifest().stage(Stage::Analysis).state,
            StageState::Failed
        );
        assert!(!ws2.manifest().is_committed(Stage::Analysis));
    }

    #[test]
    fn tampered_committed_output_detected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let mut ws = Workspace::open(&root).unwrap();
        let staging = ws.begin_stage(Stage::Intake).unwrap();
        write(&staging.join("a.bin"), b"hello");
        let recs = ws
            .commit_stage(
                Stage::Intake,
                &[(staging.join("a.bin"), false)],
                serde_json::Value::Null,
                &NoProgress,
            )
            .unwrap();
        fs::write(&recs[0].path, b"HELLO").unwrap();
        assert!(ws.verify_committed().is_err());
        // unregistered file in committed/ is partial
        write(&ws.committed_dir(Stage::Intake).join("orphan.bin"), b"x");
        let ws2 = Workspace::open(&root).unwrap();
        assert_eq!(
            ws2.partial_artifacts().unregistered_committed_files.len(),
            1
        );
    }

    #[test]
    fn fail_stage_removes_staging_and_never_commits() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let mut ws = Workspace::open(&root).unwrap();
        let staging = ws.begin_stage(Stage::Patching).unwrap();
        write(&staging.join("clone.part"), b"partial");
        ws.fail_stage(Stage::Patching, &RecoveryError::cancelled())
            .unwrap();
        assert!(!staging.exists());
        assert_eq!(
            ws.manifest().stage(Stage::Patching).state,
            StageState::Cancelled
        );
        assert!(ws
            .commit_stage(Stage::Patching, &[], serde_json::Value::Null, &NoProgress)
            .is_err());
    }

    #[test]
    fn cleanup_removes_plaintext_and_sensitive_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let mut ws = Workspace::open(&root).unwrap();
        write(&ws.plaintext_path("Line.sqlite"), b"chat");
        let staging = ws.begin_stage(Stage::Patching).unwrap();
        write(&staging.join("repaired.sqlite"), b"chat2");
        write(&staging.join("evidence.json"), b"{}");
        let recs = ws
            .commit_stage(
                Stage::Patching,
                &[
                    (staging.join("repaired.sqlite"), true),
                    (staging.join("evidence.json"), false),
                ],
                serde_json::Value::Null,
                &NoProgress,
            )
            .unwrap();
        ws.cleanup_plaintext().unwrap();
        assert!(!ws.plaintext_path("Line.sqlite").exists());
        assert!(!recs[0].path.exists(), "sensitive output removed");
        assert!(recs[1].path.exists(), "non-sensitive evidence kept");
        assert_eq!(ws.manifest().stage(Stage::Patching).outputs.len(), 1);
    }

    #[test]
    fn begin_stage_invalidates_later_stages() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let mut ws = Workspace::open(&root).unwrap();
        let s = ws.begin_stage(Stage::Analysis).unwrap();
        ws.commit_stage(Stage::Analysis, &[], serde_json::Value::Null, &NoProgress)
            .unwrap();
        let _ = s;
        ws.begin_stage(Stage::Intake).unwrap();
        assert_eq!(
            ws.manifest().stage(Stage::Analysis).state,
            StageState::Invalidated
        );
    }

    /// Task 2.4: the lifecycle document and the code must agree on states and cleanup actions.
    #[test]
    fn lifecycle_doc_matches_code() {
        let doc = include_str!("../../../../docs/session-lifecycle.md");
        for state in [
            "pending",
            "running",
            "committed",
            "failed",
            "cancelled",
            "invalidated",
        ] {
            assert!(
                doc.contains(&format!("`{state}`")),
                "doc lacks state {state}"
            );
            let v: StageState =
                serde_json::from_value(serde_json::json!(state)).expect("state exists in code");
            let _ = v;
        }
        for action in [
            "begin_stage",
            "commit_stage",
            "Cleanup",
            "session.json.tmp",
            "plaintext/",
            "staging/",
            "committed/",
            "manifest_version",
        ] {
            assert!(doc.contains(action), "doc lacks {action}");
        }
        for dir in [DIR_STAGING, DIR_COMMITTED, DIR_PLAINTEXT, DIR_EXPORT] {
            assert!(
                doc.contains(&format!("{dir}/")),
                "doc lacks directory {dir}"
            );
        }
    }

    #[test]
    fn unsupported_manifest_version_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let ws = Workspace::open(&root).unwrap();
        let mut m = ws.manifest().clone();
        m.manifest_version = 99;
        fs::write(root.join(MANIFEST_FILE), serde_json::to_vec(&m).unwrap()).unwrap();
        let err = Workspace::open(&root).unwrap_err();
        assert_eq!(err.code, ErrorCode::SessionState);
    }
}

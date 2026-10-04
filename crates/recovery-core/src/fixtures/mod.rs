//! Synthetic fixtures (feature = "fixtures"): encrypted backups and LINE database pairs.
//!
//! `generate` writes:
//!
//! ```text
//! <out>/old/<UDID>/…          encrypted backup of the "old" device
//! <out>/current/<UDID>/…      encrypted backup of the "current" device
//! <out>/plain/old.sqlite      plaintext databases for reference
//! <out>/plain/current.sqlite
//! <out>/plain/expected_repaired.sqlite
//! <out>/expected.json         ground truth: counts, hashes, file ids
//! ```

pub mod backup_builder;
pub mod line_db;
pub mod prng;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::backup::discovery::LINE_DOMAINS;
use crate::progress::ProgressSink;
use crate::Result;

pub use backup_builder::{BackupSpec, FixtureFile};
pub use line_db::{LineDbSpec, LineDbTruth};

pub const FIXTURE_PASSWORD: &str = "fixture-password";
pub const ACCOUNT_DIR: &str = "P_u0123456789abcdef0123456789abcdef";
pub const SECOND_ACCOUNT_DIR: &str = "P_ufedcba9876543210fedcba9876543210";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FixtureSpec {
    pub password: String,
    pub line: LineDbSpec,
    /// Protection class for Line.sqlite in both backups.
    pub protection_class: u32,
    pub with_digest: bool,
    /// Add a non-empty `Line.sqlite-wal` sibling to the current backup.
    pub pending_wal_in_current: bool,
    /// Add a second LINE account store to both backups.
    pub second_account: bool,
    /// Omit LINE entirely from the current backup.
    pub no_line_in_current: bool,
    pub current_snapshot_state: String,
    pub current_encrypted: bool,
    pub double_protection: bool,
    pub pbkdf2_iterations: u32,
    /// Declare a Manifest `Size` larger than the real plaintext, as live databases do.
    pub oversized_declared_size: bool,
    pub seed: u64,
}

impl Default for FixtureSpec {
    fn default() -> Self {
        Self {
            password: FIXTURE_PASSWORD.into(),
            line: LineDbSpec::default(),
            protection_class: 3,
            with_digest: false,
            pending_wal_in_current: false,
            second_account: false,
            no_line_in_current: false,
            current_snapshot_state: "finished".into(),
            current_encrypted: true,
            double_protection: true,
            pbkdf2_iterations: 1_000,
            oversized_declared_size: true,
            seed: 42,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureSummary {
    pub old_backup_dir: std::path::PathBuf,
    pub current_backup_dir: std::path::PathBuf,
    pub old_udid: String,
    pub current_udid: String,
    pub account_dir: String,
    pub line_relative_path: String,
    pub line_domain: String,
    pub old_line_sha256: String,
    pub current_line_sha256: String,
    pub old_line_file_id: String,
    pub truth: LineDbTruth,
    pub spec: FixtureSpec,
}

pub fn line_relative_path(account_dir: &str) -> String {
    format!("Library/Application Support/PrivateStore/{account_dir}/Messages/Line.sqlite")
}

fn common_files(
    role: &str,
    line_plain: Vec<u8>,
    spec: &FixtureSpec,
    rng: &mut prng::Prng,
) -> Vec<FixtureFile> {
    let domain = LINE_DOMAINS[0];
    let acct = ACCOUNT_DIR;
    let mut files = vec![
        FixtureFile::directory(domain, "Library"),
        FixtureFile::directory(domain, "Library/Application Support"),
        FixtureFile::directory(domain, "Library/Application Support/PrivateStore"),
        FixtureFile::directory(
            domain,
            &format!("Library/Application Support/PrivateStore/{acct}"),
        ),
        FixtureFile::directory(
            domain,
            &format!("Library/Application Support/PrivateStore/{acct}/Messages"),
        ),
        FixtureFile::regular(
            "HomeDomain",
            "Library/Preferences/com.apple.fixture.plist",
            rng.bytes(300),
            4,
        ),
        FixtureFile::regular(
            "CameraRollDomain",
            &format!("Media/DCIM/100APPLE/IMG_{role}.JPG"),
            rng.bytes(5000),
            1,
        ),
    ];
    for sibling in [
        "E2EEData.sqlite",
        "MediaMessageData.sqlite",
        "MessageExt.sqlite",
        "UserDataModel.sqlite",
    ] {
        let mut blob = b"SQLite format 3\0".to_vec();
        blob.extend(rng.bytes(4096 - 16));
        files.push(FixtureFile::regular(
            domain,
            &format!("Library/Application Support/PrivateStore/{acct}/Messages/{sibling}"),
            blob,
            spec.protection_class,
        ));
    }
    let mut line = FixtureFile::regular(
        domain,
        &line_relative_path(acct),
        line_plain,
        spec.protection_class,
    );
    line.with_digest = spec.with_digest;
    if spec.oversized_declared_size {
        line.declared_size = Some(line.plaintext.len() as u64 + 8_192 * 950);
    }
    files.push(line);
    if spec.second_account {
        let mut blob = b"SQLite format 3\0".to_vec();
        blob.extend(rng.bytes(8192 - 16));
        files.push(FixtureFile::directory(
            domain,
            &format!("Library/Application Support/PrivateStore/{SECOND_ACCOUNT_DIR}"),
        ));
        files.push(FixtureFile::regular(
            domain,
            &line_relative_path(SECOND_ACCOUNT_DIR),
            blob,
            spec.protection_class,
        ));
    }
    files
}

/// Generate the full fixture set.
pub fn generate(
    out: &Path,
    spec: &FixtureSpec,
    progress: &dyn ProgressSink,
) -> Result<FixtureSummary> {
    std::fs::create_dir_all(out).map_err(|e| crate::RecoveryError::io(e, out))?;
    progress.check_cancelled()?;
    let plain_dir = out.join("plain");
    let truth = line_db::build(&plain_dir, &spec.line)?;
    let old_plain = std::fs::read(plain_dir.join("old.sqlite"))
        .map_err(|e| crate::RecoveryError::io(e, &plain_dir))?;
    let current_plain = std::fs::read(plain_dir.join("current.sqlite"))
        .map_err(|e| crate::RecoveryError::io(e, &plain_dir))?;
    let old_sha = crate::hash::Sha256Hex::of_bytes(&old_plain).0;
    let cur_sha = crate::hash::Sha256Hex::of_bytes(&current_plain).0;
    let mut rng = prng::Prng::seeded(spec.seed ^ 0xF1);

    let old_spec = BackupSpec {
        password: spec.password.clone(),
        udid: "00008100-000A11110000FIX1".into(),
        device_name: "Old Fixture iPhone".into(),
        product_version: "17.6".into(),
        product_type: "iPhone14,5".into(),
        backup_date: 1_790_990_000,
        double_protection: spec.double_protection,
        sha256_iterations: spec.pbkdf2_iterations,
        sha1_iterations: spec.pbkdf2_iterations,
        files: common_files("old", old_plain, spec, &mut rng),
        seed: spec.seed,
        ..BackupSpec::default()
    };
    let mut current_files = if spec.no_line_in_current {
        vec![FixtureFile::regular(
            "HomeDomain",
            "Library/Preferences/com.apple.fixture.plist",
            rng.bytes(300),
            4,
        )]
    } else {
        common_files("current", current_plain, spec, &mut rng)
    };
    if spec.pending_wal_in_current {
        current_files.push(FixtureFile::regular(
            LINE_DOMAINS[0],
            &format!("{}-wal", line_relative_path(ACCOUNT_DIR)),
            rng.bytes(4096 * 3),
            spec.protection_class,
        ));
        current_files.push(FixtureFile::regular(
            LINE_DOMAINS[0],
            &format!("{}-shm", line_relative_path(ACCOUNT_DIR)),
            rng.bytes(32_768),
            spec.protection_class,
        ));
    }
    let current_spec = BackupSpec {
        password: spec.password.clone(),
        udid: "00008160-000B22220000FIX2".into(),
        device_name: "Current Fixture iPhone".into(),
        product_version: "18.0".into(),
        product_type: "iPhone17,1".into(),
        backup_date: 1_791_000_397,
        snapshot_state: spec.current_snapshot_state.clone(),
        is_encrypted: spec.current_encrypted,
        double_protection: spec.double_protection,
        sha256_iterations: spec.pbkdf2_iterations,
        sha1_iterations: spec.pbkdf2_iterations,
        files: current_files,
        seed: spec.seed ^ 0xABCD,
        ..BackupSpec::default()
    };
    progress.check_cancelled()?;
    let old_built = backup_builder::build(&out.join("old"), &old_spec)?;
    progress.check_cancelled()?;
    let current_built = backup_builder::build(&out.join("current"), &current_spec)?;
    let summary = FixtureSummary {
        old_backup_dir: old_built.backup_dir,
        current_backup_dir: current_built.backup_dir,
        old_udid: old_spec.udid.clone(),
        current_udid: current_spec.udid.clone(),
        account_dir: ACCOUNT_DIR.into(),
        line_relative_path: line_relative_path(ACCOUNT_DIR),
        line_domain: LINE_DOMAINS[0].into(),
        old_line_sha256: old_sha,
        current_line_sha256: cur_sha,
        old_line_file_id: crate::hash::backup_file_id(
            LINE_DOMAINS[0],
            &line_relative_path(ACCOUNT_DIR),
        ),
        truth,
        spec: spec.clone(),
    };
    let expected = out.join("expected.json");
    std::fs::write(&expected, serde_json::to_vec_pretty(&summary)?)
        .map_err(|e| crate::RecoveryError::io(e, &expected))?;
    Ok(summary)
}

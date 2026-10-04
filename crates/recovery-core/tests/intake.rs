//! Intake integration tests over synthetic fixtures (tasks 3.1–3.5, 1.6).

use std::path::Path;

use recovery_core::backup::layout;
use recovery_core::fixtures::{self, FixtureSpec, LineDbSpec};
use recovery_core::hash::{sha256_file, Sha256Hex};
use recovery_core::progress::{NoProgress, Stage};
use recovery_core::secret::Password;
use recovery_core::session::driver::{BackupRole, Driver, Request};
use recovery_core::ErrorCode;

fn gen(dir: &Path, spec: &FixtureSpec) -> fixtures::FixtureSummary {
    fixtures::generate(dir, spec, &NoProgress).expect("fixture")
}

fn small_spec() -> FixtureSpec {
    FixtureSpec {
        line: LineDbSpec {
            message_count: 600,
            ..LineDbSpec::default()
        },
        ..FixtureSpec::default()
    }
}

fn pw() -> Option<Password> {
    Some(Password::new(fixtures::FIXTURE_PASSWORD))
}

fn dir_hashes(dir: &Path) -> Vec<(String, Sha256Hex)> {
    let mut out = Vec::new();
    fn walk(root: &Path, d: &Path, out: &mut Vec<(String, Sha256Hex)>) {
        let mut entries: Vec<_> = std::fs::read_dir(d).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                out.push((
                    p.strip_prefix(root).unwrap().to_string_lossy().into_owned(),
                    sha256_file(&p, &NoProgress, Stage::Intake).unwrap(),
                ));
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

#[test]
fn inspect_reports_metadata_without_password() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = gen(&tmp.path().join("fx"), &small_spec());
    let (info, _) = layout::inspect(&fx.current_backup_dir).unwrap();
    assert_eq!(info.udid.as_deref(), Some(fx.current_udid.as_str()));
    assert_eq!(info.snapshot_state, "finished");
    assert!(info.is_encrypted && info.has_keybag);
    assert_eq!(
        info.backup_date.as_deref(),
        Some("2026-10-03T04:06:37+00:00")
    );
    assert_eq!(info.device_name.as_deref(), Some("Current Fixture iPhone"));
}

#[test]
fn invalid_structures_are_rejected_before_password() {
    let tmp = tempfile::tempdir().unwrap();
    // Missing Manifest.plist
    let fx = gen(&tmp.path().join("fx"), &small_spec());
    std::fs::remove_file(fx.old_backup_dir.join("Manifest.plist")).unwrap();
    assert_eq!(
        layout::inspect(&fx.old_backup_dir).unwrap_err().code,
        ErrorCode::InvalidBackupStructure
    );
    // Not a backup at all
    assert_eq!(
        layout::inspect(tmp.path()).unwrap_err().code,
        ErrorCode::InvalidBackupStructure
    );
    // Unfinished snapshot
    let fx2 = gen(
        &tmp.path().join("fx2"),
        &FixtureSpec {
            current_snapshot_state: "uploading".into(),
            ..small_spec()
        },
    );
    assert_eq!(
        layout::inspect(&fx2.current_backup_dir).unwrap_err().code,
        ErrorCode::UnsupportedBackup
    );
    // Unencrypted
    let fx3 = gen(
        &tmp.path().join("fx3"),
        &FixtureSpec {
            current_encrypted: false,
            ..small_spec()
        },
    );
    assert_eq!(
        layout::inspect(&fx3.current_backup_dir).unwrap_err().code,
        ErrorCode::UnsupportedBackup
    );
    // Malformed Status.plist
    std::fs::write(fx.current_backup_dir.join("Status.plist"), b"garbage").unwrap();
    assert_eq!(
        layout::inspect(&fx.current_backup_dir).unwrap_err().code,
        ErrorCode::MalformedMetadata
    );
}

#[test]
fn intake_succeeds_and_source_is_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = gen(&tmp.path().join("fx"), &small_spec());
    let before = dir_hashes(&fx.current_backup_dir);
    let mut driver = Driver::open(&tmp.path().join("ws")).unwrap();
    let out = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["status"], "ok");
    let intake = &out["intake"];
    assert_eq!(intake["line_db"]["sha256"], fx.current_line_sha256);
    assert_eq!(intake["selected_store"]["file_id"], fx.old_line_file_id);
    assert_eq!(
        intake["patchable"], true,
        "{}",
        intake["patchability_issues"]
    );
    assert_eq!(intake["source_unchanged"], true);
    assert_eq!(
        intake["selected_store"]["siblings"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    // Manifest Size deliberately differs from plaintext size, as live DBs do: not an error.
    assert!(
        intake["line_db"]["manifest_declared_size"]
            .as_u64()
            .unwrap()
            > intake["line_db"]["size"].as_u64().unwrap()
    );
    assert_eq!(
        dir_hashes(&fx.current_backup_dir),
        before,
        "source backup must be byte-identical"
    );
    // Plaintext lives only inside the workspace, 0600.
    let plain = Path::new(intake["line_db"]["plaintext_path"].as_str().unwrap());
    assert!(plain.starts_with(tmp.path().join("ws")));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(plain).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Stage committed with evidence for this role.
    let status = driver.execute(Request::Status, None, &NoProgress).unwrap();
    assert_eq!(status["stages"]["intake"]["state"], "committed");
    assert!(status["stages"]["intake"]["evidence"]["current"].is_object());

    // Second role keeps the first role's evidence.
    let out2 = driver
        .execute(
            Request::Intake {
                role: BackupRole::Old,
                backup_dir: fx.old_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out2["intake"]["line_db"]["sha256"], fx.old_line_sha256);
    let status = driver.execute(Request::Status, None, &NoProgress).unwrap();
    assert!(status["stages"]["intake"]["evidence"]["current"].is_object());
    assert!(status["stages"]["intake"]["evidence"]["old"].is_object());
}

#[test]
fn wrong_password_fails_closed_without_key_material() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = gen(&tmp.path().join("fx"), &small_spec());
    let before = dir_hashes(&fx.current_backup_dir);
    let mut driver = Driver::open(&tmp.path().join("ws")).unwrap();
    let err = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: None,
            },
            Some(Password::new("not-the-password")),
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::AuthenticationFailed);
    let text = serde_json::to_string(&err).unwrap();
    assert!(!text.contains("not-the-password"));
    assert!(!text.to_lowercase().contains("key:"));
    assert_eq!(dir_hashes(&fx.current_backup_dir), before);
    // No plaintext left behind.
    let plain: Vec<_> = walkdir(&tmp.path().join("ws").join("plaintext"));
    assert!(plain.is_empty(), "{plain:?}");
    let status = driver.execute(Request::Status, None, &NoProgress).unwrap();
    assert_eq!(status["stages"]["intake"]["state"], "failed");
    // Missing password is an argument error, not an auth failure.
    let err = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: None,
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

fn walkdir(d: &Path) -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                v.extend(walkdir(&e.path()));
            } else {
                v.push(e.path());
            }
        }
    }
    v
}

#[test]
fn zero_one_and_multiple_line_stores() {
    let tmp = tempfile::tempdir().unwrap();
    // zero
    let fx = gen(
        &tmp.path().join("none"),
        &FixtureSpec {
            no_line_in_current: true,
            ..small_spec()
        },
    );
    let mut driver = Driver::open(&tmp.path().join("ws0")).unwrap();
    let err = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::PayloadNotFound);
    // multiple → ambiguous, nothing committed
    let fx = gen(
        &tmp.path().join("multi"),
        &FixtureSpec {
            second_account: true,
            ..small_spec()
        },
    );
    let mut driver = Driver::open(&tmp.path().join("ws1")).unwrap();
    let out = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["status"], "ambiguous_account");
    assert_eq!(out["candidates"].as_array().unwrap().len(), 2);
    let status = driver.execute(Request::Status, None, &NoProgress).unwrap();
    assert_eq!(status["stages"]["intake"]["state"], "failed");
    assert_eq!(
        status["stages"]["intake"]["error"]["code"],
        "ambiguous_account"
    );
    // explicit selection works
    let out = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: Some(fixtures::ACCOUNT_DIR.into()),
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["status"], "ok");
    assert_eq!(out["intake"]["stores_found"].as_array().unwrap().len(), 2);
    // unknown account dir
    let err = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: Some("P_unope".into()),
            },
            pw(),
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::PayloadNotFound);
}

#[test]
fn pending_wal_blocks_patching_but_allows_diagnostics() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = gen(
        &tmp.path().join("fx"),
        &FixtureSpec {
            pending_wal_in_current: true,
            ..small_spec()
        },
    );
    let mut driver = Driver::open(&tmp.path().join("ws")).unwrap();
    let out = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["status"], "ok");
    assert_eq!(out["intake"]["patchable"], false);
    let issues = out["intake"]["patchability_issues"].as_array().unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.as_str().unwrap().contains("Line.sqlite-wal")),
        "{issues:?}"
    );
    assert_eq!(
        out["intake"]["selected_store"]["pending_journals"],
        serde_json::json!(["Line.sqlite-wal"])
    );
}

#[test]
fn unsupported_metadata_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    // Digest present → not patchable (still extractable for diagnostics).
    let fx = gen(
        &tmp.path().join("digest"),
        &FixtureSpec {
            with_digest: true,
            ..small_spec()
        },
    );
    let mut driver = Driver::open(&tmp.path().join("ws")).unwrap();
    let out = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["intake"]["patchable"], false);
    assert!(out["intake"]["patchability_issues"]
        .to_string()
        .contains("Digest"));
    // Protection class 2 → cannot even extract (asymmetric), reported as unsupported metadata.
    let fx2 = gen(
        &tmp.path().join("class2"),
        &FixtureSpec {
            protection_class: 2,
            ..small_spec()
        },
    );
    let mut driver2 = Driver::open(&tmp.path().join("ws2")).unwrap();
    let err = driver2
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx2.current_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedMetadata);
    // Classes 1 and 4 work like class 3.
    for class in [1u32, 4] {
        let fxc = gen(
            &tmp.path().join(format!("class{class}")),
            &FixtureSpec {
                protection_class: class,
                ..small_spec()
            },
        );
        let mut d = Driver::open(&tmp.path().join(format!("wsc{class}"))).unwrap();
        let out = d
            .execute(
                Request::Intake {
                    role: BackupRole::Current,
                    backup_dir: fxc.current_backup_dir.clone(),
                    account_dir: None,
                },
                pw(),
                &NoProgress,
            )
            .unwrap();
        assert_eq!(
            out["intake"]["line_db"]["sha256"], fxc.current_line_sha256,
            "class {class}"
        );
        assert_eq!(out["intake"]["patchable"], true);
    }
}

#[test]
fn single_pbkdf2_keybag_layout_is_supported() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = gen(
        &tmp.path().join("fx"),
        &FixtureSpec {
            double_protection: false,
            ..small_spec()
        },
    );
    let mut driver = Driver::open(&tmp.path().join("ws")).unwrap();
    let out = driver
        .execute(
            Request::Intake {
                role: BackupRole::Old,
                backup_dir: fx.old_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["intake"]["line_db"]["sha256"], fx.old_line_sha256);
}

#[test]
fn cancellation_during_intake_leaves_no_plaintext_and_source_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = gen(&tmp.path().join("fx"), &small_spec());
    let before = dir_hashes(&fx.current_backup_dir);
    let mut driver = Driver::open(&tmp.path().join("ws")).unwrap();
    let sink = recovery_core::progress::CancelAfter::new(3);
    let err = driver
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: fx.current_backup_dir.clone(),
                account_dir: None,
            },
            pw(),
            &sink,
        )
        .unwrap_err();
    assert!(err.is_cancelled());
    assert!(walkdir(&tmp.path().join("ws").join("plaintext")).is_empty());
    assert_eq!(dir_hashes(&fx.current_backup_dir), before);
    let status = driver.execute(Request::Status, None, &NoProgress).unwrap();
    assert_eq!(status["stages"]["intake"]["state"], "cancelled");
}

#[test]
fn fixture_generation_is_deterministic() {
    let tmp = tempfile::tempdir().unwrap();
    let a = gen(&tmp.path().join("a"), &small_spec());
    let b = gen(&tmp.path().join("b"), &small_spec());
    assert_eq!(a.old_line_sha256, b.old_line_sha256);
    assert_eq!(
        a.truth.expected_repaired_logical_digest,
        b.truth.expected_repaired_logical_digest
    );
    assert_eq!(a.truth.candidate_zids.len(), 227);
    assert_eq!(a.truth.text_differences, 221);
    assert_eq!(a.truth.metadata_differences, 145);
    assert_eq!(
        dir_hashes(&a.current_backup_dir),
        dir_hashes(&b.current_backup_dir)
    );
}

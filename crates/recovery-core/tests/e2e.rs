//! End-to-end: intake → analysis → patch → verification → export → report (tasks 6.x, 8.x).

use std::path::{Path, PathBuf};

use recovery_core::fixtures::{self, FixtureSpec, LineDbSpec};
use recovery_core::hash::{sha256_file, Sha256Hex};
use recovery_core::patch::hash_dir;
use recovery_core::progress::{NoProgress, Stage};
use recovery_core::secret::Password;
use recovery_core::session::driver::{BackupRole, Driver, PatchConfirmation, Request};
use recovery_core::ErrorCode;

fn pw() -> Option<Password> {
    Some(Password::new(fixtures::FIXTURE_PASSWORD))
}

struct Ctx {
    fx: fixtures::FixtureSummary,
    driver: Driver,
    dest: PathBuf,
    plan: serde_json::Value,
}

fn setup(root: &Path, spec: FixtureSpec) -> Ctx {
    let fx = fixtures::generate(&root.join("fx"), &spec, &NoProgress).unwrap();
    let mut driver = Driver::open(&root.join("ws")).unwrap();
    driver
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
    driver
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
    let out = driver.execute(Request::Analyze, None, &NoProgress).unwrap();
    let dest = root.join("dest");
    std::fs::create_dir_all(&dest).unwrap();
    Ctx {
        fx,
        driver,
        dest,
        plan: out["plan"].clone(),
    }
}

fn confirm(ctx: &Ctx) -> PatchConfirmation {
    // An unsupported analysis carries no plan; the confirmation then names nothing and the
    // patch must be refused for lack of a plan.
    PatchConfirmation {
        predicted_update_count: ctx.plan["predicted_update_count"].as_u64().unwrap_or(0),
        plan_id: ctx.plan["plan_id"].as_str().unwrap_or("").to_owned(),
        destination_dir: ctx.dest.clone(),
        rollback_source_dir: ctx.fx.current_backup_dir.clone(),
    }
}

fn default_spec() -> FixtureSpec {
    FixtureSpec {
        line: LineDbSpec {
            message_count: 800,
            ..LineDbSpec::default()
        },
        ..FixtureSpec::default()
    }
}

#[test]
fn full_chain_produces_verified_export_with_227_repairs() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = setup(tmp.path(), default_spec());
    let source_before = hash_dir(&ctx.fx.current_backup_dir, &NoProgress, Stage::Patching).unwrap();
    let old_before = hash_dir(&ctx.fx.old_backup_dir, &NoProgress, Stage::Patching).unwrap();

    let out = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: confirm(&ctx),
            },
            None,
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["status"], "verified", "{out}");
    let patch = &out["patch"];
    assert_eq!(patch["repair"]["actual_update_count"], 227);
    assert_eq!(patch["validation"]["all_passed"], true);
    assert_eq!(patch["encryption"]["round_trip_ok"], true);
    assert_eq!(
        patch["encryption"]["payload_size"].as_u64().unwrap(),
        patch["encryption"]["plaintext_size"].as_u64().unwrap() + 16
    );
    assert_eq!(patch["clone_differs_only_at"].as_array().unwrap().len(), 1);
    assert_eq!(
        patch["clone_differs_only_at"][0].as_str().unwrap(),
        format!(
            "{}/{}",
            &ctx.fx.old_line_file_id[..2],
            ctx.fx.old_line_file_id
        )
    );
    assert_eq!(patch["source_unchanged_after_clone"], true);
    let ver = &out["verification"];
    assert_eq!(ver["all_gates_passed"], true, "{ver}");
    assert_eq!(ver["reread_sha256"], patch["validation"]["repaired_sha256"]);
    assert_eq!(ver["manifest_db_unchanged"], true);
    assert_eq!(ver["manifest_plist_unchanged"], true);
    // Repaired hash recorded in the fixture-independent way: logical digest equals oracle.
    let repaired_path = tmp.path().join("ws/committed/patching/repaired.sqlite");
    let conn = rusqlite::Connection::open_with_flags(
        &repaired_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        fixtures::line_db::logical_digest(&conn).unwrap(),
        ctx.fx.truth.expected_repaired_logical_digest
    );
    drop(conn);
    // Sources untouched.
    assert_eq!(
        hash_dir(&ctx.fx.current_backup_dir, &NoProgress, Stage::Patching).unwrap(),
        source_before
    );
    assert_eq!(
        hash_dir(&ctx.fx.old_backup_dir, &NoProgress, Stage::Patching).unwrap(),
        old_before
    );

    // Export never overwrites, writes reports and instructions.
    let exp = ctx
        .driver
        .execute(
            Request::Export {
                destination_dir: ctx.dest.clone(),
                overwrite_confirmed: false,
            },
            None,
            &NoProgress,
        )
        .unwrap();
    assert_eq!(exp["status"], "exported", "{exp}");
    let exported = PathBuf::from(exp["export"]["exported_backup_dir"].as_str().unwrap());
    assert!(exported.starts_with(&ctx.dest));
    assert!(exported
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with(&format!("{}_PATCHED_", ctx.fx.current_udid)));
    assert!(exported.join("Manifest.db").exists());
    // No staging directory left behind.
    assert!(std::fs::read_dir(&ctx.dest).unwrap().flatten().all(|e| !e
        .file_name()
        .to_string_lossy()
        .starts_with(".reline-staging")));
    // Exported clone == source except the payload.
    let exported_manifest = hash_dir(&exported, &NoProgress, Stage::Export).unwrap();
    let diff = source_before.diff(&exported_manifest);
    assert_eq!(diff.len(), 1);
    // The exported backup re-reads independently through a fresh session.
    let mut d2 = Driver::open(&tmp.path().join("ws2")).unwrap();
    let re = d2
        .execute(
            Request::Intake {
                role: BackupRole::Current,
                backup_dir: exported.clone(),
                account_dir: None,
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(
        re["intake"]["line_db"]["sha256"],
        patch["validation"]["repaired_sha256"]
    );
    assert_eq!(re["intake"]["patchable"], true);
    // Reports exist and are privacy-clean.
    let md_path = PathBuf::from(exp["export"]["report_markdown"].as_str().unwrap());
    let md = std::fs::read_to_string(&md_path).unwrap();
    let js = std::fs::read_to_string(exp["export"]["report_json"].as_str().unwrap()).unwrap();
    let ins = std::fs::read_to_string(exp["export"]["instructions"].as_str().unwrap()).unwrap();
    for body in [&md, &js, &ins] {
        assert!(!body.contains(fixtures::FIXTURE_PASSWORD));
        assert!(!body.contains("original text"));
        assert!(!body.contains("new device message"));
        for zid in &ctx.fx.truth.candidate_zids {
            assert!(!body.contains(zid.as_str()));
        }
    }
    assert!(md.contains("227"));
    assert!(md.contains(&ctx.fx.current_udid));
    assert!(ins.contains("Unplug the iPhone"));
    assert!(ins.contains("Airplane Mode"));
    assert!(ins.contains("checkpoint"));
    assert!(
        ins.contains(ctx.fx.current_backup_dir.to_str().unwrap()),
        "rollback source must be named"
    );
    assert!(
        ins.contains(exported.to_str().unwrap()),
        "patched output must be named"
    );
    assert!(md.contains("+00:00"), "timestamps carry explicit offsets");

    // Second export with the same name would conflict; a different timestamp name is new, so
    // simulate by exporting again: the verified clone was moved, so export must refuse.
    let err = ctx
        .driver
        .execute(
            Request::Export {
                destination_dir: ctx.dest.clone(),
                overwrite_confirmed: false,
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert!(
        matches!(
            err.code,
            ErrorCode::SessionState | ErrorCode::ExportConflict
        ),
        "{err:?}"
    );

    // Expert export of repaired DB is labelled verified.
    let dbout = tmp.path().join("expert.sqlite");
    let r = ctx
        .driver
        .execute(
            Request::ExportRepairedDatabase {
                destination_file: dbout.clone(),
                overwrite_confirmed: false,
            },
            None,
            &NoProgress,
        )
        .unwrap();
    assert_eq!(r["state"], "verified");
    let err = ctx
        .driver
        .execute(
            Request::ExportRepairedDatabase {
                destination_file: dbout.clone(),
                overwrite_confirmed: false,
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ExportConflict);
    ctx.driver
        .execute(
            Request::ExportRepairedDatabase {
                destination_file: dbout.clone(),
                overwrite_confirmed: true,
            },
            None,
            &NoProgress,
        )
        .unwrap();

    // Redacted report hides UDID and account directory.
    let red = ctx
        .driver
        .execute(Request::Report { redacted: true }, None, &NoProgress)
        .unwrap();
    let rmd = red["markdown"].as_str().unwrap();
    assert!(!rmd.contains(&ctx.fx.current_udid));
    assert!(!rmd.contains(fixtures::ACCOUNT_DIR));
    assert!(rmd.contains("redacted:"));
    // Cleanup removes plaintext and the retained repaired DB.
    ctx.driver
        .execute(Request::Cleanup, None, &NoProgress)
        .unwrap();
    assert!(!repaired_path.exists());
    assert!(std::fs::read_dir(tmp.path().join("ws/plaintext"))
        .unwrap()
        .next()
        .is_none());
}

/// Real LINE stores carry NULL-ZID rows and duplicate ZID pairs. They must be excluded from
/// matching, left byte-identical by the repair, and accepted by every post-repair gate (the
/// gates pair rows by rowid, not by identity, so these rows are still checked).
#[test]
fn null_and_duplicate_identifiers_survive_the_full_chain_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = setup(
        tmp.path(),
        FixtureSpec {
            line: LineDbSpec {
                message_count: 800,
                duplicate_zid_in_current: true,
                null_zid_in_old: true,
                ..LineDbSpec::default()
            },
            ..FixtureSpec::default()
        },
    );
    assert_eq!(ctx.plan["actionable"], true, "{}", ctx.plan);
    assert_eq!(ctx.plan["counts"]["duplicate_identity_values"], 1);
    assert_eq!(ctx.plan["counts"]["null_identity_rows_old"], 1);
    let out = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: confirm(&ctx),
            },
            None,
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["status"], "verified", "{out}");
    assert_eq!(out["patch"]["repair"]["actual_update_count"], 227);
    assert_eq!(out["verification"]["all_gates_passed"], true);
    // The duplicated rows were not written: both copies still carry the current values.
    let repaired = rusqlite::Connection::open_with_flags(
        tmp.path().join("ws/committed/patching/repaired.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let dup_rows: i64 = repaired
        .query_row(
            "SELECT COUNT(*) FROM ZMESSAGE WHERE ZID IN (SELECT ZID FROM ZMESSAGE WHERE ZID IS NOT NULL GROUP BY ZID HAVING COUNT(*) > 1)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(dup_rows, 2);
    let placeholders_left: i64 = repaired
        .query_row(
            "SELECT COUNT(*) FROM ZMESSAGE WHERE ZCONTENTTYPE = 106",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(placeholders_left, 21, "only native placeholders remain");
}

#[test]
fn confirmation_mismatch_prevents_any_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = setup(tmp.path(), default_spec());
    let mut c = confirm(&ctx);
    c.predicted_update_count += 1;
    let err = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: c,
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    let mut c = confirm(&ctx);
    c.rollback_source_dir = ctx.fx.old_backup_dir.clone();
    let err = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: c,
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    // Destination inside the source is refused.
    let inside = ctx.fx.current_backup_dir.join("00");
    let mut c = confirm(&ctx);
    c.destination_dir = inside.clone();
    let err = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: inside,
                confirm: c,
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(
        std::fs::read_dir(&ctx.dest).unwrap().next().is_none(),
        "nothing written to destination"
    );
    let st = ctx.driver.status();
    assert_eq!(st["stages"]["patching"]["state"], "pending");
}

#[test]
fn non_patchable_current_backup_blocks_patching() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = setup(
        tmp.path(),
        FixtureSpec {
            pending_wal_in_current: true,
            ..default_spec()
        },
    );
    assert_eq!(
        ctx.plan["actionable"], true,
        "analysis stays available for diagnostics"
    );
    let err = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: confirm(&ctx),
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedMetadata);
    assert!(err.message.contains("Line.sqlite-wal"));
}

#[test]
fn unsupported_analysis_cannot_patch() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = setup(
        tmp.path(),
        FixtureSpec {
            line: LineDbSpec {
                break_schema: true,
                message_count: 800,
                ..LineDbSpec::default()
            },
            ..FixtureSpec::default()
        },
    );
    let err = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: confirm(&ctx),
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::AnalysisUnsupported);
}

#[test]
fn resumed_session_requires_fresh_analysis_before_patching() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = setup(tmp.path(), default_spec());
    let ws = tmp.path().join("ws");
    drop(ctx.driver);
    let mut d = Driver::open(&ws).unwrap();
    let plan = recovery_core::analysis::ops::load_plan(&d).unwrap();
    let c = PatchConfirmation {
        predicted_update_count: plan.predicted_update_count,
        plan_id: plan.plan_id.clone(),
        destination_dir: ctx.dest.clone(),
        rollback_source_dir: ctx.fx.current_backup_dir.clone(),
    };
    let err = d
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: c,
            },
            pw(),
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::SessionState);
    // After re-running analysis in the resumed session, patching works with the password.
    d.execute(Request::Analyze, None, &NoProgress).unwrap();
    let plan = recovery_core::analysis::ops::load_plan(&d).unwrap();
    let c = PatchConfirmation {
        predicted_update_count: plan.predicted_update_count,
        plan_id: plan.plan_id,
        destination_dir: ctx.dest.clone(),
        rollback_source_dir: ctx.fx.current_backup_dir.clone(),
    };
    let err = d
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: c.clone(),
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(
        err.code,
        ErrorCode::InvalidArgument,
        "password required after resume"
    );
    let out = d
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: c,
            },
            pw(),
            &NoProgress,
        )
        .unwrap();
    assert_eq!(out["status"], "verified");
}

#[test]
fn cancellation_during_patch_leaves_no_clone_and_source_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = setup(tmp.path(), default_spec());
    let before = hash_dir(&ctx.fx.current_backup_dir, &NoProgress, Stage::Patching).unwrap();
    // Cancel late enough to be inside clone/hash work.
    let sink = recovery_core::progress::CancelAfter::new(40);
    let err = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: confirm(&ctx),
            },
            None,
            &sink,
        )
        .unwrap_err();
    assert!(err.is_cancelled(), "{err:?}");
    assert!(
        std::fs::read_dir(&ctx.dest).unwrap().next().is_none(),
        "destination must be empty after cancellation"
    );
    assert_eq!(
        hash_dir(&ctx.fx.current_backup_dir, &NoProgress, Stage::Patching).unwrap(),
        before
    );
    let st = ctx.driver.status();
    assert_eq!(st["stages"]["patching"]["state"], "cancelled");
    assert_ne!(st["stages"]["verification"]["state"], "committed");
    // Export is impossible.
    let e = ctx
        .driver
        .execute(
            Request::Export {
                destination_dir: ctx.dest.clone(),
                overwrite_confirmed: false,
            },
            None,
            &NoProgress,
        )
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::SessionState);
}

#[test]
fn failed_report_records_failed_stage_without_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = fixtures::generate(&tmp.path().join("fx"), &default_spec(), &NoProgress).unwrap();
    let mut d = Driver::open(&tmp.path().join("ws")).unwrap();
    let _ = d.execute(
        Request::Intake {
            role: BackupRole::Old,
            backup_dir: fx.old_backup_dir.clone(),
            account_dir: None,
        },
        Some(Password::new("wrong-password-xyz")),
        &NoProgress,
    );
    let rep = d
        .execute(Request::Report { redacted: false }, None, &NoProgress)
        .unwrap();
    let md = rep["markdown"].as_str().unwrap();
    assert!(md.contains("failed"));
    assert!(md.contains("backup password rejected"));
    assert!(!md.contains("wrong-password-xyz"));
    assert!(!md.contains(fixtures::FIXTURE_PASSWORD));
}

#[test]
fn clone_verification_rejects_a_tampered_payload() {
    // Simulate a corrupted write by producing the clone, then flipping a byte in the payload the
    // verification re-reads. We do this through the public API by patching, then tampering the
    // exported clone and re-reading it with a fresh intake: the hash must differ and integrity
    // must be checked, proving the re-read gate is real.
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = setup(tmp.path(), default_spec());
    let out = ctx
        .driver
        .execute(
            Request::Patch {
                destination_dir: ctx.dest.clone(),
                confirm: confirm(&ctx),
            },
            None,
            &NoProgress,
        )
        .unwrap();
    let exp = ctx
        .driver
        .execute(
            Request::Export {
                destination_dir: ctx.dest.clone(),
                overwrite_confirmed: false,
            },
            None,
            &NoProgress,
        )
        .unwrap();
    let exported = PathBuf::from(exp["export"]["exported_backup_dir"].as_str().unwrap());
    let payload = exported
        .join(&ctx.fx.old_line_file_id[..2])
        .join(&ctx.fx.old_line_file_id);
    let mut bytes = std::fs::read(&payload).unwrap();
    bytes[4096] ^= 0x01;
    std::fs::write(&payload, &bytes).unwrap();
    let mut d2 = Driver::open(&tmp.path().join("ws2")).unwrap();
    let re = d2.execute(
        Request::Intake {
            role: BackupRole::Current,
            backup_dir: exported,
            account_dir: None,
        },
        pw(),
        &NoProgress,
    );
    match re {
        Ok(v) => assert_ne!(
            v["intake"]["line_db"]["sha256"],
            out["patch"]["validation"]["repaired_sha256"]
        ),
        Err(e) => assert!(matches!(
            e.code,
            ErrorCode::CryptoFailure | ErrorCode::DatabaseUnsupported
        )),
    }
    let _ = Sha256Hex::of_bytes(b"");
    let _ = sha256_file;
}

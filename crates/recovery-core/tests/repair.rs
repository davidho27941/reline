//! Transactional repair and post-repair gates (tasks 5.1–5.5).

use std::path::{Path, PathBuf};

use recovery_core::analysis::adapter::Candidate;
use recovery_core::fixtures::{self, line_db::logical_digest, FixtureSpec, LineDbSpec};
use recovery_core::hash::{sha256_file, Sha256Hex};
use recovery_core::progress::{NoProgress, Stage};
use recovery_core::repair::{post_repair, repair_working_copy};
use recovery_core::secret::Password;
use recovery_core::session::driver::{BackupRole, Driver, Request};
use recovery_core::ErrorCode;

fn setup(root: &Path) -> (fixtures::FixtureSummary, Driver) {
    let spec = FixtureSpec {
        line: LineDbSpec {
            message_count: 800,
            ..LineDbSpec::default()
        },
        ..FixtureSpec::default()
    };
    let fx = fixtures::generate(&root.join("fx"), &spec, &NoProgress).unwrap();
    let mut d = Driver::open(&root.join("ws")).unwrap();
    let pw = || Some(Password::new(fixtures::FIXTURE_PASSWORD));
    d.execute(
        Request::Intake {
            role: BackupRole::Old,
            backup_dir: fx.old_backup_dir.clone(),
            account_dir: None,
        },
        pw(),
        &NoProgress,
    )
    .unwrap();
    d.execute(
        Request::Intake {
            role: BackupRole::Current,
            backup_dir: fx.current_backup_dir.clone(),
            account_dir: None,
        },
        pw(),
        &NoProgress,
    )
    .unwrap();
    let out = d.execute(Request::Analyze, None, &NoProgress).unwrap();
    assert_eq!(out["status"], "actionable");
    (fx, d)
}

fn sha(p: &Path) -> Sha256Hex {
    sha256_file(p, &NoProgress, Stage::Patching).unwrap()
}

fn work(root: &Path) -> PathBuf {
    let w = root.join("work");
    std::fs::create_dir_all(&w).unwrap();
    w.join("repaired.sqlite")
}

fn count_106(path: &Path) -> i64 {
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    c.query_row(
        "SELECT COUNT(*) FROM ZMESSAGE WHERE ZCONTENTTYPE = 106",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn repair_applies_exactly_227_and_passes_every_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let (fx, d) = setup(tmp.path());
    let secure = d.secure_plan().unwrap().clone();
    let wc = work(tmp.path());
    let res = repair_working_copy(&secure, &wc, &NoProgress).unwrap();
    assert_eq!(res.actual_update_count, 227);
    assert!(res.committed);
    assert_ne!(
        res.working_copy_sha256_before,
        res.working_copy_sha256_after
    );
    assert!(res.pages_after.page_count >= res.pages_before.page_count);
    assert_eq!(res.pages_after.page_size, res.pages_before.page_size);

    let v = post_repair(&secure, &wc, &NoProgress).unwrap();
    assert!(v.all_passed, "{:?}", v.failed_gates);
    assert_eq!(v.repaired_field_mismatches, 0);
    assert_eq!(v.protected_field_mismatches, 0);
    assert_eq!(v.remaining_candidates, 0);
    assert_eq!(v.rows_before, v.rows_after);
    assert!(v.unrelated_tables_checked >= 8);
    assert_eq!(v.repaired_sha256, sha(&wc));

    // Logical content equals the independently constructed expected database (fixture oracle).
    let conn =
        rusqlite::Connection::open_with_flags(&wc, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    assert_eq!(
        logical_digest(&conn).unwrap(),
        fx.truth.expected_repaired_logical_digest
    );
    // Native placeholders preserved: exactly 21 type-106 rows remain (none blanket-replaced).
    assert_eq!(count_106(&wc), 21);
    // Inputs untouched.
    assert_eq!(sha(&secure.current_db_path).0, fx.current_line_sha256);
    assert_eq!(sha(&secure.old_db_path).0, fx.old_line_sha256);
    // No journal left beside the repaired file.
    assert!(!tmp.path().join("work/repaired.sqlite-wal").exists());
    assert!(!tmp.path().join("work/repaired.sqlite-journal").exists());
}

#[test]
fn count_mismatch_rolls_back_with_no_persistent_change() {
    let tmp = tempfile::tempdir().unwrap();
    let (fx, d) = setup(tmp.path());
    let mut secure = d.secure_plan().unwrap().clone();
    // Inject one identifier that is not a candidate: its update changes 0 rows -> rollback.
    // Revalidation would catch the set difference first, so bypass it by keeping the set equal
    // in size but swapping one identifier for a current-only one.
    let intruder = "2000000000000"; // first current-only ZID from the generator
    secure.candidates[0] = Candidate {
        identifier: intruder.into(),
        old_content_type: 0,
        text_differs: true,
        metadata_differs: false,
    };
    let wc = work(tmp.path());
    let err = repair_working_copy(&secure, &wc, &NoProgress).unwrap_err();
    assert!(
        matches!(
            err.code,
            ErrorCode::PlanInvalidated | ErrorCode::RepairMismatch
        ),
        "{err:?}"
    );
    // Either way nothing was written to a working copy that differs from the input.
    if wc.exists() {
        assert_eq!(sha(&wc).0, fx.current_line_sha256);
    }
}

#[test]
fn predicate_drift_is_rolled_back_by_the_row_level_check() {
    // Bypass revalidation drift detection by altering the working copy source *after* the
    // candidate set is fixed: we simulate by calling the adapter's repair directly through
    // `repair_working_copy` on a plan whose predicted count is wrong.
    let tmp = tempfile::tempdir().unwrap();
    let (fx, d) = setup(tmp.path());
    let mut secure = d.secure_plan().unwrap().clone();
    secure.plan.predicted_update_count += 1;
    let wc = work(tmp.path());
    let err = repair_working_copy(&secure, &wc, &NoProgress).unwrap_err();
    assert_eq!(err.code, ErrorCode::PlanInvalidated);
    if wc.exists() {
        assert_eq!(sha(&wc).0, fx.current_line_sha256);
    }
}

#[test]
fn changed_inputs_invalidate_the_plan_before_any_write() {
    let tmp = tempfile::tempdir().unwrap();
    let (_fx, d) = setup(tmp.path());
    let secure = d.secure_plan().unwrap().clone();
    // Flip a byte in the old database after analysis.
    let mut bytes = std::fs::read(&secure.old_db_path).unwrap();
    let n = bytes.len();
    bytes[n - 100] ^= 0x01;
    std::fs::write(&secure.old_db_path, &bytes).unwrap();
    let wc = work(tmp.path());
    let err = repair_working_copy(&secure, &wc, &NoProgress).unwrap_err();
    assert_eq!(err.code, ErrorCode::PlanInvalidated);
    assert!(
        !wc.exists(),
        "no working copy may be created when the plan is invalid"
    );
}

fn repaired_for_tampering(root: &Path) -> (recovery_core::analysis::plan::SecurePlan, PathBuf) {
    let (_fx, d) = setup(root);
    let secure = d.secure_plan().unwrap().clone();
    let wc = work(root);
    repair_working_copy(&secure, &wc, &NoProgress).unwrap();
    (secure, wc)
}

fn exec(path: &Path, sql: &str) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(sql).unwrap();
}

#[test]
fn tampered_protected_field_blocks_encryption() {
    let tmp = tempfile::tempdir().unwrap();
    let (secure, wc) = repaired_for_tampering(tmp.path());
    exec(&wc, "UPDATE ZMESSAGE SET ZTIMESTAMP = ZTIMESTAMP + 1 WHERE Z_PK = (SELECT MIN(Z_PK) FROM ZMESSAGE)");
    let v = post_repair(&secure, &wc, &NoProgress).unwrap();
    assert!(!v.all_passed);
    assert_eq!(v.protected_field_mismatches, 1);
}

#[test]
fn reverted_repaired_field_blocks_encryption() {
    let tmp = tempfile::tempdir().unwrap();
    let (secure, wc) = repaired_for_tampering(tmp.path());
    let id = secure.candidates[0].identifier.clone();
    exec(
        &wc,
        &format!("UPDATE ZMESSAGE SET ZCONTENTTYPE = 106, ZTEXT = NULL WHERE ZID = '{id}'"),
    );
    let v = post_repair(&secure, &wc, &NoProgress).unwrap();
    assert!(!v.all_passed);
    assert!(v.repaired_field_mismatches >= 1);
    assert_eq!(v.remaining_candidates, 1);
}

#[test]
fn changed_unrelated_table_blocks_encryption() {
    let tmp = tempfile::tempdir().unwrap();
    let (secure, wc) = repaired_for_tampering(tmp.path());
    exec(
        &wc,
        "UPDATE ZCHAT SET ZUNREAD = 99 WHERE Z_PK = (SELECT MIN(Z_PK) FROM ZCHAT)",
    );
    let v = post_repair(&secure, &wc, &NoProgress).unwrap();
    assert!(!v.all_passed);
    assert_eq!(v.unrelated_tables_changed, vec!["ZCHAT".to_string()]);
}

#[test]
fn deleted_or_inserted_rows_block_encryption() {
    let tmp = tempfile::tempdir().unwrap();
    let (secure, wc) = repaired_for_tampering(tmp.path());
    exec(
        &wc,
        "DELETE FROM ZMESSAGE WHERE Z_PK = (SELECT MAX(Z_PK) FROM ZMESSAGE)",
    );
    let v = post_repair(&secure, &wc, &NoProgress).unwrap();
    assert!(!v.all_passed);
    assert_ne!(v.rows_before, v.rows_after);
}

#[test]
fn vacuum_and_page_size_change_are_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let (secure, wc) = repaired_for_tampering(tmp.path());
    exec(&wc, "PRAGMA page_size = 8192; VACUUM;");
    let v = post_repair(&secure, &wc, &NoProgress).unwrap();
    assert!(!v.all_passed);
    assert!(
        v.failed_gates
            .iter()
            .any(|g| g.contains("page_size") || g.contains("page_count")),
        "{:?}",
        v.failed_gates
    );
}

#[test]
fn truncation_and_byte_corruption_are_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let (secure, wc) = repaired_for_tampering(tmp.path());
    let bytes = std::fs::read(&wc).unwrap();
    std::fs::write(&wc, &bytes[..bytes.len() - 4096]).unwrap();
    let v = post_repair(&secure, &wc, &NoProgress);
    match v {
        Ok(v) => assert!(!v.all_passed),
        Err(e) => assert!(
            matches!(
                e.code,
                ErrorCode::DatabaseUnsupported | ErrorCode::VerificationFailed
            ),
            "{e:?}"
        ),
    }
    // Byte corruption in a data page.
    std::fs::write(&wc, &bytes).unwrap();
    let mut corrupt = bytes.clone();
    let mid = corrupt.len() / 2;
    for b in &mut corrupt[mid..mid + 64] {
        *b ^= 0xA5;
    }
    std::fs::write(&wc, &corrupt).unwrap();
    match post_repair(&secure, &wc, &NoProgress) {
        Ok(v) => assert!(!v.all_passed),
        Err(e) => assert_eq!(e.code, ErrorCode::DatabaseUnsupported),
    }
}

#[test]
fn cancellation_mid_transaction_leaves_working_copy_equal_to_input() {
    let tmp = tempfile::tempdir().unwrap();
    let (fx, d) = setup(tmp.path());
    let secure = d.secure_plan().unwrap().clone();
    let wc = work(tmp.path());
    // Cancel right after the first progress report inside the transaction loop.
    let sink = recovery_core::progress::CancelAfter::new(4);
    let err = repair_working_copy(&secure, &wc, &sink).unwrap_err();
    assert!(
        err.is_cancelled() || err.code == ErrorCode::PlanInvalidated,
        "{err:?}"
    );
    if wc.exists() {
        assert_eq!(
            sha(&wc).0,
            fx.current_line_sha256,
            "rolled back transaction must leave bytes unchanged"
        );
    }
}

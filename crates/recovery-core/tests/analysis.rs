//! Analysis integration tests (tasks 4.1–4.5).

use std::path::Path;

use recovery_core::fixtures::{self, FixtureSpec, LineDbSpec};
use recovery_core::progress::NoProgress;
use recovery_core::secret::Password;
use recovery_core::session::driver::{BackupRole, Driver, Request};

fn spec_with(line: LineDbSpec) -> FixtureSpec {
    FixtureSpec {
        line,
        ..FixtureSpec::default()
    }
}

fn base_line() -> LineDbSpec {
    LineDbSpec {
        message_count: 800,
        ..LineDbSpec::default()
    }
}

/// Generate, intake both roles, analyze. Returns (summary, analyze output, driver).
fn run(root: &Path, spec: &FixtureSpec) -> (fixtures::FixtureSummary, serde_json::Value, Driver) {
    let fx = fixtures::generate(&root.join("fx"), spec, &NoProgress).unwrap();
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
    (fx, out, d)
}

#[test]
fn proven_distribution_yields_227_candidates_and_preserves_21() {
    let tmp = tempfile::tempdir().unwrap();
    let (fx, out, _d) = run(tmp.path(), &spec_with(base_line()));
    assert_eq!(out["status"], "actionable", "{out}");
    let plan = &out["plan"];
    let c = &plan["counts"];
    assert_eq!(plan["predicted_update_count"], 227);
    assert_eq!(c["candidates"], 227);
    assert_eq!(c["preserved_placeholders"], 21);
    assert_eq!(c["old_only"], 1);
    assert_eq!(c["current_only"], fx.truth.current_only);
    assert_eq!(c["text_differences"], 221);
    assert_eq!(c["metadata_differences"], 145);
    assert_eq!(c["chat_conflicts"], 0);
    assert_eq!(c["timestamp_conflicts"], 0);
    assert_eq!(c["sender_conflicts"], 0);
    assert_eq!(c["unknown_differences"], 0);
    let by_type = &c["candidates_by_old_type"];
    assert_eq!(by_type["0"], 211);
    assert_eq!(by_type["1"], 6);
    assert_eq!(by_type["112"], 4);
    assert_eq!(by_type["2"], 3);
    assert_eq!(by_type["3"], 2);
    assert_eq!(by_type["14"], 1);
    assert_eq!(
        plan["authorized_fields"],
        serde_json::json!(["ZCONTENTTYPE", "ZTEXT", "ZCONTENTMETADATA"])
    );
    assert_eq!(plan["rule_version"], "type106-placeholder-restore/2");
    assert_eq!(plan["input_hashes"]["old_database"], fx.old_line_sha256);
    assert_eq!(
        plan["input_hashes"]["current_database"],
        fx.current_line_sha256
    );
    assert_eq!(plan["public_candidate_ids"].as_array().unwrap().len(), 227);
}

#[test]
fn plan_contains_no_message_text_or_identifiers() {
    let tmp = tempfile::tempdir().unwrap();
    let (fx, out, _d) = run(tmp.path(), &spec_with(base_line()));
    let text = serde_json::to_string(&out["plan"]).unwrap();
    for zid in &fx.truth.candidate_zids {
        assert!(!text.contains(zid.as_str()), "raw ZID leaked into plan");
    }
    assert!(
        !text.contains("original text"),
        "message text leaked into plan"
    );
    assert!(
        !text.contains("new device message"),
        "message text leaked into plan"
    );
    // The persisted plan file must match.
    let persisted =
        std::fs::read_to_string(tmp.path().join("ws/committed/analysis/repair-plan.json")).unwrap();
    assert!(!persisted.contains("original text"));
    for zid in &fx.truth.candidate_zids {
        assert!(!persisted.contains(zid.as_str()));
    }
}

#[test]
fn analysis_is_deterministic_across_sessions() {
    let tmp = tempfile::tempdir().unwrap();
    let (_fx1, out1, _d1) = run(&tmp.path().join("a"), &spec_with(base_line()));
    let (_fx2, out2, _d2) = run(&tmp.path().join("b"), &spec_with(base_line()));
    assert_eq!(out1["plan"]["plan_id"], out2["plan"]["plan_id"]);
    let mut p1 = out1["plan"].clone();
    let mut p2 = out2["plan"].clone();
    // Salted public ids differ per session by design; everything else is identical.
    assert_ne!(p1["public_candidate_ids"], p2["public_candidate_ids"]);
    p1["public_candidate_ids"] = serde_json::Value::Null;
    p2["public_candidate_ids"] = serde_json::Value::Null;
    assert_eq!(p1, p2);
}

#[test]
fn repeat_analysis_in_same_session_is_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let (_fx, out1, mut d) = run(tmp.path(), &spec_with(base_line()));
    let out2 = d.execute(Request::Analyze, None, &NoProgress).unwrap();
    assert_eq!(out1["plan"], out2["plan"]);
}

#[test]
fn relationship_conflicts_are_excluded_and_counted() {
    let tmp = tempfile::tempdir().unwrap();
    let (_fx, out, _d) = run(
        tmp.path(),
        &spec_with(LineDbSpec {
            chat_conflicts: 5,
            timestamp_conflicts: 3,
            ..base_line()
        }),
    );
    let c = &out["plan"]["counts"];
    assert_eq!(
        c["candidates"], 227,
        "conflicting rows must not become candidates"
    );
    assert_eq!(c["chat_conflicts"], 5);
    assert_eq!(c["timestamp_conflicts"], 3);
    let excl = out["plan"]["exclusions"].to_string();
    assert!(excl.contains("chat relationship conflicts") && excl.contains("timestamp conflicts"));
    assert_eq!(out["status"], "actionable");
}

#[test]
fn unknown_differences_are_diagnostic_only() {
    let tmp = tempfile::tempdir().unwrap();
    let (_fx, out, _d) = run(
        tmp.path(),
        &spec_with(LineDbSpec {
            unknown_differences: 4,
            ..base_line()
        }),
    );
    assert_eq!(out["plan"]["counts"]["unknown_differences"], 4);
    assert_eq!(out["plan"]["counts"]["candidates"], 227);
}

/// Rule version 2: NULL and duplicated identifiers are excluded and counted, not blockers.
/// Real LINE stores carry 1,724 NULL-ZID local rows and a byte-identical duplicate pair, and the
/// proven 227-row repair was performed on exactly such data.
#[test]
fn duplicate_or_null_zid_is_excluded_and_counted_not_blocking() {
    let tmp = tempfile::tempdir().unwrap();
    let (fx, out, _d) = run(
        &tmp.path().join("dup"),
        &spec_with(LineDbSpec {
            duplicate_zid_in_current: true,
            ..base_line()
        }),
    );
    assert_eq!(out["status"], "actionable", "{out}");
    let plan = &out["plan"];
    assert_eq!(plan["blockers"].as_array().unwrap().len(), 0);
    assert_eq!(plan["predicted_update_count"], 227);
    assert_eq!(plan["counts"]["duplicate_identity_values"], 1);
    // The duplicated identifier is dropped from both sides, so it is neither matched nor "only".
    assert_eq!(
        plan["counts"]["matched"],
        fx.truth.old_message_count - fx.truth.old_only - 1
    );
    assert_eq!(plan["counts"]["current_only"], fx.truth.current_only);
    let excl = plan["exclusions"].to_string();
    assert!(excl.contains("identifier values duplicated"), "{excl}");
    assert!(plan["warnings"].to_string().contains("more than one row"));
    assert!(plan["candidate_predicate"]
        .as_str()
        .unwrap()
        .contains("ZID unique in both databases"));

    let (fx, out, _d) = run(
        &tmp.path().join("null"),
        &spec_with(LineDbSpec {
            null_zid_in_old: true,
            ..base_line()
        }),
    );
    assert_eq!(out["status"], "actionable", "{out}");
    let plan = &out["plan"];
    assert_eq!(plan["predicted_update_count"], 227);
    assert_eq!(plan["counts"]["null_identity_rows_old"], 1);
    assert_eq!(plan["counts"]["null_identity_rows_current"], 0);
    // The NULL row is not "old-only"; its current counterpart (real ZID) is current-only.
    assert_eq!(plan["counts"]["old_only"], fx.truth.old_only);
    assert_eq!(plan["counts"]["current_only"], fx.truth.current_only + 1);
    assert!(plan["exclusions"].to_string().contains("NULL ZID"));
    assert!(plan["warnings"].to_string().contains("NULL ZID"));
}

#[test]
fn schema_variation_is_unsupported_without_a_plan() {
    let tmp = tempfile::tempdir().unwrap();
    let (_fx, out, d) = run(
        tmp.path(),
        &spec_with(LineDbSpec {
            break_schema: true,
            ..base_line()
        }),
    );
    assert_eq!(out["status"], "unsupported", "{out}");
    assert!(out["diagnostics"]["adapter_gaps"]
        .to_string()
        .contains("ZMESSAGE.ZCONTENTMETADATA"));
    assert!(out.get("plan").is_none());
    let st = d.status();
    assert_eq!(st["stages"]["analysis"]["state"], "committed");
    assert_eq!(st["stages"]["analysis"]["evidence"]["supported"], false);
    assert!(recovery_core::analysis::ops::load_plan(&d).is_err());
}

#[test]
fn corrupted_database_fails_preflight() {
    let tmp = tempfile::tempdir().unwrap();
    let fx =
        fixtures::generate(&tmp.path().join("fx"), &spec_with(base_line()), &NoProgress).unwrap();
    let mut d = Driver::open(&tmp.path().join("ws")).unwrap();
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
    let out = d
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
    // Corrupt the extracted working copy: analysis must notice the hash drift, not run on it.
    let p = out["intake"]["line_db"]["plaintext_path"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut bytes = std::fs::read(&p).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 0xFF;
    std::fs::write(&p, &bytes).unwrap();
    let err = d.execute(Request::Analyze, None, &NoProgress).unwrap_err();
    assert_eq!(err.code, recovery_core::ErrorCode::SessionState);
}

#[test]
fn analysis_requires_both_intakes() {
    let tmp = tempfile::tempdir().unwrap();
    let fx =
        fixtures::generate(&tmp.path().join("fx"), &spec_with(base_line()), &NoProgress).unwrap();
    let mut d = Driver::open(&tmp.path().join("ws")).unwrap();
    d.execute(
        Request::Intake {
            role: BackupRole::Old,
            backup_dir: fx.old_backup_dir.clone(),
            account_dir: None,
        },
        Some(Password::new(fixtures::FIXTURE_PASSWORD)),
        &NoProgress,
    )
    .unwrap();
    let err = d.execute(Request::Analyze, None, &NoProgress).unwrap_err();
    assert_eq!(err.code, recovery_core::ErrorCode::SessionState);
}

/// Task 4.6: a sample adapter can be added without touching generic modules.
mod sample_adapter {
    use recovery_core::analysis::adapter::{AnalysisOutcome, LineAdapter};
    use recovery_core::analysis::adapters::select;
    use recovery_core::analysis::schema::SchemaFingerprint;

    struct SampleAdapter;
    impl LineAdapter for SampleAdapter {
        fn id(&self) -> &'static str {
            "sample-v0"
        }
        fn rule_version(&self) -> &'static str {
            "sample/0"
        }
        fn message_table(&self) -> &'static str {
            "ZMESSAGE"
        }
        fn identity_column(&self) -> &'static str {
            "ZID"
        }
        fn required_schema(&self) -> &'static [(&'static str, &'static [&'static str])] {
            &[("ZMESSAGE", &["ZID"]), ("ZSAMPLE", &["Z_PK"])]
        }
        fn authorized_fields(&self) -> &'static [&'static str] {
            &["ZTEXT"]
        }
        fn protected_fields(&self) -> &'static [&'static str] {
            &["ZID"]
        }
        fn candidate_predicate(&self) -> &'static str {
            "sample"
        }
        fn analyze(
            &self,
            _c: &rusqlite::Connection,
            _p: &dyn recovery_core::progress::ProgressSink,
        ) -> recovery_core::Result<AnalysisOutcome> {
            Ok(AnalysisOutcome::default())
        }
        fn repair_one(
            &self,
            _t: &rusqlite::Transaction<'_>,
            _i: &str,
        ) -> recovery_core::Result<usize> {
            Ok(0)
        }
        fn count_repaired_mismatches(
            &self,
            _c: &rusqlite::Connection,
            _i: &[String],
        ) -> recovery_core::Result<u64> {
            Ok(0)
        }
    }

    #[test]
    fn registry_selection_is_schema_driven() {
        let mut fp = SchemaFingerprint {
            tables: Default::default(),
            sha256: recovery_core::hash::Sha256Hex::of_bytes(b"x"),
        };
        fp.tables.insert("ZMESSAGE".into(), vec!["ZID".into()]);
        let adapters: Vec<Box<dyn LineAdapter>> = vec![Box::new(SampleAdapter)];
        let gaps = match select(&adapters, &fp, &fp) {
            Err(g) => g,
            Ok(_) => panic!("should not match"),
        };
        assert_eq!(gaps[0].0, "sample-v0");
        assert!(gaps[0].1.iter().any(|g| g.contains("ZSAMPLE")));
        fp.tables.insert("ZSAMPLE".into(), vec!["Z_PK".into()]);
        assert_eq!(
            select(&adapters, &fp, &fp).ok().map(|a| a.id()),
            Some("sample-v0")
        );
    }
}

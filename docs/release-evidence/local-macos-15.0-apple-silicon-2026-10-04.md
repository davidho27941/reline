# Release Evidence: developer machine, macOS 15.0 (24A335), Apple Silicon, 2026-10-04

Not a clean machine; recorded as the baseline for task 9.3. Clean-machine runs are still owed.

## Automated suites

| Suite | Result |
|---|---|
| `cargo fmt --check`, `cargo clippy -D warnings` | clean |
| `cargo test --workspace --all-features` | 62 passed, 0 failed |
| same suite under AddressSanitizer (nightly, `-Zsanitizer=address`) | 62 passed, no reports |
| `scripts/swift-test.sh` (Swift Testing, Command Line Tools) | 20 passed incl. Keychain |
| `cargo test --workspace --all-features` after rule version 2 (see below) | 63 passed, 0 failed |
| `scripts/ui-test.sh` (6 XCUITests, task 7.3/7.4: gating, VoiceOver labels, keyboard, cancel during intake, unsupported input, structured error) | 6 passed, 0 failed (71.6 s) |
| `scripts/gen-licenses.py --check` | 87 dependencies, allow-list clean |
| `scripts/verify_fixture_reference.py` (iphone_backup_decrypt 0.11.2) | old and current fixture hashes MATCH |

## Performance bound (`scripts/scale-test.sh`, 400,000 messages, 300 chats, 5,000 current-only)

| Step | Wall clock |
|---|---|
| fixture generation | 7 s |
| intake old / current (72 MB databases) | 0 s / 1 s |
| analyze | 3 s |
| analyze + repair + encrypt + round trip + clone + replace + re-read | 15 s |
| export, cleanup | 0 s each |
| peak resident set | 352 MB |
| result | 227 updates, every gate passed, page_count 17825 → 17908 |

Real backups are dominated by payload size (62 GB per device here); the four full-directory
hash passes during patching scale linearly with that size.

## Cancellation and immutability

Covered by `tests/intake.rs::cancellation_during_intake_leaves_no_plaintext_and_source_untouched`,
`tests/repair.rs::cancellation_mid_transaction_leaves_working_copy_equal_to_input`,
`tests/e2e.rs::cancellation_during_patch_leaves_no_clone_and_source_untouched`, and the
source-hash comparisons in every full-chain test.

## Real backups: acceptance chain (task 8.5), 2026-10-04 03:32–03:40 UTC

Inputs: preserved copies `Backup_20261003/<old-udid>` (old, iOS 26.5) and
`Backup_20261003/<current-udid>` (current, iOS 27.0.1, byte-identical to
`FINDER_ORIGINAL_…`), via `scripts/acceptance-real-backup.sh`; password supplied once on stdin.

| Step | Result |
|---|---|
| intake old / current | committed in 2 s total; `Line.sqlite` plaintext 580,571,136 / 580,706,304 bytes, 165,017 manifest records each |
| analysis | plan `f8de17f7…`, rule `type106-placeholder-restore/2`, actionable, 227 predicted (211/6/4/3/2/1 by old type 0/1/112/2/3/14), 21 native placeholders preserved, 1 old-only, 97 current-only, 0 chat/timestamp/sender conflicts, 0 unknown differences; exclusions: 1,724 NULL-ZID rows in each database, 1 duplicated ZID value |
| repair | 227 rows updated, committed; page_count 141,774 → 141,776, page_size 4096, freelist 0 |
| post-repair validation | integrity ok, 0 authorized-field mismatches, 0 remaining candidates, 0 protected-field changes (rows paired by rowid), row set unchanged, every other table identical |
| encryption | protection class 3, payload 580,714,512 bytes, decrypt-and-hash round trip ok |
| clone | 111,762 files / 67.0 GB, all via `clonefile`, same volume; source re-hashed unchanged after clone; clone differs from source only at `d5/d58dda5f…` |
| re-read verification | all 8 gates passed; re-read plaintext SHA-256 = repaired SHA-256 |
| export | `…/dest/<current-udid>_PATCHED_20261004-034026` + `.report.md/.json` + `RESTORE-INSTRUCTIONS.md`; reports contain neither the password nor message text |
| wall clock / peak RSS | 508 s / 301 MB for the whole script (clone + four 63 GB hash passes dominate) |
| source immutability | `Manifest.db`, `Manifest.plist`, `Status.plist` and the LINE payload of both sources hash identical before and after (independent `shasum`) |
| cleanup | `cleanup` removed every plaintext file; `partial_artifacts` empty |

Repaired plaintext SHA-256 is `b0cc594ef6983beb239c289d27dac94b44986e216cf492574e11547291344309`,
not the `b4abc7a3…` recorded by the manual October 2026 repair. The two files are the same size
(580,714,496 bytes) and differ in 17,119 bytes: header bytes 96–99 (SQLite library version
that last wrote the file: bundled 3.53.2 vs system 3.43.2) and freed cell space inside
`ZMESSAGE` leaf pages (system SQLite zeroes it with `secure_delete=ON`; the bundled build uses
`FAST`). A per-table, rowid-ordered row digest over all 19 tables plus the schema is identical
between the two files, so the logical result equals the proven manual repair. Byte equality of
the plaintext across SQLite versions is not an achievable criterion; logical equality is the one
recorded here.

### Rule version 2 (found by this run)

Version 1 of the identity preflight treated any NULL or duplicated `ZID` as a blocker. The real
stores carry 1,724 NULL-ZID local rows (content type 0) and one byte-identical duplicate pair in
both databases, so version 1 produced a diagnostic-only plan with 0 candidates. Version 2
excludes exactly those rows from matching and repair, reports the counts as exclusions and
warnings, re-checks uniqueness inside the repair statement, and the post-repair gates pair rows
by rowid instead of identity. Covered by `tests/analysis.rs::duplicate_or_null_zid_is_excluded_and_counted_not_blocking`
and `tests/e2e.rs::null_and_duplicate_identifiers_survive_the_full_chain_untouched`.

## Real backups (read-only, no password)

`inspect` parsed both preserved real backups: old device iOS 26.5 (backup 2026-10-03T03:02:26+00:00),
current device iOS 27.0.1 (backup 2026-10-03T04:06:37+00:00, Status UUID redacted), both `finished`,
encrypted, keybag present, 256 payload shards. Values match report §12.2.

## Application bundle

`scripts/package-app.sh --adhoc` assembled `dist/Reline.app`, signed ad hoc with
`--options runtime`; `codesign --verify --deep --strict` passed; embedded entitlements are
exactly `files.user-selected.read-write` and `files.bookmarks.app-scope`. Launching the bundle
creates a 900×652 on-screen window and the process stays alive; it quits cleanly on request.
Screenshot capture was blocked by the Screen Recording permission on this machine.

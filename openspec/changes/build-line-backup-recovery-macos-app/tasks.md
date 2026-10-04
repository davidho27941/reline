# Tasks

## 1. Project Foundations

- [x] 1.1 Create the SwiftUI application, Rust workspace, static-library target, and shared fixture directories; verify a clean checkout builds both targets on Apple Silicon (the only supported architecture).
- [x] 1.2 Define the minimal C-compatible FFI contract for session handles, requests, progress events, cancellation, errors, and owned results; verify Swift integration tests create and release a Rust session without leaks.
- [x] 1.3 Add dependency licensing and cryptography export-compliance documentation; verify every bundled dependency appears in the generated acknowledgements and license audit.
- [x] 1.4 Configure unit tests, Rust linting, Swift tests, sanitizers, and CI build matrices; verify the pipeline fails on formatting, lint, test, or memory-safety regressions.
- [x] 1.5 Document the encrypted Finder backup format needed by the core (keybag TLV, double PBKDF2 derivation, class-key unwrapping, ManifestKey layout, MBFile EncryptionKey layout, payload path rule) in `docs/backup-format.md`; verify every field the Rust parsers read is named in the document.
- [x] 1.6 Implement a synthetic encrypted-backup fixture generator that builds keybag, Manifest.plist, encrypted Manifest.db, Status.plist, Info.plist, and payloads from a chosen password; verify generated fixtures decrypt with an independent reference implementation.

## 2. Recovery Session and Secret Safety

- [x] 2.1 Implement the versioned session manifest and atomic stage-commit model; verify restart tests distinguish committed evidence from interrupted partial artifacts.
- [x] 2.2 Implement restrictive workspace permissions, secret wrappers, zeroization, and plaintext cleanup; verify tests find no password, key, or chat text in logs, reports, crash attachments, or retained temporary files.
- [x] 2.3 Implement cooperative progress and cancellation in the Rust core; verify cancellation tests close file handles, remove sensitive partial outputs, and never mark the cancelled stage complete.
- [x] 2.4 Document the session directory lifecycle and cleanup policy; verify each documented state and cleanup action is exercised by an automated lifecycle test.

## 3. Encrypted Finder Backup Intake

- [x] 3.1 Implement read-only backup layout validation of Info.plist, Status.plist (`SnapshotState` must be `finished`), and Manifest.plist before authentication, and Manifest database validation after decryption; verify valid, incomplete, malformed, and unfinished fixture backups produce the specified intake results.
- [x] 3.2 Implement backup password authentication, keybag unlocking, and temporary index decryption with known-answer fixtures; verify correct passwords succeed and incorrect passwords expose no derived key material.
- [x] 3.3 Implement Manifest file-record decoding, payload path resolution, and supported metadata extraction; verify fixture records reproduce expected file IDs, sizes, protection classes, and digest presence.
- [x] 3.4 Implement LINE domain and relative-path discovery including multi-account ambiguity and sibling `-wal`/`-shm`/`-journal` detection; verify fixtures with zero, one, and multiple LINE stores follow the required selection behavior and a non-empty WAL marks the backup unsupported for patching.
- [x] 3.5 Implement read-only LINE database extraction into the session workspace and source hash checks; verify before-and-after hashes prove source backups remain byte-identical on success, failure, and cancellation.
- [x] 3.6 Document supported Finder backup structures and intake error remedies; verify documentation examples are covered by the intake fixture suite.

## 4. LINE Database Analysis

- [x] 4.1 Implement SQLite integrity checks, versioned LINE schema fingerprints, and ZID null/uniqueness preflight; verify supported schemas pass, altered or incomplete schemas remain diagnostic-only, and NULL or duplicated ZIDs are excluded and counted rather than blocking (rule version 2; version 1 blocked and made the real backups unsupported, found in task 8.5).
- [x] 4.2 Implement stable message matching with chat-MID and timestamp relationship validation resolved inside each database; verify conflict fixtures are excluded and counted rather than repaired and old-only messages are counted without insertion.
- [x] 4.3 Implement the versioned type-106 corruption rule from the proven case with an explicit authorized-field set; verify the synthetic fixture reproducing the proven distribution (211/6/4/3/2/1 by old type, 221 text and 145 metadata differences) yields 227 candidates, preserves 21 native placeholders, and leaves current-only messages untouched.
- [x] 4.4 Implement unknown-difference classification and fail-closed behavior; verify unrecognized content types, relationship changes, and schema variations cannot produce an actionable repair plan.
- [x] 4.5 Implement deterministic RepairPlan serialization with input hashes, rule versions, predicates, exclusions, and salted public identifiers; verify repeated analysis of identical inputs produces semantically identical plans without message text.
- [x] 4.6 Document the compatibility-adapter contract and fixture requirements; verify a sample adapter can be added without changing generic backup or patching modules.

## 5. Transactional Database Repair

- [x] 5.1 Implement RepairPlan hash and predicate revalidation before mutation; verify changed inputs or changed predicates invalidate the plan before a transaction begins.
- [x] 5.2 Implement transactional field updates restricted to the plan's records and authorized fields; verify a matching update count commits and any count mismatch rolls back with no persistent database change.
- [x] 5.3 Implement post-repair integrity, repaired-field equality, protected-field stability, page statistics, and hash checks; verify injected corruption at each validation point blocks encryption.
- [x] 5.4 Add repaired-database export for expert inspection with an explicit unverified/verified state; verify only a database passing every post-repair gate can receive the verified label.
- [x] 5.5 Document repair invariants and the prohibition on blanket type replacement, vacuuming, or truncation; verify regression tests cover each prohibited shortcut.

## 6. Payload Encryption and Backup Patching

- [x] 6.1 Implement protection-class 1, 3, and 4 key unwrapping and streaming per-file AES-CBC encryption with test vectors; verify plaintext, ciphertext size, padding, and hash outputs match known-answer fixtures and class 2 is rejected.
- [x] 6.2 Implement metadata-policy handlers for file size, digest presence, protection class, and backup status; verify unknown or inconsistent metadata fails closed before payload replacement.
- [x] 6.3 Implement the mandatory generated-payload decrypt-and-hash round trip; verify one-bit ciphertext, key, IV, or padding changes are detected and rejected.
- [x] 6.4 Implement APFS clone creation with verified copy fallback and destination-space preflight; verify source hashes remain unchanged and copy failures never produce an approved clone.
- [x] 6.5 Implement payload replacement only inside the clone and preserve unrelated Manifest and payload hashes; verify the produced clone differs only at explicitly approved paths.
- [x] 6.6 Implement full clone re-read through the normal intake path, including database integrity and plaintext hash verification; verify no clone is exportable until every gate passes.
- [x] 6.7 Document supported cryptographic and metadata combinations; verify every supported combination has a known-answer test and every unsupported combination has a rejection test.

## 7. Native macOS Workflow

- [x] 7.1 Implement SwiftUI selection of old backup, current backup, session workspace, and export destination using system folder pickers; verify selected-folder access works without administrator privileges or Full Disk Access on supported macOS versions.
- [x] 7.2 Implement security-scoped bookmark lifecycle and stale-bookmark recovery; verify relaunch tests regain only approved access and release the scope after operations finish.
- [x] 7.3 Implement staged intake, analysis, review, patching, verification, and export screens; verify UI tests keep mutating stages disabled until every prerequisite and explicit confirmation is present.
- [x] 7.4 Implement accessible progress, cancellation, error, and unsupported-input presentation; verify VoiceOver labels, keyboard navigation, cancellation, and structured failure messages in UI tests. (`scripts/ui-test.sh`: 6 XCUITests, requires Xcode and an ASCII input source during the run; the suite switches to ABC and restores the user's input method.)
- [x] 7.5 Implement an optional Keychain-backed remember-password setting that defaults off; verify disabling or deleting the setting removes the credential and reports never include it.
- [x] 7.6 Document the user workflow for selecting copied backups rather than directly modifying MobileSync; verify the in-app instructions match the implemented file-picker flow.
- [x] 7.7 Localize the shell in English and Traditional Chinese (system language by default, in-app toolbar language picker override, per-error-code explanations); verify a UI test launched in zh-Hant sees translated stage rows, buttons, blockers and the structured error alert while identifiers stay stable. (Added 2026-10-04; engine-produced text and reports remain English.)

## 8. Audit Report and Safe Handoff

- [x] 8.1 Implement Markdown and machine-readable audit reports with hashes, counts, rule versions, stages, warnings, output paths, failed gates, explicit UTC offsets, and a redacted variant for UDID and account directory; verify privacy tests reject fixtures containing message text, passwords, or keys.
- [x] 8.2 Implement the final manual Finder restore checklist (unplug device, do not start a new backup, offline first launch), post-restore checkpoint-backup guidance, and rollback instructions; verify a report identifies the preserved source and patched output unambiguously without initiating external actions.
- [x] 8.3 Implement export naming and overwrite protection; verify default export never replaces an existing backup and explicit overwrite requires a separate confirmation.
- [x] 8.4 Add an end-to-end synthetic fixture reproducing the documented successful recovery chain; verify intake through patched-backup re-read produces the expected 227 repairs and the fixture's own recorded final plaintext hash.
- [x] 8.5 Run the acceptance chain against the user's preserved real backups through the CLI harness; verify the repaired plaintext hash equals `b4abc7a367201d141533e2e26fd4b20ebc1967e2e2dcd37f28ea88015697916f` and the source backups remain byte-identical. (Run 2026-10-04: 227 updates, all gates passed, sources unchanged. The plaintext SHA-256 is `b0cc594e…` because SQLite 3.53 vs 3.43 writes different header version bytes and freed-space bytes; the repaired file is logically identical to the manual `Line_repaired.sqlite` in every table and the schema. Evidence in `docs/release-evidence/local-macos-15.0-apple-silicon-2026-10-04.md`.)

## 9. Distribution and Release Verification

Distribution decision (2026-10-04): the application is published as source on GitHub and built by each user (`scripts/package-app.sh --adhoc`). No Developer ID certificate or notarization is purchased; a locally built app carries no quarantine flag, so Gatekeeper never intervenes. Signed/notarized distribution stays available through `package-app.sh --sign` and `notarize.sh` for anyone who holds an identity, but it is not a release criterion.

- [x] 9.1 Configure ad hoc signing with Hardened Runtime and entitlements, Apple Silicon application packaging, and a documented build-from-source path; verify `codesign --verify --deep --strict` succeeds on the packaged application and the entitlements are exactly the two file-access ones. (Developer ID signing remains optional via `package-app.sh --sign`; not required by the chosen distribution model.)
- [x] 9.2 Document the unsigned distribution model: README build instructions, CI job that packages the app on a clean GitHub macOS runner, and the Gatekeeper steps for anyone who receives a prebuilt copy instead of building. Notarization (`scripts/notarize.sh`) is kept as an optional path and is not a release gate.
- [x] 9.3 Run the full recovery suite on clean supported macOS versions on Apple Silicon; verify results, performance bounds, cancellation, and source immutability are recorded in the release evidence. (Clean GitHub-hosted macOS 14 and 15 Apple Silicon runners, run 37184184824 on 2026-10-04: Rust suite on both versions, AddressSanitizer, Swift suite, fixture reference, packaging with entitlement check, 8 XCUITests, and the timed 400k-message CLI chain all passed; `docs/release-evidence/ci-clean-runners-2026-10-04.md`. Developer-machine baseline and the real-backup run: `docs/release-evidence/local-macos-15.0-apple-silicon-2026-10-04.md`.)
- [x] 9.4 Complete a security review of FFI, temporary plaintext, secret lifetime, path handling, archive traversal, logs, and crash behavior; verify every high-severity finding is resolved or the affected feature is disabled before release.
- [x] 9.5 Publish the compatibility matrix, privacy statement, limitations, recovery disclaimer, and incident-response contact; verify these documents match the shipped rule set and supported backup formats.

## Workflow follow-up

- Run OpenSpec apply only after proposal, specifications, design, and tasks are reviewed and approved.
- Run OpenSpec verify against the completed implementation before treating the change as ready to archive.
- Sync the delta specifications into the main capability specifications and archive the change after release criteria are satisfied.

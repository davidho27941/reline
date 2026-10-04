# Design

## Context

See `proposal.md` for motivation. The manual recovery documented in `outputs/LINE_iPhone_聊天紀錄修復完整技術報告.md` proved the end-to-end path but depended on hand-written SQL, a Python decryption library's internal APIs, shell commands, and manual interpretation of validation output. The product must preserve that workflow's layered evidence and rollback properties while handling multi-gigabyte backups, sensitive keys, changing LINE schemas, and macOS file-access controls.

The primary stakeholders are users recovering their own backups, support engineers reviewing evidence, and maintainers adding explicitly tested compatibility rules. The tool must operate offline and must never present an unverified clone as safe for restore.

## Goals / Non-Goals

**Goals:**

- Provide a native, understandable macOS workflow around a deterministic recovery engine.
- Keep backup passwords, keys, decrypted databases, and chat content local.
- Make original backup immutability and independent round-trip verification architectural invariants.
- Separate generic iOS backup handling from versioned LINE corruption rules.
- Produce auditable outputs that can explain why a repair was or was not considered safe.

**Non-Goals:**

- Automating Finder or controlling an attached iPhone.
- Modifying the active MobileSync backup directory in place.
- Synchronizing with LINE servers or bypassing account authentication.
- Supporting an unknown LINE schema through heuristics that mutate data.
- Recovering a backup without its correct encryption password.
- Shipping through the Mac App Store in the initial release.

## Decisions

### Native SwiftUI shell with an in-process Rust core

SwiftUI owns macOS lifecycle, system file pickers, security-scoped access, Keychain opt-in, accessibility, cancellation controls, and user-facing error presentation. Rust owns parsing, comparison, repair, cryptography, hashing, and report data.

The Rust core is built as a static library with a small C-compatible ABI and generated bindings. Operations exchange opaque session handles, immutable request structures, progress events, and structured results. Secrets never cross into UI logs.

Alternatives considered:

- Tauri would accelerate a web-style interface but adds a WebView and IPC surface without improving the recovery engine.
- A pure Rust GUI reduces languages but makes native permission, Keychain, accessibility, and macOS lifecycle integration less direct.
- A spawned CLI provides process isolation but complicates sandbox-derived file access and secret transport. It may be added later as a separate expert interface, not as the GUI's core path.

### Explicit trust boundaries

```text
User-selected source backups
        │ read-only
        ▼
Backup intake and temporary plaintext workspace
        │ validated immutable evidence
        ▼
Analysis and RepairPlan
        │ explicit user approval
        ▼
Destination clone only
        │ repair encryption and verification
        ▼
Verified export plus audit report
```

The source backup boundary forbids writes. The mutation boundary opens only after a repair plan is complete and confirmed. The export boundary opens only after the clone is re-read through the same intake path.

### User-selected folders instead of Full Disk Access

The app uses macOS folder selection and security-scoped bookmarks. The MVP asks users to select preserved backup copies and an output directory rather than scanning or changing `MobileSync/Backup`. If TCC still blocks nested data, the UI instructs the user to copy the backup to a user-controlled folder.

This avoids administrator privileges and reduces the consequences of a compromised process. Direct MobileSync management is excluded from the MVP.

### Immutable session workspace

Each session receives a unique workspace with a manifest that records input paths, hashes, schema detections, rule versions, state transitions, and output paths. Source files are opened read-only. Decrypted temporary material is stored only inside the session workspace with restrictive permissions and is deleted on completion or cancellation unless the user explicitly retains a repaired database.

A stage becomes committed only after its outputs are fsynced, hashed, and atomically registered in the session manifest. On restart, uncommitted outputs are classified as partial and cannot be reused as verified evidence.

### Versioned compatibility and repair rules

Generic layers parse Finder backup structures and SQLite. LINE compatibility is expressed as versioned adapters containing schema fingerprints, stable identity fields, relationship checks, corruption predicates, authorized mutable fields, and validation queries.

The proven type-106 repair becomes one rule, not a universal assumption. A schema or record pattern that does not match a tested adapter can be diagnosed but cannot be patched automatically.

Identity and relationship rules for the LINE adapter are explicit because Core Data primary keys are not stable across devices:

- `ZMESSAGE.ZID` is the only cross-database identity. Rows whose `ZID` is NULL and every row carrying a `ZID` that is duplicated in either database are excluded from matching and repair and reported with counts, because the proven scalar-subquery repair would silently pick an arbitrary row for them; the repair statement re-checks uniqueness per row. Real LINE stores carry NULL-ZID local rows (content type 0) and occasional byte-identical duplicate pairs, so treating them as blockers (rule version 1) made every real store unsupported.
- Chat relationship is validated by joining `ZMESSAGE.ZCHAT` to `ZCHAT.Z_PK` inside each database and comparing the resulting `ZCHAT.ZMID` values across databases. `Z_PK` values are never compared across databases.
- Sender relationship is validated the same way through the sender's MID when the schema exposes it. When it does not, the plan records `sender_check: unavailable` as a warning; the record is not excluded, because `ZSENDER` is a protected field that the repair never writes and chat plus timestamp agreement already fixes the identity.
- `ZTIMESTAMP` must be equal. The proven case showed zero timestamp drift, so no tolerance is applied.
- Messages present only in the old database are counted and reported as `old_only`; they are never inserted. Messages present only in the current database are left untouched.

### Sibling journal files are fail closed

`Line.sqlite` is a Core Data store and a backup may also carry `Line.sqlite-wal`, `Line.sqlite-shm`, or `Line.sqlite-journal` payloads under the same relative directory. A non-empty WAL would be replayed by LINE over the repaired main file after restore. Intake therefore enumerates sibling Manifest entries for the selected database. A `-wal` or `-journal` sibling with a non-zero Manifest `Size` or a non-empty payload marks the backup unsupported for patching. Working copies are opened without changing `journal_mode`, and the repair never leaves a `-wal` or `-journal` file beside the repaired database.

### RepairPlan as the mutation contract

Analysis produces an immutable, serializable RepairPlan containing input hashes, adapter and rule versions, candidate identities, predicted count, authorized fields, exclusions, and validation predicates. Patching re-checks input hashes and predicates before beginning. Any drift invalidates the plan.

The plan does not contain message text in its default persisted representation. Candidate identifiers are hashed with a session-specific salt in user-facing reports while the secure in-memory plan retains the identifiers needed for repair.

### Transactional SQLite repair and protected-field checks

The current-device database is copied into the workspace and repaired within a SQLite transaction. Each update repeats the plan predicate. The transaction commits only when the update count equals the predicted count. Post-commit checks confirm integrity, authorized field equality, and protected-field stability.

Bundled SQLite is used for predictable behavior. The application does not run `VACUUM`, truncate files, or normalize page layout merely to match the original size.

### Streaming cryptography and independent verification

Keybag and per-file keys are derived locally and held in zeroizing secret containers. Large payloads are encrypted and hashed in bounded chunks. Algorithms and padding are selected from the supported backup format metadata rather than inferred only from file length.

Supported protection classes are exactly `1`, `3`, and `4`, whose class keys are unwrapped symmetrically (RFC 3394 AES key wrap) from the backup keybag. Class `2` uses asymmetric wrapping and is rejected. The proven case used class `3`; classes `1` and `4` share the same unwrap path and are covered by known-answer tests, not by assumption.

The keybag TLV layout, double PBKDF2 derivation (SHA-256 with `DPIC`/`DPSL`, then SHA-1 with `ITER`/`SALT`), `WPKY` unwrapping, `ManifestKey` class-prefix layout, and the `MBFile` `EncryptionKey` layout (4-byte class prefix plus 40-byte wrapped key) are reconstructed from the public `iphone_backup_decrypt` implementation and documented in `docs/backup-format.md` before the Rust implementation is written.

Verification occurs twice: first by decrypting the generated payload before insertion, then by reopening the completed clone through the normal intake path. Both plaintext hashes must equal the repaired database hash.

### Metadata policy is fail closed

The patcher has explicit handlers for supported protection classes, padding, Manifest file metadata, digest presence, and backup status. Unknown or inconsistent metadata blocks patching. It is not acceptable to preserve or rewrite a field merely because one successful case did so.

The single supported metadata policy for the MVP is the proven one: `Manifest.db` and `Manifest.plist` are left byte-identical, the `MBFile` `Size` is left as recorded even when it differs from the plaintext size (live databases routinely differ), and `Digest` must be absent. A record that carries a `Digest`, an unknown `EncryptionKey` layout, or a `Status.plist` whose `SnapshotState` is not `finished` is unsupported.

### Fixtures and acceptance evidence

The proven case left no key material behind, so every cryptographic known-answer fixture is synthetic. A fixture generator builds a complete encrypted backup from a chosen password: keybag, `Manifest.plist`, encrypted `Manifest.db`, `Status.plist`, `Info.plist`, and payloads. The analysis fixture reproduces the proven distribution (227 candidates across old types 0/1/112/2/3/14 with 221 text and 145 metadata differences, 21 native type-106 placeholders, one old-only message) so that the branches where text is equal but metadata differs are exercised.

Synthetic fixtures have their own expected hashes. The real-case hash `b4abc7a367201d141533e2e26fd4b20ebc1967e2e2dcd37f28ea88015697916f` is only reproducible against the user's preserved real backups and is treated as a separate acceptance run, not as a unit test.

### Reports redact identifiers and state time zones

Audit reports include backup UDIDs and the LINE account directory (`P_u…`) because they are needed to identify the right backup. Both are considered shareable-sensitive: the report offers a redacted variant that replaces them with salted hashes. Every timestamp in UI and reports carries an explicit UTC offset, because the proven investigation initially misread the incident window by assuming the wrong zone.

### Distribution and update model

The MVP is distributed outside the Mac App Store using Developer ID signing, Hardened Runtime, notarization, and a stapled ticket. Network access is unnecessary for recovery. Updates are downloaded separately or added later through an explicitly designed signed-update mechanism.

## Data Flow

1. SwiftUI obtains user-selected old and current backup URLs and grants scoped access.
2. Rust validates the directory layout, `Info.plist`, `Status.plist`, and `Manifest.plist`; only then does it accept the password, unlock the keybag, and decrypt `Manifest.db` into the session workspace for validation. `Manifest.db` cannot be validated before authentication because it is itself encrypted.
3. Rust locates LINE payloads, checks for sibling WAL or journal entries, and extracts working database copies.
4. The analysis adapter validates schemas and produces a RepairPlan plus diagnostics.
5. SwiftUI presents counts, exclusions, fields, risks, and destination for confirmation.
6. Rust clones the current backup, transactionally repairs a working database, and validates it.
7. Rust encrypts the payload, verifies a local round trip, replaces the payload only in the clone, and re-reads the clone.
8. SwiftUI exports the verified clone, Markdown report, machine-readable report, and manual restore and rollback instructions.

## Rollback Behavior

- Before mutation, the original current backup and its hashes are recorded as the rollback source.
- A partial or failed clone is never labeled verified and never replaces an existing export automatically.
- Export uses a new destination name; overwrite requires a separate explicit confirmation and is not part of the default path.
- Device restore remains manual. The report tells the user how to preserve the active Finder backup before placing a patched backup in MobileSync, to unplug the iPhone before swapping directories, and not to start a new backup before restoring.
- After a successful restore the report instructs the user to create a fresh encrypted checkpoint backup before deleting any preserved directory.
- If a restored result is unacceptable, the user can restore the preserved original current-device backup. The app itself does not perform the swap or restore.

## Risks / Trade-offs

- [LINE schemas and corruption signatures change] → Use fail-closed, versioned adapters and fixture tests; unsupported inputs remain diagnostic-only.
- [A crypto implementation error could create an unrestorable backup] → Require known-answer tests, two round trips, independent clone re-read, and no automatic restore.
- [Multi-gigabyte backups consume time and disk] → Use APFS cloning when available, otherwise preflight free space, stream data, and show progress and cancellation.
- [Intel Macs] → Not supported in the MVP (decision 2026-10-04): the user base is Apple Silicon only; the Rust and Swift builds target arm64.
- [Swift/Rust FFI defects can corrupt memory] → Keep the ABI small, use opaque handles and owned buffers, and test lifecycle, cancellation, and error conversion under sanitizers.
- [Temporary plaintext exposes private data] → Restrictive permissions, app-controlled workspace, zeroized secrets, no content logging, and cleanup after interruption.
- [Developer ID distribution is less discoverable than the App Store] → Prioritize capability and auditability in the MVP, then reassess sandboxed App Store distribution after direct MobileSync access remains unnecessary.
- [User may restore the wrong backup] → Include device metadata, creation time, payload hash, and an explicit manual checklist in the export report.

## Migration Plan

1. Build the Rust core as a CLI-driven test harness and validate it against synthetic fixtures, then run the acceptance chain against the user's preserved real backups.
2. Add SwiftUI intake and analysis in diagnostic-only mode.
3. Enable repaired-database export after deterministic analysis tests pass.
4. Enable patched-backup export behind all cryptographic and clone re-read gates.
5. Sign, notarize, and test the application on clean supported macOS versions.
6. Keep the manual workflow document as the rollback procedure during the MVP period.

Rollback of a released version consists of disabling affected compatibility adapters and distributing a signed update; previously created source backups remain untouched.

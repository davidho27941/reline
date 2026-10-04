# Supported Finder Backup Structures and Intake Remedies

## What the app accepts

A folder selected through the macOS folder picker that is itself a Finder/iTunes backup
directory (usually named after the device UDID) containing:

| File | Required | Check |
|---|---|---|
| `Info.plist` | yes | parseable; device name, product version, UDID shown to the user |
| `Status.plist` | yes | `SnapshotState == finished` |
| `Manifest.plist` | yes | `IsEncrypted == true`, `BackupKeyBag` and 44-byte `ManifestKey` present |
| `Manifest.db` | yes | decrypts with the password; `Files` table has `fileID, domain, relativePath, flags, file` |
| `xx/<fileID>` | for LINE | payload for the LINE database exists and decrypts to a SQLite header |

Backups are opened read-only. Source hashes of `Manifest.db`, `Manifest.plist`,
`Status.plist`, and the LINE payload are recorded before and after extraction and must match.

## LINE discovery

Domains searched: `AppDomainGroup-group.com.linecorp.line`, then `AppDomain-jp.naver.line`.
Path pattern: `Library/Application Support/PrivateStore/P_u<hex>/Messages/Line.sqlite`.
One match → selected automatically. Several → the user must pick the account directory.
Siblings (`E2EEData.sqlite`, `MediaMessageData.sqlite`, `MessageExt.sqlite`,
`UserDataModel.sqlite`, `Line.sqlite-wal`, `-shm`, `-journal`) are listed, never modified.

## Patchability policy (current backup)

| Condition | Patchable |
|---|---|
| protection class 1, 3, or 4 with a usable class key | yes |
| protection class 2 or any other | no |
| `MBFile` has `Digest` | no |
| `MBFile` lacks `EncryptionKey` or `ProtectionClass` | no |
| `Line.sqlite-wal` or `-journal` sibling with non-zero size | no (diagnostics still allowed) |
| Manifest `Size` differs from decrypted size | yes (normal for live databases) |

## Error codes and remedies

| Code | Cause | Remedy shown |
|---|---|---|
| `access_denied` | macOS TCC blocked a file inside the folder | copy the backup to a folder you own (Documents) and select the copy; no admin rights, no Full Disk Access |
| `invalid_backup_structure` | a required file is missing, or the path is not a directory | select the folder named after the UDID; make sure the backup finished |
| `unsupported_backup` | not encrypted, or `SnapshotState != finished` | create a new encrypted backup |
| `malformed_metadata` | plist, keybag, Manifest.db or MBFile could not be decoded | the backup is damaged; use another copy |
| `authentication_failed` | keybag integrity check failed | check the password; nothing was changed |
| `payload_not_found` | no LINE store, or the chosen account directory does not exist | confirm LINE was installed when the backup was made |
| `ambiguous_account` | more than one LINE account | choose the account directory |
| `unsupported_metadata` | protection class, Digest or key layout outside policy | diagnostics only; patching disabled |
| `database_unsupported` | decrypted payload is not SQLite | the backup is damaged |
| `verification_failed` | source hashes changed during intake | unplug the iPhone, stop Finder, use a preserved copy |
| `cancelled` | user cancelled | plaintext removed; nothing changed |

## Fixture coverage

Every row above is exercised by `crates/recovery-core/tests/intake.rs`:
`inspect_reports_metadata_without_password`, `invalid_structures_are_rejected_before_password`,
`intake_succeeds_and_source_is_byte_identical`, `wrong_password_fails_closed_without_key_material`,
`zero_one_and_multiple_line_stores`, `pending_wal_blocks_patching_but_allows_diagnostics`,
`unsupported_metadata_fails_closed`, `single_pbkdf2_keybag_layout_is_supported`,
`cancellation_during_intake_leaves_no_plaintext_and_source_untouched`. The fixture format is
cross-checked against the public `iphone_backup_decrypt` library by
`scripts/verify_fixture_reference.py`.

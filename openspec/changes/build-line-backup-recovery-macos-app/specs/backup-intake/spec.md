# Spec Delta

## Purpose

Provide a safe, local entry point for selecting, authenticating, validating, and staging encrypted Finder backups without changing their original contents.

## ADDED Requirements

### Requirement: User-selected backup access
The application SHALL access a backup only after the user selects its directory through a macOS system file picker.

#### Scenario: Select a backup directory
- **WHEN** the user selects a directory containing a Finder backup
- **THEN** the application receives access to that directory and begins read-only validation

#### Scenario: Protected directory remains inaccessible
- **WHEN** macOS denies access to files inside the selected directory
- **THEN** the application reports the blocked path and offers instructions to copy or reselect the backup without requesting administrator credentials

### Requirement: Backup structure validation
The application SHALL reject a directory that does not contain a coherent Finder backup structure before requesting a password, and SHALL validate the decrypted Manifest database immediately after authentication and before any payload work.

#### Scenario: Valid backup structure
- **WHEN** the selected directory contains `Info.plist`, `Status.plist`, `Manifest.plist`, and `Manifest.db`, and `Status.plist` reports `SnapshotState` equal to `finished`
- **THEN** the application identifies it as a candidate backup and displays device name, product version, backup date with explicit UTC offset, and UDID

#### Scenario: Incomplete backup structure
- **WHEN** a required file is absent or unreadable, or `SnapshotState` is not `finished`
- **THEN** the application marks the backup invalid and performs no extraction or mutation

#### Scenario: Manifest database validated after authentication
- **WHEN** the keybag is unlocked and `Manifest.db` is decrypted into the session workspace
- **THEN** the application validates its `Files` table before locating any payload and marks the backup malformed if validation fails

### Requirement: Secure backup authentication
The application SHALL use the supplied backup password only in local memory and SHALL NOT record the password or derived keys in logs, reports, analytics, or crash metadata.

#### Scenario: Correct password
- **WHEN** the user supplies the correct encrypted-backup password
- **THEN** the application unlocks the backup index and continues without persisting the password by default

#### Scenario: Incorrect password
- **WHEN** backup authentication fails
- **THEN** the application reports an authentication error without revealing derived key material or changing the backup

### Requirement: LINE payload discovery
The application SHALL locate candidate LINE databases by Manifest domain and relative path and SHALL report ambiguity instead of choosing an account automatically.

#### Scenario: One LINE account database
- **WHEN** exactly one supported LINE database path is present
- **THEN** the application records its domain, relative path, file identifier, and non-secret file metadata

#### Scenario: Multiple LINE account databases
- **WHEN** more than one supported LINE account database is present
- **THEN** the application requires the user to select the intended account before analysis

### Requirement: Sibling journal detection
The application SHALL enumerate `-wal`, `-shm`, and `-journal` Manifest entries beside the selected LINE database and SHALL refuse patching when a write-ahead log or rollback journal could be replayed over the repaired database.

#### Scenario: No pending journal
- **WHEN** no `-wal` or `-journal` sibling exists, or every such sibling has zero size and an empty payload
- **THEN** the database is eligible for analysis and patching

#### Scenario: Pending write-ahead log
- **WHEN** a `-wal` or `-journal` sibling has a non-zero Manifest size or a non-empty payload
- **THEN** the application marks the backup unsupported for patching, explains the reason, and still permits diagnostic analysis

### Requirement: Immutable source backups
The application MUST treat selected source backups as immutable and SHALL place all decrypted files and temporary indexes outside the source directory.

#### Scenario: Intake completes
- **WHEN** a backup is authenticated and its LINE database is extracted
- **THEN** the source file hashes remain unchanged and the application records the working-copy location

#### Scenario: Intake is cancelled or fails
- **WHEN** the user cancels or an extraction error occurs
- **THEN** the application removes plaintext temporary material it created while leaving the selected backup unchanged

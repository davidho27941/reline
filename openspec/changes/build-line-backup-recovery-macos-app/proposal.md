# Proposal

## Why

The proven manual LINE recovery required many error-prone steps across encrypted Finder backup parsing, SQLite comparison, narrowly scoped repair, per-file re-encryption, and independent verification. A local macOS application can make the process repeatable and auditable while preserving the essential rule that no original backup is ever modified.

## What Changes

- Add a native macOS recovery application that guides users through selecting old and current encrypted Finder backups without requiring direct device control.
- Add offline backup intake that validates backup structure, accepts the password securely, locates LINE data, and extracts working copies without modifying source backups.
- Add deterministic LINE recovery analysis that compares matching message records, identifies evidence-backed corruption patterns, and produces a reviewable repair plan.
- Add verified backup patching that repairs only approved fields in a clone, re-encrypts the payload with the original file metadata, and proves a bit-for-bit round trip before export.
- Add a recovery session and audit report that records counts, hashes, validation results, warnings, and rollback locations without recording passwords, keys, or chat content.
- Ship the MVP as a Developer ID signed and notarized macOS application for Apple Silicon using a SwiftUI interface and an in-process Rust recovery core.
- Exclude automatic iPhone restore, direct modification of the active MobileSync backup, server synchronization, and any claim that one LINE corruption signature applies to every LINE or iOS version.

## Capabilities

### New Capabilities

- `backup-intake`: Select, authenticate, validate, and safely stage encrypted Finder backups and their LINE payloads.
- `reline-analysis`: Compare old and current LINE databases, detect supported corruption patterns, and produce an explicit repair plan.
- `verified-backup-patching`: Apply an approved repair to a backup clone, re-encrypt the repaired payload, and enforce validation gates before export.
- `recovery-session`: Guide the user through the recovery workflow and produce privacy-preserving progress, results, audit evidence, and rollback instructions.

### Modified Capabilities

None.

## Impact

- Introduces a macOS application target, a Rust core library, and a narrow Swift-to-Rust FFI boundary.
- Adds parsers for encrypted Finder backup metadata, LINE SQLite schemas, backup keybags, and per-file encryption metadata.
- Adds bundled SQLite and cryptographic dependencies, fixture-based compatibility tests, and large-file streaming operations.
- Requires macOS file-selection permissions, secure secret handling, Developer ID signing, Hardened Runtime, and notarization.
- Establishes an immutable-source data model and a verified-export format for patched backups and audit reports.

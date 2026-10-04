# Spec Delta

## Purpose

Create a patched Finder backup from an approved repair plan while enforcing immutable sources, transactional database repair, correct per-file encryption, and independent verification.

## ADDED Requirements

### Requirement: Patch only a verified clone
The application MUST create and verify a separate backup clone before performing any mutation and SHALL refuse to patch a source backup in place.

#### Scenario: Clone is available
- **WHEN** the user approves patch creation and sufficient destination space is available
- **THEN** the application creates a clone, records its location, and directs all writes to the clone

#### Scenario: Clone creation fails
- **WHEN** cloning or copying cannot be completed and verified
- **THEN** the application stops before database or payload mutation and leaves the source unchanged

### Requirement: Transactional database repair
The application SHALL apply only the fields and records named in the approved repair plan within a transaction, and the actual update count MUST equal the predicted count.

#### Scenario: Repair count matches
- **WHEN** every planned mutation applies and the update count matches the plan
- **THEN** the application commits the repaired working database and continues to validation

#### Scenario: Repair count differs
- **WHEN** the update count differs from the repair plan or a predicate changes
- **THEN** the application rolls back the transaction and marks the patch attempt failed

### Requirement: Post-repair SQLite validation
The application SHALL validate database integrity and every authorized repaired field before encrypting a payload.

#### Scenario: Repaired database is valid
- **WHEN** integrity passes, candidate fields equal their approved source values, and protected fields remain unchanged
- **THEN** the application records the repaired database hash and permits encryption

#### Scenario: Any database validation fails
- **WHEN** integrity, candidate-field, or protected-field validation fails
- **THEN** the application stops and does not create an encrypted replacement payload

### Requirement: Metadata-aware payload encryption
The application SHALL derive the original file encryption context from the selected current backup and SHALL refuse to patch unsupported protection or integrity metadata.

#### Scenario: Supported encryption metadata
- **WHEN** the payload has protection class 1, 3, or 4, a 44-byte wrapped file key, no `Digest`, and the backup status is `finished`
- **THEN** the application encrypts the repaired database into a replacement payload without exposing key material and leaves `Manifest.db` and `Manifest.plist` byte-identical

#### Scenario: Asymmetric protection class
- **WHEN** the payload uses protection class 2 or any class outside the supported set
- **THEN** the application marks the backup unsupported and performs no payload replacement

#### Scenario: Unsupported digest or protection metadata
- **WHEN** required metadata cannot be interpreted or safely updated
- **THEN** the application marks the backup unsupported and performs no payload replacement

### Requirement: Mandatory cryptographic round trip
The application MUST decrypt its generated payload and compare the resulting plaintext hash with the repaired database before placing the payload into the clone.

#### Scenario: Round trip matches
- **WHEN** the decrypted generated payload is byte-identical to the repaired database
- **THEN** the application may place the payload into the cloned backup

#### Scenario: Round trip differs
- **WHEN** decrypted output differs by size or hash
- **THEN** the application rejects the payload and leaves the clone unapproved

### Requirement: Patched backup re-read verification
The application MUST re-open the completed cloned backup through the normal backup-reading path and verify the repaired payload before marking it exportable.

#### Scenario: Completed backup passes every gate
- **WHEN** the cloned backup is structurally valid, its status is acceptable, its repaired database passes integrity, and its plaintext hash matches
- **THEN** the application marks the backup verified and enables export

#### Scenario: Completed backup fails a gate
- **WHEN** any structural, metadata, decryption, integrity, or hash check fails
- **THEN** the application marks the clone unsafe for restore and explains the failed gate

### Requirement: No automatic device restore
The application SHALL NOT initiate, automate, or simulate Finder device restore.

#### Scenario: Verified backup is ready
- **WHEN** patch verification completes
- **THEN** the application exports the backup and displays manual Finder restore and rollback instructions

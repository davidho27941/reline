# Spec Delta

## Purpose

Guide users through a resumable recovery session with explicit safety gates, understandable progress, privacy-preserving evidence, and actionable rollback instructions.

## ADDED Requirements

### Requirement: Guided recovery stages
The application SHALL present intake, analysis, review, patching, verification, and export as distinct stages and SHALL show which stages are complete or blocked.

#### Scenario: Stage prerequisites are satisfied
- **WHEN** all required evidence for the next stage exists
- **THEN** the application enables that stage and summarizes the evidence being carried forward

#### Scenario: Stage prerequisite fails
- **WHEN** a required validation fails or user approval is absent
- **THEN** the application blocks later mutating stages while preserving diagnostic results

### Requirement: Explicit mutation consent
The application SHALL require a separate confirmation that identifies the clone destination, predicted record count, and rollback source before patching begins.

#### Scenario: User confirms the exact plan
- **WHEN** the user approves the displayed mutation summary
- **THEN** the application begins clone creation and patching

#### Scenario: User declines or changes inputs
- **WHEN** the user cancels confirmation or changes a selected backup
- **THEN** the application performs no mutation and invalidates dependent analysis as necessary

### Requirement: Cancellable long-running work
The application SHALL expose progress and cooperative cancellation for scanning, copying, hashing, encryption, and verification without leaving a result marked valid prematurely.

#### Scenario: User cancels a running operation
- **WHEN** cancellation is requested during a long-running stage
- **THEN** the application stops at a safe boundary, closes files, removes sensitive temporary data, and marks partial output incomplete

#### Scenario: Application is interrupted
- **WHEN** the process terminates before a stage is committed
- **THEN** the next launch identifies partial session artifacts and offers safe cleanup or restart without treating them as verified

### Requirement: Privacy-preserving audit report
The application SHALL generate a Markdown and machine-readable report containing hashes, counts, rule versions, validation results, timestamps with explicit UTC offsets, warnings, and output locations without chat content, passwords, or encryption keys, and SHALL offer a redacted variant that replaces device UDIDs and LINE account directory names with salted hashes.

#### Scenario: Successful recovery session
- **WHEN** a patched backup is verified
- **THEN** the report records every passed gate, input and output hashes, rollback source, and manual next steps

#### Scenario: Failed recovery session
- **WHEN** the session stops on an error or unsupported condition
- **THEN** the report records the failed stage and safe diagnostic detail without exposing secrets or message text

### Requirement: Rollback instructions
The application SHALL provide rollback instructions that identify the preserved source backup and explain how to avoid Finder writes while exchanging backup directories.

#### Scenario: Export completes
- **WHEN** the verified patched backup is delivered
- **THEN** the application shows the preserved original, patched output, the instruction to unplug the device before swapping directories, and the manual rollback sequence

#### Scenario: Restore succeeded
- **WHEN** the user reports that the device restore completed
- **THEN** the instructions direct the user to create a fresh encrypted checkpoint backup before deleting any preserved directory

### Requirement: Offline operation
The recovery workflow SHALL require no network connection and SHALL NOT transmit backup metadata, device identifiers, message data, passwords, or keys.

#### Scenario: Network is unavailable
- **WHEN** the Mac has no network connection
- **THEN** all intake, analysis, patching, verification, and report generation capabilities remain available

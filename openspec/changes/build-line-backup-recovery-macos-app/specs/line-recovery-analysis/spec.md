# Spec Delta

## Purpose

Determine whether two LINE databases contain a safely repairable corruption pattern and express the evidence as a deterministic, reviewable repair plan.

## ADDED Requirements

### Requirement: Database preflight validation
The application SHALL validate both databases for readability, integrity, supported schema, and stable identifiers before comparing message content.

#### Scenario: Both databases pass preflight
- **WHEN** both databases are readable, pass integrity checks, and expose a supported schema
- **THEN** the application proceeds to deterministic message comparison

#### Scenario: Database fails preflight
- **WHEN** either database fails integrity or lacks required identifiers
- **THEN** the application marks analysis unsupported and produces no repair plan

#### Scenario: Message identifier is missing or not unique
- **WHEN** either database contains a null `ZID` or the same `ZID` on more than one message row
- **THEN** the application excludes those rows from matching and repair, reports the NULL-row and duplicate-value counts in the plan, and never lets a repair statement touch an identifier that is not unique in both databases

### Requirement: Stable message matching
The application SHALL match old and current messages using stable message identifiers and SHALL validate their chat and timestamp relationships before treating them as the same record. Chat relationships SHALL be compared through the chat MID resolved inside each database, never through Core Data primary keys.

#### Scenario: Stable identity agrees
- **WHEN** a message identifier exists in both databases and its relationship checks agree
- **THEN** the application may compare its content fields

#### Scenario: Identity relationship conflicts
- **WHEN** matching identifiers point to different chats or incompatible timestamps
- **THEN** the application excludes those records from automatic repair and reports the conflict count

### Requirement: Evidence-based corruption detection
The application SHALL classify records as repair candidates only through a versioned rule whose predicates, compared fields, and expected results are included in the repair plan.

#### Scenario: Supported placeholder pattern
- **WHEN** a record satisfies every predicate of a supported corruption rule
- **THEN** the application adds only the rule-authorized fields to the candidate repair

#### Scenario: Unknown difference pattern
- **WHEN** a record differs but matches no supported corruption rule
- **THEN** the application reports it as unsupported and does not propose a mutation

### Requirement: Preserve legitimate placeholders and current-only data
The application SHALL distinguish corrupt placeholders from records that were already placeholders in the old database and SHALL preserve messages found only in the current database.

#### Scenario: Placeholder already existed
- **WHEN** the corresponding old and current records are both placeholders
- **THEN** the repair plan records the item as preserved and proposes no change

#### Scenario: Current-only message
- **WHEN** a message exists only in the current database
- **THEN** the repair plan leaves the message unchanged

#### Scenario: Old-only message
- **WHEN** a message exists only in the old database
- **THEN** the repair plan counts it as old-only, reports the count, and proposes no insertion

### Requirement: Reviewable repair plan
The application SHALL present the predicted update count, authorized fields, rule version, exclusions, database hashes, and validation evidence before enabling patch creation.

#### Scenario: User reviews a complete plan
- **WHEN** analysis finds supported repair candidates
- **THEN** the application displays a plan whose candidate total can be recomputed from the two input databases

#### Scenario: No supported candidates
- **WHEN** analysis finds no safely supported repair candidates
- **THEN** the application provides a diagnostic report and disables patch creation

### Requirement: Deterministic analysis
The application SHALL produce the same repair plan for byte-identical inputs and the same rule set.

#### Scenario: Repeat analysis
- **WHEN** the same database hashes and rule-set version are analyzed twice
- **THEN** the generated candidate identifiers, counts, and authorized field changes are identical

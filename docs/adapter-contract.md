# Compatibility Adapter Contract

LINE knowledge lives only in `crates/recovery-core/src/analysis/adapters/`. The generic
`backup`, `repair`, `patch`, `report`, and `session` modules never name a LINE table, column,
content type, or rule.

## Trait

An adapter implements `analysis::adapter::LineAdapter`:

| Method | Purpose |
|---|---|
| `id()` | stable identifier, e.g. `line-ios-coredata-v1` |
| `rule_version()` | stable rule name/version, e.g. `type106-placeholder-restore/2`; recorded in every plan and report |
| `message_table()`, `identity_column()` | table and stable cross-database identity used by generic validation |
| `required_schema()` | tables and columns both databases must expose; selection is schema-driven |
| `authorized_fields()` | the only columns `repair_one` may write |
| `protected_fields()` | columns generic validation proves unchanged for every row |
| `candidate_predicate()` | plain-text predicate stored in the plan |
| `analyze(conn, progress)` | read-only comparison; `conn` is the current database with the old one attached as `olddb`; returns counts, candidates (real identifiers, memory only), warnings, blockers |
| `repair_one(tx, id)` | one statement per candidate inside the caller's transaction; must repeat the full predicate; returns rows changed (must be 1) |
| `count_repaired_mismatches(conn, ids)` | post-repair equality of authorized fields with the old values |

## Obligations

- Fail closed: anything the adapter cannot explain goes into `blockers` (plan not actionable)
  or `unknown_differences` (excluded from mutation, reported).
- Identity is the only cross-database key. Rows with a NULL identity and every row carrying an
  identity value that is duplicated in either database are excluded from matching and repair and
  reported as exclusions with counts; they are not blockers (real LINE stores contain both). The
  repair statement must re-check uniqueness so a scalar subquery can never pick an arbitrary row.
- Relationships are compared through values resolved inside each database (for example a chat
  MID), never through Core Data primary keys.
- Never read or persist message text outside the SQL engine; counts and hashes only.
- Determinism: identical inputs and rule version produce identical candidates and counts.

## Registration

Add the module under `adapters/`, append it to `adapters::registry()`, and nothing else.
`adapters::select` picks the first adapter whose `required_schema` both databases satisfy and
reports per-adapter gaps otherwise.

## Fixture requirements

Every adapter ships with a synthetic fixture under `fixtures::line_db` (or a sibling module)
that encodes the proven distribution it was derived from, including:

- the exact candidate count and the per-type breakdown,
- rows that look like candidates but conflict on a relationship (excluded),
- native placeholders that must be preserved,
- old-only and current-only rows,
- a schema variant that must be rejected,
- an `expected_repaired` database and its logical digest as an independent oracle.

`tests/analysis.rs::sample_adapter::registry_selection_is_schema_driven` demonstrates adding a
sample adapter in a test without touching generic code.

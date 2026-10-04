# Repair Invariants

These hold for every repair performed by `recovery_core::repair`. Each has a regression test.

| Invariant | Test |
|---|---|
| Input hashes and the derived candidate set are re-checked before any write; drift invalidates the plan | `repair.rs::changed_inputs_invalidate_the_plan_before_any_write`, `predicate_drift_is_rolled_back_by_the_row_level_check` |
| Work happens on a fresh private copy of the current database; sources are never opened read-write | `repair_applies_exactly_227_and_passes_every_gate` (source hashes unchanged) |
| One `UPDATE` per candidate inside a single `BEGIN IMMEDIATE` transaction; each must change exactly one row | `count_mismatch_rolls_back_with_no_persistent_change` |
| The transaction commits only when the total equals the predicted count; otherwise it rolls back and the working copy is byte-identical to the input | same, plus `cancellation_mid_transaction_leaves_working_copy_equal_to_input` |
| Only authorized fields are written; protected fields are proven unchanged for every row, paired by rowid so NULL or duplicated identities are covered too | `tampered_protected_field_blocks_encryption` |
| Every candidate's authorized fields equal the old values afterwards and no candidate remains | `reverted_repaired_field_blocks_encryption` |
| Row set unchanged (count, rowid membership, identity per rowid) | `deleted_or_inserted_rows_block_encryption` |
| Every other table is byte-identical by canonical digest | `changed_unrelated_table_blocks_encryption` |
| `PRAGMA integrity_check` must return exactly `ok` | `truncation_and_byte_corruption_are_detected` |
| `page_size` unchanged, `page_count` never decreases, file size equals `page_size * page_count`, `journal_mode` unchanged | `vacuum_and_page_size_change_are_detected`, `truncation_and_byte_corruption_are_detected` |
| No `-wal` or `-journal` file remains beside the repaired database | `repair_applies_exactly_227_and_passes_every_gate` |

## Prohibited shortcuts

- **Blanket type replacement.** Rewriting every `ZCONTENTTYPE = 106` row would destroy the
  placeholders that were already placeholders in the old database (21 in the proven case).
  The predicate requires `old.ZCONTENTTYPE != 106`; the regression test asserts exactly 21
  type-106 rows remain after repair.
- **`VACUUM`.** It rewrites every page and changes `page_count`; detected by the page gate.
- **Truncation or manual page editing to match the original size.** The proven repair grew
  the file by exactly two pages; that is normal. Detected by the size/page/integrity gates.
- **Inserting old-only rows.** Old-only messages are counted and reported, never inserted.
- **Changing `journal_mode`** or leaving a WAL for the device to replay.

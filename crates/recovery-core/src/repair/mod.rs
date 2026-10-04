//! Transactional SQLite repair of a working copy, followed by fail-closed validation.
//!
//! Invariants (see `docs/repair-invariants.md`):
//! - The plan's input hashes and predicate are re-checked before any write.
//! - Each candidate is updated by one statement that repeats the full rule predicate.
//! - The transaction commits only when the update count equals the predicted count.
//! - No `VACUUM`, no truncation, no page rewriting, no `journal_mode` change.
//! - Every post-repair gate must pass before the repaired bytes may be encrypted.

pub mod apply;
pub mod ops;
pub mod validate;

pub use apply::{repair_working_copy, RepairResult};
pub use validate::{post_repair, RepairValidation};

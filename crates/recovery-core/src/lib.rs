//! Deterministic LINE backup recovery engine.
//!
//! Layering (see `openspec/changes/build-line-backup-recovery-macos-app/design.md`):
//!
//! ```text
//! backup   -> generic encrypted Finder backup intake (read-only)
//! analysis -> versioned LINE adapters producing an immutable RepairPlan
//! repair   -> transactional SQLite repair of a working copy
//! patch    -> clone, payload encryption, replacement, re-read verification
//! session  -> workspace, manifest, stage commits, cleanup
//! report   -> privacy-preserving Markdown and JSON evidence
//! ```
//!
//! Invariants enforced by construction:
//! - Source backups are only ever opened read-only.
//! - Secrets live in zeroizing containers and never implement a revealing `Debug`.
//! - A stage is committed only after its outputs are fsynced, hashed and registered.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod error;
pub mod hash;
pub mod progress;
pub mod secret;

pub mod analysis;
pub mod backup;
pub mod patch;
pub mod repair;
pub mod report;
pub mod session;

#[cfg(feature = "fixtures")]
pub mod fixtures;

pub use error::{ErrorCode, RecoveryError, Result};

/// Semantic version of the core library.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

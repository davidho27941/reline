//! Verified backup patching: clone, payload replacement, independent re-read, export.
//!
//! Mutation boundary: nothing here writes outside the destination clone and the session
//! workspace. The source backups are hashed before and after and must be unchanged.

pub mod clone;
pub mod ops;

pub use clone::{clone_tree, hash_dir, CloneReport, DirManifest};

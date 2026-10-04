//! Recovery session: workspace, versioned manifest, atomic stage commits, cleanup, driver.
//!
//! Directory lifecycle (documented in `docs/session-lifecycle.md`):
//!
//! ```text
//! <workspace>/                 0700, created by the host from a user-selected folder
//!   session.json               manifest; replaced atomically (tmp + fsync + rename + dir fsync)
//!   staging/<stage>/           uncommitted outputs of a running stage
//!   committed/<stage>/         outputs registered in the manifest with size and SHA-256
//!   plaintext/                 decrypted indexes and databases; always removable
//!   export/                    verified artifacts awaiting user export (never plaintext)
//! ```
//!
//! A stage is *committed* only after every output is fsynced, hashed, moved into
//! `committed/<stage>/` and the manifest records it. Anything else found on disk is *partial*
//! and is never reused as evidence.

pub mod driver;
pub mod manifest;
pub mod state;
pub mod workspace;

pub use manifest::{SessionManifest, StageRecord, StageState};
pub use workspace::{OutputRecord, Workspace};

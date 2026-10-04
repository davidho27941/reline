//! Generic encrypted Finder backup intake. Read-only with respect to the source directory.
//!
//! See `docs/backup-format.md` for every structure read here.

pub mod discovery;
pub mod keybag;
pub mod layout;
pub mod manifest_db;
pub mod ops;
pub mod payload;

pub use layout::BackupInfo;
pub use manifest_db::{FileRecord, ManifestDb};

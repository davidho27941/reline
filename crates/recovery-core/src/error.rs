//! Structured, secret-free errors.
//!
//! Every error carries a stable [`ErrorCode`] that crosses the FFI boundary and lands in
//! reports. Messages are written for users and never embed passwords, keys, or chat text.

use std::path::PathBuf;

/// Stable machine-readable error categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Caller passed an invalid argument or handle.
    InvalidArgument,
    /// Filesystem operation failed; `path` names the blocked file.
    Io,
    /// macOS refused access (TCC or permissions).
    AccessDenied,
    /// Directory is not a coherent Finder backup.
    InvalidBackupStructure,
    /// Backup exists but is not finished / not encrypted / not supported version.
    UnsupportedBackup,
    /// Password rejected by keybag integrity check.
    AuthenticationFailed,
    /// Manifest, keybag, plist or MBFile could not be decoded.
    MalformedMetadata,
    /// LINE payload could not be located or is ambiguous.
    PayloadNotFound,
    /// More than one LINE account; user must choose.
    AmbiguousAccount,
    /// Sibling WAL/journal would be replayed over a repaired database.
    PendingJournal,
    /// SQLite integrity check or schema fingerprint failed.
    DatabaseUnsupported,
    /// Analysis found inputs it can diagnose but not safely repair.
    AnalysisUnsupported,
    /// A RepairPlan no longer matches its inputs.
    PlanInvalidated,
    /// Transactional repair did not match the plan; rolled back.
    RepairMismatch,
    /// A post-repair or post-patch verification gate failed.
    VerificationFailed,
    /// Protection class, digest or metadata outside the supported policy.
    UnsupportedMetadata,
    /// Cryptographic round trip or key operation failed.
    CryptoFailure,
    /// Destination lacks space or clone/copy could not be verified.
    CloneFailed,
    /// Export destination already exists and overwrite was not confirmed.
    ExportConflict,
    /// Operation cancelled cooperatively.
    Cancelled,
    /// Session workspace state is inconsistent or partial.
    SessionState,
    /// Catch-all for internal invariants; indicates a bug.
    Internal,
}

impl ErrorCode {
    /// Stable string used in reports and over FFI.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::Io => "io",
            ErrorCode::AccessDenied => "access_denied",
            ErrorCode::InvalidBackupStructure => "invalid_backup_structure",
            ErrorCode::UnsupportedBackup => "unsupported_backup",
            ErrorCode::AuthenticationFailed => "authentication_failed",
            ErrorCode::MalformedMetadata => "malformed_metadata",
            ErrorCode::PayloadNotFound => "payload_not_found",
            ErrorCode::AmbiguousAccount => "ambiguous_account",
            ErrorCode::PendingJournal => "pending_journal",
            ErrorCode::DatabaseUnsupported => "database_unsupported",
            ErrorCode::AnalysisUnsupported => "analysis_unsupported",
            ErrorCode::PlanInvalidated => "plan_invalidated",
            ErrorCode::RepairMismatch => "repair_mismatch",
            ErrorCode::VerificationFailed => "verification_failed",
            ErrorCode::UnsupportedMetadata => "unsupported_metadata",
            ErrorCode::CryptoFailure => "crypto_failure",
            ErrorCode::CloneFailed => "clone_failed",
            ErrorCode::ExportConflict => "export_conflict",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::SessionState => "session_state",
            ErrorCode::Internal => "internal",
        }
    }
}

/// The library error type. `Display` output is safe to show to users and to persist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[error("{code:?}: {message}")]
pub struct RecoveryError {
    pub code: ErrorCode,
    pub message: String,
    /// Path involved, when it helps the user remedy the problem. Never a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Optional remedy text shown by the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl RecoveryError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            path: None,
            remedy: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }

    pub fn io(err: std::io::Error, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let code = match err.kind() {
            std::io::ErrorKind::PermissionDenied => ErrorCode::AccessDenied,
            _ => ErrorCode::Io,
        };
        let mut e = Self::new(code, format!("{} ({})", err, err.kind())).with_path(path);
        if code == ErrorCode::AccessDenied {
            e = e.with_remedy(
                "macOS blocked access to this path. Copy the backup into a folder you own \
                 (for example Documents) and select the copy. Do not grant administrator \
                 rights or Full Disk Access.",
            );
        }
        e
    }

    pub fn cancelled() -> Self {
        Self::new(ErrorCode::Cancelled, "operation cancelled")
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    pub fn is_cancelled(&self) -> bool {
        self.code == ErrorCode::Cancelled
    }
}

impl From<rusqlite::Error> for RecoveryError {
    fn from(err: rusqlite::Error) -> Self {
        // rusqlite messages never include row contents for the statements this crate runs.
        Self::new(ErrorCode::DatabaseUnsupported, format!("sqlite: {err}"))
    }
}

impl From<plist::Error> for RecoveryError {
    fn from(err: plist::Error) -> Self {
        Self::new(ErrorCode::MalformedMetadata, format!("plist: {err}"))
    }
}

impl From<serde_json::Error> for RecoveryError {
    fn from(err: serde_json::Error) -> Self {
        Self::new(ErrorCode::MalformedMetadata, format!("json: {err}"))
    }
}

pub type Result<T> = std::result::Result<T, RecoveryError>;

/// Convenience for `Err(RecoveryError::new(code, msg))`.
pub fn fail<T>(code: ErrorCode, message: impl Into<String>) -> Result<T> {
    Err(RecoveryError::new(code, message))
}

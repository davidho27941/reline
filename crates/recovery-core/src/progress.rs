//! Cooperative progress reporting and cancellation.
//!
//! The core never spawns threads of its own; the host drives an operation on a worker thread
//! and may flip the [`CancelToken`] from any thread. Long loops call
//! [`ProgressSink::check_cancelled`] at every chunk boundary and unwind with
//! [`crate::ErrorCode::Cancelled`]. Callers clean up partial outputs on that error path.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::{RecoveryError, Result};

/// The six user-visible stages plus internal sub-stages that roll up into them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Intake,
    Analysis,
    Review,
    Patching,
    Verification,
    Export,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Intake => "intake",
            Stage::Analysis => "analysis",
            Stage::Review => "review",
            Stage::Patching => "patching",
            Stage::Verification => "verification",
            Stage::Export => "export",
        }
    }

    pub const ALL: [Stage; 6] = [
        Stage::Intake,
        Stage::Analysis,
        Stage::Review,
        Stage::Patching,
        Stage::Verification,
        Stage::Export,
    ];
}

/// Shared cancellation flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// A progress event. `total == 0` means unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ProgressEvent {
    pub stage: Stage,
    pub done: u64,
    pub total: u64,
}

/// Receives progress and exposes cancellation. Implemented by the FFI layer and the CLI.
pub trait ProgressSink: Send + Sync {
    fn report(&self, stage: Stage, done: u64, total: u64);
    fn is_cancelled(&self) -> bool;

    fn check_cancelled(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(RecoveryError::cancelled())
        } else {
            Ok(())
        }
    }
}

/// Sink that reports nothing and never cancels.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn report(&self, _stage: Stage, _done: u64, _total: u64) {}
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Sink backed by a [`CancelToken`] and a callback.
pub struct CallbackSink<F: Fn(ProgressEvent) + Send + Sync> {
    token: CancelToken,
    callback: F,
}

impl<F: Fn(ProgressEvent) + Send + Sync> CallbackSink<F> {
    pub fn new(token: CancelToken, callback: F) -> Self {
        Self { token, callback }
    }

    pub fn token(&self) -> &CancelToken {
        &self.token
    }
}

impl<F: Fn(ProgressEvent) + Send + Sync> std::fmt::Debug for CallbackSink<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackSink")
            .field("cancelled", &self.token.is_cancelled())
            .finish()
    }
}

impl<F: Fn(ProgressEvent) + Send + Sync> ProgressSink for CallbackSink<F> {
    fn report(&self, stage: Stage, done: u64, total: u64) {
        (self.callback)(ProgressEvent { stage, done, total });
    }
    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

/// Test helper: cancels after `n` progress reports.
#[derive(Debug)]
pub struct CancelAfter {
    remaining: std::sync::atomic::AtomicI64,
    token: CancelToken,
}

impl CancelAfter {
    pub fn new(n: i64) -> Self {
        Self {
            remaining: std::sync::atomic::AtomicI64::new(n),
            token: CancelToken::new(),
        }
    }
}

impl ProgressSink for CancelAfter {
    fn report(&self, _stage: Stage, _done: u64, _total: u64) {
        if self.remaining.fetch_sub(1, Ordering::SeqCst) <= 1 {
            self.token.cancel();
        }
    }
    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

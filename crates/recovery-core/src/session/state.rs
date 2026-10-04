//! In-memory, never-persisted session state: unlocked keybags and the secure RepairPlan.

use std::collections::HashMap;

use crate::backup::keybag::UnlockedKeybag;
use crate::session::driver::BackupRole;

/// Secrets and secure identifiers for the lifetime of a `Driver`. Dropped (and zeroized) when
/// the session is freed or `Cleanup` runs.
#[derive(Default)]
pub struct SessionState {
    pub keybags: HashMap<BackupRole, UnlockedKeybag>,
    /// The in-memory plan retains real message identifiers; the persisted plan does not.
    pub secure_plan: Option<crate::analysis::plan::SecurePlan>,
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("unlocked_backups", &self.keybags.keys().collect::<Vec<_>>())
            .field("has_secure_plan", &self.secure_plan.is_some())
            .finish()
    }
}

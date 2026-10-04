//! LINE payload discovery, multi-account ambiguity, sibling WAL/journal detection.

use serde::{Deserialize, Serialize};

use crate::backup::manifest_db::{FileEntry, FileRecord, ManifestDb};
use crate::Result;

/// Domains searched, in priority order. See `docs/backup-format.md` §6.
pub const LINE_DOMAINS: [&str; 2] = [
    "AppDomainGroup-group.com.linecorp.line",
    "AppDomain-jp.naver.line",
];
pub const LINE_DB_NAME: &str = "Line.sqlite";
const PRIVATE_STORE_PREFIX: &str = "Library/Application Support/PrivateStore/";
const MESSAGES_SUFFIX: &str = "/Messages/Line.sqlite";

/// A file in the same directory as `Line.sqlite`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingEntry {
    pub name: String,
    pub record: FileRecord,
}

/// One discovered LINE account store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineStore {
    pub domain: String,
    pub relative_path: String,
    /// The `P_u…` account directory name.
    pub account_dir: String,
    pub record: FileRecord,
    pub siblings: Vec<SiblingEntry>,
}

impl LineStore {
    /// `-wal` or `-journal` siblings that could be replayed over the repaired database.
    pub fn pending_journals(&self) -> Vec<&SiblingEntry> {
        self.siblings
            .iter()
            .filter(|s| {
                (s.name == "Line.sqlite-wal" || s.name == "Line.sqlite-journal")
                    && s.record.size.unwrap_or(0) > 0
            })
            .collect()
    }
}

/// Parse an account dir from a relative path matching the LINE store pattern.
pub fn account_dir_of(relative_path: &str) -> Option<&str> {
    let rest = relative_path.strip_prefix(PRIVATE_STORE_PREFIX)?;
    let acct = rest.strip_suffix(MESSAGES_SUFFIX)?;
    if acct.is_empty() || acct.contains('/') || !acct.starts_with("P_u") {
        return None;
    }
    Some(acct)
}

/// Enumerate LINE stores and their siblings. Deterministic order (domain priority, then path).
pub fn discover(manifest: &ManifestDb) -> Result<Vec<LineStore>> {
    let entries: Vec<FileEntry> = manifest.entries_in_domains(&LINE_DOMAINS)?;
    let mut stores = Vec::new();
    for e in &entries {
        if e.record.flags & crate::backup::manifest_db::FLAG_FILE == 0 {
            continue;
        }
        let Some(acct) = account_dir_of(&e.record.relative_path) else {
            continue;
        };
        let dir_prefix = format!("{PRIVATE_STORE_PREFIX}{acct}/Messages/");
        let siblings = entries
            .iter()
            .filter(|s| {
                s.record.domain == e.record.domain
                    && s.record.relative_path != e.record.relative_path
            })
            .filter_map(|s| {
                let name = s.record.relative_path.strip_prefix(&dir_prefix)?;
                if name.contains('/') {
                    return None;
                }
                Some(SiblingEntry {
                    name: name.to_owned(),
                    record: s.record.clone(),
                })
            })
            .collect();
        stores.push(LineStore {
            domain: e.record.domain.clone(),
            relative_path: e.record.relative_path.clone(),
            account_dir: acct.to_owned(),
            record: e.record.clone(),
            siblings,
        });
    }
    Ok(stores)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_dir_parsing() {
        assert_eq!(
            account_dir_of("Library/Application Support/PrivateStore/P_ud1a36fb6aa96feb1303f7c2f0631b837/Messages/Line.sqlite"),
            Some("P_ud1a36fb6aa96feb1303f7c2f0631b837")
        );
        assert_eq!(
            account_dir_of(
                "Library/Application Support/PrivateStore/P_u1/Messages/Line.sqlite-wal"
            ),
            None
        );
        assert_eq!(
            account_dir_of("Library/Application Support/PrivateStore/X/Messages/Line.sqlite"),
            None
        );
        assert_eq!(account_dir_of("Library/Line.sqlite"), None);
    }
}

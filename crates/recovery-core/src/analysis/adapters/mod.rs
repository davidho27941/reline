//! Registered adapters, tried in order. Adding an adapter means adding a module here and a
//! fixture set under `fixtures/`; nothing in `backup`, `repair`, or `patch` changes.

pub mod line_ios_coredata_v1;

use crate::analysis::adapter::LineAdapter;

pub fn registry() -> Vec<Box<dyn LineAdapter>> {
    vec![Box::new(line_ios_coredata_v1::LineIosCoreDataV1)]
}

/// Pick the first adapter whose schema requirements both databases satisfy.
pub fn select<'a>(
    adapters: &'a [Box<dyn LineAdapter>],
    old: &crate::analysis::schema::SchemaFingerprint,
    current: &crate::analysis::schema::SchemaFingerprint,
) -> std::result::Result<&'a dyn LineAdapter, Vec<(String, Vec<String>)>> {
    let mut gaps = Vec::new();
    for a in adapters {
        let g = a.schema_gaps(old, current);
        if g.is_empty() {
            return Ok(a.as_ref());
        }
        gaps.push((a.id().to_owned(), g));
    }
    Err(gaps)
}

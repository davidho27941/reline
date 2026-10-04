//! LINE recovery analysis: preflight, schema fingerprints, stable matching, versioned rules,
//! and the immutable RepairPlan.
//!
//! Generic code lives in `schema`, `plan`, and `ops`. Everything LINE-specific is an adapter in
//! `adapters/`; see `docs/adapter-contract.md`.

pub mod adapter;
pub mod adapters;
pub mod ops;
pub mod plan;
pub mod schema;

pub use adapter::{AnalysisOutcome, LineAdapter};
pub use plan::{RepairPlan, SecurePlan};

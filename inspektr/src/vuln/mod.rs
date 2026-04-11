//! Vulnerability matching and report generation.
//!
//! - [`matcher`] — matches packages against the vulnerability database using
//!   semver and ecosystem version ranges
//! - [`report`] — builds structured [`ScanReport`](report::ScanReport) documents
//!   with severity counts, and renders them as tables or JSON

pub mod matcher;
pub mod report;

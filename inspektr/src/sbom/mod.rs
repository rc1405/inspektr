//! SBOM encoding and decoding.
//!
//! Provides the [`SbomFormat`] trait and two implementations:
//!
//! - [`cyclonedx::CycloneDxFormat`] — CycloneDX 1.5 JSON
//! - [`spdx::SpdxFormat`] — SPDX 2.3 JSON
//!
//! Use [`pipeline::generate_sbom_bytes()`](crate::pipeline::generate_sbom_bytes)
//! for a high-level interface, or call [`SbomFormat::encode()`] / [`SbomFormat::decode()`]
//! directly for lower-level control.

pub mod cyclonedx;
pub mod spdx;

use crate::error::SbomFormatError;
use crate::models::Sbom;

/// Trait for encoding and decoding SBOMs to/from a specific format.
pub trait SbomFormat {
    /// The name of this format (e.g., `"cyclonedx"`, `"spdx"`).
    fn format_name(&self) -> &str;

    /// Encode an [`Sbom`] into bytes in this format.
    fn encode(&self, sbom: &Sbom) -> Result<Vec<u8>, SbomFormatError>;

    /// Decode bytes in this format back into an [`Sbom`].
    fn decode(&self, data: &[u8]) -> Result<Sbom, SbomFormatError>;
}

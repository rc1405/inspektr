pub mod cyclonedx;

use crate::error::SbomFormatError;
use crate::models::Sbom;

pub trait SbomFormat {
    fn format_name(&self) -> &str;
    fn encode(&self, sbom: &Sbom) -> Result<Vec<u8>, SbomFormatError>;
    fn decode(&self, data: &[u8]) -> Result<Sbom, SbomFormatError>;
}

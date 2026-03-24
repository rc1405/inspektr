//! OCI container image source.

use super::Source;
use crate::error::SourceError;
use crate::models::{FileEntry, SourceMetadata};
use crate::oci::pull::pull_and_extract_image;

/// A source that pulls and extracts files from an OCI container image.
pub struct OciImageSource {
    reference: String,
}

impl OciImageSource {
    /// Create a new OCI image source for the given image reference.
    pub fn new(reference: String) -> Self {
        Self { reference }
    }
}

impl Source for OciImageSource {
    fn files(&self) -> Result<Vec<FileEntry>, SourceError> {
        pull_and_extract_image(&self.reference).map_err(|e| SourceError::ReadFailed {
            path: self.reference.clone(),
            reason: e.to_string(),
        })
    }

    fn source_metadata(&self) -> SourceMetadata {
        SourceMetadata {
            source_type: "oci".to_string(),
            target: self.reference.clone(),
        }
    }
}

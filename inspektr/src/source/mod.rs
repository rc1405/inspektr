pub mod detect;
pub mod filesystem;
pub mod oci;

use crate::error::SourceError;
use crate::models::{FileEntry, SourceMetadata};

/// A source of files to analyze for packages.
pub trait Source {
    /// Returns all files from this source.
    fn files(&self) -> Result<Vec<FileEntry>, SourceError>;

    /// Returns metadata about this source.
    fn source_metadata(&self) -> SourceMetadata;
}

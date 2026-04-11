//! File discovery from filesystem paths and OCI container images.
//!
//! A [`Source`] is the first stage of the pipeline — it produces
//! [`FileEntry`] values that catalogers then inspect.
//!
//! Built-in implementations:
//!
//! - [`filesystem::FilesystemSource`] — reads files from a local directory or single file
//! - [`oci::OciImageSource`] — pulls and extracts files from an OCI container image
//!
//! Target detection is handled by [`detect::detect_target_type()`], which classifies
//! a string as an OCI image reference, a binary file, or a filesystem path.

pub mod detect;
pub mod filesystem;
pub mod oci;

use crate::error::SourceError;
use crate::models::{FileEntry, SourceMetadata};

/// A source of files to analyze for packages.
///
/// Implement this trait to add support for new target types beyond
/// filesystems and OCI images.
pub trait Source {
    /// Discover and return all files from this source.
    ///
    /// The returned `FileEntry` values include both the file path and contents.
    /// Catalogers use these to detect lockfiles, manifests, and binaries.
    fn files(&self) -> Result<Vec<FileEntry>, SourceError>;

    /// Return metadata describing this source (type and target string).
    fn source_metadata(&self) -> SourceMetadata;
}

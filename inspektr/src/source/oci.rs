//! OCI container image source.
//!
//! Pulls an OCI container image from a registry, extracts all layers, and
//! returns the files as [`FileEntry`] values for
//! catalogers to inspect. Whiteout files and directories are skipped.

use oci_client::secrets::RegistryAuth;

use super::Source;
use crate::error::SourceError;
use crate::models::{FileEntry, SourceMetadata};
use crate::oci::pull::pull_and_extract_image;

/// A [`Source`] that pulls and extracts files from an OCI container image.
///
/// Supports any registry that implements the OCI Distribution Spec, including
/// Docker Hub, GitHub Container Registry, and private registries.
///
/// # Authentication
///
/// Pass [`RegistryAuth::Anonymous`] for public images, or
/// [`RegistryAuth::Basic`] with username/password for private registries.
pub struct OciImageSource {
    reference: String,
    auth: RegistryAuth,
}

impl OciImageSource {
    /// Create a new OCI image source for the given image reference.
    ///
    /// The reference should be a full OCI image reference like
    /// `docker.io/library/alpine:3.19` or `ghcr.io/org/repo:tag`.
    pub fn new(reference: String, auth: RegistryAuth) -> Self {
        Self { reference, auth }
    }
}

impl Source for OciImageSource {
    fn files(&self) -> Result<Vec<FileEntry>, SourceError> {
        pull_and_extract_image(&self.reference, &self.auth).map_err(|e| SourceError::ReadFailed {
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

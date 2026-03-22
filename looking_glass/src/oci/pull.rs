//! OCI artifact and image pull functionality.

use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;
use oci_distribution::{
    client::{ClientConfig, ClientProtocol},
    manifest::OciManifest,
    Client, Reference,
};

use crate::error::OciError;
use crate::models::{FileContents, FileEntry};
use crate::source::filesystem::is_binary_content;

use super::resolve_auth;

/// Pull an OCI artifact (e.g. a database file) and write it to `output_path`.
///
/// This is used for pulling the vulnerability DB artifact stored as a single-layer
/// OCI artifact.
pub fn pull_artifact(reference_str: &str, output_path: &Path) -> Result<(), OciError> {
    let reference: Reference = reference_str.parse().map_err(|e: oci_distribution::ParseError| {
        OciError::InvalidReference {
            reference: format!("{}: {}", reference_str, e),
        }
    })?;

    let auth = resolve_auth(reference.registry());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| OciError::PullFailed {
            reference: reference_str.to_string(),
            reason: format!("failed to create async runtime: {}", e),
        })?;

    rt.block_on(async {
        let config = ClientConfig {
            protocol: ClientProtocol::Https,
            ..Default::default()
        };
        let client = Client::new(config);

        // Pull the manifest (returns OciManifest enum)
        let (manifest, _digest) = client
            .pull_manifest(&reference, &auth)
            .await
            .map_err(|e| OciError::PullFailed {
                reference: reference_str.to_string(),
                reason: e.to_string(),
            })?;

        // Extract the image manifest layers
        let layers = match &manifest {
            OciManifest::Image(img) => img.layers.clone(),
            OciManifest::ImageIndex(_) => {
                return Err(OciError::PullFailed {
                    reference: reference_str.to_string(),
                    reason: "image index manifests are not supported for artifact pull".to_string(),
                })
            }
        };

        let first_layer = layers.first().ok_or_else(|| OciError::PullFailed {
            reference: reference_str.to_string(),
            reason: "manifest has no layers".to_string(),
        })?;

        // Pull the blob data
        let mut blob_data: Vec<u8> = Vec::new();
        client
            .pull_blob(&reference, first_layer, &mut blob_data)
            .await
            .map_err(|e| OciError::PullFailed {
                reference: reference_str.to_string(),
                reason: e.to_string(),
            })?;

        // Write to output path
        std::fs::write(output_path, &blob_data).map_err(|e| OciError::PullFailed {
            reference: reference_str.to_string(),
            reason: format!("failed to write artifact to {}: {}", output_path.display(), e),
        })?;

        Ok(())
    })
}

/// Pull and extract an OCI container image, returning all files as `FileEntry` items.
///
/// This is used for analyzing container images as a source for SBOM generation.
/// Layers are decompressed and extracted from gzip+tar format.
/// Whiteout files (`.wh.`) and directories are skipped.
pub fn pull_and_extract_image(reference_str: &str) -> Result<Vec<FileEntry>, OciError> {
    let reference: Reference = reference_str.parse().map_err(|e: oci_distribution::ParseError| {
        OciError::InvalidReference {
            reference: format!("{}: {}", reference_str, e),
        }
    })?;

    let auth = resolve_auth(reference.registry());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| OciError::PullFailed {
            reference: reference_str.to_string(),
            reason: format!("failed to create async runtime: {}", e),
        })?;

    rt.block_on(async {
        let config = ClientConfig {
            protocol: ClientProtocol::Https,
            ..Default::default()
        };
        let client = Client::new(config);

        let accepted_media_types = vec![
            oci_distribution::manifest::IMAGE_MANIFEST_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_MANIFEST_LIST_MEDIA_TYPE,
            oci_distribution::manifest::OCI_IMAGE_MEDIA_TYPE,
            oci_distribution::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_LAYER_MEDIA_TYPE,
        ];

        let image_data = client
            .pull(&reference, &auth, accepted_media_types)
            .await
            .map_err(|e| OciError::PullFailed {
                reference: reference_str.to_string(),
                reason: e.to_string(),
            })?;

        let mut entries: Vec<FileEntry> = Vec::new();

        for layer in &image_data.layers {
            extract_layer(&layer.data, &mut entries).map_err(|e| OciError::PullFailed {
                reference: reference_str.to_string(),
                reason: format!("failed to extract layer: {}", e),
            })?;
        }

        Ok(entries)
    })
}

/// Extract files from a gzip-compressed tar layer.
fn extract_layer(data: &[u8], entries: &mut Vec<FileEntry>) -> Result<(), std::io::Error> {
    // Try gzip decompression first; fall back to raw tar if it fails
    let decompressed: Vec<u8> = {
        let mut decoder = GzDecoder::new(data);
        let mut buf = Vec::new();
        match decoder.read_to_end(&mut buf) {
            Ok(_) => buf,
            Err(_) => {
                // Not gzipped — try as raw tar
                data.to_vec()
            }
        }
    };

    let mut archive = tar::Archive::new(decompressed.as_slice());

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();

        // Skip directories
        if entry.header().entry_type().is_dir() {
            continue;
        }

        // Skip whiteout files
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if file_name.starts_with(".wh.") {
            continue;
        }

        // Read file content
        let mut file_bytes = Vec::new();
        entry.read_to_end(&mut file_bytes)?;

        let contents = if is_binary_content(&file_bytes) {
            FileContents::Binary(file_bytes)
        } else {
            FileContents::Text(String::from_utf8_lossy(&file_bytes).into_owned())
        };

        entries.push(FileEntry { path, contents });
    }

    Ok(())
}

//! OCI artifact push functionality.
//!
//! Pushes files (e.g., the vulnerability database) as gzip-compressed OCI
//! artifacts to a registry.
//!
//! Requires the `db-admin` feature.

use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use oci_client::Reference;
use oci_client::client::{ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::secrets::RegistryAuth;

use crate::error::OciError;

/// Push a file as a gzip-compressed OCI artifact to a registry.
///
/// The file is gzip-compressed before upload to reduce transfer size and
/// registry storage. The media type is appended with `+gzip` to indicate
/// compression. The corresponding `pull_artifact` automatically detects
/// and decompresses gzipped blobs.
pub fn push_artifact(
    reference_str: &str,
    file_path: &Path,
    media_type: &str,
    auth: &RegistryAuth,
) -> Result<(), OciError> {
    let reference: Reference =
        reference_str
            .parse()
            .map_err(|e: oci_client::ParseError| OciError::InvalidReference {
                reference: format!("{}: {}", reference_str, e),
            })?;

    let raw_data = std::fs::read(file_path).map_err(|e| OciError::PushFailed {
        reference: reference_str.to_string(),
        reason: format!("failed to read file {}: {}", file_path.display(), e),
    })?;

    // Gzip compress the data
    let compressed = {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&raw_data)
            .map_err(|e| OciError::PushFailed {
                reference: reference_str.to_string(),
                reason: format!("failed to compress data: {}", e),
            })?;
        encoder.finish().map_err(|e| OciError::PushFailed {
            reference: reference_str.to_string(),
            reason: format!("failed to finish compression: {}", e),
        })?
    };

    let raw_size = raw_data.len();
    let compressed_size = compressed.len();
    let ratio = if raw_size > 0 {
        (compressed_size as f64 / raw_size as f64 * 100.0) as u32
    } else {
        100
    };
    eprintln!(
        "Compressed {} -> {} ({}% of original)",
        format_size(raw_size),
        format_size(compressed_size),
        ratio,
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| OciError::PushFailed {
            reference: reference_str.to_string(),
            reason: format!("failed to create async runtime: {}", e),
        })?;

    rt.block_on(async {
        let config = ClientConfig {
            protocol: ClientProtocol::Https,
            ..Default::default()
        };
        let client = oci_client::Client::new(config);

        // Use +gzip suffix on media type to indicate compression
        let gzip_media_type = format!("{}+gzip", media_type);
        let layer = ImageLayer::new(compressed, gzip_media_type, None);
        let config_data = Config::oci_v1(b"{}".to_vec(), None);

        client
            .push(&reference, &[layer], config_data, auth, None)
            .await
            .map_err(|e| OciError::PushFailed {
                reference: reference_str.to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    })
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

use std::path::Path;

use oci_client::Reference;
use oci_client::client::{ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_client::secrets::RegistryAuth;

use crate::error::OciError;

/// Push a file as an OCI artifact to a registry.
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

    let data = std::fs::read(file_path).map_err(|e| OciError::PushFailed {
        reference: reference_str.to_string(),
        reason: format!("failed to read file {}: {}", file_path.display(), e),
    })?;

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

        let layer = ImageLayer::new(data, media_type.to_string(), None);
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

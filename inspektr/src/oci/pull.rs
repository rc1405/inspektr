//! OCI artifact and image pull functionality.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use bollard::Docker;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use oci_client::{
    Client, Reference,
    client::{ClientConfig, ClientProtocol},
    manifest::OciManifest,
    secrets::RegistryAuth,
};

use crate::error::OciError;
use crate::models::{FileContents, FileEntry};
use crate::source::filesystem::is_binary_content;

/// Pull an OCI artifact and return its raw bytes.
///
/// Downloads a single-layer OCI artifact from a registry. If the layer is
/// gzip-compressed, it is automatically decompressed before returning.
///
/// This is the building block for both [`pull_artifact()`] (write to file)
/// and [`crate::db::download_to_memory()`] (load directly into a `VulnStore`).
pub fn pull_artifact_bytes(reference_str: &str, auth: &RegistryAuth) -> Result<Vec<u8>, OciError> {
    let reference: Reference =
        reference_str
            .parse()
            .map_err(|e: oci_client::ParseError| OciError::InvalidReference {
                reference: format!("{}: {}", reference_str, e),
            })?;

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
        let (manifest, _digest) =
            client
                .pull_manifest(&reference, auth)
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
                });
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

        // Decompress if gzipped (detected by gzip magic bytes 1f 8b)
        if blob_data.len() >= 2 && blob_data[0] == 0x1f && blob_data[1] == 0x8b {
            let mut decoder = GzDecoder::new(&blob_data[..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| OciError::PullFailed {
                    reference: reference_str.to_string(),
                    reason: format!("failed to decompress artifact: {}", e),
                })?;
            Ok(decompressed)
        } else {
            Ok(blob_data)
        }
    })
}

/// Pull an OCI artifact and write it to `output_path`.
///
/// This is used for pulling the vulnerability DB artifact stored as a single-layer
/// OCI artifact. See also [`pull_artifact_bytes()`] to get the raw bytes without
/// writing to disk.
pub fn pull_artifact(
    reference_str: &str,
    output_path: &Path,
    auth: &RegistryAuth,
) -> Result<(), OciError> {
    let data = pull_artifact_bytes(reference_str, auth)?;
    std::fs::write(output_path, &data).map_err(|e| OciError::PullFailed {
        reference: reference_str.to_string(),
        reason: format!(
            "failed to write artifact to {}: {}",
            output_path.display(),
            e
        ),
    })?;
    Ok(())
}

/// Pull and extract an OCI container image, returning all files as `FileEntry` items.
///
/// This is used for analyzing container images as a source for SBOM generation.
/// Layers are decompressed and extracted from gzip+tar format.
/// Whiteout files (`.wh.`) and directories are skipped.
///
/// First tries to load the image from the local Docker daemon (to reuse cached
/// images and avoid registry rate limits). If the daemon is unavailable or the
/// image isn't present locally, falls back to pulling directly from the registry.
pub fn pull_and_extract_image(
    reference_str: &str,
    auth: &RegistryAuth,
) -> Result<Vec<FileEntry>, OciError> {
    let reference: Reference =
        reference_str
            .parse()
            .map_err(|e: oci_client::ParseError| OciError::InvalidReference {
                reference: format!("{}: {}", reference_str, e),
            })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| OciError::PullFailed {
            reference: reference_str.to_string(),
            reason: format!("failed to create async runtime: {}", e),
        })?;

    rt.block_on(async {
        // Try local Docker daemon first. On any error, fall back to registry pull.
        if let Some(entries) = try_load_from_docker_daemon(reference_str).await {
            return Ok(entries);
        }

        let config = ClientConfig {
            protocol: ClientProtocol::Https,
            ..Default::default()
        };
        let client = Client::new(config);

        let accepted_media_types = vec![
            // Manifest types
            oci_client::manifest::IMAGE_MANIFEST_MEDIA_TYPE,
            oci_client::manifest::IMAGE_MANIFEST_LIST_MEDIA_TYPE,
            oci_client::manifest::OCI_IMAGE_MEDIA_TYPE,
            oci_client::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
            // OCI layer types
            oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
            // Docker layer types (used by Docker Hub images)
            oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
            oci_client::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
        ];

        let image_data = client
            .pull(&reference, auth, accepted_media_types)
            .await
            .map_err(|e| OciError::PullFailed {
                reference: reference_str.to_string(),
                reason: e.to_string(),
            })?;

        let mut entries: Vec<FileEntry> = Vec::new();
        let mut symlinks: Vec<(PathBuf, PathBuf)> = Vec::new();

        for layer in &image_data.layers {
            extract_layer(&layer.data, &mut entries, &mut symlinks).map_err(|e| {
                OciError::PullFailed {
                    reference: reference_str.to_string(),
                    reason: format!("failed to extract layer: {}", e),
                }
            })?;
        }

        resolve_symlinks(&mut entries, &symlinks);
        Ok(entries)
    })
}

/// Try to load an image from the local Docker daemon via `export_image`.
///
/// Returns `Some(entries)` if the image was found locally and successfully
/// extracted. Returns `None` on any failure (daemon unavailable, image not
/// present, parse error, etc.) so the caller can fall back to a registry pull.
async fn try_load_from_docker_daemon(reference_str: &str) -> Option<Vec<FileEntry>> {
    // Connect to the local Docker daemon. `connect_with_defaults` picks the
    // platform-appropriate transport (unix socket on Linux, named pipe on Windows,
    // or `DOCKER_HOST` if set).
    let docker = Docker::connect_with_defaults().ok()?;

    // Verify the daemon is actually reachable before asking it to export.
    // If ping fails we short-circuit and let the caller fall back to registry pull.
    let ping_result: Result<_, bollard::errors::Error> = docker.ping().await;
    ping_result.ok()?;

    // Collect the export stream into a single buffer. `export_image` returns the
    // same tar format as `docker save`: an outer tar containing `manifest.json`
    // plus per-layer tarballs referenced by the manifest.
    let mut stream = docker.export_image(reference_str);
    let mut tar_bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk_bytes = chunk.ok()?;
        tar_bytes.extend_from_slice(chunk_bytes.as_ref());
    }

    if tar_bytes.is_empty() {
        return None;
    }

    extract_docker_save_tar(&tar_bytes).ok()
}

/// Parse a `docker save`-format tar and extract all layer files into `FileEntry` items.
///
/// The outer tar contains a `manifest.json` listing the layer file paths in order.
/// Each layer file is itself a tarball (possibly gzipped) of the layer's filesystem
/// contents. We parse `manifest.json` first to learn the layer ordering, then walk
/// the outer tar again to extract each referenced layer in manifest order.
fn extract_docker_save_tar(tar_bytes: &[u8]) -> Result<Vec<FileEntry>, std::io::Error> {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ManifestEntry {
        #[serde(rename = "Layers")]
        layers: Vec<String>,
    }

    // First pass: find and parse manifest.json to learn layer order.
    let layer_order: Vec<String> = {
        let mut archive = tar::Archive::new(tar_bytes);
        let mut manifest_bytes: Option<Vec<u8>> = None;
        for entry_result in archive.entries()? {
            let mut entry = entry_result?;
            let path = entry.path()?.to_path_buf();
            if path == Path::new("manifest.json") {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                manifest_bytes = Some(buf);
                break;
            }
        }
        let manifest_bytes = manifest_bytes.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "docker save tar is missing manifest.json",
            )
        })?;
        let manifests: Vec<ManifestEntry> =
            serde_json::from_slice(&manifest_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse docker save manifest.json: {}", e),
                )
            })?;
        let first = manifests.into_iter().next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "docker save manifest.json has no entries",
            )
        })?;
        first.layers
    };

    let layer_set: HashSet<&str> = layer_order.iter().map(|s| s.as_str()).collect();

    // Second pass: collect the raw bytes of each referenced layer file.
    let mut layer_bytes: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut archive = tar::Archive::new(tar_bytes);
    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy().into_owned();
        if layer_set.contains(path_str.as_str()) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            layer_bytes.insert(path_str, buf);
        }
    }

    // Third pass: extract each layer in manifest order. Layer files from
    // `docker save` are typically uncompressed tar, but `extract_layer` handles
    // both gzipped and raw tar transparently.
    let mut entries: Vec<FileEntry> = Vec::new();
    let mut symlinks: Vec<(PathBuf, PathBuf)> = Vec::new();
    for layer_path in &layer_order {
        if let Some(data) = layer_bytes.get(layer_path) {
            extract_layer(data, &mut entries, &mut symlinks)?;
        }
    }

    resolve_symlinks(&mut entries, &symlinks);
    Ok(entries)
}

/// Extract files from a gzip-compressed tar layer.
///
/// Regular files are pushed to `entries` with their contents. Symlinks (and
/// hard links) are recorded in `symlinks` as `(link_path, target_path)` pairs
/// so they can be resolved against real file content after all layers have
/// been extracted — see [`resolve_symlinks`].
fn extract_layer(
    data: &[u8],
    entries: &mut Vec<FileEntry>,
    symlinks: &mut Vec<(PathBuf, PathBuf)>,
) -> Result<(), std::io::Error> {
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
        let entry_type = entry.header().entry_type();

        // Skip directories
        if entry_type.is_dir() {
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

        // Record symlinks (and hard links) for later resolution against real
        // file content. The link target is stored in the tar header, not the
        // data stream, so reading bytes would yield an empty file.
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            if let Ok(Some(target)) = entry.link_name() {
                symlinks.push((path, target.into_owned()));
            }
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

/// Resolve symlinks against the extracted file entries.
///
/// For each `(link_path, target_path)` pair collected during layer extraction,
/// locate the target's content in `entries` and push a new [`FileEntry`] with
/// the symlink's path but the target's contents. This lets catalogers that
/// look for conventional paths like `/etc/os-release` still find content when
/// the path is actually a symlink (e.g., Debian points `/etc/os-release` at
/// `/usr/lib/os-release`).
///
/// Resolution handles:
/// - Absolute link targets (`/usr/lib/os-release`)
/// - Relative link targets interpreted from the symlink's parent directory
///   (`../usr/lib/os-release`)
/// - Chained symlinks (up to 8 hops before giving up, matching the typical
///   kernel `MAXSYMLINKS` for scanning purposes)
///
/// Missing targets (the symlink points at a file we never extracted) are
/// silently skipped — catalogers that care about such files will fall back
/// on whatever other paths they check.
fn resolve_symlinks(entries: &mut Vec<FileEntry>, symlinks: &[(PathBuf, PathBuf)]) {
    if symlinks.is_empty() {
        return;
    }

    // Build a lookup of path -> index into entries so we can find target
    // content without rescanning the whole vector for each symlink. Layer
    // ordering means later layers override earlier ones; the last insert wins.
    let mut index: HashMap<PathBuf, usize> = HashMap::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        index.insert(e.path.clone(), i);
    }

    // Also index the symlinks themselves so we can chase chains. We resolve
    // lazily rather than building a full graph.
    let symlink_map: HashMap<PathBuf, PathBuf> = symlinks
        .iter()
        .map(|(l, t)| (l.clone(), t.clone()))
        .collect();

    const MAX_HOPS: usize = 8;

    for (link_path, target) in symlinks {
        // Start by normalizing the immediate target relative to the symlink.
        let mut current = normalize_symlink_target(link_path, target);
        let mut hops = 0;
        let resolved_idx: Option<usize> = loop {
            if hops >= MAX_HOPS {
                break None;
            }
            if let Some(idx) = index.get(&current) {
                break Some(*idx);
            }
            // Not a real file — maybe it's another symlink. Chase it.
            if let Some(next_target) = symlink_map.get(&current) {
                current = normalize_symlink_target(&current, next_target);
                hops += 1;
                continue;
            }
            break None;
        };

        if let Some(idx) = resolved_idx {
            let contents = entries[idx].contents.clone();
            entries.push(FileEntry {
                path: link_path.clone(),
                contents,
            });
        }
    }
}

/// Resolve a (possibly relative) symlink target against the symlink's own path.
///
/// Returns a lexically-normalized relative path suitable for lookup in the
/// extracted layer's path index. This purely manipulates path components and
/// does not touch the filesystem.
///
/// Examples (with no leading slash, matching how tar stores paths):
/// - `etc/os-release` + `../usr/lib/os-release` → `usr/lib/os-release`
/// - `etc/mtab` + `/proc/self/mounts` → `proc/self/mounts`
/// - `bin/sh` + `dash` → `bin/dash`
fn normalize_symlink_target(link_path: &Path, target: &Path) -> PathBuf {
    // Absolute targets (starting with `/`) are interpreted as rooted at the
    // image root. We strip the leading `/` so the result matches the layer's
    // stored path format (which omits leading slashes).
    let base: PathBuf = if target.is_absolute() {
        PathBuf::new()
    } else {
        link_path.parent().unwrap_or(Path::new("")).to_path_buf()
    };

    let mut components: Vec<Component> = Vec::new();
    for c in base.components().chain(target.components()) {
        match c {
            Component::Prefix(_) | Component::RootDir => {
                // Reset — treat as "from root", stripping the leading slash.
                components.clear();
            }
            Component::CurDir => { /* skip */ }
            Component::ParentDir => {
                components.pop();
            }
            Component::Normal(_) => components.push(c),
        }
    }

    components.iter().collect()
}

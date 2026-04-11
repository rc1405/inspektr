//! Target type detection for the pipeline.
//!
//! Determines whether a user-supplied target string refers to an OCI container
//! image, a compiled binary, or a filesystem path. This drives the choice of
//! [`Source`](crate::source::Source) implementation in the pipeline.

use crate::oci::ImageReference;
use std::path::Path;

/// The kind of target that a user-supplied string refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetType {
    /// An OCI container image reference (e.g., `docker.io/library/alpine:3.19`).
    OciImage,
    /// A compiled binary file (ELF, Mach-O, or PE).
    Binary,
    /// A filesystem path (directory or non-binary file).
    Filesystem,
}

/// Detect the target type from a user-supplied string.
///
/// Detection order:
/// 1. If it looks like an OCI image reference (contains a registry hostname), returns [`TargetType::OciImage`]
/// 2. If it points to an existing file with binary magic bytes, returns [`TargetType::Binary`]
/// 3. Otherwise, returns [`TargetType::Filesystem`]
pub fn detect_target_type(target: &str) -> TargetType {
    if ImageReference::looks_like_image_ref(target) {
        return TargetType::OciImage;
    }
    let path = Path::new(target);
    if path.is_file() {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes.len() >= 4 && crate::source::filesystem::is_binary_content(&bytes) {
                return TargetType::Binary;
            }
        }
    }
    TargetType::Filesystem
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_detect_oci_reference() {
        // Registry with dotted hostname
        assert_eq!(
            detect_target_type("ghcr.io/myorg/myrepo:v1.2.3"),
            TargetType::OciImage
        );
        assert_eq!(
            detect_target_type("docker.io/library/golang:1.21"),
            TargetType::OciImage
        );
        // Bare name with digest
        assert_eq!(
            detect_target_type("myrepo@sha256:abc123"),
            TargetType::OciImage
        );
    }

    #[test]
    fn test_detect_relative_paths_not_oci() {
        // Paths where the first segment exists on disk are filesystem, not OCI
        assert_eq!(detect_target_type("src/models"), TargetType::Filesystem);
    }

    #[test]
    fn test_detect_docker_hub_short_form() {
        // Docker Hub short-form: user/repo:tag
        assert_eq!(
            detect_target_type("rc1405/inspektr-db:latest"),
            TargetType::OciImage
        );
        // user/repo without tag — non-existent path treated as OCI
        assert_eq!(detect_target_type("myorg/myrepo"), TargetType::OciImage);
    }

    #[test]
    fn test_detect_filesystem() {
        // An absolute path that starts with '/' is not an image ref.
        // A non-existent path that doesn't look like an image ref → Filesystem.
        let result = detect_target_type("/some/nonexistent/directory");
        assert_eq!(result, TargetType::Filesystem);

        // An existing directory also resolves to Filesystem.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("go.mod"), "module foo\n").unwrap();
        let result = detect_target_type(dir.path().to_str().unwrap());
        assert_eq!(result, TargetType::Filesystem);
    }

    #[test]
    fn test_detect_does_not_confuse_paths_with_images() {
        // Absolute paths starting with '/' are never OCI refs.
        assert_eq!(
            detect_target_type("/usr/bin/app"),
            // The path doesn't exist so it falls through to Filesystem.
            TargetType::Filesystem
        );

        // A plain directory name without special characters is also Filesystem.
        assert_eq!(detect_target_type("my-local-dir"), TargetType::Filesystem);
    }
}

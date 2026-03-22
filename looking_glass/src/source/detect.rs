use std::path::Path;
use crate::oci::ImageReference;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetType {
    OciImage,
    Binary,
    Filesystem,
}

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
        // A string with a slash looks like an OCI image reference.
        assert_eq!(
            detect_target_type("ghcr.io/myorg/myrepo:v1.2.3"),
            TargetType::OciImage
        );
        assert_eq!(
            detect_target_type("myrepo:latest"),
            TargetType::OciImage
        );
        assert_eq!(
            detect_target_type("myorg/myrepo"),
            TargetType::OciImage
        );
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

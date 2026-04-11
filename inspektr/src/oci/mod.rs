//! OCI registry interaction for pulling images and pushing/pulling artifacts.
//!
//! This module provides:
//!
//! - [`pull::pull_artifact()`] — pull a single-layer OCI artifact (e.g., the
//!   vulnerability database)
//! - [`pull::pull_and_extract_image()`] — pull and extract all files from a
//!   container image
//! - `push` — push artifacts to a registry (requires `db-admin` feature)
//! - [`ImageReference`] — parse and inspect OCI image reference strings
//! - [`RegistryAuth`] — re-exported authentication type (so consumers don't
//!   need `oci_client` as a direct dependency)

pub mod pull;
#[cfg(feature = "db-admin")]
pub mod push;

/// Re-exported from `oci_client` so consumers don't need it as a direct dependency.
///
/// Use [`RegistryAuth::Anonymous`] for public images, or [`RegistryAuth::Basic`]
/// with username/password for private registries.
pub use oci_client::secrets::RegistryAuth;

/// Build a [`RegistryAuth`] from optional username/password.
///
/// Returns [`RegistryAuth::Basic`] if both are provided, otherwise
/// [`RegistryAuth::Anonymous`].
pub fn build_auth(username: Option<&str>, password: Option<&str>) -> RegistryAuth {
    match (username, password) {
        (Some(u), Some(p)) => RegistryAuth::Basic(u.to_string(), p.to_string()),
        _ => RegistryAuth::Anonymous,
    }
}

/// A parsed OCI image reference.
///
/// Splits a reference string like `ghcr.io/myorg/myrepo:v1.2.3` into its
/// components. Docker Hub short-form references (e.g., `ubuntu:22.04`) are
/// expanded to their full form (`registry-1.docker.io/library/ubuntu`).
#[derive(Debug, Clone, PartialEq)]
pub struct ImageReference {
    /// The registry hostname (e.g., `"ghcr.io"`, `"registry-1.docker.io"`).
    pub registry: String,
    /// The repository path (e.g., `"myorg/myrepo"`, `"library/ubuntu"`).
    pub repository: String,
    /// The image tag (e.g., `"v1.2.3"`, `"latest"`). Defaults to `"latest"` if
    /// neither tag nor digest is specified.
    pub tag: Option<String>,
    /// The image digest (e.g., `"sha256:abc123..."`). Mutually exclusive with tag.
    pub digest: Option<String>,
}

impl ImageReference {
    /// Parse an OCI image reference string into its components.
    ///
    /// Format: `[registry/]repository[:tag][@digest]`
    pub fn parse(reference: &str) -> Result<Self, String> {
        let mut remainder = reference.to_string();

        // 1. Split off digest (@sha256:...)
        let digest = if let Some(at_pos) = remainder.find('@') {
            let d = remainder[at_pos + 1..].to_string();
            remainder = remainder[..at_pos].to_string();
            Some(d)
        } else {
            None
        };

        // 2. Split off tag (:tag) — but NOT if the colon is part of a port
        //    A port colon only appears in the registry segment (before any '/').
        //    So we check: does the part after the last ':' contain a '/'? If so,
        //    the colon is a port separator, not a tag separator.
        let tag = if digest.is_none() {
            // Only extract tag if there's no digest
            if let Some(colon_pos) = remainder.rfind(':') {
                let after_colon = &remainder[colon_pos + 1..];
                // If after_colon contains '/', this colon is part of a port in registry
                if !after_colon.contains('/') {
                    let t = after_colon.to_string();
                    remainder = remainder[..colon_pos].to_string();
                    Some(t)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // 3. Split registry/repository
        //    The first segment is the registry if it contains '.' or ':' or is "localhost"
        let (registry, repository) = if let Some(slash_pos) = remainder.find('/') {
            let first_segment = &remainder[..slash_pos];
            if first_segment.contains('.')
                || first_segment.contains(':')
                || first_segment == "localhost"
            {
                (
                    first_segment.to_string(),
                    remainder[slash_pos + 1..].to_string(),
                )
            } else {
                ("registry-1.docker.io".to_string(), remainder.clone())
            }
        } else {
            // No slash at all — it's a Docker Hub official image (e.g. "ubuntu")
            (
                "registry-1.docker.io".to_string(),
                format!("library/{}", remainder),
            )
        };

        // 4. Default tag to "latest" if no tag or digest
        let tag = if tag.is_none() && digest.is_none() {
            Some("latest".to_string())
        } else {
            tag
        };

        Ok(ImageReference {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// Returns true if the string looks like an OCI image reference (not a file path).
    ///
    /// Detection order per spec: the first segment (before the first `/`) must
    /// contain a dot (registry hostname like `docker.io`, `ghcr.io`) or be
    /// `localhost`. Paths like `test-fixtures/javascript/` or `./foo` are not
    /// image references.
    pub fn looks_like_image_ref(s: &str) -> bool {
        if s.is_empty() || s.starts_with('/') || s.starts_with('.') {
            return false;
        }
        if let Some(slash_pos) = s.find('/') {
            let first_segment = &s[..slash_pos];
            // Registry hostname (contains dot) or localhost
            if first_segment.contains('.') || first_segment == "localhost" {
                return true;
            }
            // Docker Hub short-form: user/repo:tag or user/repo@digest
            let remainder = &s[slash_pos + 1..];
            if remainder.contains(':') || remainder.contains('@') {
                return true;
            }
            // user/repo without tag — check if the first segment exists
            // as a directory on disk (filesystem path) or not (image ref)
            !std::path::Path::new(first_segment).exists()
        } else {
            // No slash — could be a bare image name like "ubuntu" but
            // we can't distinguish from a local directory name, so
            // we require at least a tag or digest marker
            s.contains('@') || s.contains(':')
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_reference() {
        let r = ImageReference::parse("ghcr.io/myorg/myrepo:v1.2.3").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "myorg/myrepo");
        assert_eq!(r.tag, Some("v1.2.3".to_string()));
        assert_eq!(r.digest, None);
    }

    #[test]
    fn test_parse_with_digest() {
        let r = ImageReference::parse("ghcr.io/myorg/myrepo@sha256:abc123def456").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "myorg/myrepo");
        assert_eq!(r.tag, None);
        assert_eq!(r.digest, Some("sha256:abc123def456".to_string()));
    }

    #[test]
    fn test_parse_no_tag_defaults_to_latest() {
        let r = ImageReference::parse("ghcr.io/myorg/myrepo").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "myorg/myrepo");
        assert_eq!(r.tag, Some("latest".to_string()));
        assert_eq!(r.digest, None);
    }

    #[test]
    fn test_parse_localhost_with_port() {
        let r = ImageReference::parse("localhost:5000/myrepo:latest").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "myrepo");
        assert_eq!(r.tag, Some("latest".to_string()));
        assert_eq!(r.digest, None);
    }

    #[test]
    fn test_looks_like_image_ref() {
        // Registry with dot in hostname
        assert!(ImageReference::looks_like_image_ref("ghcr.io/myorg/myrepo:v1"));
        assert!(ImageReference::looks_like_image_ref("docker.io/library/golang:1.21"));
        // Localhost
        assert!(ImageReference::looks_like_image_ref("localhost/myrepo"));
        // Bare name with digest
        assert!(ImageReference::looks_like_image_ref("myrepo@sha256:abc123"));
        // Bare name with tag
        assert!(ImageReference::looks_like_image_ref("ubuntu:22.04"));
        // Docker Hub short-form: user/repo:tag
        assert!(ImageReference::looks_like_image_ref("rc1405/inspektr-db:latest"));
        assert!(ImageReference::looks_like_image_ref("myuser/myrepo:v1.0"));
        // Docker Hub short-form with digest
        assert!(ImageReference::looks_like_image_ref("myuser/myrepo@sha256:abc"));
        // NOT image refs — filesystem paths
        assert!(!ImageReference::looks_like_image_ref("/absolute/path"));
        assert!(!ImageReference::looks_like_image_ref(""));
        assert!(!ImageReference::looks_like_image_ref("./relative/path"));
        // Paths where first segment exists as a directory are filesystem, not image refs
        assert!(!ImageReference::looks_like_image_ref("src/models"));
    }
}

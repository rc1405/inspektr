pub mod pull;
#[cfg(feature = "db-admin")]
pub mod push;

/// Re-export RegistryAuth so consumers don't need oci_client as a direct dependency.
pub use oci_client::secrets::RegistryAuth;

/// Build a `RegistryAuth` from optional username/password.
/// If both are provided, uses Basic auth. Otherwise, anonymous.
pub fn build_auth(username: Option<&str>, password: Option<&str>) -> RegistryAuth {
    match (username, password) {
        (Some(u), Some(p)) => RegistryAuth::Basic(u.to_string(), p.to_string()),
        _ => RegistryAuth::Anonymous,
    }
}

/// Parsed OCI image reference.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl ImageReference {
    /// Parse an OCI image reference string into its components.
    ///
    /// Format: [registry/]repository[:tag][@digest]
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
            first_segment.contains('.') || first_segment == "localhost"
        } else {
            // No slash — could be a bare image name like "ubuntu" but
            // we can't distinguish from a local directory name, so
            // we require at least a tag or digest marker
            s.contains('@')
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
        assert!(ImageReference::looks_like_image_ref(
            "ghcr.io/myorg/myrepo:v1"
        ));
        assert!(ImageReference::looks_like_image_ref(
            "docker.io/library/golang:1.21"
        ));
        // Localhost
        assert!(ImageReference::looks_like_image_ref("localhost/myrepo"));
        // Bare name with digest
        assert!(ImageReference::looks_like_image_ref("myrepo@sha256:abc123"));
        // NOT image refs — these are filesystem paths
        assert!(!ImageReference::looks_like_image_ref("/absolute/path"));
        assert!(!ImageReference::looks_like_image_ref(""));
        assert!(!ImageReference::looks_like_image_ref("myorg/myrepo")); // no dot in first segment
        assert!(!ImageReference::looks_like_image_ref(
            "test-fixtures/javascript/"
        ));
        assert!(!ImageReference::looks_like_image_ref("./relative/path"));
    }
}

pub mod pull;
#[cfg(feature = "db-admin")]
pub mod push;

use base64::Engine;
use oci_distribution::secrets::RegistryAuth;

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

    /// Returns true if the string looks like an OCI image reference.
    pub fn looks_like_image_ref(s: &str) -> bool {
        // Must contain at least one '/' after an optional registry prefix,
        // or look like a well-known registry host.
        // Simple heuristic: contains '/', ':', or '@' and doesn't start with '/'
        if s.starts_with('/') || s.is_empty() {
            return false;
        }
        s.contains('/') || s.contains('@') || s.contains(':')
    }
}

/// Resolve authentication for a registry.
///
/// Checks (in order):
/// 1. LOOKING_GLASS_REGISTRY_TOKEN env var (as bearer token, username "token")
/// 2. Docker config.json (~/.docker/config.json)
/// 3. Anonymous
pub fn resolve_auth(registry: &str) -> RegistryAuth {
    // 1. Check env var
    if let Ok(token) = std::env::var("LOOKING_GLASS_REGISTRY_TOKEN") {
        if !token.is_empty() {
            return RegistryAuth::Basic("token".to_string(), token);
        }
    }

    // 2. Try Docker config.json
    if let Some(auth) = read_docker_config(registry) {
        return auth;
    }

    // 3. Anonymous
    RegistryAuth::Anonymous
}

/// Read Docker config.json and extract auth for the given registry.
fn read_docker_config(registry: &str) -> Option<RegistryAuth> {
    let home = std::env::var("HOME").ok()?;
    let config_path = format!("{}/.docker/config.json", home);
    let content = std::fs::read_to_string(&config_path).ok()?;
    let config: serde_json::Value = serde_json::from_str(&content).ok()?;

    let auths = config.get("auths")?.as_object()?;

    // Try the registry as-is, then with https:// prefix
    let keys_to_try = [
        registry.to_string(),
        format!("https://{}", registry),
        format!("https://{}/v1/", registry),
    ];

    for key in &keys_to_try {
        if let Some(entry) = auths.get(key) {
            if let Some(auth_str) = entry.get("auth").and_then(|v| v.as_str()) {
                if let Ok(decoded) = base64_decode(auth_str) {
                    if let Some(colon_pos) = decoded.find(':') {
                        let username = decoded[..colon_pos].to_string();
                        let password = decoded[colon_pos + 1..].to_string();
                        return Some(RegistryAuth::Basic(username, password));
                    }
                }
            }
        }
    }

    None
}

/// Decode a base64-encoded string using the standard engine.
pub fn base64_decode(encoded: &str) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
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
        let r = ImageReference::parse(
            "ghcr.io/myorg/myrepo@sha256:abc123def456",
        )
        .unwrap();
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
        assert!(ImageReference::looks_like_image_ref("ghcr.io/myorg/myrepo:v1"));
        assert!(ImageReference::looks_like_image_ref("myrepo:latest"));
        assert!(ImageReference::looks_like_image_ref(
            "myrepo@sha256:abc123"
        ));
        assert!(!ImageReference::looks_like_image_ref("/absolute/path"));
        assert!(!ImageReference::looks_like_image_ref(""));
        assert!(ImageReference::looks_like_image_ref("myorg/myrepo"));
    }
}

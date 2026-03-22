use std::collections::HashMap;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use super::Cataloger;

pub struct ConanCataloger;

impl Cataloger for ConanCataloger {
    fn name(&self) -> &str { "conan" }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "conan.lock"
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name == "conan.lock" {
                if let Some(text) = file.as_text() {
                    for mut pkg in parse_conan_lock(text)? {
                        pkg.source_file = Some(file.path.display().to_string());
                        let key = format!("{}@{}", pkg.name, pkg.version);
                        if seen.insert(key) {
                            packages.push(pkg);
                        }
                    }
                }
            }
        }

        Ok(packages)
    }
}

fn make_conan_package(name: &str, version: &str) -> Package {
    Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Conan,
        purl: format!("pkg:conan/{}@{}", name, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

/// Parse a conan.lock file (Conan 2.x JSON format).
/// The `requires` array contains entries like "zlib/1.3.0#hash" or "boost/1.82.0".
pub fn parse_conan_lock(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| CatalogerError::ParseFailed {
            file: "conan.lock".to_string(),
            reason: e.to_string(),
        })?;

    let mut packages = Vec::new();

    if let Some(requires) = doc.get("requires").and_then(|v| v.as_array()) {
        for req in requires {
            if let Some(req_str) = req.as_str() {
                // Format: "name/version#hash" or "name/version"
                if let Some((name, rest)) = req_str.split_once('/') {
                    // Strip the #hash suffix from the version
                    let version = rest.split('#').next().unwrap_or(rest);
                    if !name.is_empty() && !version.is_empty() {
                        packages.push(make_conan_package(name, version));
                    }
                }
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::models::{FileContents, FileEntry};

    fn text_entry(path: &str, content: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Text(content.to_string()),
        }
    }

    #[test]
    fn test_can_catalog_yes() {
        let files = vec![text_entry("/project/conan.lock", "{}")];
        assert!(ConanCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_no() {
        let files = vec![
            text_entry("/project/package.json", "{}"),
            text_entry("/project/go.mod", "module example.com/app\n"),
        ];
        assert!(!ConanCataloger.can_catalog(&files));
    }

    #[test]
    fn test_parse_conan_lock() {
        let content = r#"{"version":"0.5","requires":["zlib/1.3.0#abc123","boost/1.82.0#def456"]}"#;
        let pkgs = parse_conan_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "zlib" && p.version == "1.3.0"));
        assert!(pkgs.iter().any(|p| p.name == "boost" && p.version == "1.82.0"));
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Conan));
    }

    #[test]
    fn test_catalog_sets_source_file() {
        let content = r#"{"version":"0.5","requires":["zlib/1.3.0#abc"]}"#;
        let files = vec![text_entry("/project/conan.lock", content)];
        let pkgs = ConanCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].source_file, Some("/project/conan.lock".to_string()));
    }

    #[test]
    fn test_parse_with_hash_stripped() {
        let content = r#"{"version":"0.5","requires":["openssl/3.0.0#somehash123"]}"#;
        let pkgs = parse_conan_lock(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "openssl");
        assert_eq!(pkgs[0].version, "3.0.0");
        assert_eq!(pkgs[0].purl, "pkg:conan/openssl@3.0.0");
    }
}

use std::collections::HashMap;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use super::Cataloger;

pub struct VcpkgCataloger;

impl Cataloger for VcpkgCataloger {
    fn name(&self) -> &str { "vcpkg" }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "vcpkg.json"
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name == "vcpkg.json" {
                if let Some(text) = file.as_text() {
                    for mut pkg in parse_vcpkg_json(text)? {
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

fn make_vcpkg_package(name: &str, version: &str) -> Package {
    Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Vcpkg,
        purl: format!("pkg:vcpkg/{}@{}", name, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

/// Parse a vcpkg.json manifest file.
/// Dependencies can be strings (no version, skip) or objects with `name` and `version>=`.
pub fn parse_vcpkg_json(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| CatalogerError::ParseFailed {
            file: "vcpkg.json".to_string(),
            reason: e.to_string(),
        })?;

    let mut packages = Vec::new();

    if let Some(deps) = doc.get("dependencies").and_then(|v| v.as_array()) {
        for dep in deps {
            // Only include object dependencies that have a version
            if let Some(obj) = dep.as_object() {
                let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let version = obj.get("version>=").and_then(|v| v.as_str()).unwrap_or("");
                if !name.is_empty() && !version.is_empty() {
                    packages.push(make_vcpkg_package(name, version));
                }
            }
            // String dependencies (no version) are skipped
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
        let files = vec![text_entry("/project/vcpkg.json", "{}")];
        assert!(VcpkgCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_no() {
        let files = vec![
            text_entry("/project/package.json", "{}"),
            text_entry("/project/go.mod", "module example.com/app\n"),
        ];
        assert!(!VcpkgCataloger.can_catalog(&files));
    }

    #[test]
    fn test_parse_vcpkg_json() {
        let content = r#"{"name":"app","dependencies":["zlib",{"name":"boost","version>=":"1.82.0"},{"name":"fmt","version>=":"10.1.0"}]}"#;
        let pkgs = parse_vcpkg_json(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "boost" && p.version == "1.82.0"));
        assert!(pkgs.iter().any(|p| p.name == "fmt" && p.version == "10.1.0"));
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Vcpkg));
    }

    #[test]
    fn test_skips_string_deps() {
        let content = r#"{"name":"app","dependencies":["zlib","curl",{"name":"boost","version>=":"1.82.0"}]}"#;
        let pkgs = parse_vcpkg_json(content).unwrap();
        // Only boost has a version; zlib and curl are strings without versions
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "boost");
        assert_eq!(pkgs[0].version, "1.82.0");
    }
}

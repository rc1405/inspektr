use super::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

pub struct RustCataloger;

impl Cataloger for RustCataloger {
    fn name(&self) -> &str {
        "rust"
    }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "Cargo.lock"
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name != "Cargo.lock" {
                continue;
            }
            if let Some(text) = file.as_text() {
                for mut pkg in parse_cargo_lock(text)? {
                    pkg.metadata
                        .insert("source".to_string(), "Cargo.lock".to_string());
                    pkg.source_file = Some(file.path.display().to_string());
                    let key = format!("{}@{}", pkg.name, pkg.version);
                    if seen.insert(key) {
                        packages.push(pkg);
                    }
                }
            }
        }
        Ok(packages)
    }
}

fn make_rust_package(name: &str, version: &str) -> Package {
    Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Rust,
        purl: format!("pkg:cargo/{}@{}", name, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

pub fn parse_cargo_lock(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: toml::Value =
        content
            .parse()
            .map_err(|e: toml::de::Error| CatalogerError::ParseFailed {
                file: "Cargo.lock".to_string(),
                reason: e.to_string(),
            })?;
    let mut packages = Vec::new();
    if let Some(pkgs) = doc.get("package").and_then(|v| v.as_array()) {
        for pkg in pkgs {
            // Skip packages without a source field (root project packages)
            if pkg.get("source").is_none() {
                continue;
            }
            let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if !name.is_empty() && !version.is_empty() {
                packages.push(make_rust_package(name, version));
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
    use crate::models::{FileContents, FileEntry};
    use std::path::PathBuf;

    fn text_entry(path: &str, content: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Text(content.to_string()),
        }
    }

    #[test]
    fn can_catalog_yes() {
        let files = vec![text_entry("/project/Cargo.lock", "version = 3\n")];
        assert!(RustCataloger.can_catalog(&files));
    }

    #[test]
    fn can_catalog_no() {
        let files = vec![
            text_entry("/project/go.mod", "module example.com/app\n"),
            text_entry("/project/package-lock.json", "{}"),
        ];
        assert!(!RustCataloger.can_catalog(&files));
    }

    #[test]
    fn parse_cargo_lock_finds_serde() {
        let content = r#"version = 3

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-app"
version = "0.1.0"
"#;
        let pkgs = parse_cargo_lock(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].version, "1.0.193");
        assert_eq!(pkgs[0].purl, "pkg:cargo/serde@1.0.193");
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Rust);
    }

    #[test]
    fn skips_root_package_no_source() {
        let content = r#"version = 3

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let pkgs = parse_cargo_lock(content).unwrap();
        // Only serde should be included; my-app has no source
        assert_eq!(pkgs.len(), 1);
        assert!(pkgs.iter().all(|p| p.name != "my-app"));
        assert!(pkgs.iter().any(|p| p.name == "serde"));
    }
}

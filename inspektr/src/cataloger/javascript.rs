//! JavaScript/Node.js ecosystem cataloger.
//!
//! Discovers npm packages from `package-lock.json` and `yarn.lock` files.

use super::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

/// Cataloger for JavaScript/Node.js packages.
pub struct JavaScriptCataloger;

impl Cataloger for JavaScriptCataloger {
    fn name(&self) -> &str {
        "javascript"
    }
    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "package-lock.json" || name == "yarn.lock"
        })
    }
    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let source = file_name.to_string();
            let parsed = match file_name {
                "package-lock.json" => {
                    if let Some(text) = file.as_text() {
                        parse_package_lock(text)?
                    } else {
                        continue;
                    }
                }
                "yarn.lock" => {
                    if let Some(text) = file.as_text() {
                        parse_yarn_lock(text)?
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };
            for mut pkg in parsed {
                pkg.metadata.insert("source".to_string(), source.clone());
                pkg.source_file = Some(file.path.display().to_string());
                let key = format!("{}@{}", pkg.name, pkg.version);
                if seen.insert(key) {
                    packages.push(pkg);
                }
            }
        }
        Ok(packages)
    }
}

fn make_js_package(name: &str, version: &str) -> Package {
    let purl_name = name.replace('@', "%40");
    Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::JavaScript,
        purl: format!("pkg:npm/{}@{}", purl_name, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

pub fn parse_package_lock(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: serde_json::Value =
        serde_json::from_str(content).map_err(|e| CatalogerError::ParseFailed {
            file: "package-lock.json".to_string(),
            reason: e.to_string(),
        })?;
    let mut packages = Vec::new();
    if let Some(pkgs) = doc.get("packages").and_then(|v| v.as_object()) {
        for (key, value) in pkgs {
            let name = if let Some(stripped) = key.strip_prefix("node_modules/") {
                stripped
            } else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
                packages.push(make_js_package(name, version));
            }
        }
    } else if let Some(deps) = doc.get("dependencies").and_then(|v| v.as_object()) {
        for (name, value) in deps {
            if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
                packages.push(make_js_package(name, version));
            }
        }
    }
    Ok(packages)
}

pub fn parse_yarn_lock(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && trimmed.ends_with(':') {
            let header = trimmed.trim_end_matches(':').trim_matches('"');
            if let Some(at_pos) = header.rfind('@').filter(|&p| p > 0) {
                current_name = Some(header[..at_pos].to_string());
            }
        } else if trimmed.starts_with("version \"") {
            if let Some(name) = current_name.take() {
                let version = trimmed
                    .strip_prefix("version \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or("");
                if !version.is_empty() {
                    packages.push(make_js_package(&name, version));
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
    use crate::models::{FileContents, FileEntry};
    use std::path::PathBuf;

    fn text_entry(path: &str, content: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Text(content.to_string()),
        }
    }

    #[test]
    fn test_can_catalog_with_package_lock() {
        let files = vec![text_entry("/project/package-lock.json", "{}")];
        assert!(JavaScriptCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_without_js_files() {
        let files = vec![
            text_entry("/project/go.mod", "module example.com/app\n"),
            text_entry("/project/Cargo.toml", "[package]"),
        ];
        assert!(!JavaScriptCataloger.can_catalog(&files));
    }

    #[test]
    fn test_parse_package_lock_v3() {
        let content = r#"{
  "name": "myapp",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "myapp", "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2" },
    "node_modules/lodash": { "version": "4.17.21" }
  }
}"#;
        let pkgs = parse_package_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "express" && p.version == "4.18.2")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "lodash" && p.version == "4.17.21")
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::JavaScript));
    }

    #[test]
    fn test_parse_package_lock_v2() {
        let content = r#"{
  "name": "myapp",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "dependencies": {
    "express": { "version": "4.18.2" },
    "lodash": { "version": "4.17.21" }
  }
}"#;
        let pkgs = parse_package_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "express" && p.version == "4.18.2")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "lodash" && p.version == "4.17.21")
        );
    }

    #[test]
    fn test_parse_yarn_lock() {
        let content = r#"# yarn lockfile v1

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
  integrity sha512-xxx

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-yyy
"#;
        let pkgs = parse_yarn_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "express" && p.version == "4.18.2")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "lodash" && p.version == "4.17.21")
        );
    }

    #[test]
    fn test_parse_yarn_lock_scoped() {
        let content = r#"# yarn lockfile v1

"@types/node@^20.0.0":
  version "20.10.0"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.10.0.tgz"
  integrity sha512-zzz
"#;
        let pkgs = parse_yarn_lock(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@types/node");
        assert_eq!(pkgs[0].version, "20.10.0");
        assert_eq!(pkgs[0].purl, "pkg:npm/%40types/node@20.10.0");
    }

    #[test]
    fn test_catalog_package_lock() {
        let content = r#"{
  "name": "myapp",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/express": { "version": "4.18.2" }
  }
}"#;
        let files = vec![text_entry("/project/package-lock.json", content)];
        let pkgs = JavaScriptCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
        assert_eq!(pkgs[0].version, "4.18.2");
        assert_eq!(
            pkgs[0].metadata.get("source").map(|s| s.as_str()),
            Some("package-lock.json")
        );
    }

    #[test]
    fn test_catalog_yarn_lock() {
        let content = r#"# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"#;
        let files = vec![text_entry("/project/yarn.lock", content)];
        let pkgs = JavaScriptCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, "4.17.21");
        assert_eq!(
            pkgs[0].metadata.get("source").map(|s| s.as_str()),
            Some("yarn.lock")
        );
    }
}

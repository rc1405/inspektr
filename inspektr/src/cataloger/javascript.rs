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
            let path_str = f.path.to_string_lossy();
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "package-lock.json"
                || name == "yarn.lock"
                || is_node_modules_package_json(&path_str)
        })
    }
    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // First pass: lockfiles (package-lock.json, yarn.lock)
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

        // Second pass: node_modules/*/package.json
        for file in files {
            let path_str = file.path.to_string_lossy();
            if !is_node_modules_package_json(&path_str) {
                continue;
            }
            let text = match file.as_text() {
                Some(t) => t,
                None => continue,
            };
            let mut pkg = match parse_node_modules_package_json(text) {
                Some(p) => p,
                None => continue,
            };
            let key = format!("{}@{}", pkg.name, pkg.version);
            if seen.insert(key) {
                pkg.metadata
                    .insert("source".to_string(), "package.json".to_string());
                pkg.source_file = Some(path_str.into_owned());
                packages.push(pkg);
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

/// Parse a single `package.json` from a `node_modules` directory.
///
/// Extracts `name` and `version` from the top-level JSON object.
/// Returns `None` if parsing fails or either field is missing/empty.
fn parse_node_modules_package_json(content: &str) -> Option<Package> {
    let doc: serde_json::Value = serde_json::from_str(content).ok()?;
    let name = doc.get("name")?.as_str().filter(|s| !s.is_empty())?;
    let version = doc.get("version")?.as_str().filter(|s| !s.is_empty())?;
    Some(make_js_package(name, version))
}

/// True if `path` points to a `package.json` inside a `node_modules` directory.
fn is_node_modules_package_json(path: &str) -> bool {
    path.ends_with("/package.json")
        && (path.contains("/node_modules/") || path.starts_with("node_modules/"))
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

    #[test]
    fn test_parse_node_modules_package_json_basic() {
        let content = r#"{"name": "express", "version": "4.18.2"}"#;
        let pkg = parse_node_modules_package_json(content).unwrap();
        assert_eq!(pkg.name, "express");
        assert_eq!(pkg.version, "4.18.2");
        assert_eq!(pkg.purl, "pkg:npm/express@4.18.2");
        assert_eq!(pkg.ecosystem, Ecosystem::JavaScript);
    }

    #[test]
    fn test_parse_node_modules_package_json_scoped() {
        let content = r#"{"name": "@types/node", "version": "20.10.0"}"#;
        let pkg = parse_node_modules_package_json(content).unwrap();
        assert_eq!(pkg.name, "@types/node");
        assert_eq!(pkg.version, "20.10.0");
        assert_eq!(pkg.purl, "pkg:npm/%40types/node@20.10.0");
    }

    #[test]
    fn test_parse_node_modules_package_json_missing_name() {
        let content = r#"{"version": "1.0.0"}"#;
        assert!(parse_node_modules_package_json(content).is_none());
    }

    #[test]
    fn test_parse_node_modules_package_json_missing_version() {
        let content = r#"{"name": "express"}"#;
        assert!(parse_node_modules_package_json(content).is_none());
    }

    #[test]
    fn test_parse_node_modules_package_json_empty_name() {
        let content = r#"{"name": "", "version": "1.0.0"}"#;
        assert!(parse_node_modules_package_json(content).is_none());
    }

    #[test]
    fn test_parse_node_modules_package_json_empty_version() {
        let content = r#"{"name": "express", "version": ""}"#;
        assert!(parse_node_modules_package_json(content).is_none());
    }

    #[test]
    fn test_parse_node_modules_package_json_invalid_json() {
        assert!(parse_node_modules_package_json("not json").is_none());
    }

    #[test]
    fn test_parse_node_modules_package_json_extra_fields_ignored() {
        let content = r#"{
            "name": "lodash",
            "version": "4.17.21",
            "description": "Lodash modular utilities",
            "license": "MIT",
            "dependencies": {}
        }"#;
        let pkg = parse_node_modules_package_json(content).unwrap();
        assert_eq!(pkg.name, "lodash");
        assert_eq!(pkg.version, "4.17.21");
    }

    #[test]
    fn test_is_node_modules_package_json_positive() {
        assert!(is_node_modules_package_json(
            "usr/local/lib/node_modules/npm/package.json"
        ));
        assert!(is_node_modules_package_json(
            "node_modules/express/package.json"
        ));
        assert!(is_node_modules_package_json(
            "/app/node_modules/@types/node/package.json"
        ));
        assert!(is_node_modules_package_json(
            "usr/local/lib/node_modules/npm/node_modules/semver/package.json"
        ));
    }

    #[test]
    fn test_is_node_modules_package_json_negative() {
        assert!(!is_node_modules_package_json("/app/package.json"));
        assert!(!is_node_modules_package_json("package.json"));
        assert!(!is_node_modules_package_json(
            "node_modules/express/index.js"
        ));
        assert!(!is_node_modules_package_json(
            "node_modules/express/package-lock.json"
        ));
    }

    #[test]
    fn test_can_catalog_with_node_modules_package_json() {
        let files = vec![text_entry(
            "usr/local/lib/node_modules/npm/package.json",
            r#"{"name": "npm", "version": "10.8.2"}"#,
        )];
        assert!(JavaScriptCataloger.can_catalog(&files));
    }

    #[test]
    fn test_catalog_node_modules_package_json() {
        let files = vec![
            text_entry(
                "usr/local/lib/node_modules/npm/package.json",
                r#"{"name": "npm", "version": "10.8.2"}"#,
            ),
            text_entry(
                "usr/local/lib/node_modules/corepack/package.json",
                r#"{"name": "corepack", "version": "0.34.6"}"#,
            ),
        ];
        let pkgs = JavaScriptCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "npm" && p.version == "10.8.2")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "corepack" && p.version == "0.34.6")
        );
        assert_eq!(
            pkgs[0].metadata.get("source").map(|s| s.as_str()),
            Some("package.json")
        );
    }

    #[test]
    fn test_catalog_dedup_lockfile_and_node_modules() {
        let lockfile = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/express": { "version": "4.18.2" }
            }
        }"#;
        let files = vec![
            text_entry("/app/package-lock.json", lockfile),
            text_entry(
                "/app/node_modules/express/package.json",
                r#"{"name": "express", "version": "4.18.2"}"#,
            ),
        ];
        let pkgs = JavaScriptCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 1, "duplicate should be deduped");
        assert_eq!(pkgs[0].name, "express");
    }

    #[test]
    fn test_catalog_node_modules_skips_invalid_package_json() {
        let files = vec![
            text_entry("node_modules/broken/package.json", "not valid json"),
            text_entry(
                "node_modules/express/package.json",
                r#"{"name": "express", "version": "4.18.2"}"#,
            ),
        ];
        let pkgs = JavaScriptCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
    }

    #[test]
    fn test_catalog_skips_root_package_json() {
        let files = vec![text_entry(
            "/app/package.json",
            r#"{"name": "my-app", "version": "1.0.0"}"#,
        )];
        let pkgs = JavaScriptCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 0);
    }
}

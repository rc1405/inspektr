use super::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

pub struct PhpCataloger;

impl Cataloger for PhpCataloger {
    fn name(&self) -> &str {
        "php"
    }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "composer.lock"
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name != "composer.lock" {
                continue;
            }
            if let Some(text) = file.as_text() {
                for mut pkg in parse_composer_lock(text)? {
                    pkg.metadata
                        .insert("source".to_string(), "composer.lock".to_string());
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

fn make_php_package(name: &str, version: &str) -> Package {
    let version = version.strip_prefix('v').unwrap_or(version);
    Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Php,
        purl: format!("pkg:composer/{}@{}", name, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

pub fn parse_composer_lock(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: serde_json::Value =
        serde_json::from_str(content).map_err(|e| CatalogerError::ParseFailed {
            file: "composer.lock".to_string(),
            reason: e.to_string(),
        })?;
    let mut packages = Vec::new();
    for section in &["packages", "packages-dev"] {
        if let Some(pkgs) = doc.get(section).and_then(|v| v.as_array()) {
            for pkg in pkgs {
                let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
                if !name.is_empty() && !version.is_empty() {
                    packages.push(make_php_package(name, version));
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
    fn can_catalog_yes() {
        let files = vec![text_entry("/project/composer.lock", "{}")];
        assert!(PhpCataloger.can_catalog(&files));
    }

    #[test]
    fn can_catalog_no() {
        let files = vec![
            text_entry("/project/go.mod", "module example.com/app\n"),
            text_entry("/project/package-lock.json", "{}"),
        ];
        assert!(!PhpCataloger.can_catalog(&files));
    }

    #[test]
    fn parse_composer_lock_includes_both_sections() {
        let content = r#"{
  "packages": [
    {"name": "monolog/monolog", "version": "3.5.0"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "10.5.3"}
  ]
}"#;
        let pkgs = parse_composer_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "monolog/monolog" && p.version == "3.5.0")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "phpunit/phpunit" && p.version == "10.5.3")
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Php));
    }

    #[test]
    fn strips_v_prefix() {
        let content = r#"{
  "packages": [
    {"name": "vendor/lib", "version": "v1.2.3"}
  ],
  "packages-dev": []
}"#;
        let pkgs = parse_composer_lock(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, "1.2.3");
        assert_eq!(pkgs[0].purl, "pkg:composer/vendor/lib@1.2.3");
    }
}

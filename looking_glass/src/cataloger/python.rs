use std::collections::HashMap;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use super::Cataloger;

pub struct PythonCataloger;

impl Cataloger for PythonCataloger {
    fn name(&self) -> &str { "python" }
    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "requirements.txt" || name == "Pipfile.lock" || name == "poetry.lock"
        })
    }
    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let source = file_name.to_string();
            let parsed = match file_name {
                "requirements.txt" => { if let Some(t) = file.as_text() { parse_requirements_txt(t)? } else { continue; } }
                "Pipfile.lock" => { if let Some(t) = file.as_text() { parse_pipfile_lock(t)? } else { continue; } }
                "poetry.lock" => { if let Some(t) = file.as_text() { parse_poetry_lock(t)? } else { continue; } }
                _ => continue,
            };
            for mut pkg in parsed {
                pkg.metadata.insert("source".to_string(), source.clone());
                let key = format!("{}@{}", pkg.name, pkg.version);
                if seen.insert(key) { packages.push(pkg); }
            }
        }
        Ok(packages)
    }
}

fn make_python_package(name: &str, version: &str) -> Package {
    let normalized = name.to_lowercase();
    Package {
        name: name.to_string(), version: version.to_string(),
        ecosystem: Ecosystem::Python,
        purl: format!("pkg:pypi/{}@{}", normalized, version),
        metadata: HashMap::new(),
    }
}

/// Parse requirements.txt. Only extracts packages with pinned versions (==).
pub fn parse_requirements_txt(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') { continue; }
        if let Some((name_part, version)) = line.split_once("==") {
            let name = name_part.split('[').next().unwrap_or(name_part).trim();
            let version = version.split([';', ' ', '#']).next().unwrap_or("").trim();
            if !name.is_empty() && !version.is_empty() {
                packages.push(make_python_package(name, version));
            }
        }
    }
    Ok(packages)
}

/// Parse Pipfile.lock (JSON format).
pub fn parse_pipfile_lock(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| CatalogerError::ParseFailed { file: "Pipfile.lock".to_string(), reason: e.to_string() })?;
    let mut packages = Vec::new();
    for section in &["default", "develop"] {
        if let Some(deps) = doc.get(section).and_then(|v| v.as_object()) {
            for (name, value) in deps {
                if let Some(version_str) = value.get("version").and_then(|v| v.as_str()) {
                    let version = version_str.strip_prefix("==").unwrap_or(version_str);
                    if !version.is_empty() { packages.push(make_python_package(name, version)); }
                }
            }
        }
    }
    Ok(packages)
}

/// Parse poetry.lock (TOML format).
pub fn parse_poetry_lock(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: toml::Value = content.parse()
        .map_err(|e: toml::de::Error| CatalogerError::ParseFailed { file: "poetry.lock".to_string(), reason: e.to_string() })?;
    let mut packages = Vec::new();
    if let Some(pkgs) = doc.get("package").and_then(|v| v.as_array()) {
        for pkg in pkgs {
            let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if !name.is_empty() && !version.is_empty() {
                packages.push(make_python_package(name, version));
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
    fn test_can_catalog_with_requirements() {
        let files = vec![
            text_entry("/project/requirements.txt", "requests==2.31.0\n"),
        ];
        assert!(PythonCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_without_python_files() {
        let files = vec![
            text_entry("/project/go.mod", "module example.com/app\n"),
            text_entry("/project/package-lock.json", "{}"),
        ];
        assert!(!PythonCataloger.can_catalog(&files));
    }

    #[test]
    fn test_parse_requirements_txt() {
        let content = "requests==2.31.0\nflask==3.0.0\n# comment\nnumpy>=1.24.0,<2.0.0\nsetuptools\n-e ./local\n";
        let pkgs = parse_requirements_txt(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "requests" && p.version == "2.31.0"));
        assert!(pkgs.iter().any(|p| p.name == "flask" && p.version == "3.0.0"));
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Python));
    }

    #[test]
    fn test_parse_requirements_txt_extras() {
        let content = "requests[security]==2.31.0\nuvicorn[standard]==0.24.0\n";
        let pkgs = parse_requirements_txt(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "requests" && p.version == "2.31.0"));
        assert!(pkgs.iter().any(|p| p.name == "uvicorn" && p.version == "0.24.0"));
    }

    #[test]
    fn test_parse_pipfile_lock() {
        let content = r#"{
  "_meta": { "hash": { "sha256": "abc" } },
  "default": {
    "requests": { "version": "==2.31.0" },
    "flask": { "version": "==3.0.0" }
  },
  "develop": {
    "pytest": { "version": "==7.4.0" }
  }
}"#;
        let pkgs = parse_pipfile_lock(content).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert!(pkgs.iter().any(|p| p.name == "requests" && p.version == "2.31.0"));
        assert!(pkgs.iter().any(|p| p.name == "flask" && p.version == "3.0.0"));
        assert!(pkgs.iter().any(|p| p.name == "pytest" && p.version == "7.4.0"));
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Python));
    }

    #[test]
    fn test_parse_poetry_lock() {
        let content = r#"[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "flask"
version = "3.0.0"
description = "A simple framework for building complex web applications."
"#;
        let pkgs = parse_poetry_lock(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "requests" && p.version == "2.31.0"));
        assert!(pkgs.iter().any(|p| p.name == "flask" && p.version == "3.0.0"));
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::Python));
    }

    #[test]
    fn test_catalog_requirements() {
        let content = "requests==2.31.0\nflask==3.0.0\n";
        let files = vec![text_entry("/project/requirements.txt", content)];
        let pkgs = PythonCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "requests" && p.version == "2.31.0"));
        assert!(pkgs.iter().any(|p| p.name == "flask" && p.version == "3.0.0"));
        assert!(pkgs.iter().all(|p| p.metadata.get("source").map(|s| s.as_str()) == Some("requirements.txt")));
    }

    #[test]
    fn test_purl_is_lowercase() {
        let content = "Flask==3.0.0\n";
        let pkgs = parse_requirements_txt(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "Flask");
        assert_eq!(pkgs[0].purl, "pkg:pypi/flask@3.0.0");
    }
}

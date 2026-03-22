use std::collections::HashMap;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use super::Cataloger;

pub struct SwiftCataloger;

impl Cataloger for SwiftCataloger {
    fn name(&self) -> &str { "swift" }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "Package.resolved"
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name != "Package.resolved" { continue; }
            if let Some(text) = file.as_text() {
                for mut pkg in parse_package_resolved(text)? {
                    pkg.metadata.insert("source".to_string(), "Package.resolved".to_string());
                    pkg.source_file = Some(file.path.display().to_string());
                    let key = format!("{}@{}", pkg.name, pkg.version);
                    if seen.insert(key) { packages.push(pkg); }
                }
            }
        }
        Ok(packages)
    }
}

fn make_swift_package(name: &str, version: &str) -> Package {
    Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::Swift,
        purl: format!("pkg:swift/{}@{}", name, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

pub fn parse_package_resolved(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| CatalogerError::ParseFailed {
            file: "Package.resolved".to_string(),
            reason: e.to_string(),
        })?;

    let format_version = doc.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    let mut packages = Vec::new();

    let pins = if format_version >= 2 {
        // V2: top-level "pins" array
        doc.get("pins").and_then(|v| v.as_array())
    } else {
        // V1: "object" -> "pins" array
        doc.get("object").and_then(|o| o.get("pins")).and_then(|v| v.as_array())
    };

    if let Some(pins) = pins {
        for pin in pins {
            // V2 uses "identity", V1 uses "package"
            let name = pin.get("identity")
                .or_else(|| pin.get("package"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let version = pin.get("state")
                .and_then(|s| s.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if name.is_empty() || version.is_empty() { continue; }
            packages.push(make_swift_package(name, version));
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
    fn can_catalog_yes() {
        let files = vec![text_entry("/project/Package.resolved", "{}")];
        assert!(SwiftCataloger.can_catalog(&files));
    }

    #[test]
    fn can_catalog_no() {
        let files = vec![
            text_entry("/project/go.mod", "module example.com/app\n"),
            text_entry("/project/package-lock.json", "{}"),
        ];
        assert!(!SwiftCataloger.can_catalog(&files));
    }

    #[test]
    fn parse_v2() {
        let content = r#"{
  "pins": [
    {
      "identity": "swift-argument-parser",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-argument-parser",
      "state": {
        "revision": "abc123",
        "version": "1.3.0"
      }
    }
  ],
  "version": 2
}"#;
        let pkgs = parse_package_resolved(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "swift-argument-parser");
        assert_eq!(pkgs[0].version, "1.3.0");
        assert_eq!(pkgs[0].purl, "pkg:swift/swift-argument-parser@1.3.0");
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Swift);
    }

    #[test]
    fn parse_v1() {
        let content = r#"{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "state": {
          "version": "5.8.0"
        }
      }
    ]
  },
  "version": 1
}"#;
        let pkgs = parse_package_resolved(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "Alamofire");
        assert_eq!(pkgs[0].version, "5.8.0");
        assert_eq!(pkgs[0].purl, "pkg:swift/Alamofire@5.8.0");
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Swift);
    }
}

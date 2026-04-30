//! .NET ecosystem cataloger.
//!
//! Discovers NuGet packages from `packages.lock.json`, `*.csproj`, and
//! `packages.config` files.

use super::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

/// Cataloger for .NET/NuGet packages.
pub struct DotNetCataloger;

impl Cataloger for DotNetCataloger {
    fn name(&self) -> &str {
        "dotnet"
    }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "packages.lock.json" || name.ends_with(".csproj") || name == "packages.config"
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let parsed = if file_name == "packages.lock.json" {
                if let Some(text) = file.as_text() {
                    parse_packages_lock_json(text)?
                } else {
                    continue;
                }
            } else if file_name.ends_with(".csproj") {
                if let Some(text) = file.as_text() {
                    parse_csproj(text)?
                } else {
                    continue;
                }
            } else if file_name == "packages.config" {
                if let Some(text) = file.as_text() {
                    parse_packages_config(text)?
                } else {
                    continue;
                }
            } else {
                continue;
            };

            for mut pkg in parsed {
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

fn make_dotnet_package(name: &str, version: &str) -> Package {
    Package {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: Ecosystem::DotNet,
        purl: format!("pkg:nuget/{}@{}", name, version),
        metadata: HashMap::new(),
        source_file: None,
    }
}

/// Parse packages.lock.json (NuGet lock file format).
/// Structure: {"version":1,"dependencies":{"net8.0":{"PackageName":{"resolved":"1.2.3"}}}}
pub fn parse_packages_lock_json(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let doc: serde_json::Value =
        serde_json::from_str(content).map_err(|e| CatalogerError::ParseFailed {
            file: "packages.lock.json".to_string(),
            reason: e.to_string(),
        })?;

    let mut packages = Vec::new();

    if let Some(deps) = doc.get("dependencies").and_then(|v| v.as_object()) {
        for (_framework, pkg_map) in deps {
            if let Some(pkgs) = pkg_map.as_object() {
                for (name, info) in pkgs {
                    if let Some(version) = info.get("resolved").and_then(|v| v.as_str())
                        && !version.is_empty() {
                            packages.push(make_dotnet_package(name, version));
                        }
                }
            }
        }
    }

    Ok(packages)
}

/// Parse a .csproj file for PackageReference elements.
/// Uses simple string matching to find Include and Version attributes.
pub fn parse_csproj(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("PackageReference") {
            continue;
        }
        if let (Some(name), Some(version)) = (
            extract_attr(trimmed, "Include"),
            extract_attr(trimmed, "Version"),
        )
            && !name.is_empty() && !version.is_empty() {
                packages.push(make_dotnet_package(&name, &version));
            }
    }

    Ok(packages)
}

/// Parse a packages.config file for package elements.
/// Uses simple string matching to find id and version attributes.
pub fn parse_packages_config(content: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("<package") {
            continue;
        }
        if let (Some(name), Some(version)) = (
            extract_attr(trimmed, "id"),
            extract_attr(trimmed, "version"),
        )
            && !name.is_empty() && !version.is_empty() {
                packages.push(make_dotnet_package(&name, &version));
            }
    }

    Ok(packages)
}

/// Extract the value of an XML attribute by name from a line of text.
/// Handles both `Attr="value"` and `Attr='value'` forms.
fn extract_attr(line: &str, attr: &str) -> Option<String> {
    // Search for `attr="` or `attr='`
    let search_dq = format!("{}=\"", attr);
    let search_sq = format!("{}='", attr);

    let (start, quote_char) = if let Some(pos) = line.find(&search_dq) {
        (pos + search_dq.len(), '"')
    } else if let Some(pos) = line.find(&search_sq) {
        (pos + search_sq.len(), '\'')
    } else {
        return None;
    };

    let rest = &line[start..];
    let end = rest.find(quote_char)?;
    Some(rest[..end].to_string())
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
    fn test_can_catalog_lock() {
        let files = vec![text_entry("/project/packages.lock.json", "{}")];
        assert!(DotNetCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_csproj() {
        let files = vec![text_entry("/project/MyApp.csproj", "<Project/>")];
        assert!(DotNetCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_no() {
        let files = vec![
            text_entry("/project/package.json", "{}"),
            text_entry("/project/go.mod", "module example.com/app\n"),
        ];
        assert!(!DotNetCataloger.can_catalog(&files));
    }

    #[test]
    fn test_parse_packages_lock_json() {
        let content = r#"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"resolved":"13.0.3"},"Serilog":{"resolved":"3.1.1"}}}}"#;
        let pkgs = parse_packages_lock_json(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "Newtonsoft.Json" && p.version == "13.0.3")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "Serilog" && p.version == "3.1.1")
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::DotNet));
    }

    #[test]
    fn test_parse_csproj() {
        let content = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="3.1.1" />
  </ItemGroup>
</Project>"#;
        let pkgs = parse_csproj(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "Newtonsoft.Json" && p.version == "13.0.3")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "Serilog" && p.version == "3.1.1")
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::DotNet));
    }

    #[test]
    fn test_parse_packages_config() {
        let content = r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="Serilog" version="3.1.1" targetFramework="net48" />
</packages>"#;
        let pkgs = parse_packages_config(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "Newtonsoft.Json" && p.version == "13.0.3")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "Serilog" && p.version == "3.1.1")
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == Ecosystem::DotNet));
    }
}

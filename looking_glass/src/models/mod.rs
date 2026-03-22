use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A file discovered by a Source.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub contents: FileContents,
}

#[derive(Debug, Clone)]
pub enum FileContents {
    Text(String),
    Binary(Vec<u8>),
}

impl FileEntry {
    pub fn is_binary(&self) -> bool {
        matches!(self.contents, FileContents::Binary(_))
    }

    pub fn as_text(&self) -> Option<&str> {
        match &self.contents {
            FileContents::Text(s) => Some(s),
            FileContents::Binary(_) => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.contents {
            FileContents::Text(s) => s.as_bytes(),
            FileContents::Binary(b) => b,
        }
    }
}

/// Metadata about where files came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMetadata {
    pub source_type: String,
    pub target: String,
}

/// Supported ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Go,
    JavaScript,
    Python,
    Java,
}

impl Ecosystem {
    pub fn as_osv_ecosystem(&self) -> &'static str {
        match self {
            Ecosystem::Go => "Go",
            Ecosystem::JavaScript => "npm",
            Ecosystem::Python => "PyPI",
            Ecosystem::Java => "Maven",
        }
    }
}

/// A discovered software package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub purl: String,
    pub metadata: HashMap<String, String>,
    pub source_file: Option<String>,
}

impl Package {
    pub fn to_purl(&self) -> String {
        match self.ecosystem {
            Ecosystem::Go => format!("pkg:golang/{}@{}", self.name, self.version),
            Ecosystem::JavaScript => {
                // npm scoped packages: @scope/name → %40scope/name
                let encoded = self.name.replace('@', "%40");
                format!("pkg:npm/{}@{}", encoded, self.version)
            }
            Ecosystem::Python => {
                format!("pkg:pypi/{}@{}", self.name.to_lowercase(), self.version)
            }
            Ecosystem::Java => {
                // Maven coordinates: groupId:artifactId → groupId/artifactId
                let purl_name = self.name.replace(':', "/");
                format!("pkg:maven/{}@{}", purl_name, self.version)
            }
        }
    }
}

/// An SBOM document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub source: SourceMetadata,
    pub packages: Vec<Package>,
}

/// Vulnerability severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// A vulnerability record from the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub details: String,
    pub severity: Severity,
    pub published: String,
    pub modified: String,
    pub withdrawn: Option<String>,
    pub source: String,
    pub cvss_score: Option<f64>,
}

/// A match between a package and a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMatch {
    pub package: Package,
    pub vulnerability: Vulnerability,
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_purl_generation() {
        let pkg = Package {
            name: "github.com/stretchr/testify".to_string(),
            version: "v1.8.4".to_string(),
            ecosystem: Ecosystem::Go,
            purl: String::new(),
            metadata: HashMap::new(),
            source_file: None,
        };
        let purl = pkg.to_purl();
        assert_eq!(purl, "pkg:golang/github.com/stretchr/testify@v1.8.4");
    }

    #[test]
    fn test_ecosystem_display() {
        assert_eq!(Ecosystem::Go.as_osv_ecosystem(), "Go");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::None);
    }

    #[test]
    fn test_file_entry_creation() {
        let entry = FileEntry {
            path: PathBuf::from("/usr/bin/app"),
            contents: FileContents::Binary(vec![0x7f, 0x45, 0x4c, 0x46]),
        };
        assert!(entry.is_binary());
    }

    #[test]
    fn test_ecosystem_javascript() {
        assert_eq!(Ecosystem::JavaScript.as_osv_ecosystem(), "npm");
    }

    #[test]
    fn test_ecosystem_python() {
        assert_eq!(Ecosystem::Python.as_osv_ecosystem(), "PyPI");
    }

    #[test]
    fn test_ecosystem_java() {
        assert_eq!(Ecosystem::Java.as_osv_ecosystem(), "Maven");
    }

    #[test]
    fn test_purl_javascript() {
        let pkg = Package {
            name: "express".to_string(),
            version: "4.18.2".to_string(),
            ecosystem: Ecosystem::JavaScript,
            purl: String::new(),
            metadata: HashMap::new(),
            source_file: None,
        };
        assert_eq!(pkg.to_purl(), "pkg:npm/express@4.18.2");
    }

    #[test]
    fn test_purl_javascript_scoped() {
        let pkg = Package {
            name: "@types/node".to_string(),
            version: "20.10.0".to_string(),
            ecosystem: Ecosystem::JavaScript,
            purl: String::new(),
            metadata: HashMap::new(),
            source_file: None,
        };
        assert_eq!(pkg.to_purl(), "pkg:npm/%40types/node@20.10.0");
    }

    #[test]
    fn test_purl_python() {
        let pkg = Package {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            ecosystem: Ecosystem::Python,
            purl: String::new(),
            metadata: HashMap::new(),
            source_file: None,
        };
        assert_eq!(pkg.to_purl(), "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn test_purl_java() {
        let pkg = Package {
            name: "org.apache.commons:commons-lang3".to_string(),
            version: "3.14.0".to_string(),
            ecosystem: Ecosystem::Java,
            purl: String::new(),
            metadata: HashMap::new(),
            source_file: None,
        };
        assert_eq!(pkg.to_purl(), "pkg:maven/org.apache.commons/commons-lang3@3.14.0");
    }
}

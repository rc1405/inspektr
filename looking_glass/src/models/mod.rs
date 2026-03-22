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
}

impl Ecosystem {
    pub fn as_osv_ecosystem(&self) -> &'static str {
        match self {
            Ecosystem::Go => "Go",
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
}

impl Package {
    pub fn to_purl(&self) -> String {
        match self.ecosystem {
            Ecosystem::Go => format!("pkg:golang/{}@{}", self.name, self.version),
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
}

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
    Conan,
    Vcpkg,
    DotNet,
    Php,
    Rust,
    Ruby,
    Swift,
    // OS distributions — apk-based
    Alpine,
    Wolfi,
    Chainguard,
    // OS distributions — dpkg-based
    Debian,
    Ubuntu,
    Distroless,
    // OS distributions — rpm-based
    RedHat,
    CentOS,
    Rocky,
    AlmaLinux,
    OracleLinux,
    SUSE,
    Photon,
    AzureLinux,
    CoreOS,
    Bottlerocket,
    Echo,
    MinimOS,
}

impl Ecosystem {
    pub fn as_osv_ecosystem(&self) -> &'static str {
        match self {
            Ecosystem::Go => "Go",
            Ecosystem::JavaScript => "npm",
            Ecosystem::Python => "PyPI",
            Ecosystem::Java => "Maven",
            Ecosystem::Conan => "ConanCenter",
            Ecosystem::Vcpkg => "vcpkg",
            Ecosystem::DotNet => "NuGet",
            Ecosystem::Php => "Packagist",
            Ecosystem::Rust => "crates.io",
            Ecosystem::Ruby => "RubyGems",
            Ecosystem::Swift => "SwiftURL",
            Ecosystem::Alpine => "Alpine",
            Ecosystem::Wolfi => "Wolfi",
            Ecosystem::Chainguard => "Chainguard",
            Ecosystem::Debian => "Debian",
            Ecosystem::Ubuntu => "Ubuntu",
            Ecosystem::Distroless => "Debian",
            Ecosystem::RedHat => "Red Hat",
            Ecosystem::CentOS => "CentOS",
            Ecosystem::Rocky => "Rocky Linux",
            Ecosystem::AlmaLinux => "AlmaLinux",
            Ecosystem::OracleLinux => "Oracle",
            Ecosystem::SUSE => "SUSE",
            Ecosystem::Photon => "Photon OS",
            Ecosystem::AzureLinux => "Azure Linux",
            Ecosystem::CoreOS => "CoreOS",
            Ecosystem::Bottlerocket => "Bottlerocket",
            Ecosystem::Echo => "Echo",
            Ecosystem::MinimOS => "MinimOS",
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
            Ecosystem::Conan => format!("pkg:conan/{}@{}", self.name, self.version),
            Ecosystem::Vcpkg => format!("pkg:vcpkg/{}@{}", self.name, self.version),
            Ecosystem::DotNet => format!("pkg:nuget/{}@{}", self.name, self.version),
            Ecosystem::Php => format!("pkg:composer/{}@{}", self.name, self.version),
            Ecosystem::Rust => format!("pkg:cargo/{}@{}", self.name, self.version),
            Ecosystem::Ruby => format!("pkg:gem/{}@{}", self.name, self.version),
            Ecosystem::Swift => format!("pkg:swift/{}@{}", self.name, self.version),
            // dpkg-based
            Ecosystem::Debian | Ecosystem::Distroless => {
                format!("pkg:deb/debian/{}@{}", self.name, self.version)
            }
            Ecosystem::Ubuntu => {
                format!("pkg:deb/ubuntu/{}@{}", self.name, self.version)
            }
            // apk-based
            Ecosystem::Alpine => format!("pkg:apk/alpine/{}@{}", self.name, self.version),
            Ecosystem::Wolfi => format!("pkg:apk/wolfi/{}@{}", self.name, self.version),
            Ecosystem::Chainguard => format!("pkg:apk/chainguard/{}@{}", self.name, self.version),
            // rpm-based
            Ecosystem::RedHat => format!("pkg:rpm/redhat/{}@{}", self.name, self.version),
            Ecosystem::CentOS => format!("pkg:rpm/centos/{}@{}", self.name, self.version),
            Ecosystem::Rocky => format!("pkg:rpm/rocky/{}@{}", self.name, self.version),
            Ecosystem::AlmaLinux => format!("pkg:rpm/almalinux/{}@{}", self.name, self.version),
            Ecosystem::OracleLinux => format!("pkg:rpm/oraclelinux/{}@{}", self.name, self.version),
            Ecosystem::SUSE => format!("pkg:rpm/suse/{}@{}", self.name, self.version),
            Ecosystem::Photon => format!("pkg:rpm/photon/{}@{}", self.name, self.version),
            Ecosystem::AzureLinux => format!("pkg:rpm/azurelinux/{}@{}", self.name, self.version),
            Ecosystem::CoreOS => format!("pkg:rpm/coreos/{}@{}", self.name, self.version),
            Ecosystem::Bottlerocket => {
                format!("pkg:rpm/bottlerocket/{}@{}", self.name, self.version)
            }
            Ecosystem::Echo => format!("pkg:rpm/echo/{}@{}", self.name, self.version),
            Ecosystem::MinimOS => format!("pkg:rpm/minimos/{}@{}", self.name, self.version),
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
        assert_eq!(
            pkg.to_purl(),
            "pkg:maven/org.apache.commons/commons-lang3@3.14.0"
        );
    }

    #[test]
    fn test_new_ecosystem_osv_names() {
        assert_eq!(Ecosystem::Conan.as_osv_ecosystem(), "ConanCenter");
        assert_eq!(Ecosystem::Vcpkg.as_osv_ecosystem(), "vcpkg");
        assert_eq!(Ecosystem::DotNet.as_osv_ecosystem(), "NuGet");
        assert_eq!(Ecosystem::Php.as_osv_ecosystem(), "Packagist");
        assert_eq!(Ecosystem::Rust.as_osv_ecosystem(), "crates.io");
        assert_eq!(Ecosystem::Ruby.as_osv_ecosystem(), "RubyGems");
        assert_eq!(Ecosystem::Swift.as_osv_ecosystem(), "SwiftURL");
    }

    #[test]
    fn test_os_ecosystem_osv_names() {
        assert_eq!(Ecosystem::Alpine.as_osv_ecosystem(), "Alpine");
        assert_eq!(Ecosystem::Debian.as_osv_ecosystem(), "Debian");
        assert_eq!(Ecosystem::Ubuntu.as_osv_ecosystem(), "Ubuntu");
        assert_eq!(Ecosystem::RedHat.as_osv_ecosystem(), "Red Hat");
        assert_eq!(Ecosystem::Distroless.as_osv_ecosystem(), "Debian");
    }

    #[test]
    fn test_os_ecosystem_purls() {
        let make_pkg = |name: &str, version: &str, ecosystem: Ecosystem| Package {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
            purl: String::new(),
            metadata: HashMap::new(),
            source_file: None,
        };

        assert_eq!(
            make_pkg("libc6", "2.36-9+deb12u3", Ecosystem::Debian).to_purl(),
            "pkg:deb/debian/libc6@2.36-9+deb12u3"
        );
        assert_eq!(
            make_pkg("libc6", "2.38-1ubuntu6", Ecosystem::Ubuntu).to_purl(),
            "pkg:deb/ubuntu/libc6@2.38-1ubuntu6"
        );
        assert_eq!(
            make_pkg("musl", "1.2.4-r2", Ecosystem::Alpine).to_purl(),
            "pkg:apk/alpine/musl@1.2.4-r2"
        );
        assert_eq!(
            make_pkg("glibc", "2.34-60.el9", Ecosystem::RedHat).to_purl(),
            "pkg:rpm/redhat/glibc@2.34-60.el9"
        );
        assert_eq!(
            make_pkg("base-files", "11.1+deb11u7", Ecosystem::Distroless).to_purl(),
            "pkg:deb/debian/base-files@11.1+deb11u7"
        );
    }

    #[test]
    fn test_new_ecosystem_purls() {
        let make_pkg = |name: &str, version: &str, ecosystem: Ecosystem| Package {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
            purl: String::new(),
            metadata: HashMap::new(),
            source_file: None,
        };

        assert_eq!(
            make_pkg("zlib", "1.2.11", Ecosystem::Conan).to_purl(),
            "pkg:conan/zlib@1.2.11"
        );
        assert_eq!(
            make_pkg("zlib", "1.2.11", Ecosystem::Vcpkg).to_purl(),
            "pkg:vcpkg/zlib@1.2.11"
        );
        assert_eq!(
            make_pkg("Newtonsoft.Json", "13.0.3", Ecosystem::DotNet).to_purl(),
            "pkg:nuget/Newtonsoft.Json@13.0.3"
        );
        assert_eq!(
            make_pkg("monolog/monolog", "3.5.0", Ecosystem::Php).to_purl(),
            "pkg:composer/monolog/monolog@3.5.0"
        );
        assert_eq!(
            make_pkg("serde", "1.0.193", Ecosystem::Rust).to_purl(),
            "pkg:cargo/serde@1.0.193"
        );
        assert_eq!(
            make_pkg("rails", "7.1.2", Ecosystem::Ruby).to_purl(),
            "pkg:gem/rails@7.1.2"
        );
        assert_eq!(
            make_pkg("github.com/apple/swift-nio", "2.62.0", Ecosystem::Swift).to_purl(),
            "pkg:swift/github.com/apple/swift-nio@2.62.0"
        );
    }
}

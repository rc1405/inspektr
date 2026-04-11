//! Core data types used throughout the library.
//!
//! This module defines the primary types that flow through the
//! [pipeline](crate::pipeline): files, packages, SBOMs, ecosystems,
//! vulnerabilities, and severity levels.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A file discovered by a [`Source`](crate::source::Source).
///
/// Represents a single file with its path and contents. Files are classified
/// as either text (UTF-8) or binary, which determines how catalogers process them.
/// For example, Go binary analysis requires [`FileContents::Binary`], while
/// lockfile parsing uses [`FileContents::Text`].
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// The path where this file was found (absolute for filesystem sources,
    /// layer-relative for OCI images).
    pub path: PathBuf,
    /// The file contents, classified as text or binary.
    pub contents: FileContents,
}

/// The contents of a discovered file.
///
/// Files are classified at discovery time based on a heuristic check for
/// null bytes. Text files are decoded as UTF-8 (with lossy conversion for
/// non-UTF-8 content).
#[derive(Debug, Clone)]
pub enum FileContents {
    /// UTF-8 text content (lockfiles, manifests, config files).
    Text(String),
    /// Raw binary content (compiled executables, compressed archives).
    Binary(Vec<u8>),
}

impl FileEntry {
    /// Returns `true` if this file contains binary (non-text) data.
    pub fn is_binary(&self) -> bool {
        matches!(self.contents, FileContents::Binary(_))
    }

    /// Returns the text content if this is a text file, or `None` for binary files.
    pub fn as_text(&self) -> Option<&str> {
        match &self.contents {
            FileContents::Text(s) => Some(s),
            FileContents::Binary(_) => None,
        }
    }

    /// Returns the raw bytes of the file content, regardless of type.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.contents {
            FileContents::Text(s) => s.as_bytes(),
            FileContents::Binary(b) => b,
        }
    }
}

/// Metadata about where files came from.
///
/// Included in every [`Sbom`] to record what was scanned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMetadata {
    /// The kind of source: `"filesystem"`, `"oci"`, or `"binary"`.
    pub source_type: String,
    /// The target that was scanned (directory path, image reference, or binary path).
    pub target: String,
}

/// A software ecosystem that a [`Package`] belongs to.
///
/// Ecosystems fall into two categories:
///
/// - **Language ecosystems** (Go, JavaScript, Python, etc.) — packages come from
///   lockfiles and manifests.
/// - **OS distribution ecosystems** (Alpine, Debian, RedHat, etc.) — packages come
///   from OS package managers (apk, dpkg, rpm) found in container images.
///
/// Each ecosystem maps to an OSV ecosystem name (via [`as_osv_ecosystem()`](Ecosystem::as_osv_ecosystem))
/// and a PURL type prefix (via [`from_purl()`](Ecosystem::from_purl) and
/// [`Package::to_purl()`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    /// Unrecognized or unsupported ecosystem.
    Unknown,
    /// Go modules (`go.mod`, `go.sum`, Go binaries).
    Go,
    /// JavaScript / Node.js (`package-lock.json`, `yarn.lock`).
    JavaScript,
    /// Python (`requirements.txt`, `Pipfile.lock`, `poetry.lock`).
    Python,
    /// Java (`pom.xml`, `build.gradle`, `build.gradle.kts`).
    Java,
    /// C/C++ Conan packages (`conan.lock`).
    Conan,
    /// C/C++ vcpkg packages (`vcpkg.json`).
    Vcpkg,
    /// .NET / NuGet (`packages.lock.json`, `*.csproj`, `packages.config`).
    DotNet,
    /// PHP Composer (`composer.lock`).
    Php,
    /// Rust / Cargo (`Cargo.lock`).
    Rust,
    /// Ruby / RubyGems (`Gemfile.lock`).
    Ruby,
    /// Swift Package Manager (`Package.resolved`).
    Swift,
    // OS distributions — apk-based
    /// Alpine Linux (apk).
    Alpine,
    /// Wolfi Linux (apk).
    Wolfi,
    /// Chainguard (apk).
    Chainguard,
    // OS distributions — dpkg-based
    /// Debian (dpkg).
    Debian,
    /// Ubuntu (dpkg).
    Ubuntu,
    /// Google Distroless (dpkg, maps to Debian for vulnerability data).
    Distroless,
    // OS distributions — rpm-based
    /// Red Hat Enterprise Linux (rpm).
    RedHat,
    /// CentOS (rpm).
    CentOS,
    /// Rocky Linux (rpm).
    Rocky,
    /// AlmaLinux (rpm).
    AlmaLinux,
    /// Oracle Linux (rpm).
    OracleLinux,
    /// SUSE Linux (rpm).
    SUSE,
    /// VMware Photon OS (rpm).
    Photon,
    /// Microsoft Azure Linux / CBL-Mariner (rpm).
    AzureLinux,
    /// Fedora CoreOS (rpm).
    CoreOS,
    /// AWS Bottlerocket (rpm).
    Bottlerocket,
    /// Echo Linux (rpm).
    Echo,
    /// MinimOS (rpm).
    MinimOS,
}

impl Ecosystem {
    /// Detect ecosystem from a PURL string prefix.
    ///
    /// For OS package types (`deb`, `apk`, `rpm`), the namespace is inspected
    /// to pick the right distro variant.
    ///
    /// # Fallback
    /// Unrecognized PURL prefixes return `Ecosystem::Unknown`.
    pub fn from_purl(purl: &str) -> Ecosystem {
        if purl.starts_with("pkg:golang/") {
            Ecosystem::Go
        } else if purl.starts_with("pkg:npm/") {
            Ecosystem::JavaScript
        } else if purl.starts_with("pkg:pypi/") {
            Ecosystem::Python
        } else if purl.starts_with("pkg:maven/") {
            Ecosystem::Java
        } else if purl.starts_with("pkg:conan/") {
            Ecosystem::Conan
        } else if purl.starts_with("pkg:vcpkg/") {
            Ecosystem::Vcpkg
        } else if purl.starts_with("pkg:nuget/") {
            Ecosystem::DotNet
        } else if purl.starts_with("pkg:composer/") {
            Ecosystem::Php
        } else if purl.starts_with("pkg:cargo/") {
            Ecosystem::Rust
        } else if purl.starts_with("pkg:gem/") {
            Ecosystem::Ruby
        } else if purl.starts_with("pkg:swift/") {
            Ecosystem::Swift
        } else if purl.starts_with("pkg:deb/") {
            if purl.starts_with("pkg:deb/ubuntu/") {
                Ecosystem::Ubuntu
            } else {
                Ecosystem::Debian
            }
        } else if purl.starts_with("pkg:apk/") {
            if purl.starts_with("pkg:apk/wolfi/") {
                Ecosystem::Wolfi
            } else if purl.starts_with("pkg:apk/chainguard/") {
                Ecosystem::Chainguard
            } else {
                Ecosystem::Alpine
            }
        } else if purl.starts_with("pkg:rpm/") {
            if purl.starts_with("pkg:rpm/centos/") {
                Ecosystem::CentOS
            } else if purl.starts_with("pkg:rpm/rocky/") {
                Ecosystem::Rocky
            } else if purl.starts_with("pkg:rpm/almalinux/") {
                Ecosystem::AlmaLinux
            } else if purl.starts_with("pkg:rpm/oraclelinux/") {
                Ecosystem::OracleLinux
            } else if purl.starts_with("pkg:rpm/suse/") {
                Ecosystem::SUSE
            } else if purl.starts_with("pkg:rpm/photon/") {
                Ecosystem::Photon
            } else if purl.starts_with("pkg:rpm/azurelinux/") {
                Ecosystem::AzureLinux
            } else if purl.starts_with("pkg:rpm/coreos/") {
                Ecosystem::CoreOS
            } else if purl.starts_with("pkg:rpm/bottlerocket/") {
                Ecosystem::Bottlerocket
            } else if purl.starts_with("pkg:rpm/echo/") {
                Ecosystem::Echo
            } else if purl.starts_with("pkg:rpm/minimos/") {
                Ecosystem::MinimOS
            } else {
                Ecosystem::RedHat
            }
        } else {
            Ecosystem::Unknown
        }
    }

    /// Returns the OSV ecosystem name for this ecosystem.
    ///
    /// These names match the identifiers used by the
    /// [OSV database](https://osv.dev/list) (e.g., `"Go"`, `"npm"`, `"PyPI"`).
    pub fn as_osv_ecosystem(&self) -> &'static str {
        match self {
            Ecosystem::Unknown => "Unknown",
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
///
/// Packages are produced by [`Cataloger`](crate::cataloger::Cataloger) implementations
/// and represent a single versioned software component. Each package has a
/// [Package URL (PURL)](https://github.com/package-url/purl-spec) for unique
/// identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// The package name (e.g., `"express"`, `"github.com/stretchr/testify"`, `"openssl"`).
    pub name: String,
    /// The package version string (e.g., `"4.18.2"`, `"v1.8.4"`, `"3.0.11-1~deb12u3"`).
    pub version: String,
    /// The ecosystem this package belongs to.
    pub ecosystem: Ecosystem,
    /// The [Package URL](https://github.com/package-url/purl-spec) for this package.
    pub purl: String,
    /// Arbitrary metadata (e.g., `"osv_ecosystem"` for versioned OS ecosystem names).
    pub metadata: HashMap<String, String>,
    /// The source file where this package was discovered (e.g., `"/project/go.mod"`).
    pub source_file: Option<String>,
}

impl Package {
    /// Generate a [Package URL](https://github.com/package-url/purl-spec) string
    /// from this package's ecosystem, name, and version.
    ///
    /// The PURL format varies by ecosystem. For example:
    /// - Go: `pkg:golang/github.com/stretchr/testify@v1.8.4`
    /// - npm: `pkg:npm/express@4.18.2`
    /// - Debian: `pkg:deb/debian/openssl@3.0.11`
    pub fn to_purl(&self) -> String {
        match self.ecosystem {
            Ecosystem::Unknown => format!("pkg:unknown/{}@{}", self.name, self.version),
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

/// A Software Bill of Materials (SBOM) document.
///
/// Contains the list of packages discovered from a target along with
/// metadata about the source that was scanned. This is the primary output of
/// [`pipeline::generate_sbom()`](crate::pipeline::generate_sbom) and can be
/// encoded to CycloneDX or SPDX using [`SbomFormat`](crate::sbom::SbomFormat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    /// Metadata about the scanned target.
    pub source: SourceMetadata,
    /// All packages discovered in the target.
    pub packages: Vec<Package>,
}

/// Vulnerability severity levels, ordered from least to most severe.
///
/// Variants are ordered so that `Severity::Critical > Severity::High > ... > Severity::None`,
/// which allows direct comparison with `<`, `>`, and `max()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// No severity assigned or unknown.
    None,
    /// Low severity.
    Low,
    /// Medium severity (also called "Moderate" in some databases).
    Medium,
    /// High severity (also called "Important" in some databases).
    High,
    /// Critical severity.
    Critical,
}

impl Severity {
    /// Parse a severity string (case-insensitive) into a `Severity` value.
    ///
    /// Handles common synonyms used by different vulnerability databases:
    /// - NVD uses uppercase (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
    /// - OVAL uses title case with synonyms (`Important`, `Moderate`)
    /// - OSV uses uppercase with `MODERATE` as an alias for `MEDIUM`
    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" | "IMPORTANT" => Severity::High,
            "MEDIUM" | "MODERATE" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::None,
        }
    }
}

/// A vulnerability record from the database.
///
/// Represents a single known vulnerability (CVE, GHSA, DSA, etc.) with its
/// severity assessment from a specific data source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// The vulnerability identifier (e.g., `"CVE-2023-44487"`, `"GHSA-xxxx"`, `"GO-2023-0001"`).
    pub id: String,
    /// A short description of the vulnerability.
    pub summary: String,
    /// The severity level.
    pub severity: Severity,
    /// ISO 8601 timestamp when this vulnerability was first published.
    pub published: String,
    /// ISO 8601 timestamp when this vulnerability was last modified.
    pub modified: String,
    /// ISO 8601 timestamp if this vulnerability was withdrawn/retracted.
    pub withdrawn: Option<String>,
    /// The data source that provided this record (e.g., `"osv"`, `"nvd"`).
    pub source: String,
    /// CVSS v3 base score (0.0–10.0), if available.
    pub cvss_score: Option<f64>,
}

/// A match between a package and a vulnerability.
///
/// Produced by [`vuln::matcher::match_package()`](crate::vuln::matcher::match_package)
/// when a package's version falls within a vulnerable range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMatch {
    /// The affected package.
    pub package: Package,
    /// The matched vulnerability.
    pub vulnerability: Vulnerability,
    /// The version where the vulnerability was introduced, if known.
    pub introduced: Option<String>,
    /// The version where the vulnerability was fixed, if known.
    /// `None` means no fix is available yet.
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

    // -----------------------------------------------------------------------
    // Ecosystem::from_purl tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_purl_language_ecosystems() {
        assert_eq!(
            Ecosystem::from_purl("pkg:golang/github.com/x/y@v1.0"),
            Ecosystem::Go
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:npm/express@4.18.2"),
            Ecosystem::JavaScript
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:pypi/requests@2.31.0"),
            Ecosystem::Python
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:maven/org.apache/commons@3.14"),
            Ecosystem::Java
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:conan/zlib@1.2.11"),
            Ecosystem::Conan
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:vcpkg/zlib@1.2.11"),
            Ecosystem::Vcpkg
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:nuget/Newtonsoft.Json@13.0"),
            Ecosystem::DotNet
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:composer/monolog/monolog@3.5"),
            Ecosystem::Php
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:cargo/serde@1.0.193"),
            Ecosystem::Rust
        );
        assert_eq!(Ecosystem::from_purl("pkg:gem/rails@7.1.2"), Ecosystem::Ruby);
        assert_eq!(
            Ecosystem::from_purl("pkg:swift/github.com/apple/swift-nio@2.62"),
            Ecosystem::Swift
        );
    }

    #[test]
    fn test_from_purl_deb_namespaces() {
        assert_eq!(
            Ecosystem::from_purl("pkg:deb/ubuntu/libc6@2.38"),
            Ecosystem::Ubuntu
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:deb/debian/libc6@2.36"),
            Ecosystem::Debian
        );
        // Unknown deb namespace defaults to Debian
        assert_eq!(
            Ecosystem::from_purl("pkg:deb/other/libc6@2.36"),
            Ecosystem::Debian
        );
    }

    #[test]
    fn test_from_purl_apk_namespaces() {
        assert_eq!(
            Ecosystem::from_purl("pkg:apk/wolfi/musl@1.2"),
            Ecosystem::Wolfi
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:apk/chainguard/musl@1.2"),
            Ecosystem::Chainguard
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:apk/alpine/musl@1.2"),
            Ecosystem::Alpine
        );
        // Unknown apk namespace defaults to Alpine
        assert_eq!(
            Ecosystem::from_purl("pkg:apk/other/musl@1.2"),
            Ecosystem::Alpine
        );
    }

    #[test]
    fn test_from_purl_rpm_namespaces() {
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/redhat/glibc@2.34"),
            Ecosystem::RedHat
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/centos/glibc@2.34"),
            Ecosystem::CentOS
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/rocky/glibc@2.34"),
            Ecosystem::Rocky
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/almalinux/glibc@2.34"),
            Ecosystem::AlmaLinux
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/oraclelinux/glibc@2.34"),
            Ecosystem::OracleLinux
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/suse/glibc@2.34"),
            Ecosystem::SUSE
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/photon/glibc@2.34"),
            Ecosystem::Photon
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/azurelinux/glibc@2.34"),
            Ecosystem::AzureLinux
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/coreos/glibc@2.34"),
            Ecosystem::CoreOS
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/bottlerocket/glibc@2.34"),
            Ecosystem::Bottlerocket
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/echo/glibc@2.34"),
            Ecosystem::Echo
        );
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/minimos/glibc@2.34"),
            Ecosystem::MinimOS
        );
        // Unknown rpm namespace defaults to RedHat
        assert_eq!(
            Ecosystem::from_purl("pkg:rpm/unknown/glibc@2.34"),
            Ecosystem::RedHat
        );
    }

    #[test]
    fn test_from_purl_unknown_fallback() {
        // Unrecognized PURL prefix returns Ecosystem::Unknown
        assert_eq!(
            Ecosystem::from_purl("pkg:unknown/foo@1.0"),
            Ecosystem::Unknown
        );
        assert_eq!(Ecosystem::from_purl(""), Ecosystem::Unknown);
    }

    // -----------------------------------------------------------------------
    // Severity::parse tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_parse_standard() {
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::parse("HIGH"), Severity::High);
        assert_eq!(Severity::parse("MEDIUM"), Severity::Medium);
        assert_eq!(Severity::parse("LOW"), Severity::Low);
    }

    #[test]
    fn test_severity_parse_synonyms() {
        assert_eq!(Severity::parse("IMPORTANT"), Severity::High);
        assert_eq!(Severity::parse("MODERATE"), Severity::Medium);
    }

    #[test]
    fn test_severity_parse_case_insensitive() {
        assert_eq!(Severity::parse("Critical"), Severity::Critical);
        assert_eq!(Severity::parse("high"), Severity::High);
        assert_eq!(Severity::parse("Medium"), Severity::Medium);
        assert_eq!(Severity::parse("Important"), Severity::High);
        assert_eq!(Severity::parse("Moderate"), Severity::Medium);
        assert_eq!(Severity::parse("low"), Severity::Low);
    }

    #[test]
    fn test_severity_parse_unknown() {
        assert_eq!(Severity::parse("UNKNOWN"), Severity::None);
        assert_eq!(Severity::parse(""), Severity::None);
        assert_eq!(Severity::parse("N/A"), Severity::None);
    }
}

//! OS-level package cataloger for container images.
//!
//! Detects the Linux distribution from `/etc/os-release` and dispatches to
//! the appropriate package database parser:
//!
//! - [`dpkg`] — Debian, Ubuntu, Distroless
//! - [`apk`] — Alpine, Wolfi, Chainguard
//! - [`rpm`] — RHEL, CentOS, Rocky, Alma, Oracle, SUSE, Photon, Azure Linux,
//!   CoreOS, Bottlerocket, Echo, MinimOS

pub mod apk;
pub mod dpkg;
pub mod rpm;

use super::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};

/// Information about the detected Linux distribution.
///
/// Parsed from `/etc/os-release` inside a container image.
#[derive(Debug, Clone)]
pub struct DistroInfo {
    /// The distribution ID (e.g., `"alpine"`, `"debian"`, `"rhel"`).
    pub id: String,
    /// The distribution version (e.g., `"3.19"`, `"12"`, `"9.3"`).
    pub version: String,
    /// The human-readable distribution name.
    pub name: String,
    /// The ecosystem this distribution maps to.
    pub ecosystem: Ecosystem,
    /// The package format used by this distribution.
    pub package_format: PackageFormat,
}

/// The package database format used by a Linux distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageFormat {
    /// Debian package format (`/var/lib/dpkg/status`).
    Dpkg,
    /// Alpine package format (`/lib/apk/db/installed`).
    Apk,
    /// RPM package format (`/var/lib/rpm/rpmdb.sqlite` or `/var/lib/rpm/Packages`).
    Rpm,
}

/// Trait for OS package database parsers.
///
/// Implement this trait to add support for a new OS package format.
pub trait OsPackageParser {
    /// File paths this parser looks for in container image layers.
    fn package_db_paths(&self) -> &[&str];

    /// Parse packages from the package database files.
    fn parse_packages(
        &self,
        files: &[FileEntry],
        distro: &DistroInfo,
    ) -> Result<Vec<Package>, CatalogerError>;
}

/// The OS cataloger — detects the Linux distribution from `/etc/os-release`
/// and dispatches to the appropriate package database parser.
pub struct OsCataloger;

impl Cataloger for OsCataloger {
    fn name(&self) -> &str {
        "os"
    }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        // Can catalog if we find an os-release file AND a package database
        detect_distro(files).is_some()
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let distro = match detect_distro(files) {
            Some(d) => d,
            None => return Ok(Vec::new()),
        };

        let parser: Box<dyn OsPackageParser> = match distro.package_format {
            PackageFormat::Dpkg => Box::new(dpkg::DpkgParser),
            PackageFormat::Apk => Box::new(apk::ApkParser),
            PackageFormat::Rpm => Box::new(rpm::RpmParser),
        };

        let mut packages = parser.parse_packages(files, &distro)?;

        // Compute the versioned OSV ecosystem name (e.g., "Alpine:v3.18")
        let osv_ecosystem = versioned_osv_ecosystem(&distro);

        for pkg in &mut packages {
            // Set the versioned OSV ecosystem for the matcher to query
            pkg.metadata
                .insert("osv_ecosystem".to_string(), osv_ecosystem.clone());

            // Set source_file to the package database path
            if pkg.source_file.is_none() {
                for db_path in parser.package_db_paths() {
                    if files
                        .iter()
                        .any(|f| f.path.to_string_lossy().ends_with(db_path))
                    {
                        pkg.source_file = Some(db_path.to_string());
                        break;
                    }
                }
            }
        }

        Ok(packages)
    }
}

/// Detect the Linux distribution from /etc/os-release or fallback files.
pub fn detect_distro(files: &[FileEntry]) -> Option<DistroInfo> {
    // Try /etc/os-release first
    for file in files {
        let path_str = file.path.to_string_lossy();
        if path_str.ends_with("/etc/os-release") || path_str == "etc/os-release" {
            if let Some(text) = file.as_text() {
                return parse_os_release(text);
            }
        }
    }

    // Fallback: /etc/alpine-release
    for file in files {
        let path_str = file.path.to_string_lossy();
        if path_str.ends_with("/etc/alpine-release") || path_str == "etc/alpine-release" {
            if let Some(text) = file.as_text() {
                let version = text.trim().to_string();
                return Some(DistroInfo {
                    id: "alpine".to_string(),
                    version,
                    name: "Alpine Linux".to_string(),
                    ecosystem: Ecosystem::Alpine,
                    package_format: PackageFormat::Apk,
                });
            }
        }
    }

    // Fallback: check for dpkg status (Distroless images may lack os-release)
    for file in files {
        let path_str = file.path.to_string_lossy();
        if path_str.ends_with("/var/lib/dpkg/status")
            || path_str == "var/lib/dpkg/status"
            || path_str.contains("/var/lib/dpkg/status.d/")
            || path_str.starts_with("var/lib/dpkg/status.d/")
        {
            return Some(DistroInfo {
                id: "distroless".to_string(),
                version: String::new(),
                name: "Distroless".to_string(),
                ecosystem: Ecosystem::Distroless,
                package_format: PackageFormat::Dpkg,
            });
        }
    }

    None
}

/// Parse /etc/os-release into a DistroInfo.
fn parse_os_release(content: &str) -> Option<DistroInfo> {
    let mut id = String::new();
    let mut version_id = String::new();
    let mut pretty_name = String::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("ID=") {
            id = val.trim_matches('"').to_lowercase();
        } else if let Some(val) = line.strip_prefix("VERSION_ID=") {
            version_id = val.trim_matches('"').to_string();
        } else if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
            pretty_name = val.trim_matches('"').to_string();
        }
    }

    if id.is_empty() {
        return None;
    }

    let (ecosystem, package_format) = map_distro_id(&id)?;

    Some(DistroInfo {
        id,
        version: version_id,
        name: if pretty_name.is_empty() {
            "Unknown".to_string()
        } else {
            pretty_name
        },
        ecosystem,
        package_format,
    })
}

/// Map an os-release ID to an Ecosystem variant and package format.
/// Adding a new distro = adding one arm to this match.
pub fn map_distro_id(id: &str) -> Option<(Ecosystem, PackageFormat)> {
    match id {
        // apk-based
        "alpine" => Some((Ecosystem::Alpine, PackageFormat::Apk)),
        "wolfi" => Some((Ecosystem::Wolfi, PackageFormat::Apk)),
        "chainguard" => Some((Ecosystem::Chainguard, PackageFormat::Apk)),
        // dpkg-based
        "debian" => Some((Ecosystem::Debian, PackageFormat::Dpkg)),
        "ubuntu" => Some((Ecosystem::Ubuntu, PackageFormat::Dpkg)),
        // rpm-based
        "rhel" => Some((Ecosystem::RedHat, PackageFormat::Rpm)),
        "centos" => Some((Ecosystem::CentOS, PackageFormat::Rpm)),
        "rocky" => Some((Ecosystem::Rocky, PackageFormat::Rpm)),
        "almalinux" => Some((Ecosystem::AlmaLinux, PackageFormat::Rpm)),
        "ol" => Some((Ecosystem::OracleLinux, PackageFormat::Rpm)),
        "sles" | "opensuse-leap" | "opensuse-tumbleweed" | "opensuse" => {
            Some((Ecosystem::SUSE, PackageFormat::Rpm))
        }
        "photon" => Some((Ecosystem::Photon, PackageFormat::Rpm)),
        "azurelinux" | "mariner" => Some((Ecosystem::AzureLinux, PackageFormat::Rpm)),
        "coreos" => Some((Ecosystem::CoreOS, PackageFormat::Rpm)),
        "bottlerocket" => Some((Ecosystem::Bottlerocket, PackageFormat::Rpm)),
        "echo" => Some((Ecosystem::Echo, PackageFormat::Rpm)),
        "minimos" => Some((Ecosystem::MinimOS, PackageFormat::Rpm)),
        _ => None,
    }
}

/// Build the versioned OSV ecosystem name for a distro.
///
/// OSV uses versioned ecosystem names for OS distributions, e.g.:
/// - Alpine → `"Alpine:v3.18"` (major.minor with `v` prefix)
/// - Debian → `"Debian:12"` (major only)
/// - Ubuntu → `"Ubuntu:22.04"` (major.minor)
/// - Red Hat → `"Red Hat:9"` (major only)
///
/// The input `distro.version` may come from `/etc/os-release` (typically a
/// canonical form like `"13"`) or from a third-party SBOM's operating-system
/// component (which may include patch versions like `"13.4"`). This function
/// normalizes both into the canonical OSV form.
pub fn versioned_osv_ecosystem(distro: &DistroInfo) -> String {
    let base = distro.ecosystem.as_osv_ecosystem();
    if distro.version.is_empty() {
        return base.to_string();
    }

    match distro.ecosystem {
        // Alpine uses "Alpine:v3.18" format — major.minor with leading `v`.
        Ecosystem::Alpine | Ecosystem::Wolfi | Ecosystem::Chainguard => {
            let version = if distro.version.starts_with('v') {
                distro.version.clone()
            } else {
                // Use major.minor only, dropping any patch/build suffix.
                let parts: Vec<&str> = distro.version.split('.').collect();
                if parts.len() >= 2 {
                    format!("v{}.{}", parts[0], parts[1])
                } else {
                    format!("v{}", distro.version)
                }
            };
            format!("{}:{}", base, version)
        }
        // Debian OSV keys are major-only (`"Debian:12"`). Third-party SBOMs
        // sometimes report point releases like `"13.4"`; strip to major.
        Ecosystem::Debian | Ecosystem::Distroless => {
            let major = distro.version.split('.').next().unwrap_or(&distro.version);
            format!("{}:{}", base, major)
        }
        // Ubuntu OSV keys include the release type: `"Ubuntu:22.04:LTS"` for
        // LTS releases, `"Ubuntu:25.10"` for non-LTS. The LTS suffix is
        // detected from the distro's pretty name (e.g., "Ubuntu 22.04.5 LTS").
        Ecosystem::Ubuntu => {
            let parts: Vec<&str> = distro.version.split('.').collect();
            let ver = if parts.len() >= 2 {
                format!("{}.{}", parts[0], parts[1])
            } else {
                distro.version.clone()
            };
            let is_lts = distro.name.contains("LTS");
            if is_lts {
                format!("{}:{}:LTS", base, ver)
            } else {
                format!("{}:{}", base, ver)
            }
        }
        // RPM distros typically use major version only.
        _ => {
            let major = distro.version.split('.').next().unwrap_or(&distro.version);
            format!("{}:{}", base, major)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FileContents, FileEntry};
    use std::path::PathBuf;

    fn text_entry(path: &str, contents: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Text(contents.to_string()),
        }
    }

    #[test]
    fn test_parse_os_release_debian() {
        let content = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n";
        let info = parse_os_release(content).unwrap();
        assert_eq!(info.id, "debian");
        assert_eq!(info.version, "12");
        assert_eq!(info.ecosystem, Ecosystem::Debian);
        assert_eq!(info.package_format, PackageFormat::Dpkg);
    }

    #[test]
    fn test_parse_os_release_alpine() {
        let content = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.19.0\nPRETTY_NAME=\"Alpine Linux v3.19\"\n";
        let info = parse_os_release(content).unwrap();
        assert_eq!(info.id, "alpine");
        assert_eq!(info.version, "3.19.0");
        assert_eq!(info.ecosystem, Ecosystem::Alpine);
        assert_eq!(info.package_format, PackageFormat::Apk);
    }

    #[test]
    fn test_parse_os_release_rhel() {
        let content = "NAME=\"Red Hat Enterprise Linux\"\nVERSION_ID=\"9.3\"\nID=\"rhel\"\n";
        let info = parse_os_release(content).unwrap();
        assert_eq!(info.id, "rhel");
        assert_eq!(info.ecosystem, Ecosystem::RedHat);
        assert_eq!(info.package_format, PackageFormat::Rpm);
    }

    #[test]
    fn test_parse_os_release_unknown() {
        let content = "ID=someunknowndistro\nVERSION_ID=1.0\n";
        assert!(parse_os_release(content).is_none());
    }

    #[test]
    fn test_detect_distro_from_os_release() {
        let files = vec![text_entry(
            "etc/os-release",
            "ID=debian\nVERSION_ID=\"12\"\n",
        )];
        let distro = detect_distro(&files).unwrap();
        assert_eq!(distro.id, "debian");
    }

    #[test]
    fn test_detect_distro_alpine_fallback() {
        let files = vec![text_entry("etc/alpine-release", "3.19.0\n")];
        let distro = detect_distro(&files).unwrap();
        assert_eq!(distro.id, "alpine");
        assert_eq!(distro.version, "3.19.0");
    }

    #[test]
    fn test_detect_distro_distroless_fallback() {
        let files = vec![text_entry(
            "var/lib/dpkg/status",
            "Package: base-files\nStatus: install ok installed\nVersion: 12.4\n",
        )];
        let distro = detect_distro(&files).unwrap();
        assert_eq!(distro.id, "distroless");
        assert_eq!(distro.ecosystem, Ecosystem::Distroless);
    }

    #[test]
    fn test_detect_distro_none() {
        let files = vec![text_entry("app/main.go", "package main\n")];
        assert!(detect_distro(&files).is_none());
    }

    #[test]
    fn test_map_distro_id_coverage() {
        // Verify all supported distros map correctly
        let cases = vec![
            ("alpine", Ecosystem::Alpine, PackageFormat::Apk),
            ("wolfi", Ecosystem::Wolfi, PackageFormat::Apk),
            ("chainguard", Ecosystem::Chainguard, PackageFormat::Apk),
            ("debian", Ecosystem::Debian, PackageFormat::Dpkg),
            ("ubuntu", Ecosystem::Ubuntu, PackageFormat::Dpkg),
            ("rhel", Ecosystem::RedHat, PackageFormat::Rpm),
            ("centos", Ecosystem::CentOS, PackageFormat::Rpm),
            ("rocky", Ecosystem::Rocky, PackageFormat::Rpm),
            ("almalinux", Ecosystem::AlmaLinux, PackageFormat::Rpm),
            ("ol", Ecosystem::OracleLinux, PackageFormat::Rpm),
            ("sles", Ecosystem::SUSE, PackageFormat::Rpm),
            ("photon", Ecosystem::Photon, PackageFormat::Rpm),
            ("azurelinux", Ecosystem::AzureLinux, PackageFormat::Rpm),
            ("coreos", Ecosystem::CoreOS, PackageFormat::Rpm),
            ("bottlerocket", Ecosystem::Bottlerocket, PackageFormat::Rpm),
            ("echo", Ecosystem::Echo, PackageFormat::Rpm),
            ("minimos", Ecosystem::MinimOS, PackageFormat::Rpm),
        ];
        for (id, expected_eco, expected_fmt) in cases {
            let (eco, fmt) =
                map_distro_id(id).unwrap_or_else(|| panic!("missing mapping for {}", id));
            assert_eq!(eco, expected_eco, "ecosystem mismatch for {}", id);
            assert_eq!(fmt, expected_fmt, "format mismatch for {}", id);
        }
    }
}

//! Debian dpkg package database parser.
//!
//! Parses `/var/lib/dpkg/status` to discover installed packages on
//! Debian, Ubuntu, and Distroless images.

use super::{DistroInfo, OsPackageParser};
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

/// Parser for dpkg package databases (Debian, Ubuntu, Distroless).
pub struct DpkgParser;

impl OsPackageParser for DpkgParser {
    fn package_db_paths(&self) -> &[&str] {
        &[
            "/var/lib/dpkg/status",
            "var/lib/dpkg/status",
            "/var/lib/dpkg/status.d/",
            "var/lib/dpkg/status.d/",
        ]
    }

    fn parse_packages(
        &self,
        files: &[FileEntry],
        distro: &DistroInfo,
    ) -> Result<Vec<Package>, CatalogerError> {
        // Collect content from all dpkg status files
        let mut combined = String::new();

        for file in files {
            let path_str = file.path.to_string_lossy();
            let is_status =
                path_str.ends_with("/var/lib/dpkg/status") || path_str == "var/lib/dpkg/status";
            let is_status_d = path_str.contains("/var/lib/dpkg/status.d/")
                || path_str.starts_with("var/lib/dpkg/status.d/");

            if is_status || is_status_d {
                if let Some(text) = file.as_text() {
                    if !combined.is_empty() {
                        combined.push_str("\n\n");
                    }
                    combined.push_str(text);
                }
            }
        }

        if combined.is_empty() {
            return Ok(Vec::new());
        }

        parse_dpkg_status(&combined, distro)
    }
}

/// Determine the PURL distro id from the DistroInfo.
fn dpkg_distro_id(distro: &DistroInfo) -> &str {
    match distro.ecosystem {
        Ecosystem::Ubuntu => "ubuntu",
        _ => "debian",
    }
}

/// Parse dpkg status file content into packages.
pub fn parse_dpkg_status(
    content: &str,
    distro: &DistroInfo,
) -> Result<Vec<Package>, CatalogerError> {
    let distro_id = dpkg_distro_id(distro);
    let mut packages = Vec::new();

    for record in content.split("\n\n") {
        let record = record.trim();
        if record.is_empty() {
            continue;
        }

        let mut name = None;
        let mut version = None;
        let mut status = None;

        for line in record.lines() {
            if let Some(val) = line.strip_prefix("Package:") {
                name = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Version:") {
                version = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Status:") {
                status = Some(val.trim().to_string());
            }
        }

        // Only include packages that are installed.
        // The Status field has three space-separated tokens: want, error, status.
        // We require the third token to be exactly "installed".
        let is_installed = status
            .as_deref()
            .map(|s| {
                s.split_whitespace()
                    .nth(2)
                    .map(|state| state == "installed")
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        if !is_installed {
            continue;
        }

        if let (Some(name), Some(version)) = (name, version) {
            let purl = format!("pkg:deb/{}/{}@{}", distro_id, name, version);
            packages.push(Package {
                name,
                version,
                ecosystem: distro.ecosystem,
                purl,
                metadata: HashMap::new(),
                source_file: None,
            });
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Ecosystem;

    fn make_distro(id: &str, ecosystem: Ecosystem) -> DistroInfo {
        DistroInfo {
            id: id.to_string(),
            version: "12".to_string(),
            name: id.to_string(),
            ecosystem,
            package_format: super::super::PackageFormat::Dpkg,
        }
    }

    #[test]
    fn test_parse_dpkg_status() {
        let content = "\
Package: openssl
Status: install ok installed
Version: 3.0.11-1~deb12u2
Architecture: amd64

Package: libc6
Status: install ok installed
Version: 2.36-9+deb12u3
Architecture: amd64
";
        let distro = make_distro("debian", Ecosystem::Debian);
        let pkgs = parse_dpkg_status(content, &distro).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "openssl");
        assert_eq!(pkgs[0].version, "3.0.11-1~deb12u2");
        assert_eq!(pkgs[0].purl, "pkg:deb/debian/openssl@3.0.11-1~deb12u2");
        assert_eq!(pkgs[1].name, "libc6");
        assert_eq!(pkgs[1].version, "2.36-9+deb12u3");
    }

    #[test]
    fn test_skips_not_installed() {
        let content = "\
Package: openssl
Status: install ok installed
Version: 3.0.11-1~deb12u2

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0.0

Package: purged-pkg
Status: purge ok not-installed
Version: 2.0.0
";
        let distro = make_distro("debian", Ecosystem::Debian);
        let pkgs = parse_dpkg_status(content, &distro).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "openssl");
    }

    #[test]
    fn test_ubuntu_purl() {
        let content = "\
Package: libc6
Status: install ok installed
Version: 2.38-1ubuntu6
";
        let distro = make_distro("ubuntu", Ecosystem::Ubuntu);
        let pkgs = parse_dpkg_status(content, &distro).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl, "pkg:deb/ubuntu/libc6@2.38-1ubuntu6");
    }
}

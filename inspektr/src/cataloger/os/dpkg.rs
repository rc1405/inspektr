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
        // Container images ship a copy of `/var/lib/dpkg/status` in every
        // layer that touched packages. Each copy is a complete snapshot.
        // We want the most complete one (largest), which is the top
        // layer's version. We can't rely on ordering because Docker
        // daemon exports may return layers in non-manifest order.
        //
        // For `status.d/*` (distroless), each file represents a different
        // package's control record, so we dedupe by path instead of
        // keeping only the largest entry. Later layers overwriting the same
        // path still win by HashMap insert order.
        let mut best_status: Option<&str> = None;
        let mut best_status_len: usize = 0;
        let mut status_d: HashMap<String, &str> = HashMap::new();

        for file in files {
            let path_str = file.path.to_string_lossy();
            let is_status =
                path_str.ends_with("/var/lib/dpkg/status") || path_str == "var/lib/dpkg/status";
            let is_status_d = path_str.contains("/var/lib/dpkg/status.d/")
                || path_str.starts_with("var/lib/dpkg/status.d/");

            if is_status {
                if let Some(text) = file.as_text()
                    && text.len() > best_status_len
                {
                    best_status = Some(text);
                    best_status_len = text.len();
                }
            } else if is_status_d && let Some(text) = file.as_text() {
                status_d.insert(path_str.into_owned(), text);
            }
        }

        let mut combined = String::new();
        if let Some(text) = best_status {
            combined.push_str(text);
        }
        for text in status_d.values() {
            if !combined.is_empty() {
                combined.push_str("\n\n");
            }
            combined.push_str(text);
        }

        if combined.is_empty() {
            return Ok(Vec::new());
        }

        parse_dpkg_status(&combined, distro)
    }
}

/// Encode a Debian version for use in a PURL.
///
/// Strips the epoch prefix (e.g. `1:2.41-5` → `2.41-5`) since epochs are
/// Debian-internal and not part of the upstream version identity. Also
/// percent-encodes `+` as `%2B` per the PURL spec.
fn purl_encode_deb_version(version: &str) -> String {
    let without_epoch = match version.find(':') {
        Some(pos) => &version[pos + 1..],
        None => version,
    };
    without_epoch.replace('+', "%2B")
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
        let mut source = None;

        for line in record.lines() {
            if let Some(val) = line.strip_prefix("Package:") {
                name = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Version:") {
                version = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Status:") {
                status = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Source:") {
                let src = val.trim();
                let src_name = src.split_whitespace().next().unwrap_or(src);
                source = Some(src_name.to_string());
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
            let purl_version = purl_encode_deb_version(&version);
            let purl = format!("pkg:deb/{}/{}@{}", distro_id, name, purl_version);
            let mut metadata = HashMap::new();
            if let Some(src) = source
                && src != name
            {
                metadata.insert("source_package".to_string(), src);
            }
            packages.push(Package {
                name,
                version,
                ecosystem: distro.ecosystem,
                purl,
                metadata,
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
    fn test_parse_packages_uses_latest_status_not_concat() {
        // Simulate a multi-layer image: an early layer installed
        // `base-files` at v1; a later layer upgraded `base-files` and
        // added `openssl`. Both layers hand us their own copy of
        // `var/lib/dpkg/status`. We must use the LAST copy only; otherwise
        // the parser produces duplicates and stale versions.
        let parser = DpkgParser;
        let distro = make_distro("debian", Ecosystem::Debian);

        let early_status = "\
Package: base-files
Status: install ok installed
Version: 1.0

";
        let late_status = "\
Package: base-files
Status: install ok installed
Version: 2.0

Package: openssl
Status: install ok installed
Version: 3.0.11-1

";
        let files = vec![
            FileEntry {
                path: std::path::PathBuf::from("var/lib/dpkg/status"),
                contents: crate::models::FileContents::Text(early_status.to_string()),
            },
            FileEntry {
                path: std::path::PathBuf::from("var/lib/dpkg/status"),
                contents: crate::models::FileContents::Text(late_status.to_string()),
            },
        ];
        let pkgs = parser.parse_packages(&files, &distro).unwrap();
        assert_eq!(pkgs.len(), 2, "expected exactly 2 packages, no duplicates");
        let base = pkgs.iter().find(|p| p.name == "base-files").unwrap();
        assert_eq!(
            base.version, "2.0",
            "expected upgraded version from top layer"
        );
        assert!(pkgs.iter().any(|p| p.name == "openssl"));
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

    #[test]
    fn test_purl_strips_epoch_and_encodes_plus() {
        let distro = make_distro("debian", Ecosystem::Debian);
        let content = "\
Package: bsdutils
Version: 1:2.41-5
Status: install ok installed

Package: base-files
Version: 13.8+deb13u4
Status: install ok installed
";
        let pkgs = parse_dpkg_status(content, &distro).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].purl, "pkg:deb/debian/bsdutils@2.41-5");
        assert_eq!(pkgs[0].version, "1:2.41-5");
        assert_eq!(pkgs[1].purl, "pkg:deb/debian/base-files@13.8%2Bdeb13u4");
        assert_eq!(pkgs[1].version, "13.8+deb13u4");
    }
}

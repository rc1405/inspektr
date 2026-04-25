//! Alpine apk package database parser.
//!
//! Parses `/lib/apk/db/installed` to discover installed packages on
//! Alpine, Wolfi, and Chainguard images.

use super::{DistroInfo, OsPackageParser};
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

/// Parser for apk package databases (Alpine, Wolfi, Chainguard).
pub struct ApkParser;

impl OsPackageParser for ApkParser {
    fn package_db_paths(&self) -> &[&str] {
        &["/lib/apk/db/installed", "lib/apk/db/installed"]
    }

    fn parse_packages(
        &self,
        files: &[FileEntry],
        distro: &DistroInfo,
    ) -> Result<Vec<Package>, CatalogerError> {
        // Multi-layer alpine images ship a copy of `/lib/apk/db/installed`
        // in every layer that ran apk. Each copy is a complete snapshot.
        // Pick the largest one (most packages) since Docker daemon
        // exports may return layers in non-manifest order.
        let mut best: Option<&str> = None;
        let mut best_len: usize = 0;
        for file in files {
            let path_str = file.path.to_string_lossy();
            if path_str.ends_with("/lib/apk/db/installed") || path_str == "lib/apk/db/installed" {
                if let Some(text) = file.as_text() {
                    if text.len() > best_len {
                        best = Some(text);
                        best_len = text.len();
                    }
                }
            }
        }
        match best {
            Some(text) => parse_apk_installed(text, distro),
            None => Ok(Vec::new()),
        }
    }
}

/// Determine the PURL distro id from DistroInfo.
fn apk_distro_id(distro: &DistroInfo) -> &str {
    match distro.ecosystem {
        Ecosystem::Wolfi => "wolfi",
        Ecosystem::Chainguard => "chainguard",
        _ => "alpine",
    }
}

/// Parse `/lib/apk/db/installed` content into packages.
pub fn parse_apk_installed(
    content: &str,
    distro: &DistroInfo,
) -> Result<Vec<Package>, CatalogerError> {
    let distro_id = apk_distro_id(distro);
    let mut packages = Vec::new();

    for record in content.split("\n\n") {
        let record = record.trim();
        if record.is_empty() {
            continue;
        }

        let mut name = None;
        let mut version = None;

        for line in record.lines() {
            if let Some(val) = line.strip_prefix("P:") {
                name = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("V:") {
                version = Some(val.trim().to_string());
            }
        }

        if let (Some(name), Some(version)) = (name, version) {
            let purl = format!("pkg:apk/{}/{}@{}", distro_id, name, version);
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
            version: "3.19.0".to_string(),
            name: id.to_string(),
            ecosystem,
            package_format: super::super::PackageFormat::Apk,
        }
    }

    #[test]
    fn test_parse_apk_installed() {
        let content = "\
P:busybox
V:1.36.1-r15
A:x86_64
S:526648
I:1519616
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Sören Tempel <soeren+alpine@soeren-tempel.net>
t:1698347374
c:fd0ad890bef4bcd42dcb33e73ad48f46f8fd2b72

P:musl
V:1.2.4-r2
A:x86_64
S:383152
I:622592
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Timo Teräs <timo.teras@iki.fi>
t:1687762500
c:0f5b7c37c8b7a386d23f0c66e7a0e0b80b9979d1
";
        let distro = make_distro("alpine", Ecosystem::Alpine);
        let pkgs = parse_apk_installed(content, &distro).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "busybox");
        assert_eq!(pkgs[0].version, "1.36.1-r15");
        assert_eq!(pkgs[0].purl, "pkg:apk/alpine/busybox@1.36.1-r15");
        assert_eq!(pkgs[1].name, "musl");
        assert_eq!(pkgs[1].version, "1.2.4-r2");
    }

    #[test]
    fn test_wolfi_purl() {
        let content = "\
P:glibc
V:2.38-r5
A:x86_64
";
        let distro = make_distro("wolfi", Ecosystem::Wolfi);
        let pkgs = parse_apk_installed(content, &distro).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl, "pkg:apk/wolfi/glibc@2.38-r5");
    }
}

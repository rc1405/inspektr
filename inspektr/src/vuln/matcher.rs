//! Vulnerability matching engine.
//!
//! Matches [`Package`] values against the vulnerability
//! database by ecosystem and version range. Language ecosystems use semver
//! comparison; OS ecosystems use string-based version comparison.
//!
//! The main entry points are:
//!
//! - [`match_package()`] — match a single package
//! - [`match_packages()`] — match a slice of packages

use crate::db::store::VulnStore;
use crate::models::{Ecosystem, Package, Vulnerability, VulnerabilityMatch};
use semver::Version;

fn strip_epoch(version: &str) -> &str {
    match version.find(':') {
        Some(pos) if version[..pos].bytes().all(|b| b.is_ascii_digit()) => &version[pos + 1..],
        _ => version,
    }
}

/// Compare two OS package version strings using dpkg-style ordering.
///
/// Splits each version into alternating non-digit and digit segments,
/// comparing non-digit parts lexicographically and digit parts numerically.
/// Handles the `~` prefix (sorts before everything, used for pre-release).
///
/// Returns `std::cmp::Ordering`.
fn compare_os_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut ai = 0;
    let mut bi = 0;

    loop {
        // Skip non-alphanumeric, non-tilde characters (like `.` and `-`)
        while ai < a_bytes.len() && !a_bytes[ai].is_ascii_alphanumeric() && a_bytes[ai] != b'~' {
            ai += 1;
        }
        while bi < b_bytes.len() && !b_bytes[bi].is_ascii_alphanumeric() && b_bytes[bi] != b'~' {
            bi += 1;
        }

        // Handle tilde: sorts before everything (including end-of-string)
        match (
            ai < a_bytes.len() && a_bytes[ai] == b'~',
            bi < b_bytes.len() && b_bytes[bi] == b'~',
        ) {
            (true, true) => {
                ai += 1;
                bi += 1;
                continue;
            }
            (true, false) => return std::cmp::Ordering::Less,
            (false, true) => return std::cmp::Ordering::Greater,
            _ => {}
        }

        // Both exhausted
        if ai >= a_bytes.len() && bi >= b_bytes.len() {
            return std::cmp::Ordering::Equal;
        }

        // One exhausted — shorter is less (unless tilde handled above)
        if ai >= a_bytes.len() {
            return std::cmp::Ordering::Less;
        }
        if bi >= b_bytes.len() {
            return std::cmp::Ordering::Greater;
        }

        // Compare non-digit segment lexicographically
        if !a_bytes[ai].is_ascii_digit() || !b_bytes[bi].is_ascii_digit() {
            // Extract non-digit runs
            let a_start = ai;
            while ai < a_bytes.len() && a_bytes[ai].is_ascii_alphabetic() {
                ai += 1;
            }
            let b_start = bi;
            while bi < b_bytes.len() && b_bytes[bi].is_ascii_alphabetic() {
                bi += 1;
            }
            let a_seg = &a_bytes[a_start..ai];
            let b_seg = &b_bytes[b_start..bi];
            match a_seg.cmp(b_seg) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }

        // Compare digit segment numerically (skip leading zeros)
        let a_start = ai;
        while ai < a_bytes.len() && a_bytes[ai].is_ascii_digit() {
            ai += 1;
        }
        let b_start = bi;
        while bi < b_bytes.len() && b_bytes[bi].is_ascii_digit() {
            bi += 1;
        }

        let a_num: u64 = std::str::from_utf8(&a_bytes[a_start..ai])
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        let b_num: u64 = std::str::from_utf8(&b_bytes[b_start..bi])
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        match a_num.cmp(&b_num) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
}

fn is_os_ecosystem(eco: Ecosystem) -> bool {
    matches!(
        eco,
        Ecosystem::Alpine
            | Ecosystem::Wolfi
            | Ecosystem::Chainguard
            | Ecosystem::Debian
            | Ecosystem::Ubuntu
            | Ecosystem::Distroless
            | Ecosystem::RedHat
            | Ecosystem::CentOS
            | Ecosystem::Rocky
            | Ecosystem::AlmaLinux
            | Ecosystem::OracleLinux
            | Ecosystem::SUSE
            | Ecosystem::Photon
            | Ecosystem::AzureLinux
            | Ecosystem::CoreOS
            | Ecosystem::Bottlerocket
            | Ecosystem::Echo
            | Ecosystem::MinimOS
    )
}

/// Match a single package against the vulnerability database.
///
/// Strips a leading "v" from the version string before attempting semver
/// parsing. Both SEMVER and ECOSYSTEM range types are evaluated (ECOSYSTEM
/// is used by npm, PyPI, and Maven in OSV). If the version cannot be parsed
/// as semver the function returns an empty list.
pub fn match_package(store: &VulnStore, package: &Package) -> Vec<VulnerabilityMatch> {
    // OS ecosystems always use string-based version matching. Some OS
    // versions (e.g., Alpine's "1.36.1-r20") accidentally parse as valid
    // semver, but their ranges are ECOSYSTEM-typed and stored under
    // versioned ecosystem keys (e.g., "Alpine:v3.19") that the semver
    // path can't reach.
    if is_os_ecosystem(package.ecosystem) {
        return match_os_package(store, package);
    }

    let ecosystem = package.ecosystem.as_osv_ecosystem();

    // Strip leading "v" (e.g. Go uses "v1.2.3").
    let version_str = package.version.trim_start_matches('v');

    let pkg_version = match Version::parse(version_str) {
        Ok(v) => v,
        Err(_) => {
            return Vec::new();
        }
    };

    // Normalize package name for querying — PyPI uses lowercase names in OSV
    let query_name = match package.ecosystem {
        Ecosystem::Python => package.name.to_lowercase(),
        _ => package.name.clone(),
    };

    let query_results = match store.query(ecosystem, &query_name) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut matches = Vec::new();

    for result in query_results {
        for range in &result.ranges {
            // Accept both SEMVER and ECOSYSTEM range types — OSV uses ECOSYSTEM
            // for npm, PyPI, and Maven while Go uses SEMVER
            if range.range_type != "SEMVER" && range.range_type != "ECOSYSTEM" {
                continue;
            }

            let introduced = match &range.introduced {
                Some(v) if v != "0" => match Version::parse(v.trim_start_matches('v')) {
                    Ok(ver) => ver,
                    Err(_) => continue,
                },
                _ => Version::new(0, 0, 0),
            };

            // Is the package version at least as new as "introduced"?
            if pkg_version < introduced {
                continue;
            }

            // If there is a "fixed" version, the package must be older than it.
            if let Some(fixed_str) = &range.fixed {
                let fixed = match Version::parse(fixed_str.trim_start_matches('v')) {
                    Ok(ver) => ver,
                    Err(_) => continue,
                };
                if pkg_version >= fixed {
                    continue;
                }
            }

            // The package falls within this vulnerable range.
            matches.push(VulnerabilityMatch {
                package: package.clone(),
                vulnerability: Vulnerability {
                    id: result.id.clone(),
                    summary: result.summary.clone(),
                    severity: result.severity,
                    published: result.published.clone(),
                    modified: result.modified.clone(),
                    withdrawn: None,
                    source: result.source.clone(),
                    cvss_score: result.cvss_score,
                },
                introduced: range.introduced.clone(),
                fixed: range.fixed.clone(),
            });

            // Only report the first matching range per vulnerability result.
            break;
        }
    }

    matches
}

/// Match an OS package using string-based version comparison.
/// OS packages don't use semver, so we compare version strings directly.
/// This is imperfect but catches most cases where OSV provides ECOSYSTEM ranges.
fn match_os_package(store: &VulnStore, package: &Package) -> Vec<VulnerabilityMatch> {
    // Use the versioned OSV ecosystem name if available (e.g., "Alpine:v3.18")
    // Falls back to the base ecosystem name if not set
    let ecosystem = package
        .metadata
        .get("osv_ecosystem")
        .cloned()
        .unwrap_or_else(|| package.ecosystem.as_osv_ecosystem().to_string());

    // Query with the binary package name first.
    let mut query_results = store.query(&ecosystem, &package.name).unwrap_or_default();

    // Debian/Ubuntu OSV entries use source package names (e.g., "shadow")
    // while dpkg lists binary names (e.g., "login", "passwd"). Query with
    // the source package name too if it differs from the binary name.
    // Matches found via the source name use the source package identity so
    // the report-layer dedup (keyed by vuln_id + package_name + version)
    // collapses them across sibling binary packages.
    // Skip source-package lookup for the "linux" kernel source package
    // unless the binary IS the kernel (linux-image-*). The linux source
    // produces thousands of kernel CVEs that don't apply to userspace
    // packages like linux-libc-dev (just headers).
    let source_pkg = package
        .metadata
        .get("source_package")
        .filter(|s| s.as_str() != "linux" || package.name.starts_with("linux-image"));
    let mut source_result_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(src) = source_pkg
        && let Ok(source_results) = store.query(&ecosystem, src) {
            let seen: std::collections::HashSet<String> =
                query_results.iter().map(|r| r.id.clone()).collect();
            for r in source_results {
                if !seen.contains(&r.id) {
                    source_result_ids.insert(r.id.clone());
                    query_results.push(r);
                }
            }
        }

    let pkg_version = strip_epoch(&package.version);

    let mut matches = Vec::new();

    for result in query_results {
        for range in &result.ranges {
            if range.range_type != "ECOSYSTEM" {
                continue;
            }

            let is_after_introduced = match &range.introduced {
                Some(intro) if intro != "0" => {
                    compare_os_versions(pkg_version, strip_epoch(intro)) != std::cmp::Ordering::Less
                }
                _ => true,
            };

            let is_before_fixed = match &range.fixed {
                Some(fix) => {
                    compare_os_versions(pkg_version, strip_epoch(fix)) == std::cmp::Ordering::Less
                }
                None => true,
            };

            if is_after_introduced && is_before_fixed {
                let mut matched_pkg = package.clone();
                if source_result_ids.contains(&result.id)
                    && let Some(src) = source_pkg {
                        matched_pkg.name = src.clone();
                    }
                matches.push(VulnerabilityMatch {
                    package: matched_pkg,
                    vulnerability: crate::models::Vulnerability {
                        id: result.id.clone(),
                        summary: result.summary.clone(),
                        severity: result.severity,
                        published: result.published.clone(),
                        modified: result.modified.clone(),
                        withdrawn: None,
                        source: result.source.clone(),
                        cvss_score: result.cvss_score,
                    },
                    introduced: range.introduced.clone(),
                    fixed: range.fixed.clone(),
                });
                break;
            }
        }
    }

    matches
}

/// Match every package in the slice against the vulnerability database.
pub fn match_packages(store: &VulnStore, packages: &[Package]) -> Vec<VulnerabilityMatch> {
    packages
        .iter()
        .flat_map(|pkg| match_package(store, pkg))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::store::{AffectedPackage, AffectedRange, VulnRecord};
    use crate::models::{Ecosystem, Severity};
    use std::collections::HashMap;

    fn build_store() -> VulnStore {
        let mut store = VulnStore::open_in_memory().expect("in-memory db");
        let record = VulnRecord {
            id: "GO-2023-0001".to_string(),
            original_id: None,
            summary: "Test vulnerability".to_string(),
            severity: Severity::High,
            published: "2023-01-01T00:00:00Z".to_string(),
            modified: "2023-02-01T00:00:00Z".to_string(),
            withdrawn: None,
            source: "osv".to_string(),
            cvss_score: None,
            affected: vec![AffectedPackage {
                ecosystem: "Go".to_string(),
                package_name: "github.com/example/pkg".to_string(),
                ranges: vec![AffectedRange {
                    range_type: "SEMVER".to_string(),
                    introduced: Some("1.0.0".to_string()),
                    fixed: Some("1.2.3".to_string()),
                }],
                severity_override: None,
            }],
        };
        store.insert_vulnerabilities(&[record]).expect("insert");
        store
    }

    fn make_pkg(name: &str, version: &str) -> Package {
        Package {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: Ecosystem::Go,
            purl: format!("pkg:golang/{}@{}", name, version),
            metadata: HashMap::new(),
            source_file: None,
        }
    }

    #[test]
    fn test_match_vulnerable_package() {
        let store = build_store();
        let pkg = make_pkg("github.com/example/pkg", "v1.1.0");
        let results = match_package(&store, &pkg);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vulnerability.id, "GO-2023-0001");
        assert_eq!(results[0].vulnerability.severity, Severity::High);
    }

    #[test]
    fn test_no_match_fixed_version() {
        let store = build_store();
        // v1.2.3 is the fixed version (not affected).
        let pkg = make_pkg("github.com/example/pkg", "v1.2.3");
        let results = match_package(&store, &pkg);
        assert!(results.is_empty());
    }

    #[test]
    fn test_no_match_different_package() {
        let store = build_store();
        let pkg = make_pkg("github.com/other/pkg", "v1.1.0");
        let results = match_package(&store, &pkg);
        assert!(results.is_empty());
    }

    #[test]
    fn test_match_os_package_debian() {
        let mut store = VulnStore::open_in_memory().expect("in-memory db");
        store
            .insert_vulnerabilities(&[VulnRecord {
                id: "DSA-5678".to_string(),
                original_id: None,
                summary: "Debian openssl vuln".to_string(),
                severity: Severity::High,
                published: "2024-01-01T00:00:00Z".to_string(),
                modified: "2024-01-01T00:00:00Z".to_string(),
                withdrawn: None,
                affected: vec![AffectedPackage {
                    ecosystem: "Debian".to_string(),
                    package_name: "openssl".to_string(),
                    ranges: vec![AffectedRange {
                        range_type: "ECOSYSTEM".to_string(),
                        introduced: Some("0".to_string()),
                        fixed: Some("3.0.11-1~deb12u3".to_string()),
                    }],
                    severity_override: None,
                }],
                source: "osv".to_string(),
                cvss_score: None,
            }])
            .unwrap();

        let pkg = Package {
            name: "openssl".to_string(),
            version: "3.0.11-1~deb12u2".to_string(),
            ecosystem: Ecosystem::Debian,
            purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u2".to_string(),
            metadata: HashMap::new(),
            source_file: None,
        };

        let results = match_package(&store, &pkg);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vulnerability.id, "DSA-5678");
    }

    #[test]
    fn test_match_all_packages() {
        let store = build_store();
        let packages = vec![
            make_pkg("github.com/example/pkg", "v1.1.0"), // vulnerable
            make_pkg("github.com/example/pkg", "v1.2.3"), // fixed
            make_pkg("github.com/other/pkg", "v1.1.0"),   // not in db
        ];
        let results = match_packages(&store, &packages);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vulnerability.id, "GO-2023-0001");
    }

    #[test]
    fn test_compare_os_versions_numeric() {
        use std::cmp::Ordering::*;
        // Numeric segments compare numerically, not lexicographically
        assert_eq!(compare_os_versions("5.40", "5.8"), Greater);
        assert_eq!(compare_os_versions("2.36", "2.6"), Greater);
        assert_eq!(compare_os_versions("13.8", "2.6"), Greater);
        assert_eq!(compare_os_versions("1.3.1", "1.3.5"), Less);
        assert_eq!(compare_os_versions("1.0", "1.0"), Equal);
    }

    #[test]
    fn test_compare_os_versions_debian_style() {
        use std::cmp::Ordering::*;
        // Full Debian version strings
        assert_eq!(compare_os_versions("5.40.0-6", "5.8.0-7"), Greater);
        assert_eq!(compare_os_versions("2.36-9+deb12u13", "2.6.6-1"), Greater);
        assert_eq!(compare_os_versions("1.36.1-r20", "1.36.1-r21"), Less);
        assert_eq!(
            compare_os_versions("3.0.11-1~deb12u2", "3.0.11-1~deb12u3"),
            Less
        );
    }

    #[test]
    fn test_compare_os_versions_tilde() {
        use std::cmp::Ordering::*;
        // Tilde sorts before everything (pre-release)
        assert_eq!(compare_os_versions("1.0~beta1", "1.0"), Less);
        assert_eq!(compare_os_versions("1.0~beta1", "1.0~beta2"), Less);
        assert_eq!(compare_os_versions("1.0", "1.0~beta1"), Greater);
    }

    #[test]
    fn test_compare_os_versions_alpha_segments() {
        use std::cmp::Ordering::*;
        assert_eq!(compare_os_versions("1.0a", "1.0b"), Less);
        assert_eq!(compare_os_versions("1.0b", "1.0a"), Greater);
        assert_eq!(compare_os_versions("1.0a1", "1.0a2"), Less);
    }

    #[test]
    fn test_compare_os_versions_alpine() {
        use std::cmp::Ordering::*;
        // Alpine uses -rN suffixes
        assert_eq!(compare_os_versions("1.36.1-r20", "1.36.1-r21"), Less);
        assert_eq!(
            compare_os_versions("1.2.4_git20230717-r5", "1.2.4_git20230717-r6"),
            Less
        );
    }
}

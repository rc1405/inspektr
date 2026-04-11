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
    let ecosystem = package.ecosystem.as_osv_ecosystem();

    // Strip leading "v" (e.g. Go uses "v1.2.3").
    let version_str = package.version.trim_start_matches('v');

    let pkg_version = match Version::parse(version_str) {
        Ok(v) => v,
        Err(_) => {
            // For OS ecosystems, fall back to string-based matching
            if is_os_ecosystem(package.ecosystem) {
                return match_os_package(store, package);
            }
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
                Some(v) => match Version::parse(v.trim_start_matches('v')) {
                    Ok(ver) => ver,
                    Err(_) => continue,
                },
                // No introduced means affected from the beginning.
                None => Version::new(0, 0, 0),
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

    let query_name = package.name.clone();
    let query_results = match store.query(&ecosystem, &query_name) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut matches = Vec::new();

    for result in query_results {
        for range in &result.ranges {
            if range.range_type != "ECOSYSTEM" {
                continue;
            }

            // For OS packages with ECOSYSTEM ranges, check:
            // 1. If there's a fixed version and our version string != the fixed version,
            //    and our version is lexicographically less than fixed → vulnerable
            // 2. If there's no fixed version → all versions after introduced are vulnerable
            let is_after_introduced = match &range.introduced {
                Some(intro) if intro != "0" => package.version.as_str() >= intro.as_str(),
                _ => true,
            };

            let is_before_fixed = match &range.fixed {
                Some(fix) => package.version.as_str() < fix.as_str(),
                None => true,
            };

            if is_after_introduced && is_before_fixed {
                matches.push(VulnerabilityMatch {
                    package: package.clone(),
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
}

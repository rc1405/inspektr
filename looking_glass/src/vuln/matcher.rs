use crate::db::store::VulnStore;
use crate::models::{Package, VulnerabilityMatch, Vulnerability};
use semver::Version;

/// Match a single package against the vulnerability database.
///
/// Strips a leading "v" from the version string before attempting semver
/// parsing. Only SEMVER ranges are evaluated; ranges of other types are
/// skipped. If the version cannot be parsed as semver the function returns
/// an empty list.
pub fn match_package(store: &VulnStore, package: &Package) -> Vec<VulnerabilityMatch> {
    let ecosystem = package.ecosystem.as_osv_ecosystem();

    // Strip leading "v" (e.g. Go uses "v1.2.3").
    let version_str = package.version.trim_start_matches('v');

    let pkg_version = match Version::parse(version_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let query_results = match store.query(ecosystem, &package.name) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut matches = Vec::new();

    for result in query_results {
        for range in &result.ranges {
            if range.range_type != "SEMVER" {
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
                    details: result.details.clone(),
                    severity: result.severity,
                    published: result.published.clone(),
                    modified: result.modified.clone(),
                    withdrawn: None,
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
            details: "Details here.".to_string(),
            severity: Severity::High,
            published: "2023-01-01T00:00:00Z".to_string(),
            modified: "2023-02-01T00:00:00Z".to_string(),
            withdrawn: None,
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

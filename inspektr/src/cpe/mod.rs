pub mod mappings;

use mappings::{resolve_by_target_sw, resolve_by_vendor};

/// A CPE that has been resolved to an ecosystem + package name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCpe {
    pub ecosystem: String,
    pub package_name: String,
}

/// The subset of CPE 2.3 fields we care about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeFields {
    pub vendor: String,
    pub product: String,
    pub target_sw: String,
}

/// Parse a CPE 2.3 formatted string and return the relevant fields.
///
/// Only CPEs with part type `a` (application) are accepted.
/// The expected format is:
///   `cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>`
///
/// Returns `None` if the string does not look like a valid CPE 2.3 application entry.
pub fn parse_cpe(cpe: &str) -> Option<CpeFields> {
    // Must start with "cpe:2.3:"
    let without_prefix = cpe.strip_prefix("cpe:2.3:")?;

    let parts: Vec<&str> = without_prefix.splitn(11, ':').collect();
    // We need at least: part, vendor, product, version, update, edition,
    //                   language, sw_edition, target_sw  (index 8)
    if parts.len() < 9 {
        return None;
    }

    // Only handle application CPEs
    if parts[0] != "a" {
        return None;
    }

    let vendor = parts[1].to_string();
    let product = parts[2].to_string();
    let target_sw = parts[8].to_string();

    Some(CpeFields {
        vendor,
        product,
        target_sw,
    })
}

/// Attempt to resolve a CPE string to an ecosystem + package name.
///
/// Strategy:
/// 1. Parse the CPE – if parsing fails return `None`.
/// 2. Try `resolve_by_target_sw` (only when target_sw is not `*`).
/// 3. Fall back to `resolve_by_vendor`.
pub fn resolve_cpe(cpe: &str) -> Option<ResolvedCpe> {
    let fields = parse_cpe(cpe)?;

    // Try target_sw first (skip wildcard / not-applicable values)
    if fields.target_sw != "*" && fields.target_sw != "-" {
        if let Some(resolved) = resolve_by_target_sw(&fields) {
            return Some(resolved);
        }
    }

    // Fall back to vendor heuristics
    resolve_by_vendor(&fields)
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_cpe ---------------------------------------------------------------------------------

    #[test]
    fn test_parse_cpe_full() {
        // lodash with node.js as target_sw
        let cpe = "cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:node.js:*:*";
        let fields = parse_cpe(cpe).expect("should parse");
        assert_eq!(fields.vendor, "lodash");
        assert_eq!(fields.product, "lodash");
        assert_eq!(fields.target_sw, "node.js");
    }

    #[test]
    fn test_parse_cpe_short() {
        // apache log4j – target_sw is wildcard
        let cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*";
        let fields = parse_cpe(cpe).expect("should parse");
        assert_eq!(fields.vendor, "apache");
        assert_eq!(fields.product, "log4j");
        assert_eq!(fields.target_sw, "*");
    }

    #[test]
    fn test_parse_cpe_invalid() {
        // plain string – not a CPE
        assert!(parse_cpe("not-a-cpe-string").is_none());
        // OS type (part = "o") – should be rejected
        assert!(parse_cpe("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*").is_none());
    }

    // -- resolve_cpe: target_sw path ---------------------------------------------------------------

    #[test]
    fn test_resolve_npm_by_target_sw() {
        let cpe = "cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:node.js:*:*";
        let resolved = resolve_cpe(cpe).expect("should resolve");
        assert_eq!(resolved.ecosystem, "npm");
        assert_eq!(resolved.package_name, "lodash");
    }

    #[test]
    fn test_resolve_pypi_by_target_sw() {
        let cpe = "cpe:2.3:a:pallets:flask:2.0.1:*:*:*:*:python:*:*";
        let resolved = resolve_cpe(cpe).expect("should resolve");
        assert_eq!(resolved.ecosystem, "PyPI");
        assert_eq!(resolved.package_name, "flask");
    }

    #[test]
    fn test_resolve_maven_by_target_sw() {
        let cpe = "cpe:2.3:a:fasterxml:jackson-databind:2.13.0:*:*:*:*:java:*:*";
        let resolved = resolve_cpe(cpe).expect("should resolve");
        assert_eq!(resolved.ecosystem, "Maven");
        assert_eq!(resolved.package_name, "fasterxml:jackson-databind");
    }

    #[test]
    fn test_resolve_go_by_target_sw() {
        let cpe = "cpe:2.3:a:hashicorp:vault:1.9.0:*:*:*:*:go:*:*";
        let resolved = resolve_cpe(cpe).expect("should resolve");
        assert_eq!(resolved.ecosystem, "Go");
        assert_eq!(resolved.package_name, "hashicorp/vault");
    }

    // -- resolve_cpe: vendor heuristic path -------------------------------------------------------

    #[test]
    fn test_resolve_npm_by_vendor_project_suffix() {
        // vendor = "minimist_project" -> npm
        let cpe = "cpe:2.3:a:minimist_project:minimist:1.2.5:*:*:*:*:*:*:*";
        let resolved = resolve_cpe(cpe).expect("should resolve");
        assert_eq!(resolved.ecosystem, "npm");
        assert_eq!(resolved.package_name, "minimist");
    }

    #[test]
    fn test_resolve_java_by_known_vendor() {
        // vendor = "fasterxml" -> Maven, group = "com.fasterxml"
        let cpe = "cpe:2.3:a:fasterxml:jackson-core:2.13.0:*:*:*:*:*:*:*";
        let resolved = resolve_cpe(cpe).expect("should resolve");
        assert_eq!(resolved.ecosystem, "Maven");
        assert_eq!(resolved.package_name, "com.fasterxml:jackson-core");
    }

    #[test]
    fn test_resolve_python_by_known_vendor() {
        // vendor = "djangoproject" -> PyPI
        let cpe = "cpe:2.3:a:djangoproject:django:4.0.0:*:*:*:*:*:*:*";
        let resolved = resolve_cpe(cpe).expect("should resolve");
        assert_eq!(resolved.ecosystem, "PyPI");
        assert_eq!(resolved.package_name, "django");
    }

    #[test]
    fn test_resolve_unknown_skipped() {
        // vendor and target_sw give no hints
        let cpe = "cpe:2.3:a:someunknownvendor:sometool:1.0.0:*:*:*:*:*:*:*";
        assert!(resolve_cpe(cpe).is_none());
    }
}

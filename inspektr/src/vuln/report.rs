//! Vulnerability scan report generation and rendering.
//!
//! Builds structured [`ScanReport`] documents from vulnerability matches,
//! merging assessments from multiple data sources (e.g., OSV and NVD) into
//! a single report. Reports can be rendered as:
//!
//! - Human-readable tables via [`render_report_table()`]
//! - JSON via [`render_report_json()`]

use crate::models::{Severity, VulnerabilityMatch};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// A complete vulnerability scan report.
///
/// Contains metadata about the scan (target, tool version, severity counts)
/// and a list of vulnerability details. This is the primary output of
/// [`pipeline::scan_and_report()`](crate::pipeline::scan_and_report).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Metadata about the scan itself.
    pub metadata: ScanMetadata,
    /// Individual vulnerability findings, deduplicated across data sources.
    pub vulnerabilities: Vec<VulnDetail>,
}

/// Metadata about a vulnerability scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// The tool name (`"inspektr"`).
    pub tool: String,
    /// The tool version.
    pub version: String,
    /// ISO 8601 timestamp when the scan was performed.
    pub timestamp: String,
    /// The target that was scanned.
    pub target: String,
    /// The type of target (`"filesystem"`, `"oci"`, `"binary"`, `"sbom"`).
    pub target_type: String,
    /// Total number of packages scanned.
    pub total_packages: usize,
    /// Total number of unique vulnerabilities found.
    pub total_vulnerabilities: usize,
    /// Breakdown of vulnerabilities by severity level.
    pub severity_counts: SeverityCounts,
}

/// Vulnerability counts by severity level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCounts {
    /// Number of critical-severity vulnerabilities.
    pub critical: usize,
    /// Number of high-severity vulnerabilities.
    pub high: usize,
    /// Number of medium-severity vulnerabilities.
    pub medium: usize,
    /// Number of low-severity vulnerabilities.
    pub low: usize,
    /// Number of vulnerabilities with no assigned severity.
    pub none: usize,
}

/// Detailed information about a single vulnerability finding.
///
/// When the same vulnerability (e.g., `CVE-2023-44487`) is reported by
/// multiple data sources (OSV, NVD), their assessments are merged into the
/// [`assessments`](VulnDetail::assessments) map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnDetail {
    /// The vulnerability identifier (e.g., `"CVE-2023-44487"`).
    pub id: String,
    /// A short description of the vulnerability.
    pub summary: String,
    /// The affected package name.
    pub package_name: String,
    /// The affected package version.
    pub package_version: String,
    /// The ecosystem name (OSV format).
    pub ecosystem: String,
    /// The Package URL of the affected package.
    pub purl: String,
    /// The source file where the package was discovered.
    pub source_file: Option<String>,
    /// The version where the vulnerability was introduced.
    pub introduced: Option<String>,
    /// The version where the vulnerability was fixed.
    pub fixed_version: Option<String>,
    /// When the vulnerability was first published.
    pub published: String,
    /// Severity assessments from each data source (key = source name).
    pub assessments: HashMap<String, SourceAssessment>,
}

/// A severity assessment from a single data source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAssessment {
    /// The severity level assigned by this source.
    pub severity: Severity,
    /// The CVSS v3 base score (0.0–10.0), if available from this source.
    pub cvss_score: Option<f64>,
}

// ---------------------------------------------------------------------------
// Report builder
// ---------------------------------------------------------------------------

/// Build a [`ScanReport`] from vulnerability matches.
///
/// Deduplicates vulnerabilities by (ID, package name, package version) and
/// merges assessments from multiple data sources into a single entry.
pub fn build_scan_report(
    target: &str,
    target_type: &str,
    total_packages: usize,
    matches: &[VulnerabilityMatch],
) -> ScanReport {
    let mut details: Vec<VulnDetail> = Vec::new();
    let mut index: HashMap<(String, String, String), usize> = HashMap::new();

    for m in matches {
        // Strip Debian epoch from version for dedup — binary packages from
        // the same source can have different epochs (e.g., "1:2.41-5" vs
        // "2.41-5") but represent the same upstream version.
        let dedup_version = match m.package.version.find(':') {
            Some(pos) if m.package.version[..pos].bytes().all(|b| b.is_ascii_digit()) => {
                m.package.version[pos + 1..].to_string()
            }
            _ => m.package.version.clone(),
        };
        let key = (
            m.vulnerability.id.clone(),
            m.package.name.clone(),
            dedup_version,
        );

        if let Some(&idx) = index.get(&key) {
            details[idx].assessments.insert(
                m.vulnerability.source.clone(),
                SourceAssessment {
                    severity: m.vulnerability.severity,
                    cvss_score: m.vulnerability.cvss_score,
                },
            );
        } else {
            let idx = details.len();
            index.insert(key, idx);
            let mut assessments = HashMap::new();
            assessments.insert(
                m.vulnerability.source.clone(),
                SourceAssessment {
                    severity: m.vulnerability.severity,
                    cvss_score: m.vulnerability.cvss_score,
                },
            );
            details.push(VulnDetail {
                id: m.vulnerability.id.clone(),
                summary: m.vulnerability.summary.clone(),
                package_name: m.package.name.clone(),
                package_version: m.package.version.clone(),
                ecosystem: m.package.ecosystem.as_osv_ecosystem().to_string(),
                purl: m.package.purl.clone(),
                source_file: m.package.source_file.clone(),
                introduced: m.introduced.clone(),
                fixed_version: m.fixed.clone(),
                published: m.vulnerability.published.clone(),
                assessments,
            });
        }
    }

    // Severity counts using highest per vuln
    let mut counts = SeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        none: 0,
    };
    for v in &details {
        match highest_severity(v) {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::None => counts.none += 1,
        }
    }

    let timestamp = crate::sbom::spdx::chrono_now();

    ScanReport {
        metadata: ScanMetadata {
            tool: "inspektr".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp,
            target: target.to_string(),
            target_type: target_type.to_string(),
            total_packages,
            total_vulnerabilities: details.len(),
            severity_counts: counts,
        },
        vulnerabilities: details,
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Return the highest severity across all data source assessments for a vulnerability.
pub fn highest_severity(v: &VulnDetail) -> Severity {
    v.assessments
        .values()
        .map(|a| a.severity)
        .max()
        .unwrap_or(Severity::None)
}

fn best_cvss_score(v: &VulnDetail) -> Option<f64> {
    v.assessments
        .values()
        .filter_map(|a| a.cvss_score)
        .reduce(f64::max)
}

fn sources_list(v: &VulnDetail) -> String {
    let mut sources: Vec<&str> = v.assessments.keys().map(|s| s.as_str()).collect();
    sources.sort();
    sources.join(",")
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

/// Render a scan report as a human-readable ASCII table.
///
/// Includes a summary header with target, package count, and severity
/// breakdown, followed by a columnar table of vulnerability details.
pub fn render_report_table(report: &ScanReport) -> String {
    let mut output = String::new();

    // Summary header
    output.push_str(&format!("Target: {}\n", report.metadata.target));
    let c = &report.metadata.severity_counts;
    output.push_str(&format!(
        "Packages: {} | Vulnerabilities: {} (Critical: {}, High: {}, Medium: {}, Low: {})\n\n",
        report.metadata.total_packages,
        report.metadata.total_vulnerabilities,
        c.critical,
        c.high,
        c.medium,
        c.low,
    ));

    if report.vulnerabilities.is_empty() {
        output.push_str("No vulnerabilities found.\n");
        return output;
    }

    let header = [
        "VULNERABILITY",
        "PACKAGE",
        "VERSION",
        "SEVERITY",
        "CVSS",
        "FIXED",
        "SOURCE",
        "SOURCES",
    ];

    let rows: Vec<[String; 8]> = report
        .vulnerabilities
        .iter()
        .map(|v| {
            let severity = format!("{:?}", highest_severity(v));
            let cvss = best_cvss_score(v)
                .map(|s| format!("{:.1}", s))
                .unwrap_or_else(|| "-".to_string());
            let fixed = v.fixed_version.clone().unwrap_or_else(|| "-".to_string());
            let source = v.source_file.as_deref().unwrap_or("-").to_string();
            let source_short = source.rsplit('/').next().unwrap_or(&source).to_string();
            [
                v.id.clone(),
                v.package_name.clone(),
                v.package_version.clone(),
                severity,
                cvss,
                fixed,
                source_short,
                sources_list(v),
            ]
        })
        .collect();

    // Compute widths
    let mut widths: [usize; 8] = std::array::from_fn(|i| header[i].len());
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    // Header
    for (i, h) in header.iter().enumerate() {
        if i > 0 {
            output.push_str("  ");
        }
        output.push_str(&format!("{:<w$}", h, w = widths[i]));
    }
    output.push('\n');

    // Separator
    let sep: String = widths
        .iter()
        .map(|&w| "-".repeat(w))
        .collect::<Vec<_>>()
        .join("  ");
    output.push_str(&sep);
    output.push('\n');

    // Rows
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                output.push_str("  ");
            }
            output.push_str(&format!("{:<w$}", cell, w = widths[i]));
        }
        output.push('\n');
    }

    output
}

/// Render a scan report as pretty-printed JSON.
pub fn render_report_json(report: &ScanReport) -> Result<String, crate::error::InspektrError> {
    serde_json::to_string_pretty(report).map_err(|e| {
        crate::error::InspektrError::SbomFormat(crate::error::SbomFormatError::EncodeFailed(
            e.to_string(),
        ))
    })
}

/// Return `true` if any vulnerability in the report has a severity at or above `threshold`.
pub fn has_severity_at_or_above_report(report: &ScanReport, threshold: Severity) -> bool {
    report
        .vulnerabilities
        .iter()
        .any(|v| highest_severity(v) >= threshold)
}

/// Return true if any match has a severity at or above `threshold`.
pub fn has_severity_at_or_above(matches: &[VulnerabilityMatch], threshold: Severity) -> bool {
    matches
        .iter()
        .any(|m| m.vulnerability.severity >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Ecosystem, Package, Vulnerability, VulnerabilityMatch};
    use std::collections::HashMap;

    fn make_match(id: &str, severity: Severity, fixed: Option<&str>) -> VulnerabilityMatch {
        VulnerabilityMatch {
            package: Package {
                name: "github.com/example/pkg".to_string(),
                version: "v1.1.0".to_string(),
                ecosystem: Ecosystem::Go,
                purl: "pkg:golang/github.com/example/pkg@v1.1.0".to_string(),
                metadata: HashMap::new(),
                source_file: None,
            },
            vulnerability: Vulnerability {
                id: id.to_string(),
                summary: "Test summary".to_string(),
                severity,
                published: "2023-01-01T00:00:00Z".to_string(),
                modified: "2023-02-01T00:00:00Z".to_string(),
                withdrawn: None,
                source: "osv".to_string(),
                cvss_score: None,
            },
            introduced: Some("1.0.0".to_string()),
            fixed: fixed.map(|s| s.to_string()),
        }
    }

    fn make_match_with_source(
        id: &str,
        severity: Severity,
        fixed: Option<&str>,
        source: &str,
        cvss: Option<f64>,
    ) -> VulnerabilityMatch {
        VulnerabilityMatch {
            package: Package {
                name: "github.com/example/pkg".to_string(),
                version: "v1.1.0".to_string(),
                ecosystem: Ecosystem::Go,
                purl: "pkg:golang/github.com/example/pkg@v1.1.0".to_string(),
                metadata: HashMap::new(),
                source_file: Some("/project/go.mod".to_string()),
            },
            vulnerability: Vulnerability {
                id: id.to_string(),
                summary: "Test vulnerability".to_string(),
                severity,
                published: "2023-01-01T00:00:00Z".to_string(),
                modified: "2023-01-01T00:00:00Z".to_string(),
                withdrawn: None,
                source: source.to_string(),
                cvss_score: cvss,
            },
            introduced: Some("1.0.0".to_string()),
            fixed: fixed.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_report_json() {
        let matches = vec![make_match_with_source(
            "GO-2023-0001",
            Severity::High,
            Some("1.2.3"),
            "osv",
            None,
        )];
        let report = build_scan_report("target", "filesystem", 1, &matches);
        let json = render_report_json(&report).expect("should render JSON");
        assert!(json.contains("GO-2023-0001"));
        assert!(json.contains("High"));
        // Pretty-printed JSON should contain newlines.
        assert!(json.contains('\n'));
        // Should be valid JSON with metadata.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");
        assert!(parsed.is_object());
        assert!(parsed["metadata"].is_object());
        assert!(parsed["vulnerabilities"].is_array());
        assert_eq!(parsed["vulnerabilities"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_report_table() {
        let matches = vec![
            make_match_with_source("GO-2023-0001", Severity::High, Some("1.2.3"), "osv", None),
            make_match_with_source("GO-2023-0002", Severity::Critical, None, "osv", None),
        ];
        let report = build_scan_report("target", "filesystem", 2, &matches);
        let table = render_report_table(&report);
        assert!(table.contains("VULNERABILITY"));
        assert!(table.contains("PACKAGE"));
        assert!(table.contains("VERSION"));
        assert!(table.contains("SEVERITY"));
        assert!(table.contains("FIXED"));
        assert!(table.contains("GO-2023-0001"));
        assert!(table.contains("GO-2023-0002"));
        assert!(table.contains("High"));
        assert!(table.contains("Critical"));
        assert!(table.contains("1.2.3"));
        // Second match has no fix.
        assert!(table.contains('-'));
    }

    #[test]
    fn test_has_severity_at_or_above() {
        let matches = vec![
            make_match("GO-2023-0001", Severity::Medium, Some("1.2.3")),
            make_match("GO-2023-0002", Severity::High, None),
        ];

        assert!(has_severity_at_or_above(&matches, Severity::High));
        assert!(has_severity_at_or_above(&matches, Severity::Medium));
        assert!(!has_severity_at_or_above(&matches, Severity::Critical));
        assert!(!has_severity_at_or_above(&[], Severity::None));
    }

    #[test]
    fn test_build_scan_report_merges_sources() {
        let matches = vec![
            make_match_with_source("CVE-2021-001", Severity::High, Some("1.2.0"), "osv", None),
            make_match_with_source(
                "CVE-2021-001",
                Severity::Critical,
                Some("1.2.0"),
                "nvd",
                Some(9.8),
            ),
        ];
        let report = build_scan_report("test-target", "filesystem", 5, &matches);
        assert_eq!(report.vulnerabilities.len(), 1);
        assert_eq!(report.vulnerabilities[0].assessments.len(), 2);
        assert!(report.vulnerabilities[0].assessments.contains_key("osv"));
        assert!(report.vulnerabilities[0].assessments.contains_key("nvd"));
        assert_eq!(
            report.vulnerabilities[0].assessments["nvd"].cvss_score,
            Some(9.8)
        );
    }

    #[test]
    fn test_build_scan_report_severity_counts() {
        let matches = vec![
            make_match_with_source("CVE-001", Severity::Critical, None, "osv", None),
            make_match_with_source("CVE-002", Severity::Medium, Some("2.0"), "osv", None),
        ];
        let report = build_scan_report("target", "filesystem", 10, &matches);
        assert_eq!(report.metadata.severity_counts.critical, 1);
        assert_eq!(report.metadata.severity_counts.medium, 1);
        assert_eq!(report.metadata.total_vulnerabilities, 2);
        assert_eq!(report.metadata.total_packages, 10);
    }

    #[test]
    fn test_render_report_table_has_header() {
        let matches = vec![make_match_with_source(
            "CVE-001",
            Severity::High,
            Some("2.0"),
            "osv",
            Some(7.5),
        )];
        let report = build_scan_report("test-target", "filesystem", 3, &matches);
        let table = render_report_table(&report);
        assert!(table.contains("Target: test-target"));
        assert!(table.contains("Packages: 3"));
        assert!(table.contains("VULNERABILITY"));
        assert!(table.contains("CVSS"));
        assert!(table.contains("SOURCES"));
        assert!(table.contains("CVE-001"));
    }

    #[test]
    fn test_render_report_json_has_metadata() {
        let matches = vec![make_match_with_source(
            "CVE-001",
            Severity::High,
            Some("2.0"),
            "osv",
            None,
        )];
        let report = build_scan_report("target", "filesystem", 5, &matches);
        let json = render_report_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["metadata"]["tool"], "inspektr");
        assert_eq!(parsed["metadata"]["total_packages"], 5);
        assert!(parsed["vulnerabilities"].is_array());
    }
}

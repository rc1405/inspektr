use crate::error::LookingGlassError;
use crate::models::{Severity, VulnerabilityMatch};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// New report types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub metadata: ScanMetadata,
    pub vulnerabilities: Vec<VulnDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub tool: String,
    pub version: String,
    pub timestamp: String,
    pub target: String,
    pub target_type: String,
    pub total_packages: usize,
    pub total_vulnerabilities: usize,
    pub severity_counts: SeverityCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub none: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnDetail {
    pub id: String,
    pub summary: String,
    pub package_name: String,
    pub package_version: String,
    pub ecosystem: String,
    pub purl: String,
    pub source_file: Option<String>,
    pub introduced: Option<String>,
    pub fixed_version: Option<String>,
    pub published: String,
    pub assessments: HashMap<String, SourceAssessment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAssessment {
    pub severity: Severity,
    pub cvss_score: Option<f64>,
}

// ---------------------------------------------------------------------------
// New report builder
// ---------------------------------------------------------------------------

pub fn build_scan_report(
    target: &str,
    target_type: &str,
    total_packages: usize,
    matches: &[VulnerabilityMatch],
) -> ScanReport {
    let mut details: Vec<VulnDetail> = Vec::new();
    let mut index: HashMap<(String, String, String), usize> = HashMap::new();

    for m in matches {
        let key = (
            m.vulnerability.id.clone(),
            m.package.name.clone(),
            m.package.version.clone(),
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
            tool: "looking-glass".to_string(),
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
// Helper functions for new report types
// ---------------------------------------------------------------------------

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
// New renderers
// ---------------------------------------------------------------------------

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

pub fn render_report_json(report: &ScanReport) -> Result<String, crate::error::LookingGlassError> {
    serde_json::to_string_pretty(report).map_err(|e| {
        crate::error::LookingGlassError::SbomFormat(crate::error::SbomFormatError::EncodeFailed(
            e.to_string(),
        ))
    })
}

pub fn has_severity_at_or_above_report(report: &ScanReport, threshold: Severity) -> bool {
    report
        .vulnerabilities
        .iter()
        .any(|v| highest_severity(v) >= threshold)
}

// ---------------------------------------------------------------------------
// Legacy functions (kept for backward compatibility)
// ---------------------------------------------------------------------------

/// Render vulnerability matches as a pretty-printed JSON string.
pub fn render_json(matches: &[VulnerabilityMatch]) -> Result<String, LookingGlassError> {
    serde_json::to_string_pretty(matches).map_err(|e| {
        LookingGlassError::SbomFormat(crate::error::SbomFormatError::EncodeFailed(e.to_string()))
    })
}

/// Render vulnerability matches as a fixed-width text table.
///
/// Columns: VULNERABILITY | PACKAGE | VERSION | SEVERITY | FIX
pub fn render_table(matches: &[VulnerabilityMatch]) -> String {
    if matches.is_empty() {
        return "No vulnerabilities found.\n".to_string();
    }

    // Collect rows first so we can compute column widths.
    let header = ["VULNERABILITY", "PACKAGE", "VERSION", "SEVERITY", "FIX"];

    let rows: Vec<[String; 5]> = matches
        .iter()
        .map(|m| {
            [
                m.vulnerability.id.clone(),
                m.package.name.clone(),
                m.package.version.clone(),
                format!("{:?}", m.vulnerability.severity),
                m.fixed.clone().unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect();

    // Compute column widths.
    let mut widths = [
        header[0].len(),
        header[1].len(),
        header[2].len(),
        header[3].len(),
        header[4].len(),
    ];

    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }

    let mut output = String::new();

    // Header row.
    output.push_str(&format!(
        "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}\n",
        header[0],
        header[1],
        header[2],
        header[3],
        header[4],
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4],
    ));

    // Separator line.
    let separator: String = widths
        .iter()
        .map(|&w| "-".repeat(w))
        .collect::<Vec<_>>()
        .join("  ");
    output.push_str(&separator);
    output.push('\n');

    // Data rows.
    for row in &rows {
        output.push_str(&format!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}\n",
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4],
        ));
    }

    output
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
                details: "Test details.".to_string(),
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
                details: String::new(),
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
        let matches = vec![make_match("GO-2023-0001", Severity::High, Some("1.2.3"))];
        let json = render_json(&matches).expect("should render JSON");
        assert!(json.contains("GO-2023-0001"));
        assert!(json.contains("High"));
        // Pretty-printed JSON should contain newlines.
        assert!(json.contains('\n'));
        // Should be valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_report_table() {
        let matches = vec![
            make_match("GO-2023-0001", Severity::High, Some("1.2.3")),
            make_match("GO-2023-0002", Severity::Critical, None),
        ];
        let table = render_table(&matches);
        assert!(table.contains("VULNERABILITY"));
        assert!(table.contains("PACKAGE"));
        assert!(table.contains("VERSION"));
        assert!(table.contains("SEVERITY"));
        assert!(table.contains("FIX"));
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
        assert_eq!(parsed["metadata"]["tool"], "looking-glass");
        assert_eq!(parsed["metadata"]["total_packages"], 5);
        assert!(parsed["vulnerabilities"].is_array());
    }
}

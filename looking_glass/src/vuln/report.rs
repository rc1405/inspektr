use crate::error::LookingGlassError;
use crate::models::{Severity, VulnerabilityMatch};

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
            },
            vulnerability: Vulnerability {
                id: id.to_string(),
                summary: "Test summary".to_string(),
                details: "Test details.".to_string(),
                severity,
                published: "2023-01-01T00:00:00Z".to_string(),
                modified: "2023-02-01T00:00:00Z".to_string(),
                withdrawn: None,
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
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("should be valid JSON");
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
}

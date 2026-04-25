//! OSV (Open Source Vulnerability) data importer.
//!
//! Downloads and parses OSV bulk data for all supported ecosystems. OSV
//! provides vulnerability data for both language ecosystems and OS
//! distributions.
//!
//! Requires the `db-admin` feature.

use crate::db::store::{AffectedPackage, AffectedRange, VulnRecord, VulnStore};
use crate::models::Severity;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// OSV JSON schema structs
// ---------------------------------------------------------------------------

/// A single OSV vulnerability entry, as parsed from the OSV JSON format.
#[derive(Debug, Deserialize)]
pub struct OsvEntry {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub published: String,
    #[serde(default)]
    pub modified: String,
    pub withdrawn: Option<String>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    pub database_specific: Option<OsvDatabaseSpecific>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffected {
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub ecosystem_specific: Option<OsvEcosystemSpecific>,
}

#[derive(Debug, Deserialize)]
pub struct OsvEcosystemSpecific {
    #[serde(default)]
    pub urgency: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvDatabaseSpecific {
    pub severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type", default)]
    pub severity_type: String,
    pub score: String,
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parse a single OSV JSON string into a `VulnRecord`.
///
/// OSV represents affected ranges as a list of events in the form
/// `[{introduced: "X"}, {fixed: "Y"}, ...]`.  We convert consecutive
/// introduced/fixed pairs into `AffectedRange` values.
pub fn parse_osv_entry(json: &str) -> Result<VulnRecord, serde_json::Error> {
    let entry: OsvEntry = serde_json::from_str(json)?;

    // --- Severity resolution (CVSS vector > database_specific > None) ---
    let (severity, cvss_score) = resolve_severity(&entry);

    // --- ID normalization: prefer CVE alias ---
    let (id, original_id) = normalize_id(&entry.id, &entry.aliases);

    let affected = entry
        .affected
        .into_iter()
        .filter_map(|a| {
            let pkg = a.package?;
            let ranges = a
                .ranges
                .into_iter()
                .flat_map(|r| events_to_ranges(&r.range_type, &r.events))
                .collect();

            let severity_override = a
                .ecosystem_specific
                .as_ref()
                .and_then(|es| es.urgency.as_deref())
                .and_then(urgency_to_severity);

            Some(AffectedPackage {
                ecosystem: pkg.ecosystem,
                package_name: pkg.name,
                ranges,
                severity_override,
            })
        })
        .collect();

    Ok(VulnRecord {
        id,
        original_id,
        summary: entry.summary,
        severity,
        published: entry.published,
        modified: entry.modified,
        withdrawn: entry.withdrawn,
        source: "osv".to_string(),
        cvss_score,
        affected,
    })
}

/// Map a Debian/Ubuntu `ecosystem_specific.urgency` value to a severity.
///
/// Returns `None` for "not yet assigned" (untriaged) so NVD enrichment
/// can fill it in later, and for unrecognized values.
fn urgency_to_severity(urgency: &str) -> Option<Severity> {
    match urgency.to_lowercase().as_str() {
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "unimportant" => Some(Severity::Low),
        _ => None,
    }
}

/// Resolve severity from an OSV entry using priority:
/// 1. Top-level `severity[]` CVSS_V3 vector → score + level
/// 2. `database_specific.severity` text → level only
/// 3. None
fn resolve_severity(entry: &OsvEntry) -> (Severity, Option<f64>) {
    for sev in &entry.severity {
        if sev.severity_type == "CVSS_V3" {
            if let Some(score) = parse_cvss_v3_base_score(&sev.score) {
                return (severity_from_cvss_score(score), Some(score));
            }
        }
    }

    let sev = entry
        .database_specific
        .as_ref()
        .and_then(|d| d.severity.as_deref())
        .map(Severity::parse)
        .unwrap_or(Severity::None);

    (sev, None)
}

/// Normalize an OSV advisory ID to a CVE when possible.
///
/// Resolution order:
/// 1. Scan `aliases` for the first `CVE-` prefixed entry.
/// 2. If the ID itself embeds a CVE (e.g., `DEBIAN-CVE-2023-1234`,
///    `ALPINE-CVE-2023-1234`), extract it.
/// 3. Otherwise keep the original ID.
fn normalize_id(id: &str, aliases: &[String]) -> (String, Option<String>) {
    if let Some(cve) = aliases.iter().find(|a| a.starts_with("CVE-")) {
        return (cve.clone(), Some(id.to_string()));
    }
    if !id.starts_with("CVE-") {
        if let Some(pos) = id.find("-CVE-") {
            let cve = &id[pos + 1..];
            return (cve.to_string(), Some(id.to_string()));
        }
    }
    (id.to_string(), None)
}

/// Convert a list of OSV events into `AffectedRange` pairs.
///
/// OSV events alternate between `introduced` and `fixed` entries within a
/// single range block. We walk them in order and emit one `AffectedRange`
/// per introduced/fixed pair.
fn events_to_ranges(range_type: &str, events: &[OsvEvent]) -> Vec<AffectedRange> {
    let mut ranges = Vec::new();
    let mut current_introduced: Option<String> = None;

    for event in events {
        if let Some(introduced) = &event.introduced {
            current_introduced = Some(introduced.clone());
        } else if let Some(fixed) = &event.fixed {
            ranges.push(AffectedRange {
                range_type: range_type.to_string(),
                introduced: current_introduced.take(),
                fixed: Some(fixed.clone()),
            });
        }
    }

    // An open-ended range (introduced but never fixed).
    if let Some(introduced) = current_introduced {
        ranges.push(AffectedRange {
            range_type: range_type.to_string(),
            introduced: Some(introduced),
            fixed: None,
        });
    }

    ranges
}

/// Convert a CVSS v3 base score to a severity level using the standard ranges.
fn severity_from_cvss_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::None
    }
}

/// Parse a CVSS v3.0/3.1 vector string and compute the base score.
///
/// Implements the NIST CVSS v3.1 base score formula. Returns `None` for
/// invalid or non-v3 vectors.
fn parse_cvss_v3_base_score(vector: &str) -> Option<f64> {
    let rest = vector
        .strip_prefix("CVSS:3.1/")
        .or_else(|| vector.strip_prefix("CVSS:3.0/"))?;

    let mut metrics = std::collections::HashMap::new();
    for part in rest.split('/') {
        let (k, v) = part.split_once(':')?;
        metrics.insert(k, v);
    }

    let av = match *metrics.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.20,
        _ => return None,
    };
    let ac = match *metrics.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr_raw = *metrics.get("PR")?;
    let scope_changed = *metrics.get("S")? == "C";
    let pr = match (pr_raw, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        _ => return None,
    };
    let ui = match *metrics.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let c = match *metrics.get("C")? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };
    let i = match *metrics.get("I")? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };
    let a = match *metrics.get("A")? {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    };

    let exploitability = 8.22 * av * ac * pr * ui;
    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));

    if iss <= 0.0 {
        return Some(0.0);
    }

    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powf(15.0)
    } else {
        6.42 * iss
    };

    let raw = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };

    // CVSS scores are rounded up to the nearest tenth.
    let score = (raw * 10.0_f64).ceil() / 10.0;
    Some(score.min(10.0))
}

// ---------------------------------------------------------------------------
// Import function (requires reqwest + zip; only compiled with db-admin)
// ---------------------------------------------------------------------------

#[cfg(feature = "db-admin")]
/// Download and import all OSV vulnerability data for the given ecosystem.
///
/// The OSV database publishes a ZIP archive at
/// `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip`
/// containing one JSON file per vulnerability. Each JSON file is parsed with
/// `parse_osv_entry` and inserted into `store` in bulk.
///
/// Returns the number of vulnerabilities successfully imported.
pub fn import_osv_ecosystem(
    store: &mut VulnStore,
    ecosystem: &str,
) -> Result<usize, crate::error::DatabaseError> {
    use std::io::Read;
    use zip::ZipArchive;

    let url = format!(
        "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip",
        ecosystem
    );

    let response = reqwest::blocking::get(&url)
        .map_err(|e| crate::error::DatabaseError::ImportFailed(e.to_string()))?;

    let bytes = response
        .bytes()
        .map_err(|e| crate::error::DatabaseError::ImportFailed(e.to_string()))?;

    let cursor = std::io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| crate::error::DatabaseError::ImportFailed(e.to_string()))?;

    let mut records = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| crate::error::DatabaseError::ImportFailed(e.to_string()))?;

        let name = file.name().to_string();
        if !name.ends_with(".json") {
            continue;
        }

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| crate::error::DatabaseError::ImportFailed(e.to_string()))?;

        match parse_osv_entry(&contents) {
            Ok(record) => records.push(record),
            Err(e) => {
                // Log but continue — a single bad record should not abort the import.
                eprintln!("Warning: failed to parse {}: {}", name, e);
            }
        }
    }

    let count = records.len();
    store.insert_vulnerabilities(&records)?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// VulnSource implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "db-admin")]
use super::VulnSource;

#[cfg(feature = "db-admin")]
pub struct OsvSource;

#[cfg(feature = "db-admin")]
impl VulnSource for OsvSource {
    fn name(&self) -> &str {
        "osv"
    }

    fn import(
        &self,
        store: &mut VulnStore,
        ecosystem: Option<&str>,
    ) -> Result<usize, crate::error::DatabaseError> {
        let total = match ecosystem {
            Some(eco) => {
                eprintln!("osv: importing {}...", eco);
                let count = import_osv_ecosystem(store, eco)?;
                eprintln!("osv: {} — {} vulnerabilities", eco, count);
                count
            }
            None => {
                let mut total = 0;
                for eco in super::ALL_ECOSYSTEMS {
                    eprintln!("osv: importing {}...", eco);
                    let count = import_osv_ecosystem(store, eco)?;
                    eprintln!("osv: {} — {} vulnerabilities", eco, count);
                    total += count;
                }
                total
            }
        };

        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_OSV: &str = r#"
    {
        "id": "GO-2023-1234",
        "summary": "Arbitrary code execution in example/lib",
        "details": "An attacker can trigger arbitrary code execution via a crafted input.",
        "published": "2023-06-01T00:00:00Z",
        "modified": "2023-07-01T00:00:00Z",
        "affected": [
            {
                "package": {
                    "ecosystem": "Go",
                    "name": "github.com/example/lib"
                },
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.2.0"}
                        ]
                    }
                ]
            }
        ],
        "database_specific": {
            "severity": "HIGH"
        }
    }
    "#;

    const SAMPLE_OSV_NO_SEVERITY: &str = r#"
    {
        "id": "GO-2023-9999",
        "summary": "Minor issue",
        "details": "A minor issue with no severity rating.",
        "published": "2023-03-01T00:00:00Z",
        "modified": "2023-04-01T00:00:00Z",
        "affected": [
            {
                "package": {
                    "ecosystem": "Go",
                    "name": "github.com/example/other"
                },
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "2.0.0"}
                        ]
                    }
                ]
            }
        ]
    }
    "#;

    #[test]
    fn test_parse_severity() {
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::parse("HIGH"), Severity::High);
        assert_eq!(Severity::parse("MEDIUM"), Severity::Medium);
        assert_eq!(Severity::parse("MODERATE"), Severity::Medium);
        assert_eq!(Severity::parse("LOW"), Severity::Low);
        assert_eq!(Severity::parse("UNKNOWN"), Severity::None);
        assert_eq!(Severity::parse(""), Severity::None);
    }

    #[test]
    fn test_parse_osv_entry() {
        let record = parse_osv_entry(SAMPLE_OSV).expect("should parse");

        assert_eq!(record.id, "GO-2023-1234");
        assert_eq!(record.summary, "Arbitrary code execution in example/lib");
        assert_eq!(record.severity, Severity::High);
        assert_eq!(record.published, "2023-06-01T00:00:00Z");
        assert!(record.withdrawn.is_none());

        assert_eq!(record.affected.len(), 1);
        let pkg = &record.affected[0];
        assert_eq!(pkg.ecosystem, "Go");
        assert_eq!(pkg.package_name, "github.com/example/lib");

        assert_eq!(pkg.ranges.len(), 1);
        assert_eq!(pkg.ranges[0].range_type, "SEMVER");
        assert_eq!(pkg.ranges[0].introduced, Some("0".to_string()));
        assert_eq!(pkg.ranges[0].fixed, Some("1.2.0".to_string()));
    }

    #[test]
    fn test_ecosystem_osv_names_are_valid() {
        use crate::models::Ecosystem;
        assert_eq!(Ecosystem::Go.as_osv_ecosystem(), "Go");
        assert_eq!(Ecosystem::JavaScript.as_osv_ecosystem(), "npm");
        assert_eq!(Ecosystem::Python.as_osv_ecosystem(), "PyPI");
        assert_eq!(Ecosystem::Java.as_osv_ecosystem(), "Maven");
    }

    #[test]
    fn test_parse_osv_entry_no_severity() {
        let record = parse_osv_entry(SAMPLE_OSV_NO_SEVERITY).expect("should parse");

        assert_eq!(record.id, "GO-2023-9999");
        assert_eq!(record.severity, Severity::None);

        assert_eq!(record.affected.len(), 1);
        let pkg = &record.affected[0];
        assert_eq!(pkg.ranges.len(), 1);
        // Open-ended range — no fixed version.
        assert_eq!(pkg.ranges[0].introduced, Some("2.0.0".to_string()));
        assert!(pkg.ranges[0].fixed.is_none());
    }

    #[cfg(feature = "db-admin")]
    #[test]
    fn test_osv_source_name() {
        let source = OsvSource;
        assert_eq!(source.name(), "osv");
    }

    #[test]
    fn cvss_v3_critical() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
        let score = parse_cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        assert!(score.is_some());
        assert!((score.unwrap() - 10.0).abs() < 0.1);
    }

    #[test]
    fn cvss_v3_high() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
        let score = parse_cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
        assert!(score.is_some());
        assert!((score.unwrap() - 7.5).abs() < 0.1);
    }

    #[test]
    fn cvss_v3_medium() {
        // CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N = 5.4
        let score = parse_cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
        assert!(score.is_some());
        assert!((score.unwrap() - 5.4).abs() < 0.1);
    }

    #[test]
    fn cvss_v3_low() {
        // CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 3.3
        let score = parse_cvss_v3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
        assert!(score.is_some());
        assert!((score.unwrap() - 3.3).abs() < 0.1);
    }

    #[test]
    fn cvss_v3_none_impact() {
        // All impact metrics None → score 0.0
        let score = parse_cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
        assert!(score.is_some());
        assert!((score.unwrap() - 0.0).abs() < 0.01);
    }

    #[test]
    fn cvss_v3_handles_3_0_prefix() {
        let score = parse_cvss_v3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
        assert!(score.is_some());
        assert!((score.unwrap() - 7.5).abs() < 0.1);
    }

    #[test]
    fn cvss_v3_returns_none_for_garbage() {
        assert!(parse_cvss_v3_base_score("not-a-vector").is_none());
        assert!(parse_cvss_v3_base_score("").is_none());
        assert!(parse_cvss_v3_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").is_none());
    }

    const SAMPLE_DEBIAN_WITH_ALIASES: &str = r#"
    {
        "id": "DEBIAN-CVE-2023-44487",
        "summary": "HTTP/2 rapid reset attack",
        "published": "2023-10-10T00:00:00Z",
        "modified": "2023-11-01T00:00:00Z",
        "aliases": ["CVE-2023-44487"],
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        ],
        "affected": [
            {
                "package": {
                    "ecosystem": "Debian:13",
                    "name": "nginx"
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.25.3-1"}
                        ]
                    }
                ]
            }
        ]
    }
    "#;

    #[test]
    fn parse_osv_entry_uses_cve_alias_as_id() {
        let record = parse_osv_entry(SAMPLE_DEBIAN_WITH_ALIASES).expect("should parse");
        assert_eq!(record.id, "CVE-2023-44487");
        assert_eq!(
            record.original_id.as_deref(),
            Some("DEBIAN-CVE-2023-44487")
        );
    }

    #[test]
    fn parse_osv_entry_extracts_cvss_severity() {
        let record = parse_osv_entry(SAMPLE_DEBIAN_WITH_ALIASES).expect("should parse");
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H = 7.5 → High
        assert_eq!(record.severity, Severity::High);
        assert!(record.cvss_score.is_some());
        assert!((record.cvss_score.unwrap() - 7.5).abs() < 0.1);
    }

    #[test]
    fn severity_from_cvss_score_boundaries() {
        assert_eq!(severity_from_cvss_score(0.0), Severity::None);
        assert_eq!(severity_from_cvss_score(0.1), Severity::Low);
        assert_eq!(severity_from_cvss_score(3.9), Severity::Low);
        assert_eq!(severity_from_cvss_score(4.0), Severity::Medium);
        assert_eq!(severity_from_cvss_score(6.9), Severity::Medium);
        assert_eq!(severity_from_cvss_score(7.0), Severity::High);
        assert_eq!(severity_from_cvss_score(8.9), Severity::High);
        assert_eq!(severity_from_cvss_score(9.0), Severity::Critical);
        assert_eq!(severity_from_cvss_score(10.0), Severity::Critical);
    }

    #[test]
    fn parse_osv_entry_cvss_wins_over_database_specific() {
        let json = r#"
        {
            "id": "TEST-001",
            "summary": "Both severity sources present",
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
            ],
            "database_specific": {
                "severity": "LOW"
            },
            "affected": []
        }
        "#;
        let record = parse_osv_entry(json).expect("should parse");
        // CVSS gives 7.5 (High), database_specific says LOW. CVSS wins.
        assert_eq!(record.severity, Severity::High);
        assert!(record.cvss_score.is_some());
    }

    #[test]
    fn parse_osv_entry_falls_back_to_database_specific() {
        // No severity[] array, only database_specific — existing behavior preserved.
        let record = parse_osv_entry(SAMPLE_OSV).expect("should parse");
        assert_eq!(record.severity, Severity::High);
        assert!(record.cvss_score.is_none());
    }

    #[test]
    fn parse_osv_entry_no_aliases_keeps_original_id() {
        let record = parse_osv_entry(SAMPLE_OSV).expect("should parse");
        assert_eq!(record.id, "GO-2023-1234");
        assert!(record.original_id.is_none());
    }

    #[test]
    fn parse_osv_entry_multiple_aliases_prefers_cve() {
        let json = r#"
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Test",
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["GHSA-aaaa-bbbb-cccc", "CVE-2024-1234", "CVE-2024-5678"],
            "affected": []
        }
        "#;
        let record = parse_osv_entry(json).expect("should parse");
        assert_eq!(record.id, "CVE-2024-1234");
        assert_eq!(
            record.original_id.as_deref(),
            Some("GHSA-xxxx-yyyy-zzzz")
        );
    }

    #[test]
    fn parse_osv_entry_non_cve_aliases_keep_original_id() {
        let json = r#"
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Test",
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["GHSA-aaaa-bbbb-cccc", "DSA-1234"],
            "affected": []
        }
        "#;
        let record = parse_osv_entry(json).expect("should parse");
        assert_eq!(record.id, "GHSA-xxxx-yyyy-zzzz");
        assert!(record.original_id.is_none());
    }

    #[test]
    fn parse_osv_entry_skips_non_v3_severity() {
        let json = r#"
        {
            "id": "TEST-002",
            "summary": "Only CVSS v2",
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "severity": [
                {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}
            ],
            "affected": []
        }
        "#;
        let record = parse_osv_entry(json).expect("should parse");
        assert_eq!(record.severity, Severity::None);
        assert!(record.cvss_score.is_none());
    }

    #[test]
    fn parse_osv_entry_extracts_cve_from_prefixed_id() {
        let json = r#"
        {
            "id": "DEBIAN-CVE-1999-1332",
            "summary": "Old gzip vuln",
            "published": "1999-12-31T00:00:00Z",
            "modified": "2000-01-01T00:00:00Z",
            "affected": []
        }
        "#;
        let record = parse_osv_entry(json).expect("should parse");
        assert_eq!(record.id, "CVE-1999-1332");
        assert_eq!(record.original_id.as_deref(), Some("DEBIAN-CVE-1999-1332"));
    }

    #[test]
    fn parse_osv_entry_extracts_cve_from_alpine_prefixed_id() {
        let json = r#"
        {
            "id": "ALPINE-CVE-2023-5678",
            "summary": "Alpine vuln",
            "published": "2023-01-01T00:00:00Z",
            "modified": "2023-01-01T00:00:00Z",
            "affected": []
        }
        "#;
        let record = parse_osv_entry(json).expect("should parse");
        assert_eq!(record.id, "CVE-2023-5678");
        assert_eq!(record.original_id.as_deref(), Some("ALPINE-CVE-2023-5678"));
    }

    #[test]
    fn parse_osv_entry_alias_cve_wins_over_embedded_cve() {
        let json = r#"
        {
            "id": "DEBIAN-CVE-2023-1234",
            "summary": "Test",
            "published": "2023-01-01T00:00:00Z",
            "modified": "2023-01-01T00:00:00Z",
            "aliases": ["CVE-2023-9999"],
            "affected": []
        }
        "#;
        let record = parse_osv_entry(json).expect("should parse");
        assert_eq!(record.id, "CVE-2023-9999", "alias CVE takes priority");
        assert_eq!(record.original_id.as_deref(), Some("DEBIAN-CVE-2023-1234"));
    }
}

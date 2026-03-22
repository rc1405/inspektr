use crate::db::store::{AffectedPackage, AffectedRange, VulnRecord, VulnStore};
use crate::models::Severity;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// OSV JSON schema structs
// ---------------------------------------------------------------------------

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
}

#[derive(Debug, Deserialize)]
pub struct OsvAffected {
    pub package: OsvPackage,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
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

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Convert an OSV severity string to our internal `Severity` enum.
pub fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "MODERATE" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::None,
    }
}

/// Parse a single OSV JSON string into a `VulnRecord`.
///
/// OSV represents affected ranges as a list of events in the form
/// `[{introduced: "X"}, {fixed: "Y"}, ...]`.  We convert consecutive
/// introduced/fixed pairs into `AffectedRange` values.
pub fn parse_osv_entry(json: &str) -> Result<VulnRecord, serde_json::Error> {
    let entry: OsvEntry = serde_json::from_str(json)?;

    let severity = entry
        .database_specific
        .as_ref()
        .and_then(|d| d.severity.as_deref())
        .map(parse_severity)
        .unwrap_or(Severity::None);

    let affected = entry
        .affected
        .into_iter()
        .map(|a| {
            let ranges = a
                .ranges
                .into_iter()
                .flat_map(|r| events_to_ranges(&r.range_type, &r.events))
                .collect();

            AffectedPackage {
                ecosystem: a.package.ecosystem,
                package_name: a.package.name,
                ranges,
            }
        })
        .collect();

    Ok(VulnRecord {
        id: entry.id,
        summary: entry.summary,
        details: entry.details,
        severity,
        published: entry.published,
        modified: entry.modified,
        withdrawn: entry.withdrawn,
        affected,
    })
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
        assert_eq!(parse_severity("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity("HIGH"), Severity::High);
        assert_eq!(parse_severity("MEDIUM"), Severity::Medium);
        assert_eq!(parse_severity("MODERATE"), Severity::Medium);
        assert_eq!(parse_severity("LOW"), Severity::Low);
        assert_eq!(parse_severity("UNKNOWN"), Severity::None);
        assert_eq!(parse_severity(""), Severity::None);
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
}

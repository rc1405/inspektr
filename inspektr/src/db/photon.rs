use crate::db::store::{AffectedPackage, AffectedRange, VulnRecord};
use crate::error::DatabaseError;
use crate::models::Severity;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Photon OS CVE JSON schema structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PhotonCveEntry {
    pub cve_id: String,
    pub pkg: String,
    #[serde(default)]
    pub cve_score: String,
    #[serde(default)]
    pub aff_ver: String,
    #[serde(default)]
    pub res_ver: String,
    #[serde(default)]
    pub status: String,
}

// ---------------------------------------------------------------------------
// Parsing helper
// ---------------------------------------------------------------------------

/// Map a CVSS score to a `Severity` level.
fn score_to_severity(score: f64) -> Severity {
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

/// Parse a Photon OS CVE JSON array into a list of `VulnRecord`s.
///
/// Entries with `status == "Not Affected"` or an empty `pkg` field are skipped.
pub fn parse_photon_json(json: &str, version: &str) -> Result<Vec<VulnRecord>, DatabaseError> {
    let entries: Vec<PhotonCveEntry> =
        serde_json::from_str(json).map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

    let mut records = Vec::new();

    for entry in entries {
        // Skip not-affected and packageless entries
        if entry.status == "Not Affected" || entry.pkg.is_empty() {
            continue;
        }

        let cvss_score: Option<f64> = entry.cve_score.parse().ok();
        let severity = cvss_score.map(score_to_severity).unwrap_or(Severity::None);

        let fixed = if entry.res_ver.is_empty() {
            None
        } else {
            Some(entry.res_ver.clone())
        };

        let record = VulnRecord {
            id: entry.cve_id.clone(),
            summary: String::new(),
            details: String::new(),
            severity,
            published: String::new(),
            modified: String::new(),
            withdrawn: None,
            source: "photon".to_string(),
            cvss_score,
            affected: vec![AffectedPackage {
                ecosystem: format!("Photon OS:{}", version),
                package_name: entry.pkg.clone(),
                ranges: vec![AffectedRange {
                    range_type: "ECOSYSTEM".to_string(),
                    introduced: Some("0".to_string()),
                    fixed,
                }],
            }],
        };

        records.push(record);
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// VulnSource implementation (db-admin only)
// ---------------------------------------------------------------------------

#[cfg(feature = "db-admin")]
use super::VulnSource;
#[cfg(feature = "db-admin")]
use crate::db::store::VulnStore;

#[cfg(feature = "db-admin")]
pub struct PhotonSource;

#[cfg(feature = "db-admin")]
impl VulnSource for PhotonSource {
    fn name(&self) -> &str {
        "photon"
    }

    fn import(
        &self,
        store: &mut VulnStore,
        ecosystem: Option<&str>,
    ) -> Result<usize, DatabaseError> {
        // If an ecosystem filter is set and it doesn't belong to Photon, skip.
        if let Some(eco) = ecosystem {
            if !eco.starts_with("Photon") {
                return Ok(0);
            }
        }

        eprintln!("photon: clearing previous data...");
        store.clear_source("photon")?;

        const VERSIONS: &[&str] = &["1.0", "2.0", "3.0", "4.0", "5.0"];

        let mut total = 0;

        for version in VERSIONS {
            let url = format!(
                "https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon{}.json",
                version
            );

            eprintln!("photon: downloading {}...", url);

            let response = reqwest::blocking::get(&url)
                .map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

            let body = response
                .text()
                .map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

            let records = parse_photon_json(&body, version)?;
            let count = records.len();
            store.insert_vulnerabilities(&records)?;
            eprintln!("photon: Photon OS:{} — {} vulnerabilities", version, count);
            total += count;
        }

        store.set_last_updated("photon", &crate::sbom::spdx::chrono_now())?;

        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_photon_cve_entry() {
        let json = r#"[{
            "cve_id": "CVE-2024-1234",
            "pkg": "openssl",
            "cve_score": "7.5",
            "aff_ver": "3.0",
            "res_ver": "3.0.12-1.ph4",
            "status": "Fixed"
        }]"#;
        let records = parse_photon_json(json, "4.0").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "CVE-2024-1234");
        assert_eq!(records[0].affected[0].ecosystem, "Photon OS:4.0");
        assert_eq!(records[0].affected[0].package_name, "openssl");
        assert_eq!(
            records[0].affected[0].ranges[0].fixed,
            Some("3.0.12-1.ph4".to_string())
        );
        assert_eq!(records[0].cvss_score, Some(7.5));
        assert_eq!(records[0].severity, Severity::High);
        assert_eq!(records[0].source, "photon");
    }

    #[test]
    fn test_skips_not_affected() {
        let json = r#"[{"cve_id":"CVE-2024-5678","pkg":"curl","cve_score":"5.0","aff_ver":"3.0","res_ver":"","status":"Not Affected"}]"#;
        let records = parse_photon_json(json, "4.0").unwrap();
        assert!(records.is_empty());
    }

    #[cfg(feature = "db-admin")]
    #[test]
    fn test_photon_source_name() {
        let source = PhotonSource;
        assert_eq!(source.name(), "photon");
    }
}

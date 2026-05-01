//! AWS Bottlerocket vulnerability data importer.
//!
//! Parses Bottlerocket `updateinfo.xml` feeds to extract vulnerability records.
//!
//! Requires the `db-admin` feature.

use crate::db::store::{AffectedPackage, AffectedRange, VulnRecord};
use crate::error::DatabaseError;
use crate::models::Severity;
use quick_xml::Reader;
use quick_xml::events::Event;

/// Map Bottlerocket/updateinfo severity strings to our Severity enum.
fn map_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "important" | "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::None,
    }
}

/// Helper: extract an attribute value from an event by key name.
fn get_attr(e: &quick_xml::events::BytesStart<'_>, key: &[u8]) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == key {
            return Some(String::from_utf8_lossy(&attr.value).to_string());
        }
    }
    None
}

/// Build the version string from package attributes.
/// Format: `{version}-{release}`, prepend `{epoch}:` if epoch != "0".
fn build_version(version: &str, release: &str, epoch: &str) -> String {
    let base = format!("{}-{}", version, release);
    if epoch != "0" && !epoch.is_empty() {
        format!("{}:{}", epoch, base)
    } else {
        base
    }
}

/// Parse an updateinfo XML string (already decompressed) into VulnRecords.
pub fn parse_updateinfo_xml(xml: &str) -> Result<Vec<VulnRecord>, DatabaseError> {
    let mut reader = Reader::from_str(xml);

    let mut records: Vec<VulnRecord> = Vec::new();

    // State flags
    let mut in_update = false;
    let mut in_id = false;
    let mut in_title = false;
    let mut in_severity = false;
    let mut in_references = false;
    let mut in_pkglist = false;

    // Per-update collected data
    let mut advisory_id = String::new();
    let mut title = String::new();
    let mut severity = Severity::None;
    let mut published = String::new();
    let mut cve_ids: Vec<String> = Vec::new();
    let mut packages: Vec<(String, String)> = Vec::new(); // (name, version_string)

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    b"update" => {
                        let update_type = get_attr(e, b"type").unwrap_or_default();
                        if update_type == "security" {
                            in_update = true;
                            advisory_id.clear();
                            title.clear();
                            severity = Severity::None;
                            published.clear();
                            cve_ids.clear();
                            packages.clear();
                        }
                    }
                    b"id" if in_update => {
                        in_id = true;
                    }
                    b"title" if in_update => {
                        in_title = true;
                    }
                    b"severity" if in_update => {
                        in_severity = true;
                    }
                    b"references" if in_update => {
                        in_references = true;
                    }
                    b"pkglist" if in_update => {
                        in_pkglist = true;
                    }
                    b"issued" if in_update => {
                        if let Some(date) = get_attr(e, b"date") {
                            published = date;
                        }
                    }
                    b"reference" if in_references => {
                        let ref_type = get_attr(e, b"type").unwrap_or_default();
                        let ref_id = get_attr(e, b"id").unwrap_or_default();
                        if ref_type == "cve" && ref_id.starts_with("CVE-") {
                            cve_ids.push(ref_id);
                        }
                    }
                    b"package" if in_pkglist => {
                        let pkg_name = get_attr(e, b"name").unwrap_or_default();
                        let version = get_attr(e, b"version").unwrap_or_default();
                        let release = get_attr(e, b"release").unwrap_or_default();
                        let epoch = get_attr(e, b"epoch").unwrap_or_else(|| "0".to_string());
                        if !pkg_name.is_empty() && !version.is_empty() {
                            let ver_str = build_version(&version, &release, &epoch);
                            packages.push((pkg_name, ver_str));
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    b"issued" if in_update => {
                        if let Some(date) = get_attr(e, b"date") {
                            published = date;
                        }
                    }
                    b"reference" if in_references => {
                        let ref_type = get_attr(e, b"type").unwrap_or_default();
                        let ref_id = get_attr(e, b"id").unwrap_or_default();
                        if ref_type == "cve" && ref_id.starts_with("CVE-") {
                            cve_ids.push(ref_id);
                        }
                    }
                    b"package" if in_pkglist => {
                        let pkg_name = get_attr(e, b"name").unwrap_or_default();
                        let version = get_attr(e, b"version").unwrap_or_default();
                        let release = get_attr(e, b"release").unwrap_or_default();
                        let epoch = get_attr(e, b"epoch").unwrap_or_else(|| "0".to_string());
                        if !pkg_name.is_empty() && !version.is_empty() {
                            let ver_str = build_version(&version, &release, &epoch);
                            packages.push((pkg_name, ver_str));
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_id {
                    if let Ok(text) = e.unescape() {
                        advisory_id.push_str(&text);
                    }
                } else if in_title {
                    if let Ok(text) = e.unescape() {
                        title.push_str(&text);
                    }
                } else if in_severity {
                    if let Ok(text) = e.unescape() {
                        severity = map_severity(&text);
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    b"update" if in_update => {
                        // Emit one VulnRecord per CVE
                        for cve_id in &cve_ids {
                            let affected: Vec<AffectedPackage> = packages
                                .iter()
                                .map(|(pkg_name, pkg_ver)| AffectedPackage {
                                    ecosystem: "Bottlerocket".to_string(),
                                    package_name: pkg_name.clone(),
                                    ranges: vec![AffectedRange {
                                        range_type: "ECOSYSTEM".to_string(),
                                        introduced: Some("0".to_string()),
                                        fixed: Some(pkg_ver.clone()),
                                    }],
                                    severity_override: None,
                                })
                                .collect();

                            records.push(VulnRecord {
                                id: cve_id.clone(),
                                original_id: None,
                                summary: title.clone(),
                                severity,
                                published: published.clone(),
                                modified: String::new(),
                                withdrawn: None,
                                source: "bottlerocket".to_string(),
                                cvss_score: None,
                                affected,
                            });
                        }

                        in_update = false;
                        in_references = false;
                        in_pkglist = false;
                    }
                    b"id" => in_id = false,
                    b"title" => in_title = false,
                    b"severity" => in_severity = false,
                    b"references" => in_references = false,
                    b"pkglist" => in_pkglist = false,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(DatabaseError::ImportFailed(format!(
                    "XML parse error: {}",
                    e
                )));
            }
            _ => {}
        }
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
pub struct BottlerocketSource;

#[cfg(feature = "db-admin")]
impl VulnSource for BottlerocketSource {
    fn name(&self) -> &str {
        "bottlerocket"
    }

    fn import(
        &self,
        store: &mut VulnStore,
        ecosystem: Option<&str>,
    ) -> Result<usize, DatabaseError> {
        // If an ecosystem filter is set and it doesn't match Bottlerocket, skip.
        if let Some(eco) = ecosystem {
            if !eco.eq_ignore_ascii_case("Bottlerocket") {
                return Ok(0);
            }
        }

        const URL: &str = "https://advisories.bottlerocket.aws/updateinfo.xml.gz";

        eprintln!("bottlerocket: downloading {}...", URL);

        let response =
            reqwest::blocking::get(URL).map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

        let bytes = response
            .bytes()
            .map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

        // Decompress gzipped XML
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut decoder = GzDecoder::new(bytes.as_ref());
        let mut xml = String::new();
        decoder
            .read_to_string(&mut xml)
            .map_err(|e| DatabaseError::ImportFailed(format!("gzip decompress error: {}", e)))?;

        let records = parse_updateinfo_xml(&xml)?;
        let count = records.len();
        store.insert_vulnerabilities(&records)?;
        eprintln!("bottlerocket: {} vulnerabilities imported", count);

        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_updateinfo_xml() {
        let xml = r#"<?xml version="1.0"?>
<updates>
  <update type="security" status="stable">
    <id>BRKT-2024-001</id>
    <title>Security update</title>
    <issued date="2024-01-15"/>
    <severity>Important</severity>
    <references>
      <reference type="cve" id="CVE-2024-1234" href=""/>
    </references>
    <pkglist>
      <collection>
        <package name="openssl" version="3.0.7" release="25.br1" epoch="0" arch="x86_64"/>
      </collection>
    </pkglist>
  </update>
</updates>"#;
        let records = parse_updateinfo_xml(xml).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "CVE-2024-1234");
        assert_eq!(records[0].severity, Severity::High);
        assert_eq!(records[0].affected[0].ecosystem, "Bottlerocket");
        assert_eq!(records[0].affected[0].package_name, "openssl");
        assert_eq!(
            records[0].affected[0].ranges[0].fixed,
            Some("3.0.7-25.br1".to_string())
        );
        assert_eq!(records[0].source, "bottlerocket");
    }

    #[cfg(feature = "db-admin")]
    #[test]
    fn test_bottlerocket_source_name() {
        assert_eq!(BottlerocketSource.name(), "bottlerocket");
    }
}

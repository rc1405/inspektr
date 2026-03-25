use crate::db::store::{AffectedPackage, AffectedRange, VulnRecord};
use crate::error::DatabaseError;
use crate::models::Severity;
use quick_xml::Reader;
use quick_xml::events::Event;


/// Parse a criterion comment like "openssl is earlier than 1:3.0.7-25.el9"
/// into (package_name, version).
pub fn parse_criterion_comment(comment: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = comment.splitn(2, " is earlier than ").collect();
    if parts.len() == 2 {
        Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
    } else {
        None
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

/// Process attributes common to both Start and Empty element events.
/// Returns true if the element was handled as a self-closing tag that needs
/// no further state tracking.
fn process_element(
    e: &quick_xml::events::BytesStart<'_>,
    in_definition: bool,
    in_metadata: bool,
    in_advisory: bool,
    cve_ids: &mut Vec<String>,
    published: &mut String,
    packages: &mut Vec<(String, String)>,
) {
    let name = e.local_name();
    match name.as_ref() {
        b"reference" if in_metadata => {
            let ref_source = get_attr(e, b"source").unwrap_or_default();
            let ref_id = get_attr(e, b"ref_id").unwrap_or_default();
            if ref_source == "CVE" && !ref_id.is_empty() {
                cve_ids.push(ref_id);
            }
        }
        b"issued" if in_advisory => {
            if let Some(date) = get_attr(e, b"date") {
                *published = date;
            }
        }
        b"criterion" if in_definition => {
            if let Some(comment) = get_attr(e, b"comment") {
                if let Some(pkg) = parse_criterion_comment(&comment) {
                    packages.push(pkg);
                }
            }
        }
        _ => {}
    }
}

/// Parse OVAL XML definitions and return VulnRecords.
///
/// `distro` is used for the ecosystem (e.g., "Oracle", "Azure Linux").
/// `version` is the OS version (e.g., "9", "3.0").
pub fn parse_oval_xml(
    xml: &str,
    distro: &str,
    version: &str,
) -> Result<Vec<VulnRecord>, DatabaseError> {
    let source = match distro {
        "Azure Linux" => "azurelinux".to_string(),
        _ => distro.to_lowercase(),
    };
    let ecosystem = format!("{}:{}", distro, version);

    let mut reader = Reader::from_str(xml);

    let mut records: Vec<VulnRecord> = Vec::new();

    // State tracking
    let mut in_definition = false;
    let mut in_metadata = false;
    let mut in_advisory = false;
    let mut in_title = false;
    let mut in_severity = false;

    // Collected data for current definition
    let mut cve_ids: Vec<String> = Vec::new();
    let mut title = String::new();
    let mut severity = Severity::None;
    let mut published = String::new();
    let mut packages: Vec<(String, String)> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    b"definition" => {
                        let class = get_attr(e, b"class").unwrap_or_default();
                        if class == "patch" {
                            in_definition = true;
                            cve_ids.clear();
                            title.clear();
                            severity = Severity::None;
                            published.clear();
                            packages.clear();
                        }
                    }
                    b"metadata" if in_definition => {
                        in_metadata = true;
                    }
                    b"title" if in_metadata => {
                        in_title = true;
                    }
                    b"advisory" if in_metadata => {
                        in_advisory = true;
                    }
                    b"severity" if in_advisory => {
                        in_severity = true;
                    }
                    _ => {
                        process_element(
                            e,
                            in_definition,
                            in_metadata,
                            in_advisory,
                            &mut cve_ids,
                            &mut published,
                            &mut packages,
                        );
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                process_element(
                    e,
                    in_definition,
                    in_metadata,
                    in_advisory,
                    &mut cve_ids,
                    &mut published,
                    &mut packages,
                );
            }
            Ok(Event::Text(ref e)) => {
                if in_title {
                    if let Ok(text) = e.unescape() {
                        title.push_str(&text);
                    }
                } else if in_severity {
                    if let Ok(text) = e.unescape() {
                        severity = Severity::parse(&text);
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.local_name();
                match name.as_ref() {
                    b"definition" if in_definition => {
                        // Emit one VulnRecord per CVE
                        for cve_id in &cve_ids {
                            let affected: Vec<AffectedPackage> = packages
                                .iter()
                                .map(|(pkg_name, pkg_ver)| AffectedPackage {
                                    ecosystem: ecosystem.clone(),
                                    package_name: pkg_name.clone(),
                                    ranges: vec![AffectedRange {
                                        range_type: "ECOSYSTEM".to_string(),
                                        introduced: Some("0".to_string()),
                                        fixed: Some(pkg_ver.clone()),
                                    }],
                                })
                                .collect();

                            records.push(VulnRecord {
                                id: cve_id.clone(),
                                summary: title.clone(),
                                details: String::new(),
                                severity,
                                published: published.clone(),
                                modified: String::new(),
                                withdrawn: None,
                                source: source.clone(),
                                cvss_score: None,
                                affected,
                            });
                        }

                        in_definition = false;
                        in_metadata = false;
                        in_advisory = false;
                    }
                    b"metadata" => in_metadata = false,
                    b"advisory" => in_advisory = false,
                    b"title" => in_title = false,
                    b"severity" => in_severity = false,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oval_definition() {
        let xml = r#"<?xml version="1.0"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="oval:com.oracle.elsa:def:20240001" class="patch">
      <metadata>
        <title>ELSA-2024-0001: openssl security update (Important)</title>
        <reference source="CVE" ref_id="CVE-2024-1234" ref_url="https://cve.mitre.org/"/>
        <advisory>
          <severity>Important</severity>
          <issued date="2024-01-15"/>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:tst:1" comment="openssl is earlier than 1:3.0.7-25.el9"/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>"#;
        let records = parse_oval_xml(xml, "Oracle", "9").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "CVE-2024-1234");
        assert_eq!(records[0].severity, Severity::High);
        assert_eq!(records[0].affected[0].ecosystem, "Oracle:9");
        assert_eq!(records[0].affected[0].package_name, "openssl");
        assert_eq!(
            records[0].affected[0].ranges[0].fixed,
            Some("1:3.0.7-25.el9".to_string())
        );
        assert_eq!(records[0].source, "oracle");
    }

    #[test]
    fn test_parse_oval_multiple_cves() {
        let xml = r#"<?xml version="1.0"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="oval:def:1" class="patch">
      <metadata>
        <title>Advisory: multi-cve update</title>
        <reference source="CVE" ref_id="CVE-2024-0001" ref_url=""/>
        <reference source="CVE" ref_id="CVE-2024-0002" ref_url=""/>
        <advisory><severity>Moderate</severity><issued date="2024-01-01"/></advisory>
      </metadata>
      <criteria><criterion test_ref="t1" comment="curl is earlier than 8.5.0-1.el9"/></criteria>
    </definition>
  </definitions>
</oval_definitions>"#;
        let records = parse_oval_xml(xml, "Oracle", "9").unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.id == "CVE-2024-0001"));
        assert!(records.iter().any(|r| r.id == "CVE-2024-0002"));
    }

    #[test]
    fn test_parse_criterion_comment() {
        let (name, ver) =
            parse_criterion_comment("openssl is earlier than 1:3.0.7-25.el9").unwrap();
        assert_eq!(name, "openssl");
        assert_eq!(ver, "1:3.0.7-25.el9");

        assert!(parse_criterion_comment("no match here").is_none());
    }

    #[test]
    fn test_oval_severity_mapping() {
        assert_eq!(Severity::parse("Critical"), Severity::Critical);
        assert_eq!(Severity::parse("Important"), Severity::High);
        assert_eq!(Severity::parse("Moderate"), Severity::Medium);
        assert_eq!(Severity::parse("Low"), Severity::Low);
        assert_eq!(Severity::parse(""), Severity::None);
    }
}

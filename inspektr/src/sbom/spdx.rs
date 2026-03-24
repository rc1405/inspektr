use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::SbomFormat;
use crate::error::SbomFormatError;
use crate::models::{Ecosystem, Package, Sbom, SourceMetadata};

// ---------------------------------------------------------------------------
// SPDX 2.3 JSON document structures
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: String,
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    document_namespace: String,
    creation_info: SpdxCreationInfo,
    #[serde(default)]
    packages: Vec<SpdxPackage>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    license_list_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version_info: String,
    download_location: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    external_refs: Vec<SpdxExternalRef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}

// ---------------------------------------------------------------------------
// SbomFormat implementation
// ---------------------------------------------------------------------------

pub struct SpdxFormat;

impl SbomFormat for SpdxFormat {
    fn format_name(&self) -> &str {
        "spdx"
    }

    fn encode(&self, sbom: &Sbom) -> Result<Vec<u8>, SbomFormatError> {
        let packages: Vec<SpdxPackage> = sbom
            .packages
            .iter()
            .enumerate()
            .map(|(i, pkg)| SpdxPackage {
                spdx_id: format!("SPDXRef-Package-{}", i),
                name: pkg.name.clone(),
                version_info: pkg.version.clone(),
                download_location: "NOASSERTION".to_string(),
                external_refs: vec![SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".to_string(),
                    reference_type: "purl".to_string(),
                    reference_locator: pkg.purl.clone(),
                }],
            })
            .collect();

        let now = chrono_now();
        let doc = SpdxDocument {
            spdx_version: "SPDX-2.3".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name: "inspektr-sbom".to_string(),
            document_namespace: format!("https://inspektr.dev/spdxdocs/{}", Uuid::new_v4()),
            creation_info: SpdxCreationInfo {
                created: now,
                creators: vec!["Tool: inspektr".to_string()],
                license_list_version: Some("3.19".to_string()),
            },
            packages,
        };

        serde_json::to_vec_pretty(&doc).map_err(|e| SbomFormatError::EncodeFailed(e.to_string()))
    }

    fn decode(&self, data: &[u8]) -> Result<Sbom, SbomFormatError> {
        let doc: SpdxDocument = serde_json::from_slice(data)
            .map_err(|e| SbomFormatError::DecodeFailed(e.to_string()))?;

        let packages = doc
            .packages
            .into_iter()
            .map(|sp| {
                let purl = sp
                    .external_refs
                    .iter()
                    .find(|r| r.reference_type == "purl")
                    .map(|r| r.reference_locator.clone())
                    .unwrap_or_default();

                let ecosystem = ecosystem_from_purl(&purl);

                Package {
                    name: sp.name,
                    version: sp.version_info,
                    ecosystem,
                    purl,
                    metadata: HashMap::new(),
                    source_file: None,
                }
            })
            .collect();

        Ok(Sbom {
            source: SourceMetadata {
                source_type: "spdx".to_string(),
                target: String::new(),
            },
            packages,
        })
    }
}

/// Detect ecosystem from PURL prefix.
fn ecosystem_from_purl(purl: &str) -> Ecosystem {
    if purl.starts_with("pkg:golang/") {
        Ecosystem::Go
    } else if purl.starts_with("pkg:npm/") {
        Ecosystem::JavaScript
    } else if purl.starts_with("pkg:pypi/") {
        Ecosystem::Python
    } else if purl.starts_with("pkg:maven/") {
        Ecosystem::Java
    } else if purl.starts_with("pkg:conan/") {
        Ecosystem::Conan
    } else if purl.starts_with("pkg:vcpkg/") {
        Ecosystem::Vcpkg
    } else if purl.starts_with("pkg:nuget/") {
        Ecosystem::DotNet
    } else if purl.starts_with("pkg:composer/") {
        Ecosystem::Php
    } else if purl.starts_with("pkg:cargo/") {
        Ecosystem::Rust
    } else if purl.starts_with("pkg:gem/") {
        Ecosystem::Ruby
    } else if purl.starts_with("pkg:swift/") {
        Ecosystem::Swift
    } else if purl.starts_with("pkg:deb/") {
        Ecosystem::Debian
    } else if purl.starts_with("pkg:apk/") {
        Ecosystem::Alpine
    } else if purl.starts_with("pkg:rpm/") {
        Ecosystem::RedHat
    } else {
        Ecosystem::Go // fallback
    }
}

/// Simple ISO 8601 UTC timestamp without pulling in chrono crate.
pub fn chrono_now() -> String {
    // Use std::time to get seconds since epoch, format manually
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Convert to rough date/time (good enough for SPDX created field)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    // Days since 1970-01-01
    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Simplified Gregorian calendar conversion
    let mut y = 1970;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let month_days: &[u64] = if is_leap(y) {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for &md in month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        m += 1;
    }
    (y, m + 1, remaining + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Ecosystem, Package, Sbom, SourceMetadata};
    use std::collections::HashMap;

    fn make_sbom() -> Sbom {
        Sbom {
            source: SourceMetadata {
                source_type: "filesystem".to_string(),
                target: "/project".to_string(),
            },
            packages: vec![
                Package {
                    name: "express".to_string(),
                    version: "4.18.2".to_string(),
                    ecosystem: Ecosystem::JavaScript,
                    purl: "pkg:npm/express@4.18.2".to_string(),
                    metadata: HashMap::new(),
                    source_file: None,
                },
                Package {
                    name: "github.com/pkg/errors".to_string(),
                    version: "v0.9.1".to_string(),
                    ecosystem: Ecosystem::Go,
                    purl: "pkg:golang/github.com/pkg/errors@v0.9.1".to_string(),
                    metadata: HashMap::new(),
                    source_file: None,
                },
            ],
        }
    }

    #[test]
    fn test_format_name() {
        assert_eq!(SpdxFormat.format_name(), "spdx");
    }

    #[test]
    fn test_encode_spdx() {
        let bytes = SpdxFormat.encode(&make_sbom()).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["dataLicense"], "CC0-1.0");
        assert_eq!(doc["SPDXID"], "SPDXRef-DOCUMENT");
        assert!(
            doc["documentNamespace"]
                .as_str()
                .unwrap()
                .starts_with("https://inspektr.dev/spdxdocs/")
        );

        let creators = doc["creationInfo"]["creators"].as_array().unwrap();
        assert!(
            creators
                .iter()
                .any(|c| c.as_str().unwrap().contains("inspektr"))
        );

        let packages = doc["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 2);

        assert_eq!(packages[0]["name"], "express");
        assert_eq!(packages[0]["versionInfo"], "4.18.2");
        assert_eq!(packages[0]["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(packages[0]["downloadLocation"], "NOASSERTION");

        let ext_refs = packages[0]["externalRefs"].as_array().unwrap();
        assert_eq!(ext_refs[0]["referenceCategory"], "PACKAGE-MANAGER");
        assert_eq!(ext_refs[0]["referenceType"], "purl");
        assert_eq!(ext_refs[0]["referenceLocator"], "pkg:npm/express@4.18.2");
    }

    #[test]
    fn test_roundtrip_spdx() {
        let original = make_sbom();
        let bytes = SpdxFormat.encode(&original).unwrap();
        let decoded = SpdxFormat.decode(&bytes).unwrap();

        assert_eq!(decoded.packages.len(), 2);
        assert_eq!(decoded.packages[0].name, "express");
        assert_eq!(decoded.packages[0].version, "4.18.2");
        assert_eq!(decoded.packages[0].purl, "pkg:npm/express@4.18.2");
        assert_eq!(decoded.packages[0].ecosystem, Ecosystem::JavaScript);
        assert_eq!(decoded.packages[1].ecosystem, Ecosystem::Go);
    }

    #[test]
    fn test_decode_invalid_json() {
        let result = SpdxFormat.decode(b"not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_spdx_without_external_refs() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "created": "2026-01-01T00:00:00Z",
                "creators": ["Tool: test"]
            },
            "packages": [{
                "SPDXID": "SPDXRef-Package-0",
                "name": "some-package",
                "versionInfo": "1.0.0",
                "downloadLocation": "NOASSERTION"
            }]
        }"#;
        let sbom = SpdxFormat.decode(json.as_bytes()).unwrap();
        assert_eq!(sbom.packages.len(), 1);
        assert_eq!(sbom.packages[0].name, "some-package");
        assert_eq!(sbom.packages[0].purl, "");
    }
}

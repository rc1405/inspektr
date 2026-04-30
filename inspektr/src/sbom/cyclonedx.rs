//! CycloneDX 1.5 JSON SBOM format.
//!
//! Implements encoding and decoding of SBOMs in the
//! [CycloneDX 1.5](https://cyclonedx.org/specification/overview/) JSON format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::cataloger::os::{DistroInfo, map_distro_id, versioned_osv_ecosystem};
use crate::error::SbomFormatError;
use crate::models::{Ecosystem, Package, Sbom, SourceMetadata};
use crate::sbom::SbomFormat;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxDocument {
    bom_format: String,
    spec_version: String,
    serial_number: String,
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<CycloneDxMetadata>,
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tools: Option<CycloneDxTools>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    component: Option<CycloneDxMetadataComponent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxTools {
    #[serde(default)]
    components: Vec<CycloneDxToolComponent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxToolComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxMetadataComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bom_ref: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    #[serde(default)]
    version: String,
    /// Package URL identifying this component.
    ///
    /// CycloneDX allows components without a PURL (e.g. the top-level image
    /// itself, "operating-system" components, or file components). We keep
    /// this optional so we can decode SBOMs produced by other tools (syft,
    /// trivy) and simply skip entries that lack package identification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    /// Optional CycloneDX component properties.
    ///
    /// Used to round-trip metadata that the vulnerability matcher needs but
    /// cannot be reconstructed from the PURL alone — most notably the
    /// versioned OSV ecosystem name for OS packages (e.g. `"Debian:13"`,
    /// `"Ubuntu:22.04"`, `"Alpine:v3.19"`). Without this, OS packages loaded
    /// from a CycloneDX SBOM match against the unversioned ecosystem and
    /// miss every vuln.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    properties: Vec<CycloneDxProperty>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxProperty {
    name: String,
    value: String,
}

/// Metadata keys we round-trip through CycloneDX component properties.
///
/// Namespaced with `inspektr:` so we don't collide with properties written by
/// other tools (CycloneDX's convention for tool-specific properties).
const INSPEKTR_PROPERTY_PREFIX: &str = "inspektr:";

/// CycloneDX 1.5 JSON SBOM encoder/decoder.
pub struct CycloneDxFormat;

impl SbomFormat for CycloneDxFormat {
    fn format_name(&self) -> &str {
        "cyclonedx"
    }

    fn encode(&self, sbom: &Sbom) -> Result<Vec<u8>, SbomFormatError> {
        let components: Vec<CycloneDxComponent> = sbom
            .packages
            .iter()
            .map(|pkg| {
                // Serialize any metadata entries into CycloneDX component
                // properties with a namespaced name. This lets a scanner reading
                // the SBOM back recover fields that aren't encoded in the PURL,
                // primarily `osv_ecosystem` for OS packages.
                let mut properties: Vec<CycloneDxProperty> = pkg
                    .metadata
                    .iter()
                    .map(|(k, v)| CycloneDxProperty {
                        name: format!("{}{}", INSPEKTR_PROPERTY_PREFIX, k),
                        value: v.clone(),
                    })
                    .collect();
                // Preserve `source_file` as a dedicated property. It's not
                // in `metadata` but is crucial for per-binary remediation:
                // the same Go module in two binaries needs to round-trip as
                // two distinguishable entries so downstream consumers know
                // which binary to patch.
                if let Some(sf) = &pkg.source_file {
                    properties.push(CycloneDxProperty {
                        name: format!("{}source_file", INSPEKTR_PROPERTY_PREFIX),
                        value: sf.clone(),
                    });
                }
                properties.sort_by(|a, b| a.name.cmp(&b.name));
                CycloneDxComponent {
                    component_type: "library".to_string(),
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    purl: Some(pkg.purl.clone()),
                    properties,
                }
            })
            .collect();

        // Infer distro from packages and emit an operating-system component
        // so external scanners (trivy, grype) can determine the target OS.
        let os_component = infer_os_component(&sbom.packages);
        let mut all_components = Vec::new();
        if let Some(os) = os_component {
            all_components.push(os);
        }
        all_components.extend(components);

        let component_type = match sbom.source.source_type.as_str() {
            "oci" => "container",
            _ => "application",
        };

        let metadata = CycloneDxMetadata {
            timestamp: Some(crate::sbom::spdx::chrono_now()),
            tools: Some(CycloneDxTools {
                components: vec![CycloneDxToolComponent {
                    component_type: "application".to_string(),
                    name: "inspektr".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }],
            }),
            component: Some(CycloneDxMetadataComponent {
                component_type: component_type.to_string(),
                name: sbom.source.target.clone(),
                bom_ref: None,
            }),
        };

        let doc = CycloneDxDocument {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: Some(metadata),
            components: all_components,
        };

        serde_json::to_vec_pretty(&doc).map_err(|e| SbomFormatError::EncodeFailed(e.to_string()))
    }

    fn decode(&self, data: &[u8]) -> Result<Sbom, SbomFormatError> {
        let doc: CycloneDxDocument = serde_json::from_slice(data)
            .map_err(|e| SbomFormatError::DecodeFailed(e.to_string()))?;

        // First pass: look for an `operating-system` typed component. Both
        // syft and trivy emit one per image with the distro `name` and
        // `version`. If we find it, build a DistroInfo and derive the
        // versioned OSV ecosystem name so OS packages in this SBOM can match
        // vulns even though the distro version isn't encoded in PURLs.
        let inferred_distro = detect_os_component(&doc.components);
        let inferred_osv_ecosystem: Option<String> =
            inferred_distro.as_ref().map(versioned_osv_ecosystem);
        let inferred_ecosystem: Option<Ecosystem> = inferred_distro.as_ref().map(|d| d.ecosystem);

        // Second pass: decode package components. Only components with a
        // PURL are packages we can match vulns against. Skipping the rest
        // (typically "operating-system", "file", or the root image
        // component) keeps us compatible with SBOMs produced by other tools
        // that put non-package metadata in `components`.
        let packages: Vec<Package> = doc
            .components
            .into_iter()
            .filter_map(|comp| {
                let purl = comp.purl?;
                let ecosystem = Ecosystem::from_purl(&purl);
                // Recover any `inspektr:*` properties we wrote at encode time
                // back into the package metadata. Everything else is ignored —
                // we don't want to treat arbitrary third-party properties as
                // inspektr metadata. `source_file` is pulled out into the
                // dedicated field rather than left in metadata.
                let mut metadata: HashMap<String, String> = HashMap::new();
                let mut source_file: Option<String> = None;
                for prop in comp.properties {
                    if let Some(key) = prop.name.strip_prefix(INSPEKTR_PROPERTY_PREFIX) {
                        if key == "source_file" {
                            source_file = Some(prop.value);
                        } else {
                            metadata.insert(key.to_string(), prop.value);
                        }
                    } else if (prop.name == "syft:metadata:source"
                        || prop.name == "aquasecurity:trivy:SrcName")
                        && !prop.value.is_empty() && prop.value != comp.name {
                            metadata
                                .entry("source_package".to_string())
                                .or_insert(prop.value);
                        }
                }

                // Backfill `osv_ecosystem` from the inferred distro when the
                // SBOM didn't carry an explicit inspektr annotation. Only
                // applied to packages whose ecosystem matches the detected
                // OS — we don't want to stamp a language package like a Go
                // binary with the host distro's ecosystem.
                if !metadata.contains_key("osv_ecosystem")
                    && let (Some(osv), Some(os_ecosystem)) =
                        (&inferred_osv_ecosystem, inferred_ecosystem)
                    && ecosystem == os_ecosystem
                {
                    metadata.insert("osv_ecosystem".to_string(), osv.clone());
                }

                Some(Package {
                    name: comp.name,
                    version: comp.version,
                    ecosystem,
                    purl,
                    metadata,
                    source_file,
                })
            })
            .collect();

        Ok(Sbom {
            source: SourceMetadata {
                source_type: "cyclonedx".to_string(),
                target: String::new(),
            },
            packages,
        })
    }
}

/// Look for a CycloneDX `operating-system` typed component and build a
/// [`DistroInfo`] from it.
///
/// Returns `None` if no OS component is present, its `name` doesn't map to
/// a supported distro, or its version is missing. Both syft and trivy write
/// this component for container image scans:
///
/// - syft alpine:  `{type: "operating-system", name: "alpine", version: "3.19.9"}`
/// - trivy alpine: `{type: "operating-system", name: "alpine", version: "3.19.9"}`
/// - syft debian:  `{type: "operating-system", name: "debian", version: "13"}`
/// - trivy debian: `{type: "operating-system", name: "debian", version: "13.4"}`
///
/// Version normalization (stripping point releases, adding `v` prefix for
/// Alpine, etc.) is handled downstream by [`versioned_osv_ecosystem`].
/// Infer an `operating-system` CycloneDX component from the packages' metadata.
///
/// Looks at the first OS package's `osv_ecosystem` value (e.g. `"Debian:13"`)
/// to derive the distro name and version. Emits a component that external
/// scanners like trivy and grype use to select the right vuln database.
fn infer_os_component(packages: &[Package]) -> Option<CycloneDxComponent> {
    let osv_eco = packages
        .iter()
        .find_map(|p| p.metadata.get("osv_ecosystem"))?;
    let (name, version) = osv_eco.split_once(':')?;
    Some(CycloneDxComponent {
        component_type: "operating-system".to_string(),
        name: name.to_lowercase(),
        version: version.to_string(),
        purl: None,
        properties: Vec::new(),
    })
}

fn detect_os_component(components: &[CycloneDxComponent]) -> Option<DistroInfo> {
    let os = components
        .iter()
        .find(|c| c.component_type.eq_ignore_ascii_case("operating-system"))?;
    if os.version.is_empty() {
        return None;
    }
    let id = os.name.to_lowercase();
    let (ecosystem, package_format) = map_distro_id(&id)?;
    Some(DistroInfo {
        id,
        version: os.version.clone(),
        name: os.name.clone(),
        ecosystem,
        package_format,
    })
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
                target: "/tmp/myproject".to_string(),
            },
            packages: vec![
                Package {
                    name: "github.com/stretchr/testify".to_string(),
                    version: "v1.8.4".to_string(),
                    ecosystem: Ecosystem::Go,
                    purl: "pkg:golang/github.com/stretchr/testify@v1.8.4".to_string(),
                    metadata: HashMap::new(),
                    source_file: None,
                },
                Package {
                    name: "golang.org/x/net".to_string(),
                    version: "v0.17.0".to_string(),
                    ecosystem: Ecosystem::Go,
                    purl: "pkg:golang/golang.org/x/net@v0.17.0".to_string(),
                    metadata: HashMap::new(),
                    source_file: None,
                },
            ],
        }
    }

    #[test]
    fn test_encode_cyclonedx() {
        let fmt = CycloneDxFormat;
        let sbom = make_sbom();
        let bytes = fmt.encode(&sbom).expect("encode should succeed");

        let doc: serde_json::Value =
            serde_json::from_slice(&bytes).expect("encoded output must be valid JSON");

        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert!(
            doc["serialNumber"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:"),
            "serialNumber must be a URN UUID"
        );
        assert_eq!(doc["version"], 1);

        let components = doc["components"]
            .as_array()
            .expect("components must be array");
        assert_eq!(components.len(), 2);

        let first = &components[0];
        assert_eq!(first["type"], "library");
        assert_eq!(first["name"], "github.com/stretchr/testify");
        assert_eq!(first["version"], "v1.8.4");
        assert_eq!(
            first["purl"],
            "pkg:golang/github.com/stretchr/testify@v1.8.4"
        );
    }

    #[test]
    fn test_roundtrip_cyclonedx() {
        let fmt = CycloneDxFormat;
        let original = make_sbom();
        let bytes = fmt.encode(&original).expect("encode should succeed");
        let decoded = fmt.decode(&bytes).expect("decode should succeed");

        assert_eq!(decoded.packages.len(), original.packages.len());
        for (orig_pkg, dec_pkg) in original.packages.iter().zip(decoded.packages.iter()) {
            assert_eq!(orig_pkg.name, dec_pkg.name);
            assert_eq!(orig_pkg.version, dec_pkg.version);
            assert_eq!(orig_pkg.purl, dec_pkg.purl);
            assert_eq!(orig_pkg.ecosystem, dec_pkg.ecosystem);
        }
    }

    #[test]
    fn test_decode_invalid_json() {
        let fmt = CycloneDxFormat;
        let result = fmt.decode(b"this is not valid json at all }{");
        assert!(
            result.is_err(),
            "decoding invalid JSON must return an error"
        );
        match result.unwrap_err() {
            SbomFormatError::DecodeFailed(_) => {}
            other => panic!("expected DecodeFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_format_name() {
        let fmt = CycloneDxFormat;
        assert_eq!(fmt.format_name(), "cyclonedx");
    }

    #[test]
    fn test_metadata_roundtrip() {
        // Ensure inspektr-namespaced metadata (like osv_ecosystem for OS
        // packages) survives a CycloneDX encode/decode cycle. Without this,
        // OS package vuln matching against an SBOM fails because the matcher
        // can't reconstruct the versioned OSV ecosystem name from the PURL.
        let fmt = CycloneDxFormat;
        let mut metadata = HashMap::new();
        metadata.insert("osv_ecosystem".to_string(), "Debian:13".to_string());
        let sbom = Sbom {
            source: SourceMetadata {
                source_type: "oci".to_string(),
                target: "nginx:latest".to_string(),
            },
            packages: vec![Package {
                name: "openssl".to_string(),
                version: "3.0.11-1~deb12u2".to_string(),
                ecosystem: Ecosystem::Debian,
                purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u2".to_string(),
                metadata,
                source_file: None,
            }],
        };

        let bytes = fmt.encode(&sbom).expect("encode should succeed");

        // The property must appear in the serialized JSON with the inspektr
        // prefix so other consumers know it's tool-specific.
        let doc: serde_json::Value =
            serde_json::from_slice(&bytes).expect("encoded output must be valid JSON");
        // First component is the inferred operating-system entry.
        assert_eq!(doc["components"][0]["type"], "operating-system");
        assert_eq!(doc["components"][0]["name"], "debian");
        // Second component is the actual package.
        let props = doc["components"][1]["properties"]
            .as_array()
            .expect("component must have properties");
        assert_eq!(props.len(), 1);
        assert_eq!(props[0]["name"], "inspektr:osv_ecosystem");
        assert_eq!(props[0]["value"], "Debian:13");
        // Metadata section must exist with tool and target info.
        assert!(doc["metadata"]["tools"]["components"][0]["name"] == "inspektr");
        assert_eq!(doc["metadata"]["component"]["type"], "container");
        assert_eq!(doc["metadata"]["component"]["name"], "nginx:latest");

        // And it must come back out on decode.
        let decoded = fmt.decode(&bytes).expect("decode should succeed");
        assert_eq!(decoded.packages.len(), 1);
        assert_eq!(
            decoded.packages[0].metadata.get("osv_ecosystem"),
            Some(&"Debian:13".to_string())
        );
    }

    #[test]
    fn test_infer_os_ecosystem_from_third_party_sbom() {
        // A CycloneDX SBOM produced by another tool (here we hand-roll one
        // that mimics what syft/trivy emit for alpine): an
        // `operating-system` component plus apk packages, none of which
        // carry inspektr-specific metadata. Decode should detect the OS,
        // compute the versioned OSV ecosystem name, and stamp it on every
        // apk package so the matcher can look up vulnerabilities.
        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "version": 1,
            "components": [
                {
                    "type": "operating-system",
                    "name": "alpine",
                    "version": "3.19.9"
                },
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "3.1.4-r5",
                    "purl": "pkg:apk/alpine/openssl@3.1.4-r5"
                }
            ]
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let decoded = CycloneDxFormat.decode(&bytes).expect("decode");
        assert_eq!(decoded.packages.len(), 1);
        let pkg = &decoded.packages[0];
        assert_eq!(pkg.ecosystem, Ecosystem::Alpine);
        assert_eq!(
            pkg.metadata.get("osv_ecosystem"),
            Some(&"Alpine:v3.19".to_string()),
            "inferred OS should populate osv_ecosystem for matching apk packages"
        );
    }

    #[test]
    fn test_infer_os_ecosystem_strips_debian_point_release() {
        // trivy reports Debian versions like "13.4"; OSV keys are major
        // only ("Debian:13"). Ensure normalization happens.
        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "version": 1,
            "components": [
                {
                    "type": "operating-system",
                    "name": "debian",
                    "version": "13.4"
                },
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "3.0.11-1~deb12u2",
                    "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2"
                }
            ]
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let decoded = CycloneDxFormat.decode(&bytes).expect("decode");
        assert_eq!(decoded.packages.len(), 1);
        assert_eq!(
            decoded.packages[0].metadata.get("osv_ecosystem"),
            Some(&"Debian:13".to_string())
        );
    }

    #[test]
    fn test_infer_os_does_not_overwrite_existing_osv_ecosystem() {
        // If a package already has an `inspektr:osv_ecosystem` annotation
        // (from an inspektr-authored roundtrip), we must not clobber it
        // with the OS-inferred value.
        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "version": 1,
            "components": [
                {
                    "type": "operating-system",
                    "name": "debian",
                    "version": "13.4"
                },
                {
                    "type": "library",
                    "name": "openssl",
                    "version": "3.0.11-1",
                    "purl": "pkg:deb/debian/openssl@3.0.11-1",
                    "properties": [
                        {"name": "inspektr:osv_ecosystem", "value": "Debian:12"}
                    ]
                }
            ]
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let decoded = CycloneDxFormat.decode(&bytes).expect("decode");
        assert_eq!(
            decoded.packages[0].metadata.get("osv_ecosystem"),
            Some(&"Debian:12".to_string()),
            "explicit inspektr annotation must take precedence over inferred OS"
        );
    }

    #[test]
    fn test_infer_os_does_not_apply_to_unrelated_ecosystems() {
        // A Go package in an alpine-based image should NOT be stamped with
        // Alpine's osv_ecosystem — it's a Go module, matched against
        // the Go ecosystem.
        let doc = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "version": 1,
            "components": [
                {
                    "type": "operating-system",
                    "name": "alpine",
                    "version": "3.19.9"
                },
                {
                    "type": "library",
                    "name": "golang.org/x/net",
                    "version": "v0.17.0",
                    "purl": "pkg:golang/golang.org/x/net@v0.17.0"
                }
            ]
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let decoded = CycloneDxFormat.decode(&bytes).expect("decode");
        assert_eq!(decoded.packages.len(), 1);
        assert!(
            !decoded.packages[0].metadata.contains_key("osv_ecosystem"),
            "Go packages should not get an Alpine osv_ecosystem stamp"
        );
    }

    #[test]
    fn test_source_file_roundtrip_per_binary() {
        // Two packages that share name/version/purl but live in different
        // binaries must round-trip as two distinct entries with their
        // source_file preserved. This is what enables per-binary
        // remediation: a CVE in `mongostat` is a different fix from the
        // same CVE in an unrelated Go binary.
        let fmt = CycloneDxFormat;
        let sbom = Sbom {
            source: SourceMetadata {
                source_type: "oci".to_string(),
                target: "mongo:7.0".to_string(),
            },
            packages: vec![
                Package {
                    name: "golang.org/x/net".to_string(),
                    version: "v0.17.0".to_string(),
                    ecosystem: Ecosystem::Go,
                    purl: "pkg:golang/golang.org/x/net@v0.17.0".to_string(),
                    metadata: HashMap::new(),
                    source_file: Some("usr/bin/mongostat".to_string()),
                },
                Package {
                    name: "golang.org/x/net".to_string(),
                    version: "v0.17.0".to_string(),
                    ecosystem: Ecosystem::Go,
                    purl: "pkg:golang/golang.org/x/net@v0.17.0".to_string(),
                    metadata: HashMap::new(),
                    source_file: Some("usr/bin/mongoexport".to_string()),
                },
            ],
        };
        let bytes = fmt.encode(&sbom).expect("encode");
        let decoded = fmt.decode(&bytes).expect("decode");
        assert_eq!(decoded.packages.len(), 2, "both occurrences must survive");
        let sources: Vec<_> = decoded
            .packages
            .iter()
            .filter_map(|p| p.source_file.clone())
            .collect();
        assert!(sources.contains(&"usr/bin/mongostat".to_string()));
        assert!(sources.contains(&"usr/bin/mongoexport".to_string()));
    }

    #[test]
    fn test_encode_omits_properties_when_empty() {
        // Packages with no metadata should not emit an empty `properties` key.
        let fmt = CycloneDxFormat;
        let sbom = make_sbom();
        let bytes = fmt.encode(&sbom).expect("encode should succeed");
        let doc: serde_json::Value =
            serde_json::from_slice(&bytes).expect("encoded output must be valid JSON");
        assert!(
            doc["components"][0].get("properties").is_none(),
            "empty properties array should be skipped from output"
        );
    }
}

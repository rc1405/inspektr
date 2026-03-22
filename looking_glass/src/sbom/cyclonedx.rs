use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    version: String,
    purl: String,
}

pub struct CycloneDxFormat;

impl SbomFormat for CycloneDxFormat {
    fn format_name(&self) -> &str {
        "cyclonedx"
    }

    fn encode(&self, sbom: &Sbom) -> Result<Vec<u8>, SbomFormatError> {
        let components: Vec<CycloneDxComponent> = sbom
            .packages
            .iter()
            .map(|pkg| CycloneDxComponent {
                component_type: "library".to_string(),
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                purl: pkg.purl.clone(),
            })
            .collect();

        let doc = CycloneDxDocument {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            components,
        };

        serde_json::to_vec_pretty(&doc)
            .map_err(|e| SbomFormatError::EncodeFailed(e.to_string()))
    }

    fn decode(&self, data: &[u8]) -> Result<Sbom, SbomFormatError> {
        let doc: CycloneDxDocument = serde_json::from_slice(data)
            .map_err(|e| SbomFormatError::DecodeFailed(e.to_string()))?;

        let packages: Vec<Package> = doc
            .components
            .into_iter()
            .map(|comp| {
                let ecosystem = if comp.purl.starts_with("pkg:golang/") {
                    Ecosystem::Go
                } else if comp.purl.starts_with("pkg:npm/") {
                    Ecosystem::JavaScript
                } else if comp.purl.starts_with("pkg:pypi/") {
                    Ecosystem::Python
                } else if comp.purl.starts_with("pkg:maven/") {
                    Ecosystem::Java
                } else if comp.purl.starts_with("pkg:conan/") {
                    Ecosystem::Conan
                } else if comp.purl.starts_with("pkg:vcpkg/") {
                    Ecosystem::Vcpkg
                } else if comp.purl.starts_with("pkg:nuget/") {
                    Ecosystem::DotNet
                } else if comp.purl.starts_with("pkg:composer/") {
                    Ecosystem::Php
                } else if comp.purl.starts_with("pkg:cargo/") {
                    Ecosystem::Rust
                } else if comp.purl.starts_with("pkg:gem/") {
                    Ecosystem::Ruby
                } else if comp.purl.starts_with("pkg:swift/") {
                    Ecosystem::Swift
                } else {
                    Ecosystem::Go // fallback
                };
                Package {
                    name: comp.name,
                    version: comp.version,
                    ecosystem,
                    purl: comp.purl,
                    metadata: HashMap::new(),
                    source_file: None,
                }
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

        let components = doc["components"].as_array().expect("components must be array");
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
        assert!(result.is_err(), "decoding invalid JSON must return an error");
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
}

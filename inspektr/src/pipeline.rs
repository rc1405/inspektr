//! High-level entry points for SBOM generation and vulnerability scanning.
//!
//! This module provides the main functions most consumers will use:
//!
//! - [`generate_sbom()`] — scan a target and return an [`Sbom`]
//! - [`generate_sbom_bytes()`] — scan and encode as CycloneDX or SPDX bytes
//! - [`scan_and_report()`] — scan for vulnerabilities and return a
//!   [`ScanReport`](crate::vuln::report::ScanReport)
//! - [`run_catalogers()`] — lower-level: run all catalogers against a set of files
//! - [`default_db_path()`] — get the platform-appropriate vulnerability database path
//!
//! # Examples
//!
//! ```no_run
//! use inspektr::pipeline;
//! use inspektr::oci::RegistryAuth;
//!
//! // Generate an SBOM
//! let sbom = pipeline::generate_sbom(
//!     "/path/to/project",
//!     &RegistryAuth::Anonymous,
//! ).unwrap();
//!
//! // Scan for vulnerabilities
//! let report = pipeline::scan_and_report(
//!     Some("/path/to/project"),
//!     None,
//!     &pipeline::default_db_path(),
//!     &RegistryAuth::Anonymous,
//! ).unwrap();
//! ```

use crate::cataloger::Cataloger;
use crate::cataloger::conan::ConanCataloger;
use crate::cataloger::dotnet::DotNetCataloger;
use crate::cataloger::golang::GoCataloger;
use crate::cataloger::java::{JavaArchiveCataloger, JavaCataloger};
use crate::cataloger::javascript::JavaScriptCataloger;
use crate::cataloger::os::OsCataloger;
use crate::cataloger::php::PhpCataloger;
use crate::cataloger::python::PythonCataloger;
use crate::cataloger::ruby::RubyCataloger;
use crate::cataloger::rust_lang::RustCataloger;
use crate::cataloger::swift::SwiftCataloger;
use crate::cataloger::vcpkg::VcpkgCataloger;
use crate::error::InspektrError;
use crate::models::{FileEntry, Package, Sbom};
use crate::sbom::SbomFormat;
use crate::sbom::cyclonedx::CycloneDxFormat;
use crate::source::Source;
use crate::source::detect::{TargetType, detect_target_type};
use crate::source::filesystem::FilesystemSource;
use crate::source::oci::OciImageSource;
use crate::vuln::matcher;

/// Build the list of catalogers to run.
fn catalogers() -> Vec<Box<dyn Cataloger>> {
    vec![
        Box::new(GoCataloger),
        Box::new(JavaScriptCataloger),
        Box::new(PythonCataloger),
        Box::new(JavaCataloger),
        Box::new(JavaArchiveCataloger),
        Box::new(ConanCataloger),
        Box::new(VcpkgCataloger),
        Box::new(DotNetCataloger),
        Box::new(PhpCataloger),
        Box::new(RustCataloger),
        Box::new(RubyCataloger),
        Box::new(SwiftCataloger),
        Box::new(OsCataloger),
    ]
}

/// Run every cataloger against `files`, collect all discovered packages.
/// If a cataloger returns an error, a warning is printed to stderr and
/// the cataloger is skipped.
pub fn run_catalogers(files: &[FileEntry]) -> Vec<Package> {
    let mut packages = Vec::new();
    for cataloger in catalogers() {
        if !cataloger.can_catalog(files) {
            continue;
        }
        match cataloger.catalog(files) {
            Ok(mut pkgs) => packages.append(&mut pkgs),
            Err(e) => {
                eprintln!("Warning: cataloger '{}' failed: {}", cataloger.name(), e);
            }
        }
    }
    packages
}

/// Choose the right `Source` implementation based on the detected target type.
fn source_from_target(
    target: &str,
    auth: &oci_client::secrets::RegistryAuth,
) -> Result<Box<dyn Source>, InspektrError> {
    match detect_target_type(target) {
        TargetType::OciImage => Ok(Box::new(OciImageSource::new(
            target.to_string(),
            auth.clone(),
        ))),
        TargetType::Binary | TargetType::Filesystem => Ok(Box::new(FilesystemSource::new(
            std::path::PathBuf::from(target),
        ))),
    }
}

/// Collect files from `target`, run all catalogers, and return an SBOM.
///
/// `auth` is used for OCI image targets. Pass `RegistryAuth::Anonymous` for
/// public images or filesystem/binary targets.
pub fn generate_sbom(
    target: &str,
    auth: &oci_client::secrets::RegistryAuth,
) -> Result<Sbom, InspektrError> {
    let source = source_from_target(target, auth)?;
    let metadata = source.source_metadata();
    let files = source.files()?;
    let packages = run_catalogers(&files);
    Ok(Sbom {
        source: metadata,
        packages,
    })
}

/// Generate an SBOM and encode it in the requested format.
///
/// `format` should be `"cyclonedx"` or `"spdx"`.
pub fn generate_sbom_bytes(
    target: &str,
    format: &str,
    auth: &oci_client::secrets::RegistryAuth,
) -> Result<Vec<u8>, InspektrError> {
    let sbom = generate_sbom(target, auth)?;
    let formatter = select_format(format)?;
    Ok(formatter.encode(&sbom)?)
}

/// Scan for vulnerabilities and build a full report with metadata.
///
/// `auth` is used for OCI image targets. Pass `RegistryAuth::Anonymous` for
/// public images or filesystem/binary/SBOM targets.
pub fn scan_and_report(
    target: Option<&str>,
    sbom_path: Option<&str>,
    db_path: &std::path::Path,
    auth: &oci_client::secrets::RegistryAuth,
) -> Result<crate::vuln::report::ScanReport, InspektrError> {
    let (sbom, target_str, target_type_str) = match (target, sbom_path) {
        (_, Some(path)) => {
            let bytes = std::fs::read(path).map_err(|e| crate::error::SourceError::Io(e))?;
            let format_name = detect_sbom_format(&bytes);
            let formatter = select_format(format_name)?;
            let sbom = formatter.decode(&bytes)?;
            (sbom, path.to_string(), "sbom".to_string())
        }
        (Some(t), None) => {
            let tt = match crate::source::detect::detect_target_type(t) {
                crate::source::detect::TargetType::OciImage => "oci",
                crate::source::detect::TargetType::Binary => "binary",
                crate::source::detect::TargetType::Filesystem => "filesystem",
            };
            let sbom = generate_sbom(t, auth)?;
            (sbom, t.to_string(), tt.to_string())
        }
        (None, None) => {
            return Err(InspektrError::Source(
                crate::error::SourceError::UnsupportedTarget {
                    target: "(none)".to_string(),
                },
            ));
        }
    };

    let db_str = db_path.to_string_lossy();
    let store = crate::db::store::VulnStore::open(&db_str)?;
    let matches = matcher::match_packages(&store, &sbom.packages);
    let total_packages = sbom.packages.len();

    Ok(crate::vuln::report::build_scan_report(
        &target_str,
        &target_type_str,
        total_packages,
        &matches,
    ))
}

/// Detect an SBOM format from the raw bytes of a JSON document.
///
/// Checks for format-identifying top-level keys:
/// - CycloneDX 1.x: `"bomFormat": "CycloneDX"`
/// - SPDX 2.x: `"spdxVersion": "SPDX-2..."`
///
/// Falls back to `"cyclonedx"` if nothing matches, so existing behavior on
/// malformed or unrecognized input is preserved.
fn detect_sbom_format(bytes: &[u8]) -> &'static str {
    // Parse just enough of the document to look at its top-level keys. A full
    // decode would double the work we're about to do in the real decoder.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if value
            .get("spdxVersion")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.starts_with("SPDX-"))
        {
            return "spdx";
        }
        if value
            .get("bomFormat")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("CycloneDX"))
        {
            return "cyclonedx";
        }
    }
    "cyclonedx"
}

/// Map a format name string to a `SbomFormat` implementation.
fn select_format(format: &str) -> Result<Box<dyn SbomFormat>, InspektrError> {
    match format {
        "cyclonedx" => Ok(Box::new(CycloneDxFormat)),
        "spdx" => Ok(Box::new(crate::sbom::spdx::SpdxFormat)),
        other => Err(InspektrError::SbomFormat(
            crate::error::SbomFormatError::EncodeFailed(format!(
                "unsupported SBOM format: {}; supported formats are: cyclonedx, spdx",
                other
            )),
        )),
    }
}

/// Return the default path for the vulnerability database.
///
/// Uses `XDG_DATA_HOME` if set, otherwise `~/.local/share`, and appends
/// `inspektr/vuln.db`.
pub fn default_db_path() -> std::path::PathBuf {
    let base = if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(home).join(".local").join("share")
    };
    base.join("inspektr").join("vuln.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Ecosystem, FileContents, FileEntry};
    use std::path::PathBuf;

    fn go_mod_entry() -> FileEntry {
        let content = "module example.com/myapp\n\ngo 1.21\n\nrequire (\n    github.com/stretchr/testify v1.8.4\n)\n";
        FileEntry {
            path: PathBuf::from("/project/go.mod"),
            contents: FileContents::Text(content.to_string()),
        }
    }

    #[test]
    fn test_run_catalogers() {
        let files = vec![go_mod_entry()];
        let packages = run_catalogers(&files);
        assert!(!packages.is_empty(), "should find at least one package");
        assert!(
            packages
                .iter()
                .any(|p| p.name == "github.com/stretchr/testify"),
            "should find testify"
        );
    }

    #[test]
    fn test_run_catalogers_no_matches() {
        // Files with no recognised manifests should yield no packages.
        let files = vec![FileEntry {
            path: PathBuf::from("/project/README.md"),
            contents: FileContents::Text("# My Project\n".to_string()),
        }];
        let packages = run_catalogers(&files);
        assert!(
            packages.is_empty(),
            "should find no packages for a plain markdown file"
        );
    }

    #[test]
    fn test_run_catalogers_javascript() {
        let content = r#"{"name":"app","lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.18.2"}}}"#;
        let files = vec![FileEntry {
            path: PathBuf::from("/project/package-lock.json"),
            contents: FileContents::Text(content.to_string()),
        }];
        let packages = run_catalogers(&files);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "express");
        assert_eq!(packages[0].ecosystem, Ecosystem::JavaScript);
    }

    #[test]
    fn test_run_catalogers_python() {
        let files = vec![FileEntry {
            path: PathBuf::from("/project/requirements.txt"),
            contents: FileContents::Text("requests==2.31.0\n".to_string()),
        }];
        let packages = run_catalogers(&files);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "requests");
        assert_eq!(packages[0].ecosystem, Ecosystem::Python);
    }

    #[test]
    fn test_run_catalogers_java() {
        let content = r#"<project><dependencies>
            <dependency><groupId>org.foo</groupId><artifactId>bar</artifactId><version>1.0</version></dependency>
        </dependencies></project>"#;
        let files = vec![FileEntry {
            path: PathBuf::from("/project/pom.xml"),
            contents: FileContents::Text(content.to_string()),
        }];
        let packages = run_catalogers(&files);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].ecosystem, Ecosystem::Java);
    }

    #[test]
    fn test_run_catalogers_rust() {
        let content = "[[package]]\nname = \"serde\"\nversion = \"1.0.193\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let files = vec![FileEntry {
            path: PathBuf::from("/project/Cargo.lock"),
            contents: FileContents::Text(content.to_string()),
        }];
        let packages = run_catalogers(&files);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "serde");
        assert_eq!(packages[0].ecosystem, Ecosystem::Rust);
    }

    #[test]
    fn test_run_catalogers_php() {
        let content =
            r#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"}],"packages-dev":[]}"#;
        let files = vec![FileEntry {
            path: PathBuf::from("/project/composer.lock"),
            contents: FileContents::Text(content.to_string()),
        }];
        let packages = run_catalogers(&files);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "monolog/monolog");
        assert_eq!(packages[0].ecosystem, Ecosystem::Php);
    }

    #[test]
    fn test_run_catalogers_ruby() {
        let content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.2)\n\nPLATFORMS\n  ruby\n";
        let files = vec![FileEntry {
            path: PathBuf::from("/project/Gemfile.lock"),
            contents: FileContents::Text(content.to_string()),
        }];
        let packages = run_catalogers(&files);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "rails");
        assert_eq!(packages[0].ecosystem, Ecosystem::Ruby);
    }

    #[test]
    fn test_run_catalogers_dotnet() {
        let content =
            r#"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"resolved":"13.0.3"}}}}"#;
        let files = vec![FileEntry {
            path: PathBuf::from("/project/packages.lock.json"),
            contents: FileContents::Text(content.to_string()),
        }];
        let packages = run_catalogers(&files);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "Newtonsoft.Json");
        assert_eq!(packages[0].ecosystem, Ecosystem::DotNet);
    }

    #[test]
    fn test_run_catalogers_mixed_ecosystems_spdx_roundtrip() {
        use crate::sbom::SbomFormat;
        let go_mod = FileEntry {
            path: PathBuf::from("/project/go.mod"),
            contents: FileContents::Text(
                "module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n"
                    .to_string(),
            ),
        };
        let packages = run_catalogers(&[go_mod]);
        let sbom = Sbom {
            source: crate::models::SourceMetadata {
                source_type: "filesystem".to_string(),
                target: "/project".to_string(),
            },
            packages,
        };
        let formatter = crate::sbom::spdx::SpdxFormat;
        let encoded = formatter.encode(&sbom).unwrap();
        let decoded = formatter.decode(&encoded).unwrap();
        assert_eq!(decoded.packages.len(), 1);
        assert_eq!(decoded.packages[0].name, "github.com/pkg/errors");
    }
}

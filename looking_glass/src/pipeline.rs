use std::path::Path;
use crate::cataloger::golang::GoCataloger;
use crate::cataloger::javascript::JavaScriptCataloger;
use crate::cataloger::python::PythonCataloger;
use crate::cataloger::java::JavaCataloger;
use crate::cataloger::Cataloger;
use crate::db::store::VulnStore;
use crate::error::LookingGlassError;
use crate::models::{FileEntry, Package, Sbom, VulnerabilityMatch};
use crate::sbom::cyclonedx::CycloneDxFormat;
use crate::sbom::SbomFormat;
use crate::source::detect::{detect_target_type, TargetType};
use crate::source::filesystem::FilesystemSource;
use crate::source::oci::OciImageSource;
use crate::source::Source;
use crate::vuln::matcher;

/// Build the list of catalogers to run.
fn catalogers() -> Vec<Box<dyn Cataloger>> {
    vec![
        Box::new(GoCataloger),
        Box::new(JavaScriptCataloger),
        Box::new(PythonCataloger),
        Box::new(JavaCataloger),
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
fn source_from_target(target: &str) -> Result<Box<dyn Source>, LookingGlassError> {
    match detect_target_type(target) {
        TargetType::OciImage => Ok(Box::new(OciImageSource::new(target.to_string()))),
        TargetType::Binary | TargetType::Filesystem => {
            Ok(Box::new(FilesystemSource::new(
                std::path::PathBuf::from(target),
            )))
        }
    }
}

/// Collect files from `target`, run all catalogers, and return an SBOM.
pub fn generate_sbom(target: &str) -> Result<Sbom, LookingGlassError> {
    let source = source_from_target(target)?;
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
pub fn generate_sbom_bytes(target: &str, format: &str) -> Result<Vec<u8>, LookingGlassError> {
    let sbom = generate_sbom(target)?;
    let formatter = select_format(format)?;
    Ok(formatter.encode(&sbom)?)
}

/// Either generate an SBOM from `target` or read one from `sbom_path`, then
/// match all packages against the vulnerability database at `db_path`.
pub fn scan_vulnerabilities(
    target: Option<&str>,
    sbom_path: Option<&str>,
    db_path: &Path,
) -> Result<Vec<VulnerabilityMatch>, LookingGlassError> {
    let sbom = match (target, sbom_path) {
        (_, Some(path)) => {
            // Read SBOM from file and decode it.
            let bytes = std::fs::read(path).map_err(|e| {
                crate::error::SourceError::Io(e)
            })?;
            let formatter = select_format("cyclonedx")?;
            formatter.decode(&bytes)?
        }
        (Some(t), None) => generate_sbom(t)?,
        (None, None) => {
            return Err(LookingGlassError::Source(
                crate::error::SourceError::UnsupportedTarget {
                    target: "(none)".to_string(),
                },
            ));
        }
    };

    let db_path_str = db_path.to_string_lossy();
    let store = VulnStore::open(&db_path_str)?;
    Ok(matcher::match_packages(&store, &sbom.packages))
}

/// Map a format name string to a `SbomFormat` implementation.
fn select_format(format: &str) -> Result<Box<dyn SbomFormat>, LookingGlassError> {
    match format {
        "cyclonedx" => Ok(Box::new(CycloneDxFormat)),
        "spdx" => Ok(Box::new(crate::sbom::spdx::SpdxFormat)),
        other => Err(LookingGlassError::SbomFormat(
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
/// `looking-glass/vuln.db`.
pub fn default_db_path() -> std::path::PathBuf {
    let base = if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(home).join(".local").join("share")
    };
    base.join("looking-glass").join("vuln.db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Ecosystem, FileContents, FileEntry};
    use std::collections::HashMap;
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

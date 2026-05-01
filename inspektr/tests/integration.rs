use inspektr::cataloger::Cataloger;
use inspektr::cataloger::golang::GoCataloger;
use inspektr::db::store::{AffectedPackage, AffectedRange, VulnRecord, VulnStore};
use inspektr::models::*;
use inspektr::sbom::SbomFormat;
use inspektr::sbom::cyclonedx::CycloneDxFormat;
use inspektr::source::Source;
use inspektr::source::filesystem::FilesystemSource;
use inspektr::vuln::matcher;

#[test]
fn test_full_pipeline_go_filesystem() {
    // -----------------------------------------------------------------------
    // 1. Create a temp directory containing a go.mod with a vulnerable package.
    // -----------------------------------------------------------------------
    let dir = tempfile::tempdir().expect("create temp dir");
    let go_mod = format!(
        "module example.com/testapp\n\ngo 1.21\n\nrequire (\n    github.com/example/vuln-pkg v1.1.0\n)\n"
    );
    std::fs::write(dir.path().join("go.mod"), &go_mod).expect("write go.mod");

    // -----------------------------------------------------------------------
    // 2. FilesystemSource → collect files.
    // -----------------------------------------------------------------------
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let files = source.files().expect("collect files");
    assert_eq!(files.len(), 1, "should have exactly one file");

    // -----------------------------------------------------------------------
    // 3. GoCataloger → discover packages.
    // -----------------------------------------------------------------------
    let cataloger = GoCataloger;
    assert!(
        cataloger.can_catalog(&files),
        "GoCataloger should accept go.mod"
    );
    let packages = cataloger.catalog(&files).expect("catalog packages");
    assert_eq!(packages.len(), 1, "should find exactly one package");
    assert_eq!(packages[0].name, "github.com/example/vuln-pkg");
    assert_eq!(packages[0].version, "v1.1.0");

    // -----------------------------------------------------------------------
    // 4. CycloneDX encode → decode roundtrip.
    // -----------------------------------------------------------------------
    let sbom = Sbom {
        source: source.source_metadata(),
        packages: packages.clone(),
    };
    let fmt = CycloneDxFormat;
    let encoded = fmt.encode(&sbom).expect("encode SBOM");
    let decoded = fmt.decode(&encoded).expect("decode SBOM");

    assert_eq!(
        decoded.packages.len(),
        sbom.packages.len(),
        "roundtrip should preserve package count"
    );
    assert_eq!(decoded.packages[0].name, "github.com/example/vuln-pkg");
    assert_eq!(decoded.packages[0].version, "v1.1.0");

    // -----------------------------------------------------------------------
    // 5. VulnStore with a test vulnerability → matcher → verify match found.
    // -----------------------------------------------------------------------
    let mut store = VulnStore::open_in_memory().expect("open in-memory DB");
    let record = VulnRecord {
        id: "GO-2024-TEST-0001".to_string(),
        original_id: None,
        summary: "Test vulnerability in vuln-pkg".to_string(),
        severity: Severity::High,
        published: "2024-01-01T00:00:00Z".to_string(),
        modified: "2024-02-01T00:00:00Z".to_string(),
        withdrawn: None,
        source: "osv".to_string(),
        cvss_score: None,
        affected: vec![AffectedPackage {
            ecosystem: "Go".to_string(),
            package_name: "github.com/example/vuln-pkg".to_string(),
            ranges: vec![AffectedRange {
                range_type: "SEMVER".to_string(),
                introduced: Some("1.0.0".to_string()),
                fixed: Some("1.2.0".to_string()),
            }],
            severity_override: None,
        }],
    };
    store
        .insert_vulnerabilities(&[record])
        .expect("insert test vulnerability");

    let matches = matcher::match_packages(&store, &packages);
    assert_eq!(
        matches.len(),
        1,
        "should find exactly one vulnerability match"
    );
    assert_eq!(matches[0].vulnerability.id, "GO-2024-TEST-0001");
    assert_eq!(matches[0].vulnerability.severity, Severity::High);
    assert_eq!(matches[0].package.name, "github.com/example/vuln-pkg");
    assert_eq!(
        matches[0].fixed,
        Some("1.2.0".to_string()),
        "should report the fixed version"
    );
}

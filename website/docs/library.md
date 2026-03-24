# Library Usage

Inspektr can be used as a Rust library. Add it to your `Cargo.toml`:

```toml
[dependencies]
inspektr = { git = "https://github.com/rc1405/inspektr.git" }
```

## Generate an SBOM

```rust
use inspektr::pipeline;
use inspektr::sbom::cyclonedx::CycloneDxFormat;
use inspektr::sbom::spdx::SpdxFormat;
use inspektr::sbom::SbomFormat;

// Generate SBOM from a directory
let sbom = pipeline::generate_sbom("/path/to/project")?;

// Encode as CycloneDX JSON
let cyclonedx_bytes = CycloneDxFormat.encode(&sbom)?;

// Encode as SPDX JSON
let spdx_bytes = SpdxFormat.encode(&sbom)?;

// Generate and encode in one step
let bytes = pipeline::generate_sbom_bytes("/path/to/project", "cyclonedx")?;
```

## Vulnerability Scanning

```rust
use inspektr::pipeline;

let report = pipeline::scan_and_report(
    Some("/path/to/project"),  // target
    None,                       // or Some("sbom.json") for existing SBOM
    &pipeline::default_db_path(),
)?;

println!("Target: {}", report.metadata.target);
println!("Vulnerabilities: {}", report.metadata.total_vulnerabilities);

for vuln in &report.vulnerabilities {
    println!("{}: {} @ {} (fixed: {:?})",
        vuln.id,
        vuln.package_name,
        vuln.package_version,
        vuln.fixed_version,
    );

    for (source, assessment) in &vuln.assessments {
        println!("  [{source}] severity={:?} cvss={:?}",
            assessment.severity,
            assessment.cvss_score,
        );
    }
}
```

## Working with Individual Components

### Source

```rust
use inspektr::source::filesystem::FilesystemSource;
use inspektr::source::Source;
use std::path::PathBuf;

let source = FilesystemSource::new(PathBuf::from("/path/to/project"));
let files = source.files()?;
```

### Cataloger

```rust
use inspektr::cataloger::golang::GoCataloger;
use inspektr::cataloger::Cataloger;

let cataloger = GoCataloger;
if cataloger.can_catalog(&files) {
    let packages = cataloger.catalog(&files)?;
}
```

### Vulnerability Database

```rust
use inspektr::db::store::VulnStore;
use inspektr::vuln::matcher;

let store = VulnStore::open("/path/to/vuln.db")?;
let matches = matcher::match_packages(&store, &packages);
```

## Custom Cataloger

```rust
use inspektr::cataloger::Cataloger;
use inspektr::models::{FileEntry, Package};
use inspektr::error::CatalogerError;

struct MyCataloger;

impl Cataloger for MyCataloger {
    fn name(&self) -> &str { "my-ecosystem" }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f|
            f.path.file_name().map(|n| n == "my.lock").unwrap_or(false)
        )
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        // Parse your lockfile format here
        Ok(vec![])
    }
}
```

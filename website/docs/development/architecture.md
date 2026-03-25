# Architecture

## Pipeline

Inspektr uses a layered pipeline with five stages, each defined by a trait:

```
Source -> Cataloger -> SbomFormat -> Matcher -> Reporter
```

1. **Source** — provides files from a target (filesystem, binary, OCI image)
2. **Cataloger** — discovers packages from files (one per ecosystem + OS cataloger)
3. **SbomFormat** — serializes/deserializes SBOMs (CycloneDX, SPDX)
4. **Matcher** — queries the vulnerability database for version range matches
5. **Reporter** — renders results with scan metadata and per-source assessments

## Crate Structure

```
inspektr/              # Library crate — all core logic
inspektr_cli/          # Binary crate — thin CLI layer using clap
```

The library is usable independently for embedding in other tools.

## Key Traits

### Source

```rust
trait Source {
    fn files(&self) -> Result<Vec<FileEntry>, SourceError>;
    fn source_metadata(&self) -> SourceMetadata;
}
```

Implementations: `FilesystemSource`, `OciImageSource`

### Cataloger

```rust
trait Cataloger {
    fn name(&self) -> &str;
    fn can_catalog(&self, files: &[FileEntry]) -> bool;
    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError>;
}
```

12 language catalogers + `OsCataloger` (which internally dispatches to dpkg/apk/rpm parsers).

### SbomFormat

```rust
trait SbomFormat {
    fn format_name(&self) -> &str;
    fn encode(&self, sbom: &Sbom) -> Result<Vec<u8>, SbomFormatError>;
    fn decode(&self, data: &[u8]) -> Result<Sbom, SbomFormatError>;
}
```

Implementations: `CycloneDxFormat`, `SpdxFormat`

### VulnSource

```rust
trait VulnSource {
    fn name(&self) -> &str;
    fn import(&self, store: &mut VulnStore, ecosystem: Option<&str>) -> Result<usize, DatabaseError>;
}
```

Implementations: `OsvSource`, `NvdSource`

## Data Flow

### SBOM Generation

```
target string
  -> detect_target_type() -> TargetType (OCI/Binary/Filesystem)
  -> source_from_target() -> Box<dyn Source>
  -> source.files() -> Vec<FileEntry>
  -> run_catalogers() -> Vec<Package>
  -> SbomFormat::encode() -> bytes
```

### Vulnerability Scanning

```
target/SBOM
  -> generate or decode SBOM -> Vec<Package>
  -> VulnStore::open() -> query per package
  -> match_packages() -> Vec<VulnerabilityMatch>
  -> build_scan_report() -> ScanReport (merges duplicates, per-source assessments)
  -> render_report_table() or render_report_json()
```

### Database Build

```
for each VulnSource:
  -> source.import(store, ecosystem)
    -> OSV: download ZIP, parse JSON entries -> VulnRecord -> insert
    -> NVD: paginate API, resolve CPE -> VulnRecord -> insert
    -> Oracle: download OVAL XML (bzip2), parse definitions -> VulnRecord -> insert
    -> Photon: download JSON CVE metadata -> VulnRecord -> insert
    -> Azure Linux: download OVAL XML from GitHub -> VulnRecord -> insert
    -> Bottlerocket: download updateinfo.xml (gzip) -> VulnRecord -> insert
    -> CentOS: duplicated from Red Hat data after OSV import
```

## Feature Flags

| Feature | What it enables |
|---------|----------------|
| `default` | SBOM generation, vulnerability scanning, database pull |
| `db-admin` | `db build`, `db push` — all vulnerability importers, OCI push. Adds `quick-xml`, `bzip2`, `zip` dependencies. |

## Module Map

| Module | Responsibility |
|--------|---------------|
| `models/` | `Ecosystem`, `Package`, `Vulnerability`, `Severity`, etc. |
| `source/` | `Source` trait, filesystem/OCI implementations, target detection |
| `cataloger/` | `Cataloger` trait, 12 language catalogers, OS cataloger |
| `sbom/` | `SbomFormat` trait, CycloneDX, SPDX |
| `db/` | `VulnSource` trait, SQLite store, importers (OSV, NVD, Oracle OVAL, Photon, Azure Linux, Bottlerocket) |
| `vuln/` | Matcher (semver + OS fallback), report types, renderers |
| `oci/` | OCI registry client, image reference parsing, auth |
| `cpe/` | CPE 2.3 parser, target_sw/vendor mappings for NVD |
| `pipeline` | Orchestration — ties layers together |
| `error` | Error types (thiserror) |

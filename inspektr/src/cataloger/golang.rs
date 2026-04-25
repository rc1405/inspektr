//! Go ecosystem cataloger.
//!
//! Discovers Go packages from `go.mod`, `go.sum`, and compiled Go binaries.
//! Binary analysis uses the Go build info embedded in ELF/Mach-O/PE executables
//! (identified by [`GO_BUILDINFO_MAGIC`]).

use super::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;

/// Magic bytes found in Go binaries that contain build information.
pub const GO_BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// Cataloger for Go modules and binaries.
pub struct GoCataloger;

impl Cataloger for GoCataloger {
    fn name(&self) -> &str {
        "go"
    }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "go.mod" || name == "go.sum" || is_go_binary(f)
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages = Vec::new();

        // Manifest/lockfile scans share a dedup set: a `go.sum` typically
        // lists every version in `go.mod` plus transitive test deps, and
        // both files describe the same logical project. Deduping across
        // them avoids one module showing up twice from the same project.
        let mut manifest_seen: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for file in files {
            let file_name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name == "go.mod" {
                if let Some(text) = file.as_text() {
                    for mut pkg in parse_go_mod(text)? {
                        pkg.metadata
                            .insert("source".to_string(), "go.mod".to_string());
                        pkg.source_file = Some(file.path.display().to_string());
                        let key = format!("{}@{}", pkg.name, pkg.version);
                        if manifest_seen.insert(key) {
                            packages.push(pkg);
                        }
                    }
                }
            } else if file_name == "go.sum" {
                if let Some(text) = file.as_text() {
                    for mut pkg in parse_go_sum(text)? {
                        pkg.metadata
                            .insert("source".to_string(), "go.sum".to_string());
                        pkg.source_file = Some(file.path.display().to_string());
                        let key = format!("{}@{}", pkg.name, pkg.version);
                        if manifest_seen.insert(key) {
                            packages.push(pkg);
                        }
                    }
                }
            }
        }

        // Go binary scans: preserve per-binary attribution.
        //
        // Each binary is a distinct remediation target — a CVE in
        // `golang.org/x/net` inside `mongostat` is a different fix than
        // the same CVE inside an unrelated tool. Deduping across binaries
        // loses that mapping, so we emit one package entry per module per
        // binary and rely on `source_file` to tell them apart.
        //
        // Within a single binary we still dedupe, since Go's buildinfo
        // format already emits each module once — but a defensive set
        // avoids inflating counts if a binary somehow contains a
        // duplicate line.
        for file in files {
            if !is_go_binary(file) {
                continue;
            }
            let raw_bytes = file.as_bytes();
            let Some(text) = extract_buildinfo_from_binary(raw_bytes) else {
                continue;
            };
            let mut binary_seen: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            let source_file = file.path.display().to_string();

            if let Some(go_ver) = extract_go_version(raw_bytes) {
                let version = go_ver.strip_prefix("go").unwrap_or(&go_ver);
                let key = format!("stdlib@{}", version);
                if binary_seen.insert(key) {
                    let purl = format!("pkg:golang/stdlib@v{}", version);
                    packages.push(Package {
                        name: "stdlib".to_string(),
                        version: format!("v{}", version),
                        ecosystem: Ecosystem::Go,
                        purl,
                        metadata: HashMap::from([("source".to_string(), "binary".to_string())]),
                        source_file: Some(source_file.clone()),
                    });
                }
            }

            for mut pkg in parse_buildinfo_text(&text)? {
                let key = format!("{}@{}", pkg.name, pkg.version);
                if !binary_seen.insert(key) {
                    continue;
                }
                pkg.metadata
                    .insert("source".to_string(), "binary".to_string());
                pkg.source_file = Some(source_file.clone());
                packages.push(pkg);
            }
        }

        Ok(packages)
    }
}

/// Returns true if the file appears to be a Go binary (contains Go buildinfo magic).
pub fn is_go_binary(file: &FileEntry) -> bool {
    let bytes = file.as_bytes();
    contains_subsequence(bytes, GO_BUILDINFO_MAGIC)
}

/// Checks whether `haystack` contains `needle` as a contiguous subsequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Extract the Go toolchain version from a binary's buildinfo header.
///
/// The version string (e.g., `go1.21.8`) is embedded in the header bytes
/// between the magic marker and the module text. We scan a bounded window
/// for the `go1.` prefix and read until the next non-version byte.
pub fn extract_go_version(bytes: &[u8]) -> Option<String> {
    let magic = GO_BUILDINFO_MAGIC;
    let pos = bytes.windows(magic.len()).position(|w| w == magic)?;
    let search_end = (pos + magic.len() + 512).min(bytes.len());
    let region = &bytes[pos..search_end];
    let marker = b"go1.";
    let idx = region.windows(marker.len()).position(|w| w == marker)?;
    let start = idx;
    let version_bytes = &region[start..];
    let end = version_bytes
        .iter()
        .position(|&b| !b.is_ascii_alphanumeric() && b != b'.')
        .unwrap_or(version_bytes.len());
    let version = std::str::from_utf8(&version_bytes[..end]).ok()?;
    if version.len() >= 4 {
        Some(version.to_string())
    } else {
        None
    }
}

/// Finds the Go buildinfo magic marker in raw bytes, then locates the
/// embedded module info text (which starts with "path\t" or "mod\t")
/// and extracts it up to the first null byte.
///
/// Go's buildinfo format has a structured header between the magic marker
/// and the actual module text. The header contains flags, pointers, and
/// the Go version string. We skip past it by searching for the text markers,
/// then read the full text block (which can be many KB for binaries with
/// hundreds of dependencies).
pub fn extract_buildinfo_from_binary(bytes: &[u8]) -> Option<String> {
    let magic = GO_BUILDINFO_MAGIC;
    let pos = bytes.windows(magic.len()).position(|w| w == magic)?;

    let magic_end = pos + magic.len();

    // Scan a bounded window just past the magic to locate the start of the
    // human-readable module text. Go's buildinfo header between the magic
    // and the text is small (flags + pointers + version string), so 4KB is
    // more than enough. We only use this window to find the offset —
    // reading the text itself uses the full binary so large dep lists are
    // not truncated.
    let header_search_end = (magic_end + 4096).min(bytes.len());
    let header_region = &bytes[magic_end..header_search_end];

    let text_markers: &[&[u8]] = &[b"path\t", b"mod\t"];
    let text_start_in_header = text_markers
        .iter()
        .filter_map(|marker| header_region.windows(marker.len()).position(|w| w == *marker))
        .min()?;

    let text_start_abs = magic_end + text_start_in_header;
    let text_region = &bytes[text_start_abs..];

    // Go's buildinfo text block is null-terminated. Large binaries like
    // `grafana` can have hundreds of `dep\t...` lines totaling many KB, so
    // we must NOT cap this search — earlier versions limited it to 4KB and
    // truncated at ~40 deps.
    let end = text_region
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(text_region.len());

    // The region before the null may contain trailing non-UTF8 bytes
    // (Go's encoding can place binary data after the text block).
    // Use lossy conversion and trim to the last complete line.
    let text = String::from_utf8_lossy(&text_region[..end]);
    if let Some(last_newline) = text.rfind('\n') {
        Some(text[..=last_newline].to_string())
    } else {
        Some(text.into_owned())
    }
}

/// Parses the human-readable portion of a Go binary's build info.
/// Lines starting with "dep\t" are dependency entries.
/// Format: `dep\t<module>\t<version>[\t<hash>]`
pub fn parse_buildinfo_text(text: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("dep\t") {
            let parts: Vec<&str> = rest.splitn(3, '\t').collect();
            if parts.len() >= 2 {
                let name = parts[0].trim().to_string();
                let version = parts[1].trim().to_string();
                if !name.is_empty() && !version.is_empty() {
                    let purl = format!("pkg:golang/{}@{}", name.to_lowercase(), version);
                    packages.push(Package {
                        name,
                        version,
                        ecosystem: Ecosystem::Go,
                        purl,
                        metadata: HashMap::new(),
                        source_file: None,
                    });
                }
            }
        }
    }
    Ok(packages)
}

/// Parses a go.mod file and returns the list of required packages.
pub fn parse_go_mod(text: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();
    let mut in_require_block = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed == "require (" {
            in_require_block = true;
            continue;
        }

        if in_require_block && trimmed == ")" {
            in_require_block = false;
            continue;
        }

        if in_require_block {
            if let Some(pkg) = parse_require_line(trimmed) {
                packages.push(pkg);
            }
        } else if let Some(rest) = trimmed.strip_prefix("require ") {
            // Single-line require: `require github.com/foo/bar v1.2.3`
            if let Some(pkg) = parse_require_line(rest.trim()) {
                packages.push(pkg);
            }
        }
    }

    Ok(packages)
}

/// Parses a single require line of the form `<module> <version> [// indirect]`.
pub fn parse_require_line(line: &str) -> Option<Package> {
    // Strip inline comments
    let line = if let Some(idx) = line.find("//") {
        line[..idx].trim()
    } else {
        line.trim()
    };

    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();
    let version = parts.next()?.to_string();

    if name.is_empty() || version.is_empty() {
        return None;
    }

    let purl = format!("pkg:golang/{}@{}", name.to_lowercase(), version);
    Some(Package {
        name,
        version,
        ecosystem: Ecosystem::Go,
        purl,
        metadata: HashMap::new(),
        source_file: None,
    })
}

/// Parses a go.sum file and returns packages (one per unique name@version pair).
/// go.sum lines: `<module> <version>[/go.mod] <hash>`
pub fn parse_go_sum(text: &str) -> Result<Vec<Package>, CatalogerError> {
    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let name = match parts.next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let version_field = match parts.next() {
            Some(v) => v,
            None => continue,
        };

        // Strip /go.mod suffix from the version field if present
        let version = version_field
            .strip_suffix("/go.mod")
            .unwrap_or(version_field)
            .to_string();

        let key = format!("{}@{}", name, version);
        if seen.insert(key) {
            let purl = format!("pkg:golang/{}@{}", name.to_lowercase(), version);
            packages.push(Package {
                name,
                version,
                ecosystem: Ecosystem::Go,
                purl,
                metadata: HashMap::new(),
                source_file: None,
            });
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FileContents, FileEntry};
    use std::path::PathBuf;

    fn text_file(path: &str, content: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Text(content.to_string()),
        }
    }

    fn binary_file(path: &str, bytes: Vec<u8>) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Binary(bytes),
        }
    }

    // ------------------------------------------------------------------
    // Task 7 tests
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_go_mod() {
        let content = r#"module example.com/myapp

go 1.21

require (
    github.com/stretchr/testify v1.8.4
    golang.org/x/net v0.20.0 // indirect
)
"#;
        let pkgs = parse_go_mod(content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "github.com/stretchr/testify");
        assert_eq!(pkgs[0].version, "v1.8.4");
        assert_eq!(pkgs[1].name, "golang.org/x/net");
        assert_eq!(pkgs[1].version, "v0.20.0");
    }

    #[test]
    fn test_parse_go_mod_single_require() {
        let content = r#"module example.com/myapp

go 1.21

require github.com/pkg/errors v0.9.1
"#;
        let pkgs = parse_go_mod(content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "github.com/pkg/errors");
        assert_eq!(pkgs[0].version, "v0.9.1");
    }

    #[test]
    fn test_can_catalog_with_go_files() {
        let files = vec![text_file("/project/go.mod", "module example.com/app\n")];
        assert!(GoCataloger.can_catalog(&files));
    }

    #[test]
    fn test_can_catalog_without_go_files() {
        let files = vec![
            text_file("/project/package.json", "{}"),
            text_file("/project/Cargo.toml", "[package]"),
        ];
        assert!(!GoCataloger.can_catalog(&files));
    }

    #[test]
    fn test_catalog_go_mod() {
        let go_mod_content = r#"module example.com/myapp

go 1.21

require (
    github.com/stretchr/testify v1.8.4
    golang.org/x/net v0.20.0
)
"#;
        let files = vec![text_file("/project/go.mod", go_mod_content)];
        let pkgs = GoCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "github.com/stretchr/testify" && p.version == "v1.8.4")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "golang.org/x/net" && p.version == "v0.20.0")
        );
        // All packages should be tagged with source=go.mod
        assert!(
            pkgs.iter()
                .all(|p| p.metadata.get("source").map(|s| s.as_str()) == Some("go.mod"))
        );
    }

    #[test]
    fn test_parse_go_sum() {
        let content = r#"github.com/stretchr/testify v1.8.4 h1:CcVxWJq4=
github.com/stretchr/testify v1.8.4/go.mod h1:sz/lmYIOX=
golang.org/x/net v0.20.0 h1:aCL9BSgETF=
golang.org/x/net v0.20.0/go.mod h1:z8BVo6P=
"#;
        let pkgs = parse_go_sum(content).unwrap();
        // Each module should appear only once despite two lines per version
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "github.com/stretchr/testify" && p.version == "v1.8.4")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "golang.org/x/net" && p.version == "v0.20.0")
        );
    }

    #[test]
    fn test_catalog_go_sum_only() {
        let go_sum_content = r#"github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt0=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
"#;
        let files = vec![text_file("/project/go.sum", go_sum_content)];
        let pkgs = GoCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "github.com/pkg/errors");
        assert_eq!(pkgs[0].version, "v0.9.1");
        assert_eq!(
            pkgs[0].metadata.get("source").map(|s| s.as_str()),
            Some("go.sum")
        );
    }

    // ------------------------------------------------------------------
    // Task 8 tests
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_go_buildinfo_text() {
        let text = "path\texample.com/myapp\nmod\texample.com/myapp\tv1.0.0\ndep\tgithub.com/stretchr/testify\tv1.8.4\th1:abc123\ndep\tgolang.org/x/net\tv0.20.0\n";
        let pkgs = parse_buildinfo_text(text).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "github.com/stretchr/testify" && p.version == "v1.8.4")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "golang.org/x/net" && p.version == "v0.20.0")
        );
    }

    #[test]
    fn test_is_go_binary_elf() {
        // Build a fake "binary" containing the Go buildinfo magic
        let mut bytes: Vec<u8> = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
        bytes.extend_from_slice(&[0u8; 100]);
        bytes.extend_from_slice(GO_BUILDINFO_MAGIC);
        bytes.extend_from_slice(b"dep\tgithub.com/foo/bar\tv1.0.0\n\x00");

        let file = binary_file("/usr/bin/myapp", bytes);
        assert!(is_go_binary(&file));

        // A file without the magic should not be detected
        let non_go = binary_file("/usr/bin/other", vec![0x7f, 0x45, 0x4c, 0x46, 0, 0, 0]);
        assert!(!is_go_binary(&non_go));
    }

    #[test]
    fn test_catalog_includes_binary_source() {
        // Build a fake Go binary with embedded buildinfo (realistic format:
        // magic → header bytes → "path\t..." text with deps)
        let mut bytes: Vec<u8> = vec![0x7f, 0x45, 0x4c, 0x46];
        bytes.extend_from_slice(&[0u8; 50]);
        bytes.extend_from_slice(GO_BUILDINFO_MAGIC);
        // Simulated header (flags, pointers, go version) before the text
        bytes.extend_from_slice(&[0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(b"go1.21.0");
        bytes.extend_from_slice(&[0x00; 8]); // padding
        bytes.extend_from_slice(b"path\texample.com/app\nmod\texample.com/app\tv1.0.0\t\ndep\tgithub.com/some/lib\tv2.3.4\th1:xyz\n");
        bytes.push(0x00); // null terminator

        let files = vec![binary_file("/usr/bin/myapp", bytes)];
        let pkgs = GoCataloger.catalog(&files).unwrap();

        assert!(!pkgs.is_empty(), "should find packages in binary");
        assert!(
            pkgs.iter()
                .any(|p| p.name == "github.com/some/lib" && p.version == "v2.3.4")
        );
        assert!(
            pkgs.iter()
                .all(|p| p.metadata.get("source").map(|s| s.as_str()) == Some("binary"))
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "stdlib" && p.version == "v1.21.0" && p.purl == "pkg:golang/stdlib@v1.21.0"),
            "should emit stdlib package from Go version in binary header"
        );
    }

    #[test]
    fn test_extract_go_version() {
        let mut bytes: Vec<u8> = vec![0u8; 50];
        bytes.extend_from_slice(GO_BUILDINFO_MAGIC);
        bytes.extend_from_slice(&[0x08, 0x02, 0x00, 0x00]);
        bytes.extend_from_slice(b"go1.21.8");
        bytes.extend_from_slice(&[0x00; 20]);
        assert_eq!(extract_go_version(&bytes), Some("go1.21.8".to_string()));
    }

    #[test]
    fn test_extract_go_version_none_without_magic() {
        let bytes = vec![0u8; 100];
        assert_eq!(extract_go_version(&bytes), None);
    }

    #[test]
    fn test_catalog_sets_source_file() {
        let files = vec![text_file(
            "/project/subdir/go.mod",
            "module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
        )];
        let pkgs = GoCataloger.catalog(&files).unwrap();
        assert_eq!(
            pkgs[0].source_file,
            Some("/project/subdir/go.mod".to_string())
        );
    }
}

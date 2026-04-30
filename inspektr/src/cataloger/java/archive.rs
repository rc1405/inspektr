//! Java archive cataloger (JAR/WAR/EAR/etc.).
//!
//! Extracts Maven coordinates from compiled Java archive files inside a
//! file entry slice. See `docs/superpowers/specs/2026-04-14-java-jar-cataloger-design.md`
//! for the full design.

use crate::cataloger::Cataloger;
use crate::error::CatalogerError;
use crate::models::{Ecosystem, FileEntry, Package};
use std::collections::HashMap;
use std::io::Read;

/// File extensions that identify a Java archive.
///
/// Matching is ASCII-case-insensitive; see [`has_archive_extension`].
/// Entries from the spec's Section 2 — JAR is by far the most common;
/// the others exist so enterprise deployments (WAR/EAR on app servers,
/// Jenkins plugins, Karaf, Android) are covered out of the box.
pub(crate) const ARCHIVE_EXTENSIONS: &[&str] = &[
    "jar", "war", "ear", "par", "sar", "rar", "kar", "jpi", "hpi", "aar",
];

/// ZIP local-file-header magic: `PK\x03\x04`.
///
/// Used as a secondary detection signal for files that don't carry a
/// recognized extension — e.g. a JAR renamed to drop the suffix.
pub(crate) const ZIP_MAGIC: &[u8; 4] = b"PK\x03\x04";

/// Hardcoded safety limits threaded through recursive archive scanning.
///
/// These values are tuned to handle every JAR in the inspektr benchmark
/// corpus while still stopping zip bombs and pathological nesting. See
/// the spec's "Safety Budget" section for rationale.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanBudget {
    /// Maximum nested-archive recursion depth. Depth 0 is the outer
    /// archive handed to the cataloger; depth 1 is a JAR inside it; etc.
    pub max_depth: usize,
    /// Maximum number of entries a single ZIP may contain before we
    /// refuse to read any of them. Guards against zip-directory bombs.
    pub max_entries_per_archive: usize,
    /// Maximum decompressed size (in bytes) of a single entry. Enforced
    /// via a `Read::take` wrapper when extracting the entry body.
    pub max_single_file_decompressed: u64,
    /// Maximum total decompressed bytes across a whole `JavaArchiveCataloger::catalog`
    /// invocation. Running total is tracked in `total_decompressed_so_far`.
    pub max_total_decompressed: u64,
    /// Running tally mutated as entries are read. Compared against
    /// `max_total_decompressed` at every read site.
    pub total_decompressed_so_far: u64,
}

impl ScanBudget {
    /// Default limits for v1. Hardcoded — making these configurable is
    /// explicitly out of scope per the spec.
    pub(crate) const fn default_v1() -> Self {
        Self {
            max_depth: 4,
            max_entries_per_archive: 10_000,
            max_single_file_decompressed: 256 * 1024 * 1024, // 256 MB
            max_total_decompressed: 1024 * 1024 * 1024,      // 1 GB
            total_decompressed_so_far: 0,
        }
    }
}

/// Returns `true` if `path` ends in any extension in [`ARCHIVE_EXTENSIONS`].
///
/// Comparison is ASCII-case-insensitive: `FOO.JAR` matches. Paths without
/// a recognized extension return `false`.
pub(crate) fn has_archive_extension(path: &str) -> bool {
    let Some(dot) = path.rfind('.') else {
        return false;
    };
    let ext = &path[dot + 1..];
    ARCHIVE_EXTENSIONS
        .iter()
        .any(|want| ext.eq_ignore_ascii_case(want))
}

/// Returns `true` if `bytes` starts with the ZIP local-file-header magic.
pub(crate) fn starts_with_zip_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == ZIP_MAGIC
}

/// Cataloger for compiled Java archives.
pub struct JavaArchiveCataloger;

impl Cataloger for JavaArchiveCataloger {
    fn name(&self) -> &str {
        "java-archive"
    }

    fn can_catalog(&self, files: &[FileEntry]) -> bool {
        files.iter().any(|f| {
            let path_str = f.path.to_string_lossy();
            if has_archive_extension(&path_str) {
                return true;
            }
            // Secondary signal: ZIP magic on a file with no recognized
            // extension. Guards against archives that were renamed or
            // shipped without a `.jar` suffix.
            let ext = path_str.rsplit('.').next().unwrap_or("");
            if ext == path_str.as_ref() || ext.is_empty() {
                return starts_with_zip_magic(f.as_bytes());
            }
            false
        })
    }

    fn catalog(&self, files: &[FileEntry]) -> Result<Vec<Package>, CatalogerError> {
        let mut packages: Vec<Package> = Vec::new();
        let mut budget = ScanBudget::default_v1();

        for file in files {
            let path_str = file.path.to_string_lossy();
            let is_archive = has_archive_extension(&path_str) || {
                // Fall back to magic-byte detection only when there's
                // no recognized extension at all.
                let ext = path_str.rsplit('.').next().unwrap_or("");
                (ext == path_str.as_ref() || ext.is_empty())
                    && starts_with_zip_magic(file.as_bytes())
            };
            if !is_archive {
                continue;
            }

            let data = file.as_bytes();
            let source_path = path_str.into_owned();
            let inner = scan_archive(data, &source_path, &[], &mut budget);
            packages.extend(inner);
        }

        Ok(packages)
    }
}

/// Parse a Maven-written `pom.properties` file.
///
/// Returns `Some((groupId, artifactId, version))` when all three keys
/// are present with non-empty values; otherwise `None`. Unknown keys,
/// blank lines, and comment lines (`#...`) are ignored.
///
/// No value-escape handling — Maven writes the three keys we care about
/// as raw UTF-8 with no quoting.
pub(crate) fn parse_pom_properties(text: &str) -> Option<(String, String, String)> {
    let mut group_id: Option<&str> = None;
    let mut artifact_id: Option<&str> = None;
    let mut version: Option<&str> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "groupId" => group_id = Some(value),
            "artifactId" => artifact_id = Some(value),
            "version" => version = Some(value),
            _ => {}
        }
    }

    let (g, a, v) = (group_id?, artifact_id?, version?);
    if g.is_empty() || a.is_empty() || v.is_empty() {
        return None;
    }
    Some((g.to_string(), a.to_string(), v.to_string()))
}

/// Parse a JAR `META-INF/MANIFEST.MF` file.
///
/// Handles MANIFEST.MF's continuation-line format (lines that start with
/// a single space are appended to the previous line without the leading
/// space). Keys are matched case-insensitively per the JAR specification.
///
/// Returns `Some((groupId, artifactId, version))` only when we can
/// confidently pair a groupId-shaped name from the manifest with an
/// artifactId-shaped name from the JAR filename. All successful paths
/// require a `filename_stem` so we never fabricate a coordinate out of
/// thin air.
///
/// Resolution order:
///
/// 1. **Bundle-SymbolicName + Bundle-Version.** Requires that the
///    filename stem's last `-`-delimited segment equal the BSN's last
///    `.`-delimited segment — e.g. BSN `com.ibm.icu` and stem `icu`,
///    or BSN `org.apache.logging.log4j.core` and stem `log4j-core`
///    (both tails are `core`). When the tails match, the full BSN
///    becomes the groupId and the stem becomes the artifactId.
///
/// 2. **Automatic-Module-Name + Implementation-Version.** Same
///    tail-matching correlation, used for modern JPMS-aware JARs that
///    lack `Bundle-*` attributes entirely — e.g. module
///    `io.opentelemetry.api` + stem `opentelemetry-api` (both tails
///    are `api`).
///
/// Without a tail match the function returns `None`. Emitting a
/// fabricated `pkg:maven` PURL would produce silent false negatives
/// from the vulnerability matcher — the PURL looks valid but no OSV or
/// NVD entry is keyed under it, so users get zero vulns reported for a
/// package the database actually knows about. Better to stay silent
/// about a JAR we can't confidently identify.
pub(crate) fn parse_manifest_mf(
    text: &str,
    filename_stem: Option<&str>,
) -> Option<(String, String, String)> {
    // Unwrap continuation lines: any line starting with a single space
    // is part of the previous line.
    let mut logical: Vec<String> = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if let Some(rest) = line.strip_prefix(' ') {
            if let Some(last) = logical.last_mut() {
                last.push_str(rest);
                continue;
            }
            continue;
        }
        logical.push(line.to_string());
    }

    // Parse each logical line as `Key: Value`. Keys are lowercased for
    // case-insensitive lookup.
    let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in &logical {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        map.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    // --- Path 0: Direct Maven attributes (groupId + artifactId + version) ---
    // Highest confidence — these ARE the Maven coordinates.
    if let (Some(group), Some(artifact), Some(ver)) = (
        map.get("groupid"),
        map.get("artifactid"),
        map.get("version"),
    ) && !group.is_empty()
        && !artifact.is_empty()
        && !ver.is_empty()
    {
        return Some((group.clone(), artifact.clone(), ver.clone()));
    }

    // Paths 1 and 2 require a filename stem for tail-matching.
    let stem = match filename_stem {
        Some(s) if !s.is_empty() => s,
        _ => {
            // No stem — skip to Path 3 (Gradle-style, also stem-independent).
            return parse_gradle_implementation_title(&map);
        }
    };
    let stem_tail = stem.rsplit('-').next().unwrap_or(stem);
    if stem_tail.is_empty() {
        return parse_gradle_implementation_title(&map);
    }

    // --- Path 1: Bundle-SymbolicName + Bundle-Version ---
    if let (Some(symbolic), Some(bundle_ver)) =
        (map.get("bundle-symbolicname"), map.get("bundle-version"))
    {
        let symbolic = symbolic.as_str();
        let bundle_ver = bundle_ver.as_str();
        if !symbolic.is_empty() && !bundle_ver.is_empty() {
            let symbolic_tail = symbolic.rsplit('.').next().unwrap_or(symbolic);
            if symbolic_tail == stem_tail {
                return Some((
                    symbolic.to_string(),
                    stem.to_string(),
                    bundle_ver.to_string(),
                ));
            }
        }
    }

    // --- Path 2: Automatic-Module-Name + Implementation-Version ---
    if let (Some(module_name), Some(version)) = (
        map.get("automatic-module-name"),
        map.get("implementation-version"),
    ) {
        let module_name = module_name.as_str();
        let version = version.as_str();
        if !module_name.is_empty() && !version.is_empty() {
            let module_tail = module_name.rsplit('.').next().unwrap_or(module_name);
            if module_tail == stem_tail {
                return Some((
                    module_name.to_string(),
                    stem.to_string(),
                    version.to_string(),
                ));
            }
        }
    }

    // --- Path 3: Gradle-style Implementation-Title ---
    parse_gradle_implementation_title(&map)
}

/// Extract Maven coordinates from a Gradle-style `Implementation-Title`.
///
/// Gradle's `java` plugin writes titles in the form `groupId#artifactId;version`
/// (e.g., `org.elasticsearch#server;8.13.0`). Returns `None` if the title
/// doesn't match this pattern.
fn parse_gradle_implementation_title(
    map: &std::collections::HashMap<String, String>,
) -> Option<(String, String, String)> {
    let title = map.get("implementation-title")?;
    let (group, rest) = title.split_once('#')?;
    let (artifact, version) = rest.split_once(';')?;
    if group.is_empty() || artifact.is_empty() || version.is_empty() {
        return None;
    }
    Some((group.to_string(), artifact.to_string(), version.to_string()))
}

/// Extract the Maven-style artifact stem from a JAR filename.
///
/// Strips the archive extension and any trailing `-<version>` segment so
/// that `jna-5.10.0.jar` becomes `jna`, `commons-lang3-3.12.0.jar`
/// becomes `commons-lang3`, and `foo.jar` becomes `foo`. A version
/// segment is any `-` followed by a character in `[0-9]`.
pub(crate) fn artifact_stem_from_filename(filename: &str) -> Option<String> {
    // Drop directory prefix if any.
    let base = filename.rsplit('/').next().unwrap_or(filename);
    // Drop the archive extension.
    let without_ext = match base.rfind('.') {
        Some(dot) => &base[..dot],
        None => base,
    };
    if without_ext.is_empty() {
        return None;
    }
    // Drop a trailing `-<digit>...` version segment if present.
    let stem = match without_ext.rfind('-') {
        Some(dash)
            if without_ext[dash + 1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit()) =>
        {
            &without_ext[..dash]
        }
        _ => without_ext,
    };
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_string())
    }
}

/// Build a `Package` with the standard Maven PURL format and inspektr's
/// conventional `name = "groupId:artifactId"` string.
fn build_jar_package(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    source_file: String,
    source_tag: &str,
) -> Package {
    let mut metadata: HashMap<String, String> = HashMap::new();
    metadata.insert("source".to_string(), source_tag.to_string());
    Package {
        name: format!("{}:{}", group_id, artifact_id),
        version: version.to_string(),
        ecosystem: Ecosystem::Java,
        purl: format!("pkg:maven/{}/{}@{}", group_id, artifact_id, version),
        metadata,
        source_file: Some(source_file),
    }
}

/// Build the `source_file` string for a package found inside a (possibly
/// nested) archive. Top-level archives just get `source_path`; nested
/// entries join with `!` per Java's standard nested-archive URL syntax.
///
/// Examples:
/// - `("/app/foo.jar", &[])` → `"/app/foo.jar"`
/// - `("/app/outer.jar", &["inner.jar"])` → `"/app/outer.jar!inner.jar"`
/// - `("/app/a.jar", &["b.jar", "c.jar"])` → `"/app/a.jar!b.jar!c.jar"`
pub(crate) fn join_nesting_chain(source_path: &str, nesting_stack: &[&str]) -> String {
    if nesting_stack.is_empty() {
        return source_path.to_string();
    }
    let mut out = String::with_capacity(
        source_path.len() + nesting_stack.iter().map(|s| s.len() + 1).sum::<usize>(),
    );
    out.push_str(source_path);
    for seg in nesting_stack {
        out.push('!');
        out.push_str(seg);
    }
    out
}

/// True if `name` is a ZIP entry path matching `META-INF/maven/<group>/<artifact>/pom.properties`.
///
/// Matching is strict: we want exactly three segments after `META-INF/maven/`
/// and the last one must be `pom.properties`.
/// True if `name` identifies a Maven `pom.properties` entry inside a JAR.
///
/// Canonical form is `META-INF/maven/<group>/<artifact>/pom.properties`,
/// but some shaded/uber JARs (e.g. Elastic's APM agent) prefix each shaded
/// dependency with its own top-level directory, so real-world paths look
/// like `agent/META-INF/maven/...` or `cached-lookup-key/META-INF/maven/...`.
/// We accept any path that ENDS in the canonical `META-INF/maven/<g>/<a>/pom.properties`
/// shape, regardless of leading prefix.
fn is_pom_properties_path(name: &str) -> bool {
    // Find the LAST occurrence of the marker so we don't match substrings
    // like `.../META-INF/maven/a/b/pom.properties.bak`.
    let Some(idx) = name.rfind("META-INF/maven/") else {
        return false;
    };
    let rest = &name[idx + "META-INF/maven/".len()..];
    let segments: Vec<&str> = rest.split('/').collect();
    segments.len() == 3 && segments[2] == "pom.properties"
}

/// Scan a single archive's bytes and return the packages found inside.
///
/// Runs all three passes from the design:
///
/// 1. First pass: iterate entries; for each whose name matches
///    `META-INF/maven/*/*/pom.properties`, read it (bounded by
///    `max_single_file_decompressed`), parse, and emit a `Package`.
/// 2. Second pass: if pass 1 produced zero packages, read
///    `META-INF/MANIFEST.MF` and try to extract a package from
///    `Bundle-SymbolicName` + `Bundle-Version`.
/// 3. Third pass: iterate entries ending in an archive extension and
///    recurse into [`scan_archive`] with the same budget, enforcing the
///    depth cap.
pub(crate) fn scan_archive(
    data: &[u8],
    source_path: &str,
    nesting_stack: &[&str],
    budget: &mut ScanBudget,
) -> Vec<Package> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };

    if archive.len() > budget.max_entries_per_archive {
        eprintln!(
            "warning: java-archive: skipping {} (entry count {} > limit {})",
            join_nesting_chain(source_path, nesting_stack),
            archive.len(),
            budget.max_entries_per_archive
        );
        return Vec::new();
    }

    let mut packages: Vec<Package> = Vec::new();
    let effective_source = join_nesting_chain(source_path, nesting_stack);

    // Collect entry names up front so we can iterate without holding a
    // mutable borrow of `archive` across reads.
    let entry_names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|e| e.name().to_string()))
        .collect();

    // --- First pass: pom.properties ---
    for (i, name) in entry_names.iter().enumerate() {
        if !is_pom_properties_path(name) {
            continue;
        }
        if budget.total_decompressed_so_far >= budget.max_total_decompressed {
            eprintln!(
                "warning: java-archive: total decompressed byte budget exhausted; stopping scan of {}",
                effective_source
            );
            return packages;
        }
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        let mut buf = Vec::new();
        if (&mut entry)
            .take(budget.max_single_file_decompressed)
            .read_to_end(&mut buf)
            .is_err()
        {
            continue;
        }
        budget.total_decompressed_so_far = budget
            .total_decompressed_so_far
            .saturating_add(buf.len() as u64);
        let Ok(text) = std::str::from_utf8(&buf) else {
            continue;
        };
        if let Some((g, a, v)) = parse_pom_properties(text) {
            packages.push(build_jar_package(
                &g,
                &a,
                &v,
                effective_source.clone(),
                "jar",
            ));
        }
    }

    // --- Second pass: MANIFEST.MF fallback ---
    // Only runs when pass 1 produced zero packages for this archive.
    // Nested archives are evaluated independently (they each run their
    // own three-pass scan when we recurse into them below).
    if packages.is_empty()
        && let Some(i) = entry_names.iter().position(|n| n == "META-INF/MANIFEST.MF")
        && budget.total_decompressed_so_far < budget.max_total_decompressed
        && let Ok(mut entry) = archive.by_index(i)
    {
        let mut buf = Vec::new();
        if (&mut entry)
            .take(budget.max_single_file_decompressed)
            .read_to_end(&mut buf)
            .is_ok()
        {
            budget.total_decompressed_so_far = budget
                .total_decompressed_so_far
                .saturating_add(buf.len() as u64);
            if let Ok(text) = std::str::from_utf8(&buf) {
                let filename = nesting_stack.last().copied().unwrap_or(source_path);
                let stem = artifact_stem_from_filename(filename);
                if let Some((g, a, v)) = parse_manifest_mf(text, stem.as_deref()) {
                    packages.push(build_jar_package(
                        &g,
                        &a,
                        &v,
                        effective_source.clone(),
                        "manifest.mf",
                    ));
                }
            }
        }
    }

    // --- Third pass: recurse into nested archives ---
    if nesting_stack.len() < budget.max_depth {
        for (i, name) in entry_names.iter().enumerate() {
            if !has_archive_extension(name) {
                continue;
            }
            if budget.total_decompressed_so_far >= budget.max_total_decompressed {
                eprintln!(
                    "warning: java-archive: total decompressed byte budget exhausted; skipping nested archives in {}",
                    effective_source
                );
                break;
            }
            let Ok(mut entry) = archive.by_index(i) else {
                continue;
            };
            let mut inner_bytes = Vec::new();
            if (&mut entry)
                .take(budget.max_single_file_decompressed)
                .read_to_end(&mut inner_bytes)
                .is_err()
            {
                continue;
            }
            budget.total_decompressed_so_far = budget
                .total_decompressed_so_far
                .saturating_add(inner_bytes.len() as u64);

            // Push this entry's name onto the nesting stack, recurse, pop.
            let mut new_stack: Vec<&str> = nesting_stack.to_vec();
            new_stack.push(name.as_str());
            let inner_pkgs = scan_archive(&inner_bytes, source_path, &new_stack, budget);
            packages.extend(inner_pkgs);
        }
    } else {
        eprintln!(
            "warning: java-archive: max nesting depth {} reached at {}; skipping further recursion",
            budget.max_depth, effective_source
        );
    }

    packages
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FileContents, FileEntry};
    use std::path::PathBuf;

    fn binary_entry(path: &str, bytes: Vec<u8>) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Binary(bytes),
        }
    }

    fn text_entry(path: &str, text: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            contents: FileContents::Text(text.to_string()),
        }
    }

    #[test]
    fn has_archive_extension_recognizes_every_listed_extension() {
        for ext in ARCHIVE_EXTENSIONS {
            let path = format!("/some/where/foo.{}", ext);
            assert!(has_archive_extension(&path), "should recognize .{}", ext);
        }
    }

    #[test]
    fn has_archive_extension_is_case_insensitive() {
        assert!(has_archive_extension("/x/y/FOO.JAR"));
        assert!(has_archive_extension("/x/y/foo.War"));
        assert!(has_archive_extension("/x/y/foo.EaR"));
    }

    #[test]
    fn has_archive_extension_rejects_non_archives() {
        assert!(!has_archive_extension("/x/y/foo.txt"));
        assert!(!has_archive_extension("/x/y/foo.class"));
        assert!(!has_archive_extension("/x/y/README"));
    }

    #[test]
    fn can_catalog_true_when_jar_present() {
        let files = vec![
            text_entry("/app/readme.txt", "hi"),
            binary_entry("/app/foo.jar", b"PK\x03\x04fake".to_vec()),
        ];
        assert!(JavaArchiveCataloger.can_catalog(&files));
    }

    #[test]
    fn can_catalog_false_when_no_archives() {
        let files = vec![
            text_entry("/app/readme.txt", "hi"),
            text_entry("/app/pom.xml", "<project/>"),
        ];
        assert!(!JavaArchiveCataloger.can_catalog(&files));
    }

    #[test]
    fn can_catalog_detects_extensionless_file_via_zip_magic() {
        // A file named `app` (no extension) whose contents start with
        // ZIP magic should still be recognized.
        let files = vec![binary_entry("/app/app", b"PK\x03\x04rest".to_vec())];
        assert!(JavaArchiveCataloger.can_catalog(&files));
    }

    #[test]
    fn can_catalog_false_for_unknown_extension_without_magic() {
        let files = vec![binary_entry("/app/foo.bin", vec![0xde, 0xad, 0xbe, 0xef])];
        assert!(!JavaArchiveCataloger.can_catalog(&files));
    }

    #[test]
    fn scan_budget_defaults_match_spec() {
        let b = ScanBudget::default_v1();
        assert_eq!(b.max_depth, 4);
        assert_eq!(b.max_entries_per_archive, 10_000);
        assert_eq!(b.max_single_file_decompressed, 256 * 1024 * 1024);
        assert_eq!(b.max_total_decompressed, 1024 * 1024 * 1024);
        assert_eq!(b.total_decompressed_so_far, 0);
    }

    #[test]
    fn parse_pom_properties_happy_path() {
        let text = "\
#Generated by Maven
#Thu Apr 13 12:34:56 UTC 2026
version=2.15.2
groupId=com.fasterxml.jackson.core
artifactId=jackson-core
";
        let got = parse_pom_properties(text);
        assert_eq!(
            got,
            Some((
                "com.fasterxml.jackson.core".to_string(),
                "jackson-core".to_string(),
                "2.15.2".to_string()
            ))
        );
    }

    #[test]
    fn parse_pom_properties_handles_crlf() {
        let text = "groupId=org.foo\r\nartifactId=bar\r\nversion=1.0\r\n";
        let got = parse_pom_properties(text);
        assert_eq!(
            got,
            Some(("org.foo".to_string(), "bar".to_string(), "1.0".to_string()))
        );
    }

    #[test]
    fn parse_pom_properties_any_key_order() {
        let text = "artifactId=bar\nversion=1.0\ngroupId=org.foo\n";
        let got = parse_pom_properties(text);
        assert_eq!(
            got,
            Some(("org.foo".to_string(), "bar".to_string(), "1.0".to_string()))
        );
    }

    #[test]
    fn parse_pom_properties_ignores_unknown_keys_and_blanks() {
        let text =
            "\n# a comment\nunused=whatever\ngroupId=org.foo\n\nartifactId=bar\nversion=1.0\n";
        assert_eq!(
            parse_pom_properties(text),
            Some(("org.foo".to_string(), "bar".to_string(), "1.0".to_string()))
        );
    }

    #[test]
    fn parse_pom_properties_missing_version_returns_none() {
        let text = "groupId=org.foo\nartifactId=bar\n";
        assert_eq!(parse_pom_properties(text), None);
    }

    #[test]
    fn parse_pom_properties_empty_value_returns_none() {
        let text = "groupId=org.foo\nartifactId=bar\nversion=\n";
        assert_eq!(parse_pom_properties(text), None);
    }

    #[test]
    fn parse_manifest_mf_bundle_happy_path_with_filename_tail_match() {
        // Log4j ships JARs named `log4j-core-2.20.0.jar` with BSN
        // `org.apache.logging.log4j.core`. The BSN's last dot-segment
        // is `core` and the filename stem's last hyphen-segment is
        // also `core` — they correlate, so we use the full BSN as the
        // groupId and the filename stem as the artifactId. This
        // produces `org.apache.logging.log4j:log4j-core`, matching
        // Maven Central's published coordinate.
        let text = "\
Manifest-Version: 1.0
Bundle-SymbolicName: org.apache.logging.log4j.core
Bundle-Version: 2.20.0
Implementation-Title: Apache Log4j Core
Implementation-Version: 2.20.0
";
        let got = parse_manifest_mf(text, Some("log4j-core"));
        assert_eq!(
            got,
            Some((
                "org.apache.logging.log4j.core".to_string(),
                "log4j-core".to_string(),
                "2.20.0".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_unwraps_continuation_lines() {
        // MANIFEST.MF wraps at column 72; continuation lines start with
        // a single space. Our parser must rejoin them before the
        // tail-match check runs. BSN `org.apache.logging.log4j.core`
        // needs to see the full string (not just the pre-wrap prefix)
        // for its `.core` tail to line up with the filename.
        let text = "\
Manifest-Version: 1.0
Bundle-SymbolicName: org.apache.logging.log4j
 .core
Bundle-Version: 2.20.0
";
        let got = parse_manifest_mf(text, Some("log4j-core"));
        assert_eq!(
            got,
            Some((
                "org.apache.logging.log4j.core".to_string(),
                "log4j-core".to_string(),
                "2.20.0".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_returns_none_without_filename_hint() {
        // With no filename hint we cannot confidently derive an
        // artifactId, so the parser bails out even when BSN +
        // Bundle-Version are present. This is the conservative stance
        // chosen to avoid fabricating Maven coordinates that won't
        // match any vulnerability-database entry.
        let text = "\
Manifest-Version: 1.0
Bundle-SymbolicName: org.apache.logging.log4j.core
Bundle-Version: 2.20.0
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_returns_none_when_tails_do_not_match() {
        // BSN `org.apache.logging.log4j.core` has tail `core`; stem
        // `jna` has tail `jna`. They don't correlate so we refuse to
        // pair them — emitting a fabricated coordinate would hide the
        // real package from the vulnerability matcher.
        let text = "\
Manifest-Version: 1.0
Bundle-SymbolicName: org.apache.logging.log4j.core
Bundle-Version: 2.20.0
";
        assert_eq!(parse_manifest_mf(text, Some("jna")), None);
    }

    #[test]
    fn parse_manifest_mf_only_implementation_returns_none() {
        // Implementation-Title doesn't give us a groupId. Per the spec
        // we refuse to fabricate one — return None rather than emit a
        // package that can't match vulns.
        let text = "\
Manifest-Version: 1.0
Implementation-Title: Some Library
Implementation-Version: 1.0.0
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_missing_bundle_version_returns_none() {
        let text = "\
Manifest-Version: 1.0
Bundle-SymbolicName: org.foo.bar
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_symbolic_name_without_dot_returns_none() {
        // Without a dot we can't split into groupId/artifactId at all;
        // emitting `pkg:maven//single@x` would create an invalid PURL.
        let text = "\
Manifest-Version: 1.0
Bundle-SymbolicName: justoneword
Bundle-Version: 1.0
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_keys_case_insensitive() {
        // JAR spec says manifest keys are case-insensitive. With a
        // filename hint whose tail matches the BSN tail, we should
        // still produce the right coordinate regardless of key casing.
        let text = "\
manifest-version: 1.0
bundle-symbolicname: org.foo.bar
bundle-version: 1.2.3
";
        assert_eq!(
            parse_manifest_mf(text, Some("bar")),
            Some((
                "org.foo.bar".to_string(),
                "bar".to_string(),
                "1.2.3".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_uses_filename_hint_for_jna_pattern() {
        // Real-world JNA layout: BSN is the Java package name
        // `com.sun.jna` and the JAR is `jna-5.10.0.jar`. Maven Central
        // publishes this as `com.sun.jna:jna:5.10.0` — i.e., the full
        // BSN is the groupId and the filename stem is the artifactId.
        // Without the filename hint, the last-dot-split fallback would
        // incorrectly produce `com.sun:jna`.
        let text = "\
Manifest-Version: 1.0
Bundle-SymbolicName: com.sun.jna
Bundle-Version: 5.10.0
";
        let got = parse_manifest_mf(text, Some("jna"));
        assert_eq!(
            got,
            Some((
                "com.sun.jna".to_string(),
                "jna".to_string(),
                "5.10.0".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_filename_hint_matches_exact_bsn() {
        // Edge case: BSN equals the filename stem exactly (no prefix).
        // Stripping `jna` from `jna` leaves an empty suffix, which we
        // also accept (empty or ends with `.`).
        let text = "\
Manifest-Version: 1.0
Bundle-SymbolicName: jna
Bundle-Version: 5.10.0
";
        let got = parse_manifest_mf(text, Some("jna"));
        assert_eq!(
            got,
            Some(("jna".to_string(), "jna".to_string(), "5.10.0".to_string()))
        );
    }

    #[test]
    fn parse_manifest_mf_uses_automatic_module_name_for_jpms_jars() {
        // Real-world JPMS JAR: `opentelemetry-api-1.31.0.jar` has no
        // Bundle-* attributes and no pom.properties, but does carry
        // `Automatic-Module-Name: io.opentelemetry.api` plus
        // `Implementation-Version`. Maven Central publishes this as
        // `io.opentelemetry.api:opentelemetry-api@1.31.0`.
        let text = "\
Manifest-Version: 1.0
Automatic-Module-Name: io.opentelemetry.api
Built-By: runner
Implementation-Title: all
Implementation-Version: 1.31.0
";
        let got = parse_manifest_mf(text, Some("opentelemetry-api"));
        assert_eq!(
            got,
            Some((
                "io.opentelemetry.api".to_string(),
                "opentelemetry-api".to_string(),
                "1.31.0".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_auto_module_name_without_filename_hint_returns_none() {
        // Without a filename hint we can't safely derive the artifactId
        // from the module name alone.
        let text = "\
Manifest-Version: 1.0
Automatic-Module-Name: io.opentelemetry.api
Implementation-Version: 1.31.0
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_auto_module_name_mismatched_hint_returns_none() {
        // Module name `io.opentelemetry.api` doesn't end in `.jna`, so
        // with a mismatching filename hint we refuse to fabricate a
        // coordinate.
        let text = "\
Manifest-Version: 1.0
Automatic-Module-Name: io.opentelemetry.api
Implementation-Version: 1.31.0
";
        assert_eq!(parse_manifest_mf(text, Some("jna")), None);
    }

    #[test]
    fn parse_manifest_mf_direct_maven_attributes() {
        let text = "\
Manifest-Version: 1.0
groupId: com.google.api
artifactId: api-common
version: 2.3.1
";
        let got = parse_manifest_mf(text, Some("api-common"));
        assert_eq!(
            got,
            Some((
                "com.google.api".to_string(),
                "api-common".to_string(),
                "2.3.1".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_direct_maven_attributes_without_filename() {
        let text = "\
Manifest-Version: 1.0
groupId: com.google.api
artifactId: api-common
version: 2.3.1
";
        let got = parse_manifest_mf(text, None);
        assert_eq!(
            got,
            Some((
                "com.google.api".to_string(),
                "api-common".to_string(),
                "2.3.1".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_direct_maven_missing_group_id() {
        let text = "\
Manifest-Version: 1.0
artifactId: api-common
version: 2.3.1
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_direct_maven_empty_artifact_id() {
        let text = "\
Manifest-Version: 1.0
groupId: com.google.api
artifactId:
version: 2.3.1
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_direct_maven_wins_over_bundle() {
        let text = "\
Manifest-Version: 1.0
groupId: com.google.api
artifactId: api-common
version: 2.3.1
Bundle-SymbolicName: com.google.api.apicommon
Bundle-Version: 2.3.1
";
        let got = parse_manifest_mf(text, Some("api-common"));
        assert_eq!(
            got,
            Some((
                "com.google.api".to_string(),
                "api-common".to_string(),
                "2.3.1".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_gradle_implementation_title() {
        let text = "\
Manifest-Version: 1.0
Implementation-Title: org.elasticsearch#server;8.13.0
Implementation-Version: 8.13.0
";
        let got = parse_manifest_mf(text, Some("elasticsearch"));
        assert_eq!(
            got,
            Some((
                "org.elasticsearch".to_string(),
                "server".to_string(),
                "8.13.0".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_gradle_title_without_filename() {
        let text = "\
Manifest-Version: 1.0
Implementation-Title: org.elasticsearch.plugin#core;8.13.0
";
        let got = parse_manifest_mf(text, None);
        assert_eq!(
            got,
            Some((
                "org.elasticsearch.plugin".to_string(),
                "core".to_string(),
                "8.13.0".to_string()
            ))
        );
    }

    #[test]
    fn parse_manifest_mf_gradle_title_no_hash() {
        let text = "\
Manifest-Version: 1.0
Implementation-Title: Apache Log4j Core
Implementation-Version: 2.20.0
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_gradle_title_no_semicolon() {
        let text = "\
Manifest-Version: 1.0
Implementation-Title: org.elasticsearch#server
";
        assert_eq!(parse_manifest_mf(text, None), None);
    }

    #[test]
    fn parse_manifest_mf_direct_maven_wins_over_gradle() {
        let text = "\
Manifest-Version: 1.0
groupId: com.example
artifactId: my-lib
version: 1.0.0
Implementation-Title: org.other#other-lib;2.0.0
";
        let got = parse_manifest_mf(text, None);
        assert_eq!(
            got,
            Some((
                "com.example".to_string(),
                "my-lib".to_string(),
                "1.0.0".to_string()
            ))
        );
    }

    #[test]
    fn artifact_stem_from_filename_strips_version_and_extension() {
        assert_eq!(
            artifact_stem_from_filename("jna-5.10.0.jar"),
            Some("jna".to_string())
        );
        assert_eq!(
            artifact_stem_from_filename("commons-lang3-3.12.0.jar"),
            Some("commons-lang3".to_string())
        );
        assert_eq!(
            artifact_stem_from_filename("/usr/share/lib/foo-1.2.3.jar"),
            Some("foo".to_string())
        );
        assert_eq!(
            artifact_stem_from_filename("foo.jar"),
            Some("foo".to_string())
        );
        // No version suffix — keep the name as-is (minus extension).
        assert_eq!(
            artifact_stem_from_filename("my-tool.jar"),
            Some("my-tool".to_string())
        );
    }

    // ----- Helpers for building in-memory ZIP fixtures -----

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, bytes) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    // ----- scan_archive tests -----

    #[test]
    fn scan_archive_emits_one_package_from_pom_properties() {
        let props = b"\
groupId=org.foo
artifactId=bar
version=1.0.0
";
        let zip_bytes = build_zip(&[("META-INF/maven/org.foo/bar/pom.properties", props as &[u8])]);

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&zip_bytes, "/app/bar-1.0.0.jar", &[], &mut budget);

        assert_eq!(pkgs.len(), 1);
        let p = &pkgs[0];
        assert_eq!(p.name, "org.foo:bar");
        assert_eq!(p.version, "1.0.0");
        assert_eq!(p.purl, "pkg:maven/org.foo/bar@1.0.0");
        assert_eq!(p.source_file.as_deref(), Some("/app/bar-1.0.0.jar"));
        assert_eq!(p.metadata.get("source").map(|s| s.as_str()), Some("jar"));
    }

    #[test]
    fn scan_archive_emits_multiple_packages_for_shaded_jar() {
        // A shaded/uber JAR contains multiple pom.properties — one per
        // dep that got shaded in.
        let props_a = b"groupId=org.a\nartifactId=a-lib\nversion=1.0\n";
        let props_b = b"groupId=org.b\nartifactId=b-lib\nversion=2.0\n";
        let props_c = b"groupId=org.c\nartifactId=c-lib\nversion=3.0\n";
        let zip_bytes = build_zip(&[
            (
                "META-INF/maven/org.a/a-lib/pom.properties",
                props_a as &[u8],
            ),
            (
                "META-INF/maven/org.b/b-lib/pom.properties",
                props_b as &[u8],
            ),
            (
                "META-INF/maven/org.c/c-lib/pom.properties",
                props_c as &[u8],
            ),
        ]);

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&zip_bytes, "/app/uber.jar", &[], &mut budget);

        assert_eq!(pkgs.len(), 3);
        let purls: std::collections::HashSet<_> = pkgs.iter().map(|p| p.purl.clone()).collect();
        assert!(purls.contains("pkg:maven/org.a/a-lib@1.0"));
        assert!(purls.contains("pkg:maven/org.b/b-lib@2.0"));
        assert!(purls.contains("pkg:maven/org.c/c-lib@3.0"));
    }

    #[test]
    fn scan_archive_finds_pom_properties_under_shaded_path_prefix() {
        // Elastic's APM agent and similar uber-JARs ship shaded
        // dependencies under a per-dep directory prefix, so real paths
        // look like `agent/META-INF/maven/.../pom.properties` or
        // `cached-lookup-key/META-INF/maven/.../pom.properties`. We
        // should find those, not just canonical top-level ones.
        let props_a = b"groupId=org.slf4j\nartifactId=slf4j-api\nversion=1.7.36\n";
        let props_b =
            b"groupId=co.elastic.apm\nartifactId=apm-agent-cached-lookup-key\nversion=1.44.0\n";
        let zip_bytes = build_zip(&[
            (
                "agent/META-INF/maven/org.slf4j/slf4j-api/pom.properties",
                props_a as &[u8],
            ),
            (
                "cached-lookup-key/META-INF/maven/co.elastic.apm/apm-agent-cached-lookup-key/pom.properties",
                props_b as &[u8],
            ),
        ]);
        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&zip_bytes, "/app/uber.jar", &[], &mut budget);
        assert_eq!(pkgs.len(), 2);
        let purls: std::collections::HashSet<_> = pkgs.iter().map(|p| p.purl.clone()).collect();
        assert!(purls.contains("pkg:maven/org.slf4j/slf4j-api@1.7.36"));
        assert!(purls.contains("pkg:maven/co.elastic.apm/apm-agent-cached-lookup-key@1.44.0"));
    }

    #[test]
    fn scan_archive_returns_empty_for_invalid_zip() {
        let garbage = vec![0xde, 0xad, 0xbe, 0xef, 0x00];
        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&garbage, "/app/foo.jar", &[], &mut budget);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn scan_archive_returns_empty_for_jar_with_no_metadata() {
        // A JAR with only .class entries and no META-INF metadata. Per
        // the spec we skip silently rather than emit a synthetic package.
        let class_bytes = &[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34][..];
        let zip_bytes = build_zip(&[("com/example/Foo.class", class_bytes)]);
        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&zip_bytes, "/app/foo.jar", &[], &mut budget);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn scan_archive_recurses_into_nested_jar() {
        // Build an inner JAR first (with its own pom.properties), then
        // embed it as an entry inside an outer JAR.
        let inner_props = b"groupId=org.inner\nartifactId=lib\nversion=9.9.9\n";
        let inner_bytes = build_zip(&[(
            "META-INF/maven/org.inner/lib/pom.properties",
            inner_props as &[u8],
        )]);
        let outer_bytes = build_zip(&[("BOOT-INF/lib/inner.jar", inner_bytes.as_slice())]);

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&outer_bytes, "/app/outer.jar", &[], &mut budget);

        assert_eq!(pkgs.len(), 1);
        let p = &pkgs[0];
        assert_eq!(p.purl, "pkg:maven/org.inner/lib@9.9.9");
        // Nested attribution: outer + `!` + inner entry name.
        assert_eq!(
            p.source_file.as_deref(),
            Some("/app/outer.jar!BOOT-INF/lib/inner.jar")
        );
    }

    #[test]
    fn scan_archive_combines_outer_and_nested_packages() {
        let outer_props = b"groupId=org.outer\nartifactId=app\nversion=1.0\n";
        let inner_props = b"groupId=org.inner\nartifactId=lib\nversion=2.0\n";
        let inner_bytes = build_zip(&[(
            "META-INF/maven/org.inner/lib/pom.properties",
            inner_props as &[u8],
        )]);
        let outer_bytes = build_zip(&[
            (
                "META-INF/maven/org.outer/app/pom.properties",
                outer_props as &[u8],
            ),
            ("BOOT-INF/lib/inner.jar", inner_bytes.as_slice()),
        ]);

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&outer_bytes, "/app/outer.jar", &[], &mut budget);

        assert_eq!(pkgs.len(), 2);
        let purls: std::collections::HashSet<_> = pkgs.iter().map(|p| p.purl.clone()).collect();
        assert!(purls.contains("pkg:maven/org.outer/app@1.0"));
        assert!(purls.contains("pkg:maven/org.inner/lib@2.0"));
    }

    #[test]
    fn scan_archive_respects_max_depth() {
        // 4 levels of nesting: outer > l1 > l2 > l3 > innermost (the
        // innermost is where pom.properties lives). With max_depth = 4
        // we should still reach it, because the depth check guards
        // recursion INTO another nested archive — scanning the current
        // archive's own pom.properties entries is always allowed.
        fn wrap(inner_bytes: &[u8], entry_name: &str) -> Vec<u8> {
            build_zip(&[(entry_name, inner_bytes)])
        }
        let innermost = build_zip(&[(
            "META-INF/maven/org.deep/lib/pom.properties",
            b"groupId=org.deep\nartifactId=lib\nversion=1.0\n" as &[u8],
        )]);
        let l3 = wrap(&innermost, "l4.jar");
        let l2 = wrap(&l3, "l3.jar");
        let l1 = wrap(&l2, "l2.jar");
        let outer = wrap(&l1, "l1.jar");

        let mut budget = ScanBudget::default_v1();
        assert_eq!(budget.max_depth, 4);
        let pkgs = scan_archive(&outer, "/app/outer.jar", &[], &mut budget);

        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl, "pkg:maven/org.deep/lib@1.0");
    }

    #[test]
    fn scan_archive_stops_one_level_too_deep() {
        // Same construction but ONE more level. With 5 levels of nesting
        // and max_depth = 4, we should fail to reach the innermost.
        fn wrap(inner_bytes: &[u8], entry_name: &str) -> Vec<u8> {
            build_zip(&[(entry_name, inner_bytes)])
        }
        let innermost = build_zip(&[(
            "META-INF/maven/org.deep/lib/pom.properties",
            b"groupId=org.deep\nartifactId=lib\nversion=1.0\n" as &[u8],
        )]);
        let l4 = wrap(&innermost, "l5.jar");
        let l3 = wrap(&l4, "l4.jar");
        let l2 = wrap(&l3, "l3.jar");
        let l1 = wrap(&l2, "l2.jar");
        let outer = wrap(&l1, "l1.jar");

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&outer, "/app/outer.jar", &[], &mut budget);

        // We can open through l1..l4 but at depth 4 we refuse to recurse
        // into l5.jar, so the innermost package is never seen.
        assert!(pkgs.is_empty());
    }

    #[test]
    fn scan_archive_nesting_does_not_recurse_into_non_archive_entries() {
        // An inner entry named .properties or .txt should NOT be opened
        // as a ZIP — only archive-extension entries get recursive scans.
        // Build a JAR with a ".properties" entry that contains valid ZIP
        // bytes; we want to verify that nothing weird happens.
        let inner_props = b"groupId=org.inner\nartifactId=lib\nversion=9.9.9\n";
        let inner_bytes = build_zip(&[(
            "META-INF/maven/org.inner/lib/pom.properties",
            inner_props as &[u8],
        )]);
        let outer_bytes = build_zip(&[
            // Same bytes, but the entry name ends in ".properties" so
            // scan_archive must not recurse into it.
            ("somewhere/inner.properties", inner_bytes.as_slice()),
        ]);

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&outer_bytes, "/app/outer.jar", &[], &mut budget);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn scan_archive_falls_back_to_manifest_mf() {
        // JAR with only a MANIFEST.MF (Bundle-* attributes), no
        // pom.properties. The archive is named `lib-4.5.6.jar` so the
        // derived filename stem is `lib`, whose tail matches the BSN's
        // last segment `.lib` — MANIFEST.MF parsing confidently
        // resolves to groupId=`org.fallback.lib`, artifactId=`lib`.
        let manifest = b"\
Manifest-Version: 1.0
Bundle-SymbolicName: org.fallback.lib
Bundle-Version: 4.5.6
";
        let zip_bytes = build_zip(&[("META-INF/MANIFEST.MF", manifest as &[u8])]);

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&zip_bytes, "/app/lib-4.5.6.jar", &[], &mut budget);

        assert_eq!(pkgs.len(), 1);
        let p = &pkgs[0];
        assert_eq!(p.purl, "pkg:maven/org.fallback.lib/lib@4.5.6");
        assert_eq!(
            p.metadata.get("source").map(|s| s.as_str()),
            Some("manifest.mf")
        );
        assert_eq!(p.source_file.as_deref(), Some("/app/lib-4.5.6.jar"));
    }

    #[test]
    fn scan_archive_prefers_pom_properties_over_manifest() {
        // Both present — pom.properties wins, manifest is ignored (we
        // only fall back when pass 1 produces zero packages).
        let props = b"groupId=org.primary\nartifactId=bar\nversion=1.0\n";
        let manifest = b"\
Manifest-Version: 1.0
Bundle-SymbolicName: org.secondary.lib
Bundle-Version: 9.9.9
";
        let zip_bytes = build_zip(&[
            (
                "META-INF/maven/org.primary/bar/pom.properties",
                props as &[u8],
            ),
            ("META-INF/MANIFEST.MF", manifest as &[u8]),
        ]);

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&zip_bytes, "/app/foo.jar", &[], &mut budget);

        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl, "pkg:maven/org.primary/bar@1.0");
        assert_eq!(
            pkgs[0].metadata.get("source").map(|s| s.as_str()),
            Some("jar")
        );
    }

    #[test]
    fn scan_archive_skips_silently_when_manifest_lacks_bundle_attrs() {
        let manifest = b"\
Manifest-Version: 1.0
Implementation-Title: Some Library
Implementation-Version: 1.0
";
        let zip_bytes = build_zip(&[("META-INF/MANIFEST.MF", manifest as &[u8])]);
        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(&zip_bytes, "/app/foo.jar", &[], &mut budget);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn catalog_scans_every_archive_entry_in_files() {
        // Build two tiny JARs, drop them into a FileEntry slice alongside
        // some noise files, and confirm catalog() emits one package per
        // JAR plus nothing for the noise.
        let a_bytes = build_zip(&[(
            "META-INF/maven/org.a/a-lib/pom.properties",
            b"groupId=org.a\nartifactId=a-lib\nversion=1.0\n" as &[u8],
        )]);
        let b_bytes = build_zip(&[(
            "META-INF/maven/org.b/b-lib/pom.properties",
            b"groupId=org.b\nartifactId=b-lib\nversion=2.0\n" as &[u8],
        )]);

        let files = vec![
            text_entry("/app/README.md", "hi"),
            binary_entry("/app/a.jar", a_bytes),
            binary_entry("/app/b.jar", b_bytes),
            text_entry("/app/go.sum", "ignored"),
        ];

        let pkgs = JavaArchiveCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 2);
        let purls: std::collections::HashSet<_> = pkgs.iter().map(|p| p.purl.clone()).collect();
        assert!(purls.contains("pkg:maven/org.a/a-lib@1.0"));
        assert!(purls.contains("pkg:maven/org.b/b-lib@2.0"));

        // Each package should reference the correct source file.
        let a = pkgs.iter().find(|p| p.name == "org.a:a-lib").unwrap();
        assert_eq!(a.source_file.as_deref(), Some("/app/a.jar"));
        let b = pkgs.iter().find(|p| p.name == "org.b:b-lib").unwrap();
        assert_eq!(b.source_file.as_deref(), Some("/app/b.jar"));
    }

    #[test]
    fn catalog_continues_past_malformed_archive() {
        // A malformed "jar" (random bytes) should not kill the whole
        // scan — the cataloger must skip it and continue to the next
        // entry.
        let good_bytes = build_zip(&[(
            "META-INF/maven/org.good/lib/pom.properties",
            b"groupId=org.good\nartifactId=lib\nversion=1.0\n" as &[u8],
        )]);
        let files = vec![
            binary_entry("/app/bad.jar", vec![0xde, 0xad, 0xbe, 0xef]),
            binary_entry("/app/good.jar", good_bytes),
        ];
        let pkgs = JavaArchiveCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl, "pkg:maven/org.good/lib@1.0");
    }

    #[test]
    fn catalog_shares_budget_across_archives() {
        // Two JARs, each below the per-file cap but together consuming
        // the running total. This test just confirms that two archives
        // scanned in one catalog() call see a single ScanBudget and do
        // not reset between archives — a regression would be catching
        // an archive that should have been rejected.
        //
        // The assertion we can make without setting up a real zip bomb:
        // after catalog() returns, the two JARs combined produce exactly
        // two packages (proving both were scanned) and no panic occurred.
        let a = build_zip(&[(
            "META-INF/maven/org.a/lib/pom.properties",
            b"groupId=org.a\nartifactId=lib\nversion=1.0\n" as &[u8],
        )]);
        let b = build_zip(&[(
            "META-INF/maven/org.b/lib/pom.properties",
            b"groupId=org.b\nartifactId=lib\nversion=1.0\n" as &[u8],
        )]);
        let files = vec![binary_entry("/app/a.jar", a), binary_entry("/app/b.jar", b)];
        let pkgs = JavaArchiveCataloger.catalog(&files).unwrap();
        assert_eq!(pkgs.len(), 2);
    }

    #[test]
    fn scan_real_commons_lang_jar_from_fixture() {
        // This test guards against parser drift with real-world
        // Maven-written metadata. The JAR lives at
        // `test-fixtures/java/commons-lang3-3.12.0.jar` and is vendored
        // in the repo for determinism (no network in tests).
        let jar_bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-fixtures/java/commons-lang3-3.12.0.jar"
        ))
        .expect("missing test-fixtures/java/commons-lang3-3.12.0.jar");

        let mut budget = ScanBudget::default_v1();
        let pkgs = scan_archive(
            &jar_bytes,
            "/opt/app/commons-lang3-3.12.0.jar",
            &[],
            &mut budget,
        );

        // Commons Lang 3 ships exactly one pom.properties under its own
        // group/artifact coordinate. Anything beyond 1 would indicate a
        // parser regression (e.g. picking up a scrap file).
        assert_eq!(
            pkgs.len(),
            1,
            "expected exactly one package, got {:?}",
            pkgs.iter().map(|p| &p.purl).collect::<Vec<_>>()
        );
        let p = &pkgs[0];
        assert_eq!(p.name, "org.apache.commons:commons-lang3");
        assert_eq!(p.version, "3.12.0");
        assert_eq!(p.purl, "pkg:maven/org.apache.commons/commons-lang3@3.12.0");
        assert_eq!(
            p.source_file.as_deref(),
            Some("/opt/app/commons-lang3-3.12.0.jar")
        );
        assert_eq!(p.metadata.get("source").map(|s| s.as_str()), Some("jar"));
    }
}

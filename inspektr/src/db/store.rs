//! Vulnerability database storage engine.
//!
//! The [`VulnStore`] provides a compressed binary database backed by
//! bincode + LZ4. Vulnerabilities are indexed by `(ecosystem, package_name)`
//! for fast lookups during scanning.
//!
//! # Usage
//!
//! ```no_run
//! use inspektr::db::store::VulnStore;
//!
//! // Open an existing database
//! let store = VulnStore::open("/path/to/vuln.db").unwrap();
//!
//! // Query vulnerabilities for a specific package
//! let results = store.query("Go", "github.com/example/pkg").unwrap();
//! for result in &results {
//!     println!("{}: {}", result.id, result.summary);
//! }
//! ```

use crate::error::DatabaseError;
use crate::models::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A vulnerability record to be inserted into the database.
///
/// Used by `VulnSource` importers (with `db-admin` feature) to feed data into
/// the store via [`VulnStore::insert_vulnerabilities()`].
#[derive(Debug, Clone)]
pub struct VulnRecord {
    /// The vulnerability identifier (e.g., `"CVE-2023-44487"`, `"GO-2023-0001"`).
    pub id: String,
    /// A short description of the vulnerability.
    pub summary: String,
    /// The severity level.
    pub severity: Severity,
    /// ISO 8601 timestamp when first published.
    pub published: String,
    /// ISO 8601 timestamp when last modified.
    pub modified: String,
    /// ISO 8601 timestamp if withdrawn; withdrawn records are skipped during import.
    pub withdrawn: Option<String>,
    /// The data source name (e.g., `"osv"`, `"nvd"`).
    pub source: String,
    /// CVSS v3 base score (0.0–10.0), if available.
    pub cvss_score: Option<f64>,
    /// Packages and version ranges affected by this vulnerability.
    pub affected: Vec<AffectedPackage>,
}

/// A package affected by a vulnerability.
#[derive(Debug, Clone)]
pub struct AffectedPackage {
    /// The ecosystem name (OSV format, e.g., `"Go"`, `"npm"`, `"Alpine"`).
    pub ecosystem: String,
    /// The package name within the ecosystem.
    pub package_name: String,
    /// Version ranges in which the package is vulnerable.
    pub ranges: Vec<AffectedRange>,
}

/// A version range in which a package is vulnerable.
#[derive(Debug, Clone)]
pub struct AffectedRange {
    /// The range type: `"SEMVER"` or `"ECOSYSTEM"`.
    pub range_type: String,
    /// The version where the vulnerability was introduced (`None` = from the beginning).
    pub introduced: Option<String>,
    /// The version where the vulnerability was fixed (`None` = no fix available).
    pub fixed: Option<String>,
}

/// The result of querying the vulnerability database for a specific package.
#[derive(Debug, Clone)]
pub struct VulnQueryResult {
    /// The vulnerability identifier.
    pub id: String,
    /// A short description.
    pub summary: String,
    /// The severity level.
    pub severity: Severity,
    /// When first published.
    pub published: String,
    /// When last modified.
    pub modified: String,
    /// The data source.
    pub source: String,
    /// CVSS v3 base score, if available.
    pub cvss_score: Option<f64>,
    /// Version ranges in which the package is affected.
    pub ranges: Vec<AffectedRange>,
}

// ---------------------------------------------------------------------------
// Internal compact types (serialized to disk)
// ---------------------------------------------------------------------------

const SCHEMA_VERSION: u32 = 6;

#[derive(Serialize, Deserialize)]
struct VulnDatabase {
    version: u32,
    data: HashMap<String, Vec<CompactVuln>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CompactVuln {
    id: String,
    summary: String,
    severity: u8,
    cvss_score: Option<f32>,
    source: String,
    published: String,
    ranges: Vec<CompactRange>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CompactRange {
    range_type: u8,
    introduced: Option<String>,
    fixed: Option<String>,
}

// ---------------------------------------------------------------------------
// Key / encoding helpers
// ---------------------------------------------------------------------------

fn make_key(ecosystem: &str, package_name: &str) -> String {
    format!("{}\0{}", ecosystem, package_name)
}

fn severity_to_u8(s: Severity) -> u8 {
    match s {
        Severity::None => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn severity_from_u8(v: u8) -> Severity {
    match v {
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        4 => Severity::Critical,
        _ => Severity::None,
    }
}

fn range_type_to_u8(s: &str) -> u8 {
    match s {
        "SEMVER" => 1,
        "GIT" => 2,
        _ => 0,
    }
}

fn range_type_from_u8(v: u8) -> String {
    match v {
        1 => "SEMVER".to_string(),
        2 => "GIT".to_string(),
        _ => "ECOSYSTEM".to_string(),
    }
}

// ---------------------------------------------------------------------------
// VulnStore
// ---------------------------------------------------------------------------

/// Vulnerability database backed by bincode serialization + LZ4 compression.
///
/// The store indexes vulnerabilities by `(ecosystem, package_name)` for
/// O(1) lookup during scanning. The on-disk format is a single LZ4-compressed
/// bincode blob with a schema version check on open.
///
/// # Database lifecycle
///
/// - **Open** an existing database with [`VulnStore::open()`]
/// - **Create** a new empty database with [`VulnStore::create()`]
/// - **Query** with [`VulnStore::query()`]
/// - **Insert** records with [`VulnStore::insert_vulnerabilities()`]
/// - **Save** to disk with [`VulnStore::save()`]
pub struct VulnStore {
    db: VulnDatabase,
    path: Option<String>,
}

impl VulnStore {
    /// Open an existing database file. Returns error if file doesn't exist.
    pub fn open(path: &str) -> Result<Self, DatabaseError> {
        if !Path::new(path).exists() {
            return Err(DatabaseError::NotFound {
                path: path.to_string(),
            });
        }

        let data = std::fs::read(path)
            .map_err(|e| DatabaseError::Storage(format!("failed to read {}: {}", path, e)))?;

        // Decompress LZ4
        let decompressed = lz4_flex::decompress_size_prepended(&data)
            .map_err(|e| DatabaseError::Storage(format!("failed to decompress: {}", e)))?;

        // Deserialize bincode
        let db: VulnDatabase = bincode::deserialize(&decompressed)
            .map_err(|e| DatabaseError::Storage(format!("failed to deserialize: {}", e)))?;

        if db.version != SCHEMA_VERSION {
            return Err(DatabaseError::Storage(format!(
                "database version {} != expected {}. Rebuild with `inspektr db build`.",
                db.version, SCHEMA_VERSION
            )));
        }

        Ok(Self {
            db,
            path: Some(path.to_string()),
        })
    }

    /// Create a new empty database (for building).
    pub fn create(path: &str) -> Result<Self, DatabaseError> {
        Ok(Self {
            db: VulnDatabase {
                version: SCHEMA_VERSION,
                data: HashMap::new(),
            },
            path: Some(path.to_string()),
        })
    }

    /// Load a database from raw bytes (the on-disk LZ4+bincode format).
    ///
    /// This allows loading a database without writing it to a file first,
    /// which is useful for in-memory workflows where you pull the database
    /// from an OCI registry and use it directly.
    ///
    /// ```no_run
    /// use inspektr::db::store::VulnStore;
    /// use inspektr::oci::{RegistryAuth, pull::pull_artifact_bytes};
    ///
    /// let bytes = pull_artifact_bytes(
    ///     inspektr::db::DEFAULT_DB_REGISTRY,
    ///     &RegistryAuth::Anonymous,
    /// ).unwrap();
    /// let store = VulnStore::from_bytes(&bytes).unwrap();
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self, DatabaseError> {
        let decompressed = lz4_flex::decompress_size_prepended(data)
            .map_err(|e| DatabaseError::Storage(format!("failed to decompress: {}", e)))?;

        let db: VulnDatabase = bincode::deserialize(&decompressed)
            .map_err(|e| DatabaseError::Storage(format!("failed to deserialize: {}", e)))?;

        if db.version != SCHEMA_VERSION {
            return Err(DatabaseError::Storage(format!(
                "database version {} != expected {}. Rebuild with `inspektr db build`.",
                db.version, SCHEMA_VERSION
            )));
        }

        Ok(Self { db, path: None })
    }

    /// Open an in-memory database (useful for tests).
    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        Ok(Self {
            db: VulnDatabase {
                version: SCHEMA_VERSION,
                data: HashMap::new(),
            },
            path: None,
        })
    }

    /// Insert vulnerability records. Aggregates into the HashMap by
    /// (ecosystem, package_name). Withdrawn records are skipped.
    pub fn insert_vulnerabilities(&mut self, records: &[VulnRecord]) -> Result<(), DatabaseError> {
        for record in records {
            if record.withdrawn.is_some() {
                continue;
            }

            let compact = CompactVuln {
                id: record.id.clone(),
                summary: record.summary.clone(),
                severity: severity_to_u8(record.severity),
                cvss_score: record.cvss_score.map(|v| v as f32),
                source: record.source.clone(),
                published: record.published.clone(),
                ranges: Vec::new(), // filled per affected package below
            };

            for pkg in &record.affected {
                let key = make_key(&pkg.ecosystem, &pkg.package_name);
                let mut entry = compact.clone();
                entry.ranges = pkg
                    .ranges
                    .iter()
                    .map(|r| CompactRange {
                        range_type: range_type_to_u8(&r.range_type),
                        introduced: r.introduced.clone(),
                        fixed: r.fixed.clone(),
                    })
                    .collect();

                self.db.data.entry(key).or_default().push(entry);
            }
        }
        Ok(())
    }

    /// Query vulnerabilities affecting the given ecosystem and package name.
    pub fn query(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> Result<Vec<VulnQueryResult>, DatabaseError> {
        let key = make_key(ecosystem, package_name);
        let entries = match self.db.data.get(&key) {
            Some(e) => e,
            None => return Ok(Vec::new()),
        };

        let results = entries
            .iter()
            .map(|e| VulnQueryResult {
                id: e.id.clone(),
                summary: e.summary.clone(),
                severity: severity_from_u8(e.severity),
                published: e.published.clone(),
                modified: String::new(),
                source: e.source.clone(),
                cvss_score: e.cvss_score.map(|v| v as f64),
                ranges: e
                    .ranges
                    .iter()
                    .map(|r| AffectedRange {
                        range_type: range_type_from_u8(r.range_type),
                        introduced: r.introduced.clone(),
                        fixed: r.fixed.clone(),
                    })
                    .collect(),
            })
            .collect();

        Ok(results)
    }

    /// Write the database to disk (serialize + compress).
    pub fn save(&self) -> Result<(), DatabaseError> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| DatabaseError::Storage("cannot save in-memory database".to_string()))?;

        let encoded = bincode::serialize(&self.db)
            .map_err(|e| DatabaseError::Storage(format!("failed to serialize: {}", e)))?;

        let compressed = lz4_flex::compress_prepend_size(&encoded);

        // Write atomically via temp file
        let tmp_path = format!("{}.tmp", path);
        std::fs::write(&tmp_path, &compressed)
            .map_err(|e| DatabaseError::Storage(format!("failed to write {}: {}", tmp_path, e)))?;
        std::fs::rename(&tmp_path, path)
            .map_err(|e| DatabaseError::Storage(format!("failed to rename: {}", e)))?;

        eprintln!(
            "Database saved: {} entries, {:.1}MB compressed",
            self.db.data.len(),
            compressed.len() as f64 / 1_048_576.0,
        );

        Ok(())
    }

    /// Count unique vulnerability IDs.
    pub fn vulnerability_count(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for entries in self.db.data.values() {
            for e in entries {
                seen.insert(&e.id);
            }
        }
        seen.len()
    }

    /// No-op for binary format (no compaction needed).
    pub fn vacuum(&self) -> Result<(), DatabaseError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> VulnRecord {
        VulnRecord {
            id: "GO-2023-0001".to_string(),
            summary: "Remote code execution in example/pkg".to_string(),
            severity: Severity::High,
            published: "2023-01-01T00:00:00Z".to_string(),
            modified: "2023-02-01T00:00:00Z".to_string(),
            withdrawn: None,
            source: "osv".to_string(),
            cvss_score: Some(7.5),
            affected: vec![AffectedPackage {
                ecosystem: "Go".to_string(),
                package_name: "github.com/example/pkg".to_string(),
                ranges: vec![AffectedRange {
                    range_type: "SEMVER".to_string(),
                    introduced: Some("1.0.0".to_string()),
                    fixed: Some("1.2.3".to_string()),
                }],
            }],
        }
    }

    #[test]
    fn test_create_database() {
        let store = VulnStore::open_in_memory().expect("should create in-memory db");
        assert_eq!(store.vulnerability_count(), 0);
    }

    #[test]
    fn test_insert_and_query_vulnerability() {
        let mut store = VulnStore::open_in_memory().expect("should create in-memory db");
        let record = sample_record();

        store
            .insert_vulnerabilities(&[record])
            .expect("insert should succeed");

        assert_eq!(store.vulnerability_count(), 1);

        let results = store
            .query("Go", "github.com/example/pkg")
            .expect("query should succeed");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "GO-2023-0001");
        assert_eq!(results[0].severity, Severity::High);
        assert_eq!(results[0].ranges.len(), 1);
        assert_eq!(results[0].ranges[0].range_type, "SEMVER");
        assert_eq!(results[0].ranges[0].introduced, Some("1.0.0".to_string()));
        assert_eq!(results[0].ranges[0].fixed, Some("1.2.3".to_string()));
    }

    #[test]
    fn test_query_no_results() {
        let mut store = VulnStore::open_in_memory().expect("should create in-memory db");
        store
            .insert_vulnerabilities(&[sample_record()])
            .expect("insert should succeed");

        let results = store
            .query("Go", "github.com/other/pkg")
            .expect("query should succeed");
        assert!(results.is_empty());
    }

    #[test]
    fn test_insert_multiple_vulnerabilities() {
        let mut store = VulnStore::open_in_memory().expect("should create in-memory db");

        let mut r1 = sample_record();
        let mut r2 = sample_record();
        r2.id = "GO-2023-0002".to_string();
        r2.severity = Severity::Critical;
        r1.affected[0].ranges[0].fixed = Some("1.1.0".to_string());
        r2.affected[0].ranges[0].introduced = Some("1.1.0".to_string());

        store
            .insert_vulnerabilities(&[r1, r2])
            .expect("insert should succeed");

        assert_eq!(store.vulnerability_count(), 2);

        let results = store
            .query("Go", "github.com/example/pkg")
            .expect("query should succeed");
        assert_eq!(results.len(), 2);

        let severities: Vec<Severity> = results.iter().map(|r| r.severity).collect();
        assert!(severities.contains(&Severity::High));
        assert!(severities.contains(&Severity::Critical));
    }

    #[test]
    fn test_withdrawn_not_returned() {
        let mut store = VulnStore::open_in_memory().expect("should create in-memory db");
        let mut record = sample_record();
        record.withdrawn = Some("2023-03-01T00:00:00Z".to_string());

        store
            .insert_vulnerabilities(&[record])
            .expect("insert should succeed");

        // Withdrawn records are skipped during insertion
        assert_eq!(store.vulnerability_count(), 0);

        let results = store
            .query("Go", "github.com/example/pkg")
            .expect("query should succeed");
        assert!(
            results.is_empty(),
            "withdrawn vulnerabilities should not be returned"
        );
    }

    #[test]
    fn test_severity_roundtrip() {
        for (sev, expected) in [
            (Severity::None, 0u8),
            (Severity::Low, 1),
            (Severity::Medium, 2),
            (Severity::High, 3),
            (Severity::Critical, 4),
        ] {
            let encoded = severity_to_u8(sev);
            assert_eq!(encoded, expected);
            assert_eq!(severity_from_u8(encoded), sev);
        }
    }

    #[test]
    fn test_range_type_roundtrip() {
        for (s, expected) in [("ECOSYSTEM", 0u8), ("SEMVER", 1), ("GIT", 2)] {
            let encoded = range_type_to_u8(s);
            assert_eq!(encoded, expected);
            assert_eq!(range_type_from_u8(encoded), s);
        }
    }

    #[test]
    fn test_source_normalization() {
        let mut store = VulnStore::open_in_memory().expect("should create in-memory db");

        let mut r1 = sample_record();
        r1.source = "osv".to_string();

        let mut r2 = sample_record();
        r2.id = "CVE-2023-0001".to_string();
        r2.source = "nvd".to_string();

        store
            .insert_vulnerabilities(&[r1, r2])
            .expect("insert should succeed");

        assert_eq!(store.vulnerability_count(), 2);

        let results = store
            .query("Go", "github.com/example/pkg")
            .expect("query should succeed");
        assert_eq!(results.len(), 2);

        let sources: Vec<&str> = results.iter().map(|r| r.source.as_str()).collect();
        assert!(sources.contains(&"osv"));
        assert!(sources.contains(&"nvd"));
    }
}

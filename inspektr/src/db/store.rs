use crate::error::DatabaseError;
use crate::models::Severity;
use rusqlite::{Connection, params};
use std::collections::HashMap;

/// A vulnerability record to be stored in the database.
#[derive(Debug, Clone)]
pub struct VulnRecord {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
    pub published: String,
    pub modified: String,
    pub withdrawn: Option<String>,
    pub source: String,
    pub cvss_score: Option<f64>,
    pub affected: Vec<AffectedPackage>,
}

/// A package affected by a vulnerability.
#[derive(Debug, Clone)]
pub struct AffectedPackage {
    pub ecosystem: String,
    pub package_name: String,
    pub ranges: Vec<AffectedRange>,
}

/// A version range in which a package is vulnerable.
#[derive(Debug, Clone)]
pub struct AffectedRange {
    pub range_type: String,
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

/// The result of a vulnerability query.
#[derive(Debug, Clone)]
pub struct VulnQueryResult {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
    pub published: String,
    pub modified: String,
    pub source: String,
    pub cvss_score: Option<f64>,
    pub ranges: Vec<AffectedRange>,
}

/// Wraps a SQLite connection for vulnerability storage and retrieval.
pub struct VulnStore {
    conn: Connection,
}

// ---------------------------------------------------------------------------
// Internal encoding helpers
// ---------------------------------------------------------------------------

/// Encode a Severity value as an integer for storage.
fn severity_to_int(s: Severity) -> i32 {
    match s {
        Severity::None => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Decode an integer back to a Severity value.
fn severity_from_int(i: i32) -> Severity {
    match i {
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        4 => Severity::Critical,
        _ => Severity::None,
    }
}

/// Encode a range_type string as an integer for storage.
fn range_type_to_int(s: &str) -> i32 {
    match s {
        "SEMVER" => 1,
        "GIT" => 2,
        _ => 0, // ECOSYSTEM
    }
}

/// Decode an integer back to a range_type string.
fn range_type_from_int(i: i32) -> String {
    match i {
        1 => "SEMVER".to_string(),
        2 => "GIT".to_string(),
        _ => "ECOSYSTEM".to_string(),
    }
}

impl VulnStore {
    /// Current schema version. Increment this when the schema changes.
    const SCHEMA_VERSION: u32 = 5;

    /// Open (or create) a database at the given path.
    /// If the existing database has an older schema version, it is deleted
    /// and recreated with the current schema.
    pub fn open(path: &str) -> Result<Self, DatabaseError> {
        // Check for schema migration before opening
        if std::path::Path::new(path).exists() {
            if let Err(reason) = Self::check_schema_version(path) {
                eprintln!("Migrating database: {}. Rebuilding...", reason);
                std::fs::remove_file(path).map_err(|e| {
                    DatabaseError::Sqlite(format!("Failed to remove old database: {}", e))
                })?;
            }
        }

        let conn = Connection::open(path).map_err(|e| DatabaseError::Sqlite(e.to_string()))?;
        let mut store = Self { conn };
        store.create_tables()?;
        Ok(store)
    }

    /// Open an in-memory database (useful for tests).
    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let conn =
            Connection::open_in_memory().map_err(|e| DatabaseError::Sqlite(e.to_string()))?;
        let mut store = Self { conn };
        store.create_tables()?;
        Ok(store)
    }

    /// Check if an existing database has a compatible schema version.
    /// Returns Ok(()) if compatible, Err(reason) if migration is needed.
    fn check_schema_version(path: &str) -> Result<(), String> {
        let conn = Connection::open(path).map_err(|e| format!("cannot open: {}", e))?;

        // Check if metadata table exists
        let has_metadata: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='metadata'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if !has_metadata {
            return Err("no metadata table (pre-v2 schema)".to_string());
        }

        let version: u32 = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'schema_version'",
                [],
                |row| {
                    let v: String = row.get(0)?;
                    Ok(v.parse::<u32>().unwrap_or(0))
                },
            )
            .unwrap_or(0);

        if version < Self::SCHEMA_VERSION {
            return Err(format!(
                "schema version {} is older than current version {}",
                version,
                Self::SCHEMA_VERSION
            ));
        }

        Ok(())
    }

    /// Create all required tables and indexes if they do not already exist,
    /// and store the current schema version.
    pub fn create_tables(&mut self) -> Result<(), DatabaseError> {
        self.conn
            .execute_batch(
                "
                PRAGMA page_size = 16384;

                CREATE TABLE IF NOT EXISTS sources (
                    id   INTEGER PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ecosystems (
                    id   INTEGER PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL
                );

                CREATE TABLE IF NOT EXISTS packages (
                    id   INTEGER PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vid         INTEGER PRIMARY KEY,
                    id          TEXT NOT NULL,
                    summary     TEXT NOT NULL,
                    severity    INTEGER NOT NULL DEFAULT 0,
                    published   TEXT NOT NULL,
                    modified    TEXT NOT NULL,
                    withdrawn   INTEGER NOT NULL DEFAULT 0,
                    source_id   INTEGER NOT NULL REFERENCES sources(id),
                    cvss_score  REAL,
                    UNIQUE(id, source_id)
                );

                CREATE TABLE IF NOT EXISTS affected_packages (
                    id              INTEGER PRIMARY KEY,
                    vuln_vid        INTEGER NOT NULL REFERENCES vulnerabilities(vid),
                    ecosystem_id    INTEGER NOT NULL REFERENCES ecosystems(id),
                    package_id      INTEGER NOT NULL REFERENCES packages(id),
                    UNIQUE(vuln_vid, ecosystem_id, package_id)
                );

                CREATE INDEX IF NOT EXISTS idx_affected_packages_lookup
                    ON affected_packages(ecosystem_id, package_id);

                CREATE TABLE IF NOT EXISTS affected_ranges (
                    id              INTEGER PRIMARY KEY,
                    affected_id     INTEGER NOT NULL REFERENCES affected_packages(id),
                    range_type      INTEGER NOT NULL DEFAULT 0,
                    introduced      TEXT,
                    fixed           TEXT
                );

                CREATE TABLE IF NOT EXISTS metadata (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                ",
            )
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

        // Store the schema version
        self.set_metadata("schema_version", &Self::SCHEMA_VERSION.to_string())
    }

    /// Set a metadata value (upsert). Used internally for schema version tracking.
    fn set_metadata(&mut self, key: &str, value: &str) -> Result<(), DatabaseError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;
        Ok(())
    }

    /// Return the total number of vulnerability records stored.
    pub fn vulnerability_count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as usize
    }

    /// Insert a slice of vulnerability records in a single transaction.
    pub fn insert_vulnerabilities(&mut self, records: &[VulnRecord]) -> Result<(), DatabaseError> {
        // SAFETY: we hold &mut self so no concurrent access is possible.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;


        for record in records {
            let source_id = get_or_create_source(&tx, &record.source)?;
            let severity_int = severity_to_int(record.severity);

            tx.execute(
                "INSERT OR IGNORE INTO vulnerabilities
                 (id, summary, severity, published, modified, withdrawn, source_id, cvss_score)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    record.id,
                    record.summary,
                    severity_int,
                    record.published,
                    record.modified,
                    if record.withdrawn.is_some() { 1 } else { 0 },
                    source_id,
                    record.cvss_score,
                ],
            )
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

            // Get the vid (rowid alias) for the just-inserted/replaced vulnerability
            let vuln_vid: i64 = tx
                .query_row(
                    "SELECT vid FROM vulnerabilities WHERE id = ?1 AND source_id = ?2",
                    params![record.id, source_id],
                    |row| row.get(0),
                )
                .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

            for pkg in &record.affected {
                let ecosystem_id = get_or_create_ecosystem(&tx, &pkg.ecosystem)?;
                let package_id = get_or_create_package(&tx, &pkg.package_name)?;

                tx.execute(
                    "INSERT OR IGNORE INTO affected_packages (vuln_vid, ecosystem_id, package_id)
                     VALUES (?1, ?2, ?3)",
                    params![vuln_vid, ecosystem_id, package_id],
                )
                .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

                // Get the ID (either newly inserted or existing)
                let affected_id: i64 = tx
                    .query_row(
                        "SELECT id FROM affected_packages
                         WHERE vuln_vid = ?1 AND ecosystem_id = ?2 AND package_id = ?3",
                        params![vuln_vid, ecosystem_id, package_id],
                        |row| row.get(0),
                    )
                    .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

                for range in &pkg.ranges {
                    let rt_int = range_type_to_int(&range.range_type);
                    tx.execute(
                        "INSERT INTO affected_ranges (affected_id, range_type, introduced, fixed)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![affected_id, rt_int, range.introduced, range.fixed],
                    )
                    .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;
                }
            }
        }

        tx.commit()
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))
    }

    /// Query vulnerabilities affecting the given ecosystem and package name.
    ///
    /// Uses a single JOIN query across vulnerabilities -> affected_packages ->
    /// affected_ranges, then groups the results in Rust to avoid N+1 queries.
    pub fn query(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> Result<Vec<VulnQueryResult>, DatabaseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT v.id, v.summary, v.severity, v.published, v.modified,
                        ap.id AS affected_id, s.name AS source, v.cvss_score,
                        ar.range_type, ar.introduced, ar.fixed
                 FROM vulnerabilities v
                 JOIN sources s ON s.id = v.source_id
                 JOIN affected_packages ap ON ap.vuln_vid = v.vid
                 JOIN ecosystems e ON e.id = ap.ecosystem_id
                 JOIN packages p ON p.id = ap.package_id
                 LEFT JOIN affected_ranges ar ON ar.affected_id = ap.id
                 WHERE e.name = ?1 AND p.name = ?2
                   AND v.withdrawn = 0",
            )
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        // Each row may repeat the vulnerability fields for multiple ranges.
        // Key: (id, source, affected_id) -> index into `ordered` Vec.
        let mut index: HashMap<(String, String, i64), usize> = HashMap::new();
        let mut ordered: Vec<VulnQueryResult> = Vec::new();

        let rows = stmt
            .query_map(params![ecosystem, package_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,         // id
                    row.get::<_, String>(1)?,         // summary
                    row.get::<_, i32>(2)?,            // severity (integer)
                    row.get::<_, String>(3)?,         // published
                    row.get::<_, String>(4)?,         // modified
                    row.get::<_, i64>(5)?,            // affected_id
                    row.get::<_, String>(6)?,         // source (from sources table)
                    row.get::<_, Option<f64>>(7)?,    // cvss_score
                    row.get::<_, Option<i32>>(8)?,    // range_type (integer)
                    row.get::<_, Option<String>>(9)?, // introduced
                    row.get::<_, Option<String>>(10)?, // fixed
                ))
            })
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        for row in rows {
            let (
                id,
                summary,
                severity_int,
                published,
                modified,
                affected_id,
                source,
                cvss_score,
                range_type_int,
                introduced,
                fixed,
            ) = row.map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

            let key = (id.clone(), source.clone(), affected_id);

            let idx = if let Some(&i) = index.get(&key) {
                i
            } else {
                let i = ordered.len();
                index.insert(key, i);
                ordered.push(VulnQueryResult {
                    id,
                    summary,
                    severity: severity_from_int(severity_int),
                    published,
                    modified,
                    source,
                    cvss_score,
                    ranges: Vec::new(),
                });
                i
            };

            // Append the range if this row carries one (LEFT JOIN may return NULLs).
            if let Some(rt) = range_type_int {
                ordered[idx].ranges.push(AffectedRange {
                    range_type: range_type_from_int(rt),
                    introduced,
                    fixed,
                });
            }
        }

        Ok(ordered)
    }

    /// Compact the database file after large import operations.
    pub fn vacuum(&self) -> Result<(), DatabaseError> {
        self.conn
            .execute_batch("VACUUM")
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))
    }

    /// Retrieve the version ranges for a given affected_packages row id.
    pub fn query_ranges(&self, affected_id: i64) -> Result<Vec<AffectedRange>, DatabaseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT range_type, introduced, fixed
                 FROM affected_ranges
                 WHERE affected_id = ?1",
            )
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        let rows = stmt
            .query_map(params![affected_id], |row| {
                let rt_int: i32 = row.get(0)?;
                Ok(AffectedRange {
                    range_type: range_type_from_int(rt_int),
                    introduced: row.get(1)?,
                    fixed: row.get(2)?,
                })
            })
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        rows.map(|r| r.map_err(|e| DatabaseError::QueryFailed(e.to_string())))
            .collect()
    }
}

/// Get or create a source ID from the lookup table.
fn get_or_create_source(tx: &rusqlite::Transaction, name: &str) -> Result<i64, DatabaseError> {
    tx.execute(
        "INSERT OR IGNORE INTO sources (name) VALUES (?1)",
        params![name],
    )
    .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

    tx.query_row(
        "SELECT id FROM sources WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
    .map_err(|e| DatabaseError::Sqlite(e.to_string()))
}

/// Get or create an ecosystem ID from the lookup table.
fn get_or_create_ecosystem(tx: &rusqlite::Transaction, name: &str) -> Result<i64, DatabaseError> {
    tx.execute(
        "INSERT OR IGNORE INTO ecosystems (name) VALUES (?1)",
        params![name],
    )
    .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

    tx.query_row(
        "SELECT id FROM ecosystems WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
    .map_err(|e| DatabaseError::Sqlite(e.to_string()))
}

/// Get or create a package ID from the lookup table.
fn get_or_create_package(tx: &rusqlite::Transaction, name: &str) -> Result<i64, DatabaseError> {
    tx.execute(
        "INSERT OR IGNORE INTO packages (name) VALUES (?1)",
        params![name],
    )
    .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

    tx.query_row(
        "SELECT id FROM packages WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
    .map_err(|e| DatabaseError::Sqlite(e.to_string()))
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

        assert_eq!(store.vulnerability_count(), 1);

        let results = store
            .query("Go", "github.com/example/pkg")
            .expect("query should succeed");
        assert!(results.is_empty(), "withdrawn vulnerabilities should not be returned");
    }

    #[test]
    fn test_severity_roundtrip() {
        // Verify all severity values survive the int encoding roundtrip
        for (sev, expected_int) in [
            (Severity::None, 0),
            (Severity::Low, 1),
            (Severity::Medium, 2),
            (Severity::High, 3),
            (Severity::Critical, 4),
        ] {
            let encoded = severity_to_int(sev);
            assert_eq!(encoded, expected_int);
            assert_eq!(severity_from_int(encoded), sev);
        }
    }

    #[test]
    fn test_range_type_roundtrip() {
        for (s, expected_int) in [("ECOSYSTEM", 0), ("SEMVER", 1), ("GIT", 2)] {
            let encoded = range_type_to_int(s);
            assert_eq!(encoded, expected_int);
            assert_eq!(range_type_from_int(encoded), s);
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

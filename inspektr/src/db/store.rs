use crate::error::DatabaseError;
use crate::models::Severity;
use rusqlite::{Connection, params};
use std::collections::HashMap;

/// A vulnerability record to be stored in the database.
#[derive(Debug, Clone)]
pub struct VulnRecord {
    pub id: String,
    pub summary: String,
    pub details: String,
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
    pub details: String,
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

impl VulnStore {
    /// Current schema version. Increment this when the schema changes.
    const SCHEMA_VERSION: u32 = 2;

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
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id          TEXT NOT NULL,
                    summary     TEXT NOT NULL,
                    details     TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    published   TEXT NOT NULL,
                    modified    TEXT NOT NULL,
                    withdrawn   TEXT,
                    source      TEXT NOT NULL DEFAULT 'osv',
                    cvss_score  REAL,
                    PRIMARY KEY (id, source)
                );

                CREATE TABLE IF NOT EXISTS affected_packages (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_id         TEXT NOT NULL,
                    vuln_source     TEXT NOT NULL DEFAULT 'osv',
                    ecosystem       TEXT NOT NULL,
                    package_name    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_affected_packages_lookup
                    ON affected_packages(ecosystem, package_name);

                CREATE TABLE IF NOT EXISTS affected_ranges (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    affected_id     INTEGER NOT NULL REFERENCES affected_packages(id),
                    range_type      TEXT NOT NULL,
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

    /// Get a metadata value by key.
    pub fn get_metadata(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .ok()
    }

    /// Set a metadata value (upsert).
    pub fn set_metadata(&mut self, key: &str, value: &str) -> Result<(), DatabaseError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;
        Ok(())
    }

    /// Get the last update timestamp for a given source (e.g., "osv", "nvd").
    /// Returns an ISO 8601 string or None if never updated.
    pub fn last_updated(&self, source: &str) -> Option<String> {
        self.get_metadata(&format!("last_updated_{}", source))
    }

    /// Set the last update timestamp for a given source.
    pub fn set_last_updated(&mut self, source: &str, timestamp: &str) -> Result<(), DatabaseError> {
        self.set_metadata(&format!("last_updated_{}", source), timestamp)
    }

    /// Check database staleness and print warnings to stderr.
    /// Returns true if the database is usable (even if stale).
    pub fn check_staleness(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check the most recent update across all sources
        let mut newest_update: Option<u64> = None;
        for source in &["osv", "nvd"] {
            if let Some(ts) = self.last_updated(source) {
                if let Ok(epoch) = parse_iso8601_to_epoch(&ts) {
                    newest_update = Some(newest_update.map_or(epoch, |n: u64| n.max(epoch)));
                }
            }
        }

        let Some(last) = newest_update else {
            eprintln!(
                "WARNING: Vulnerability database has never been updated. Run `inspektr db update` or `inspektr db build`."
            );
            return;
        };

        let age_days = (now.saturating_sub(last)) / 86400;

        if age_days > 30 {
            eprintln!(
                "ERROR: Vulnerability database is {} days old. Results may be inaccurate. Run `inspektr db update` or `inspektr db build`.",
                age_days
            );
        } else if age_days > 7 {
            eprintln!(
                "WARNING: Vulnerability database is {} days old. Consider running `inspektr db update` or `inspektr db build`.",
                age_days
            );
        }
    }

    /// Return the total number of vulnerability records stored.
    pub fn vulnerability_count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as usize
    }

    /// Delete all data for a given source (e.g., "osv" or "nvd").
    /// Call this before a full re-import to avoid per-record delete overhead.
    pub fn clear_source(&mut self, source: &str) -> Result<(), DatabaseError> {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

        tx.execute(
            "DELETE FROM affected_ranges WHERE affected_id IN
             (SELECT id FROM affected_packages WHERE vuln_source = ?1)",
            params![source],
        ).map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

        tx.execute(
            "DELETE FROM affected_packages WHERE vuln_source = ?1",
            params![source],
        ).map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

        tx.execute(
            "DELETE FROM vulnerabilities WHERE source = ?1",
            params![source],
        ).map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

        tx.commit().map_err(|e| DatabaseError::Sqlite(e.to_string()))
    }

    /// Insert a slice of vulnerability records in a single transaction.
    /// For best performance on full imports, call `clear_source()` first
    /// to avoid per-record cleanup overhead.
    pub fn insert_vulnerabilities(&mut self, records: &[VulnRecord]) -> Result<(), DatabaseError> {
        // SAFETY: we hold &mut self so no concurrent access is possible.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

        for record in records {
            tx.execute(
                "INSERT OR REPLACE INTO vulnerabilities
                 (id, summary, details, severity, published, modified, withdrawn, source, cvss_score)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record.id,
                    record.summary,
                    record.details,
                    format!("{:?}", record.severity),
                    record.published,
                    record.modified,
                    record.withdrawn,
                    record.source,
                    record.cvss_score,
                ],
            )
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

            for pkg in &record.affected {
                tx.execute(
                    "INSERT INTO affected_packages (vuln_id, vuln_source, ecosystem, package_name)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![record.id, record.source, pkg.ecosystem, pkg.package_name],
                )
                .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

                let affected_id = tx.last_insert_rowid();

                for range in &pkg.ranges {
                    tx.execute(
                        "INSERT INTO affected_ranges (affected_id, range_type, introduced, fixed)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![affected_id, range.range_type, range.introduced, range.fixed],
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
    /// Uses a single JOIN query across vulnerabilities → affected_packages →
    /// affected_ranges, then groups the results in Rust to avoid N+1 queries.
    pub fn query(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> Result<Vec<VulnQueryResult>, DatabaseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT v.id, v.summary, v.details, v.severity, v.published, v.modified,
                        ap.id AS affected_id, v.source, v.cvss_score,
                        ar.range_type, ar.introduced, ar.fixed
                 FROM vulnerabilities v
                 JOIN affected_packages ap ON ap.vuln_id = v.id AND ap.vuln_source = v.source
                 LEFT JOIN affected_ranges ar ON ar.affected_id = ap.id
                 WHERE ap.ecosystem = ?1 AND ap.package_name = ?2
                   AND v.withdrawn IS NULL",
            )
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        // Each row may repeat the vulnerability fields for multiple ranges.
        // Key: (id, source, affected_id) → index into `ordered` Vec.
        let mut index: HashMap<(String, String, i64), usize> = HashMap::new();
        let mut ordered: Vec<VulnQueryResult> = Vec::new();

        let rows = stmt
            .query_map(params![ecosystem, package_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,   // id
                    row.get::<_, String>(1)?,   // summary
                    row.get::<_, String>(2)?,   // details
                    row.get::<_, String>(3)?,   // severity
                    row.get::<_, String>(4)?,   // published
                    row.get::<_, String>(5)?,   // modified
                    row.get::<_, i64>(6)?,      // affected_id
                    row.get::<_, String>(7)?,   // source
                    row.get::<_, Option<f64>>(8)?,  // cvss_score
                    row.get::<_, Option<String>>(9)?,   // range_type
                    row.get::<_, Option<String>>(10)?,  // introduced
                    row.get::<_, Option<String>>(11)?,  // fixed
                ))
            })
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        for row in rows {
            let (
                id,
                summary,
                details,
                severity_str,
                published,
                modified,
                affected_id,
                source,
                cvss_score,
                range_type,
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
                    details,
                    severity: Severity::parse(&severity_str),
                    published,
                    modified,
                    source,
                    cvss_score,
                    ranges: Vec::new(),
                });
                i
            };

            // Append the range if this row carries one (LEFT JOIN may return NULLs).
            if let Some(rt) = range_type {
                ordered[idx].ranges.push(AffectedRange {
                    range_type: rt,
                    introduced,
                    fixed,
                });
            }
        }

        Ok(ordered)
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
                Ok(AffectedRange {
                    range_type: row.get(0)?,
                    introduced: row.get(1)?,
                    fixed: row.get(2)?,
                })
            })
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        rows.map(|r| r.map_err(|e| DatabaseError::QueryFailed(e.to_string())))
            .collect()
    }
}

/// Parse a simplified ISO 8601 timestamp (YYYY-MM-DDTHH:MM:SSZ) to Unix epoch seconds.
fn parse_iso8601_to_epoch(s: &str) -> Result<u64, ()> {
    // Expect format: 2026-03-22T18:28:22Z or similar
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T').ok_or(())?;
    let date_parts: Vec<&str> = date.split('-').collect();
    let time_parts: Vec<&str> = time.split(':').collect();
    if date_parts.len() != 3 || time_parts.len() < 2 {
        return Err(());
    }
    let year: u64 = date_parts[0].parse().map_err(|_| ())?;
    let month: u64 = date_parts[1].parse().map_err(|_| ())?;
    let day: u64 = date_parts[2].parse().map_err(|_| ())?;
    let hour: u64 = time_parts[0].parse().map_err(|_| ())?;
    let min: u64 = time_parts[1].parse().map_err(|_| ())?;
    let sec: u64 = time_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    // Rough epoch calculation (ignoring leap seconds, good enough for staleness checks)
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
    }
    let month_days: [u64; 12] = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for m in 0..(month.saturating_sub(1) as usize).min(12) {
        days += month_days[m];
    }
    days += day.saturating_sub(1);

    Ok(days * 86400 + hour * 3600 + min * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> VulnRecord {
        VulnRecord {
            id: "GO-2023-0001".to_string(),
            summary: "Remote code execution in example/pkg".to_string(),
            details: "An attacker can craft a malicious request to trigger RCE.".to_string(),
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
}

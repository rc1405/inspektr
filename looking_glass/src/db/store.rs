use crate::error::DatabaseError;
use crate::models::Severity;
use rusqlite::{Connection, params};

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
    pub ranges: Vec<AffectedRange>,
}

/// Wraps a SQLite connection for vulnerability storage and retrieval.
pub struct VulnStore {
    conn: Connection,
}

impl VulnStore {
    /// Open (or create) a database at the given path.
    pub fn open(path: &str) -> Result<Self, DatabaseError> {
        let conn = Connection::open(path)
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;
        let mut store = Self { conn };
        store.create_tables()?;
        Ok(store)
    }

    /// Open an in-memory database (useful for tests).
    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;
        let mut store = Self { conn };
        store.create_tables()?;
        Ok(store)
    }

    /// Create all required tables and indexes if they do not already exist.
    pub fn create_tables(&mut self) -> Result<(), DatabaseError> {
        self.conn
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id          TEXT PRIMARY KEY,
                    summary     TEXT NOT NULL,
                    details     TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    published   TEXT NOT NULL,
                    modified    TEXT NOT NULL,
                    withdrawn   TEXT
                );

                CREATE TABLE IF NOT EXISTS affected_packages (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_id         TEXT NOT NULL REFERENCES vulnerabilities(id),
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
                ",
            )
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))
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
            tx.execute(
                "INSERT OR REPLACE INTO vulnerabilities
                 (id, summary, details, severity, published, modified, withdrawn)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.id,
                    record.summary,
                    record.details,
                    format!("{:?}", record.severity),
                    record.published,
                    record.modified,
                    record.withdrawn,
                ],
            )
            .map_err(|e| DatabaseError::Sqlite(e.to_string()))?;

            for pkg in &record.affected {
                tx.execute(
                    "INSERT INTO affected_packages (vuln_id, ecosystem, package_name)
                     VALUES (?1, ?2, ?3)",
                    params![record.id, pkg.ecosystem, pkg.package_name],
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

        tx.commit().map_err(|e| DatabaseError::Sqlite(e.to_string()))
    }

    /// Query vulnerabilities affecting the given ecosystem and package name.
    pub fn query(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> Result<Vec<VulnQueryResult>, DatabaseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT v.id, v.summary, v.details, v.severity, v.published, v.modified,
                        ap.id AS affected_id
                 FROM vulnerabilities v
                 JOIN affected_packages ap ON ap.vuln_id = v.id
                 WHERE ap.ecosystem = ?1 AND ap.package_name = ?2
                   AND v.withdrawn IS NULL",
            )
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        let rows = stmt
            .query_map(params![ecosystem, package_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            let (id, summary, details, severity_str, published, modified, affected_id) =
                row.map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

            let severity = parse_severity_str(&severity_str);
            let ranges = self.query_ranges(affected_id as i64)?;

            results.push(VulnQueryResult {
                id,
                summary,
                details,
                severity,
                published,
                modified,
                ranges,
            });
        }

        Ok(results)
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

fn parse_severity_str(s: &str) -> Severity {
    match s {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::None,
    }
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

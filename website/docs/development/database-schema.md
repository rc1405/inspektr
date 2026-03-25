# Database Schema

Inspektr stores vulnerability data in a local SQLite database.

## Tables

### vulnerabilities

Primary vulnerability records, keyed by `(id, source)` to support multiple data sources.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT NOT NULL | Vulnerability ID (CVE, GHSA, DSA, etc.) |
| `source` | TEXT NOT NULL | Data source ("osv" or "nvd") |
| `summary` | TEXT NOT NULL | Short description |
| `details` | TEXT NOT NULL | Full description |
| `severity` | TEXT NOT NULL | Severity level (Critical/High/Medium/Low/None) |
| `cvss_score` | REAL | Numeric CVSS score (NULL for OSV entries) |
| `published` | TEXT NOT NULL | Publication timestamp |
| `modified` | TEXT NOT NULL | Last modification timestamp |
| `withdrawn` | TEXT | Withdrawal timestamp (NULL if active) |

Primary key: `(id, source)`

### affected_packages

Links vulnerabilities to specific packages in specific ecosystems.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment |
| `vuln_id` | TEXT NOT NULL | References vulnerabilities.id |
| `vuln_source` | TEXT NOT NULL | References vulnerabilities.source |
| `ecosystem` | TEXT NOT NULL | OSV ecosystem name (e.g., "npm", "Alpine:v3.18") |
| `package_name` | TEXT NOT NULL | Package name |

Index: `idx_affected_packages_lookup` on `(ecosystem, package_name)`

### affected_ranges

Version ranges for affected packages.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PRIMARY KEY | Auto-increment |
| `affected_id` | INTEGER NOT NULL | References affected_packages.id |
| `range_type` | TEXT NOT NULL | "SEMVER" or "ECOSYSTEM" |
| `introduced` | TEXT | Version where vulnerability was introduced |
| `fixed` | TEXT | Version where vulnerability was fixed |

### metadata

Key-value store for schema version and import timestamps.

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT PRIMARY KEY | Metadata key |
| `value` | TEXT NOT NULL | Metadata value |

Used for:
- `schema_version` — current schema version (auto-migration on mismatch)
- `last_updated_osv` — last OSV import timestamp
- `last_updated_nvd` — last NVD import timestamp
- `last_updated_photon` — last Photon OS import timestamp
- `last_updated_oracle` — last Oracle Linux import timestamp
- `last_updated_azurelinux` — last Azure Linux import timestamp
- `last_updated_bottlerocket` — last Bottlerocket import timestamp

## Schema Versioning

The database stores its schema version in the `metadata` table. On open, `VulnStore::open()` checks if the existing database has a compatible version. If the schema is outdated, the database is automatically deleted and recreated.

To make schema changes:

1. Modify the `create_tables` SQL in `db/store.rs`
2. Increment `SCHEMA_VERSION`
3. Existing databases will auto-rebuild on next open

## Multi-Source Support

The composite primary key `(id, source)` allows the same vulnerability (e.g., `CVE-2021-44906`) to have separate entries from different sources. Each source can provide different severity ratings and CVSS scores.

Sources: `osv`, `nvd`, `photon`, `oracle`, `azurelinux`, `bottlerocket`.

The `clear_source()` method deletes all data for a specific source, enabling clean re-imports without affecting data from other sources.

## Versioned Ecosystem Names

OS distributions use versioned ecosystem names in the database to match OSV's naming:

- `Alpine:v3.18` (not just `Alpine`)
- `Debian:12`
- `Ubuntu:22.04`
- `Red Hat:9`

This is handled by the `versioned_osv_ecosystem()` function in the OS cataloger, which stores the versioned name in package metadata for the matcher to use.

# Database Management

Inspektr uses a local SQLite database for vulnerability data, stored at `~/.local/share/inspektr/vuln.db` (or `$XDG_DATA_HOME/inspektr/vuln.db`).

## Pull Pre-Built Database

The fastest way to get started:

```bash
inspektr db update
```

Pulls from `rc1405/inspektr-db:latest` on Docker Hub via OCI.

To pull from a custom registry:

```bash
inspektr db update --registry your-registry.io/security/inspektr-db:latest
```

## Build From Source Data

Requires the `db-admin` feature:

```bash
cargo build --release --features db-admin
```

### Full build

Downloads from both OSV and NVD:

```bash
inspektr db build
```

### Ecosystem-specific build

```bash
inspektr db build --ecosystem npm
inspektr db build --ecosystem Alpine
```

### NVD API key

Without a key, NVD downloads are rate-limited to 5 requests per 30 seconds. With a key, 50 per 30 seconds.

Get a free key at [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

```bash
NVD_API_KEY=your-key inspektr db build
```

### Incremental updates

After the first full NVD import, subsequent `db build` runs only fetch CVEs modified since the last import:

```bash
# First run: ~250K CVEs, takes 30+ minutes without API key
NVD_API_KEY=your-key inspektr db build

# Subsequent runs: only new/modified CVEs, much faster
NVD_API_KEY=your-key inspektr db build
```

OSV is always a full re-import (fast — bulk zip downloads).

## Push to Registry

Share your built database with your team:

```bash
inspektr db push your-registry.io/security/inspektr-db:latest
```

Team members pull with:

```bash
inspektr db update --registry your-registry.io/security/inspektr-db:latest
```

## Delete Database

```bash
inspektr db clean
```

## Schema Versioning

The database has automatic schema version tracking. When the schema changes between releases, `inspektr` detects the old version on open and rebuilds the database automatically.

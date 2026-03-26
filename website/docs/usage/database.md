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

# With authentication
inspektr db update --registry your-registry.io/security/inspektr-db:latest --username myuser --password mytoken

# Password from stdin (recommended for CI)
echo "$TOKEN" | inspektr db update --registry your-registry.io/security/inspektr-db:latest --username myuser --password-stdin
```

## Build From Source Data

Requires the `db-admin` feature:

```bash
cargo build --release --features db-admin
```

### Full build

Downloads from all vulnerability sources (OSV, NVD, Oracle OVAL, Photon OS, Azure Linux, Bottlerocket):

```bash
inspektr db build
```

### Ecosystem-specific build

```bash
inspektr db build --ecosystem npm
inspektr db build --ecosystem Alpine
inspektr db build --ecosystem Oracle
inspektr db build --ecosystem "Photon OS"
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

## Vulnerability Data Sources

`db build` imports from multiple sources automatically:

| Source | Type | Coverage |
|--------|------|----------|
| **OSV** | Bulk ZIP download | Alpine, Wolfi, Chainguard, Debian, Ubuntu, Red Hat, Rocky, AlmaLinux, SUSE, Echo, MinimOS + all language ecosystems |
| **NVD** | CVE API 2.0 (paginated) | All ecosystems via CPE mapping. Provides CVSS scores. |
| **Oracle OVAL** | OVAL XML (bzip2) | Oracle Linux 7, 8, 9 |
| **Photon OS** | JSON CVE metadata | Photon OS 1.0–5.0 |
| **Azure Linux** | OVAL XML | CBL-Mariner 1.0/2.0, Azure Linux 3.0 |
| **Bottlerocket** | updateinfo.xml (gzip) | Bottlerocket |

CentOS and CoreOS are supported for SBOM generation (distro detection and package enumeration) but have no distro-specific vulnerability feed — NVD provides partial coverage via CPE matching.

## Distribute Database

Inspektr no longer includes a built-in push command. To distribute your built database, use [ORAS](https://oras.land/) to push it as an OCI artifact:

```bash
# Push with ORAS
oras push your-registry.io/security/inspektr-db:latest \
  --artifact-type application/vnd.inspektr.db.v1 \
  vuln.db:application/vnd.inspektr.db.v1+sqlite
```

Other OCI-compatible tools (Docker, skopeo) can also be used for distribution.

Team members pull with:

```bash
# Public registry
inspektr db update --registry your-registry.io/security/inspektr-db:latest

# Private registry with authentication
echo "$TOKEN" | inspektr db update --registry your-registry.io/security/inspektr-db:latest --username myuser --password-stdin
```

## Delete Database

```bash
inspektr db clean
```

## Schema Versioning

The database has automatic schema version tracking. When the schema changes between releases, `inspektr` detects the old version on open and rebuilds the database automatically.

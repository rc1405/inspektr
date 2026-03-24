# CLI Reference

## Commands

### `inspektr sbom`

Generate a Software Bill of Materials for a target.

```
inspektr sbom [OPTIONS] <TARGET>
```

| Argument/Option | Description |
|----------------|-------------|
| `<TARGET>` | Target to scan (filesystem path, binary, or OCI image reference) |
| `--format <FORMAT>` | SBOM format: `cyclonedx` (default) or `spdx` |
| `-o, --output <FILE>` | Write output to file instead of stdout |

**Examples:**

```bash
inspektr sbom /path/to/project
inspektr sbom --format spdx -o sbom.json /path/to/project
inspektr sbom docker.io/library/alpine:3.19
inspektr sbom ~/go/bin/kubectl
```

### `inspektr vuln`

Scan a target or SBOM for known vulnerabilities.

```
inspektr vuln [OPTIONS] [TARGET]
```

| Argument/Option | Description |
|----------------|-------------|
| `[TARGET]` | Target to scan (mutually exclusive with `--sbom`) |
| `--sbom <FILE>` | Scan an existing SBOM file |
| `--format <FORMAT>` | Output format: `table` or `json` |
| `-o, --output <FILE>` | Write output to file |
| `--fail-on <SEVERITY>` | Exit non-zero if vulns at or above severity (none/low/medium/high/critical) |
| `--db <PATH>` | Path to vulnerability database |

**Format defaults:**

- No `--output`: defaults to `table`
- With `--output`: defaults to `json`
- `--format` overrides the default

**Examples:**

```bash
inspektr vuln /path/to/project
inspektr vuln --format json /path/to/project
inspektr vuln -o report.json /path/to/project
inspektr vuln --sbom sbom.json
inspektr vuln --fail-on high /path/to/project
```

### `inspektr db update`

Pull the latest pre-built vulnerability database from Docker Hub.

```
inspektr db update [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--registry <REF>` | OCI image reference (default: `rc1405/inspektr-db:latest`) |

### `inspektr db build`

Build the vulnerability database from OSV and NVD sources. Requires `db-admin` feature.

```
inspektr db build [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--ecosystem <NAME>` | Import only this ecosystem (default: all) |
| `-o, --output <PATH>` | Write database to this path |

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API key for faster downloads (50 req/30s vs 5 req/30s) |

### `inspektr db push`

Push a built database to an OCI registry. Requires `db-admin` feature.

```
inspektr db push [OPTIONS] <REGISTRY>
```

| Argument/Option | Description |
|----------------|-------------|
| `<REGISTRY>` | OCI registry reference |
| `--db <PATH>` | Path to database file to push |

### `inspektr db clean`

Delete the local vulnerability database.

```
inspektr db clean
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API key for faster database builds |
| `INSPEKTR_REGISTRY_TOKEN` | Authentication token for OCI registries |
| `XDG_DATA_HOME` | Override data directory (default: `~/.local/share`) |

## Target Detection

Inspektr auto-detects the target type:

1. **OCI image reference** — if the first path segment contains a dot (e.g., `docker.io/library/alpine:3.19`)
2. **Binary file** — if the path points to a file with ELF/Mach-O/PE magic bytes
3. **Filesystem** — everything else (scans recursively for lockfiles)

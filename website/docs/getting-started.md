# Getting Started

## Installation

### From Source

```bash
git clone https://github.com/rc1405/inspektr.git
cd inspektr
cargo build --release
```

The binary is at `target/release/inspektr_cli`.

### With Database Admin Features

To build vulnerability databases from source data:

```bash
cargo build --release --features db-admin
```

## First Scan

### 1. Get the vulnerability database

```bash
inspektr db update
```

This pulls a pre-built database from Docker Hub (`rc1405/inspektr-db:latest`).

### 2. Generate an SBOM

```bash
inspektr sbom /path/to/your/project
```

Inspektr auto-detects all supported ecosystems — Go, JavaScript, Python, Java, .NET, PHP, Rust, Ruby, Swift, C/C++.

### 3. Scan for vulnerabilities

```bash
inspektr vuln /path/to/your/project
```

Example output:

```
Target: /path/to/your/project
Packages: 45 | Vulnerabilities: 3 (Critical: 1, High: 0, Medium: 2, Low: 0)

VULNERABILITY         PACKAGE   VERSION  SEVERITY  CVSS  FIXED    SOURCE             SOURCES
GHSA-xvch-5gv4-984h  minimist  1.2.5    Critical  9.8   1.2.6    package-lock.json  osv,nvd
GHSA-29mw-wpgm-hmr9  lodash    4.17.20  Medium    6.5   4.17.21  package-lock.json  osv
```

### 4. Scan a container image

```bash
inspektr vuln docker.io/library/alpine:3.19
```

Container images are scanned for both OS packages (dpkg, apk, rpm) and application dependencies.

## What's Next

- [CLI Reference](usage/cli-reference.md) — all commands and flags
- [SBOM Generation](usage/sbom.md) — output formats and options
- [Vulnerability Scanning](usage/vulnerability-scanning.md) — report formats and CI integration
- [Database Management](usage/database.md) — building and updating the vulnerability database

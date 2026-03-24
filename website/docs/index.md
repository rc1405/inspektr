# Inspektr

A software composition analysis (SCA) tool for generating Software Bills of Materials (SBOM) and scanning for known vulnerabilities. Written in Rust, comparable in scope to Syft + Grype.

## Features

- **SBOM Generation** from container images, local filesystems, and compiled binaries
- **Vulnerability Scanning** against OSV and NVD databases
- **11 Language Ecosystems**: Go, JavaScript/Node, Python, Java, C/C++ (Conan, vcpkg), .NET, PHP, Rust, Ruby, Swift
- **18 OS Distributions**: Alpine, Wolfi, Chainguard, Debian, Ubuntu, Distroless, RHEL, CentOS, Rocky, Alma, Oracle, SUSE, Photon, Azure Linux, CoreOS, Bottlerocket, Echo, MinimOS
- **Multiple SBOM Formats**: CycloneDX 1.5 JSON, SPDX 2.3 JSON
- **Multiple Vulnerability Sources**: OSV (bulk download), NVD (CVE API 2.0 with incremental updates)
- **OCI Distribution**: Pre-built vulnerability databases distributed as OCI artifacts
- **Dual-use**: CLI tool and Rust library

## Quick Start

```bash
# Build
cargo build --release

# Generate an SBOM
inspektr sbom /path/to/project

# Pull the vulnerability database
inspektr db update

# Scan for vulnerabilities
inspektr vuln /path/to/project
```

See [Getting Started](getting-started.md) for installation and first steps.

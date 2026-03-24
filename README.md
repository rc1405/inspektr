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

# Generate an SBOM from a directory
inspektr sbom /path/to/project

# Generate an SBOM from a container image
inspektr sbom docker.io/library/alpine:3.19

# Generate an SBOM from a Go binary
inspektr sbom /path/to/binary

# Pull the pre-built vulnerability database
inspektr db update

# Scan for vulnerabilities
inspektr vuln /path/to/project

# Scan with JSON output
inspektr vuln --format json /path/to/project

# Scan and fail on critical vulnerabilities (CI mode)
inspektr vuln --fail-on critical /path/to/project
```

## Installation

### From Source

```bash
git clone https://github.com/rc1405/inspektr.git
cd inspektr
cargo build --release
```

The binary is at `target/release/inspektr_cli`.

### With Database Admin Features

To build/push vulnerability databases from source data:

```bash
cargo build --release --features db-admin
```

## Usage

See [docs/usage.md](docs/usage.md) for detailed usage documentation.

## Supported Ecosystems

| Ecosystem | Lockfiles/Manifests | PURL Scheme |
|-----------|-------------------|-------------|
| Go | `go.mod`, `go.sum`, Go binaries | `pkg:golang/` |
| JavaScript | `package-lock.json`, `yarn.lock` | `pkg:npm/` |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` | `pkg:pypi/` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts` | `pkg:maven/` |
| .NET | `packages.lock.json`, `*.csproj`, `packages.config` | `pkg:nuget/` |
| PHP | `composer.lock` | `pkg:composer/` |
| Rust | `Cargo.lock` | `pkg:cargo/` |
| Ruby | `Gemfile.lock` | `pkg:gem/` |
| Swift | `Package.resolved` (v1, v2) | `pkg:swift/` |
| C/C++ (Conan) | `conan.lock` | `pkg:conan/` |
| C/C++ (vcpkg) | `vcpkg.json` | `pkg:vcpkg/` |

### OS Package Scanning (Container Images)

| Format | Distributions |
|--------|--------------|
| dpkg | Debian, Ubuntu, Distroless |
| apk | Alpine, Wolfi, Chainguard |
| rpm | RHEL, CentOS, Rocky, Alma, Oracle, SUSE, Photon, Azure Linux, CoreOS, Bottlerocket, Echo, MinimOS |

## Architecture

Inspektr uses a layered pipeline architecture:

```
Source -> Cataloger -> SBOM Formatter -> Vulnerability Matcher -> Reporter
```

See [docs/development.md](docs/development.md) for architecture details.

## License

See [LICENSE](LICENSE) for details.

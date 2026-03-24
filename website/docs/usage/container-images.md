# Container Image Scanning

## How It Works

When you scan a container image, Inspektr:

1. Pulls the image via OCI protocol
2. Extracts all layers (handles both OCI and Docker layer formats)
3. Reconstructs the filesystem (respects whiteout files for deleted layers)
4. Runs **all catalogers** against the extracted files:
   - **OS cataloger** — detects the distro from `/etc/os-release` and parses the package database (dpkg, apk, rpm)
   - **Language catalogers** — finds lockfiles and binaries (Go, Node, Python, Java, etc.)

This means a container image with an Alpine base + a Go binary + a Node.js app produces one SBOM with Alpine OS packages, Go dependencies from the binary, and npm dependencies from `package-lock.json`.

## Scanning Images

```bash
# Docker Hub
inspektr sbom docker.io/library/alpine:3.19
inspektr vuln docker.io/library/node:18

# GitHub Container Registry
inspektr sbom ghcr.io/myorg/myapp:latest

# Private registries
inspektr sbom private.registry.io/myapp:v1
```

## Authentication

Authentication is resolved in this order:

1. **`INSPEKTR_REGISTRY_TOKEN` environment variable**
2. **Docker config.json** (`~/.docker/config.json`)
3. **Anonymous access**

```bash
INSPEKTR_REGISTRY_TOKEN=your-token inspektr sbom private.registry.io/myapp:v1
```

## Supported Image Formats

- OCI image manifests
- Docker v2 manifests
- Both gzipped and uncompressed layers
- Docker Hub, GHCR, ECR, GCR, and any OCI-compliant registry

## OS Detection

The OS cataloger identifies the distribution from:

| File | Distros |
|------|---------|
| `/etc/os-release` | All modern distros |
| `/etc/alpine-release` | Alpine (fallback) |
| `/var/lib/dpkg/status` | Distroless (fallback) |

Supported distros: Alpine, Wolfi, Chainguard, Debian, Ubuntu, Distroless, RHEL, CentOS, Rocky, Alma, Oracle, SUSE, Photon, Azure Linux, CoreOS, Bottlerocket, Echo, MinimOS.

## Notes

- Container image scanning downloads all layers into memory. Large images (800MB+) use significant RAM.
- Inspektr does not distinguish between base image layers and application layers — all files are scanned.
- Multi-architecture images: Inspektr pulls the manifest for the current platform.

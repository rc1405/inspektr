# SBOM Generation

## Supported Formats

### CycloneDX 1.5 JSON (default)

```bash
inspektr sbom /path/to/project
inspektr sbom --format cyclonedx /path/to/project
```

Produces a spec-compliant CycloneDX 1.5 JSON document with components and PURL identifiers.

### SPDX 2.3 JSON

```bash
inspektr sbom --format spdx /path/to/project
```

Produces a spec-compliant SPDX 2.3 JSON document with packages and PURL external references.

## Scan Targets

### Filesystem directory

```bash
inspektr sbom /path/to/project
```

Recursively scans for lockfiles and manifests. Multiple ecosystems are detected in a single scan — a monorepo with `go.mod`, `package-lock.json`, and `requirements.txt` produces one SBOM with all dependencies.

### Go binary

```bash
inspektr sbom ~/go/bin/kubectl
```

Go embeds build information in compiled binaries. Inspektr reads the `.go.buildinfo` section to extract module dependencies — no source code needed.

### Container image

```bash
inspektr sbom docker.io/library/node:18-alpine
```

Pulls the image via OCI, extracts all layers, and scans for both OS packages (apk, dpkg, rpm) and language dependencies. The resulting SBOM includes everything in the image.

## Writing to Files

```bash
inspektr sbom -o sbom.json /path/to/project
inspektr sbom --format spdx -o sbom-spdx.json /path/to/project
```

## Using SBOMs for Vulnerability Scanning

Generate once, scan repeatedly:

```bash
inspektr sbom -o app-sbom.json /path/to/project
inspektr vuln --sbom app-sbom.json
```

This is useful when the database is updated more frequently than the application changes.

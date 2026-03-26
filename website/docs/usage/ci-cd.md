# CI/CD Integration

## Vulnerability Gate

Fail the build if vulnerabilities exceed a severity threshold:

```bash
inspektr vuln --fail-on high /path/to/project
```

Exit codes:

- `0` — no vulnerabilities at or above the threshold
- `1` — vulnerabilities found at or above the threshold

## Generate SBOM as Build Artifact

```bash
# CycloneDX for broad tool compatibility
inspektr sbom --format cyclonedx -o sbom-cyclonedx.json /path/to/project

# SPDX for compliance/regulatory requirements
inspektr sbom --format spdx -o sbom-spdx.json /path/to/project
```

## JSON Report for Dashboards

```bash
inspektr vuln --format json -o vuln-report.json /path/to/project
```

The JSON includes scan metadata (timestamp, package count, severity breakdown) suitable for ingestion into dashboards and tracking systems.

## Container Image Scanning

```bash
docker build -t myapp:latest .
inspektr vuln docker.io/myapp:latest --fail-on critical

# Scan a private registry image
echo "$REGISTRY_TOKEN" | inspektr vuln --username myuser --password-stdin private.registry.io/myapp:latest --fail-on critical
```

## GitHub Actions Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Inspektr
        run: |
          cargo install --git https://github.com/rc1405/inspektr.git inspektr_cli

      - name: Pull vulnerability database
        run: echo "${{ secrets.REGISTRY_TOKEN }}" | inspektr db update --username ${{ secrets.REGISTRY_USERNAME }} --password-stdin
        # Or for public registries, simply: inspektr db update

      - name: Generate SBOM
        run: inspektr sbom -o sbom.json .

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json

      - name: Vulnerability scan
        run: inspektr vuln --fail-on high --format json -o vuln-report.json .

      - name: Upload vulnerability report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vuln-report
          path: vuln-report.json
```

## GitLab CI Example

```yaml
security-scan:
  stage: test
  script:
    - cargo install --git https://github.com/rc1405/inspektr.git inspektr_cli
    - inspektr db update
    - inspektr sbom -o sbom.json .
    - inspektr vuln --fail-on high --format json -o vuln-report.json .
  artifacts:
    paths:
      - sbom.json
      - vuln-report.json
    when: always
```

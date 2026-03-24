# OS Distributions

Inspektr detects and scans OS packages in container images across 18 Linux distributions.

## Supported Distributions

### apk-based

| Distribution | os-release ID | OSV Ecosystem |
|-------------|--------------|---------------|
| Alpine Linux | `alpine` | `Alpine` |
| Wolfi | `wolfi` | `Wolfi` |
| Chainguard | `chainguard` | `Chainguard` |

### dpkg-based

| Distribution | os-release ID | OSV Ecosystem |
|-------------|--------------|---------------|
| Debian | `debian` | `Debian` |
| Ubuntu | `ubuntu` | `Ubuntu` |
| Google Distroless | (detected by dpkg presence) | `Debian` |

### rpm-based

| Distribution | os-release ID | OSV Ecosystem |
|-------------|--------------|---------------|
| Red Hat Enterprise Linux | `rhel` | `Red Hat` |
| CentOS | `centos` | `CentOS` |
| Rocky Linux | `rocky` | `Rocky Linux` |
| AlmaLinux | `almalinux` | `AlmaLinux` |
| Oracle Linux | `ol` | `Oracle` |
| SUSE/openSUSE | `sles`, `opensuse-leap`, `opensuse-tumbleweed` | `SUSE` |
| Photon OS | `photon` | `Photon OS` |
| Azure Linux (Mariner) | `azurelinux`, `mariner` | `Azure Linux` |
| CoreOS | `coreos` | `CoreOS` |
| Bottlerocket | `bottlerocket` | `Bottlerocket` |
| Echo | `echo` | `Echo` |
| MinimOS | `minimos` | `MinimOS` |

## How OS Detection Works

1. Inspektr looks for `/etc/os-release` in the extracted image layers
2. Parses the `ID` and `VERSION_ID` fields to identify the distribution
3. Falls back to `/etc/alpine-release` for older Alpine images
4. Falls back to dpkg status file detection for Distroless images (which lack os-release)

## Package Database Parsing

### dpkg (Debian, Ubuntu, Distroless)

Reads `/var/lib/dpkg/status`. For Distroless images, also reads individual files from `/var/lib/dpkg/status.d/`.

Only includes packages with `Status: install ok installed`.

PURL format: `pkg:deb/{distro}/{name}@{version}`

### apk (Alpine, Wolfi, Chainguard)

Reads `/lib/apk/db/installed`.

PURL format: `pkg:apk/{distro}/{name}@{version}`

### rpm (all rpm-based distributions)

Reads the SQLite RPM database at:
- `/usr/lib/sysimage/rpm/rpmdb.sqlite` (modern)
- `/var/lib/rpm/rpmdb.sqlite` (legacy path)

Parses RPM header blobs to extract package name, version, release, and epoch.

PURL format: `pkg:rpm/{distro}/{name}@{version-release}` (with epoch prefix if non-zero)

## Version Matching

OS package versions don't follow semantic versioning. Inspektr uses string-based comparison for OS packages when semver parsing fails. This is imperfect for some version schemes but handles most common cases.

## Adding a New Distribution

Adding a new distro requires two changes:

1. Add one arm to `map_distro_id()` in `cataloger/os/mod.rs`:
```rust
"mynewdistro" => Some((Ecosystem::MyNewDistro, PackageFormat::Dpkg)),
```

2. Add the `Ecosystem` variant + `as_osv_ecosystem()` + `to_purl()` arm in `models/mod.rs`

No new parser code is needed if the distro uses dpkg, apk, or rpm.

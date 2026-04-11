//! # inspektr
//!
//! A software composition analysis (SCA) library for generating Software Bills of
//! Materials (SBOMs) and scanning for known vulnerabilities. Comparable in scope to
//! Syft + Grype, but written in Rust and usable as both a CLI tool and an embeddable
//! library.
//!
//! ## Capabilities
//!
//! - **SBOM generation** from container images, local filesystems, and compiled binaries
//! - **Vulnerability scanning** against OSV and NVD databases
//! - **11 language ecosystems**: Go, JavaScript/Node, Python, Java, C/C++ (Conan, vcpkg),
//!   .NET, PHP, Rust, Ruby, Swift
//! - **18 OS distributions**: Alpine, Wolfi, Chainguard, Debian, Ubuntu, Distroless,
//!   RHEL, CentOS, Rocky, Alma, Oracle, SUSE, Photon, Azure Linux, CoreOS, Bottlerocket,
//!   Echo, MinimOS
//! - **SBOM formats**: CycloneDX 1.5 JSON, SPDX 2.3 JSON
//! - **Vulnerability sources**: OSV (bulk), NVD (API), Oracle OVAL, Photon OS, Azure
//!   Linux OVAL, Bottlerocket
//!
//! ## Quick start
//!
//! Generate an SBOM from a filesystem path or container image:
//!
//! ```no_run
//! use inspektr::pipeline;
//! use inspektr::oci::RegistryAuth;
//!
//! // From a local directory
//! let sbom = pipeline::generate_sbom("/path/to/project", &RegistryAuth::Anonymous)
//!     .expect("failed to generate SBOM");
//! println!("Found {} packages", sbom.packages.len());
//!
//! // As formatted bytes (CycloneDX or SPDX)
//! let bytes = pipeline::generate_sbom_bytes(
//!     "docker.io/library/alpine:3.19",
//!     "cyclonedx",
//!     &RegistryAuth::Anonymous,
//! ).expect("failed to generate SBOM");
//! ```
//!
//! Scan for vulnerabilities (requires a local vulnerability database):
//!
//! ```no_run
//! use inspektr::pipeline;
//! use inspektr::oci::RegistryAuth;
//!
//! let db_path = pipeline::default_db_path();
//! let report = pipeline::scan_and_report(
//!     Some("/path/to/project"),
//!     None,
//!     &db_path,
//!     &RegistryAuth::Anonymous,
//! ).expect("scan failed");
//!
//! println!("Found {} vulnerabilities", report.metadata.total_vulnerabilities);
//! ```
//!
//! ## Module overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`pipeline`] | High-level entry points for SBOM generation and vulnerability scanning |
//! | [`models`] | Core data types: [`Package`](models::Package), [`Sbom`](models::Sbom), [`Vulnerability`](models::Vulnerability), [`Ecosystem`](models::Ecosystem) |
//! | [`source`] | File discovery from filesystems and OCI container images |
//! | [`cataloger`] | Package discovery from lockfiles, manifests, and binaries |
//! | [`sbom`] | SBOM encoding/decoding (CycloneDX, SPDX) |
//! | [`vuln`] | Vulnerability matching and report generation |
//! | [`db`] | Vulnerability database storage and querying |
//! | [`oci`] | OCI registry interaction (pull/push artifacts and images) |
//! | [`cpe`] | CPE (Common Platform Enumeration) generation for NVD matching |
//! | [`error`] | Error types used throughout the library |
//!
//! ## Pipeline architecture
//!
//! The library follows a layered pipeline:
//!
//! ```text
//! Source -> Cataloger -> SbomFormat -> Matcher -> Reporter
//! ```
//!
//! 1. A [`source::Source`] discovers files from a target (filesystem, OCI image, or binary)
//! 2. [`cataloger::Cataloger`] implementations parse lockfiles and manifests to find packages
//! 3. [`sbom::SbomFormat`] encodes the results as CycloneDX or SPDX
//! 4. [`vuln::matcher`] matches packages against the vulnerability database
//! 5. [`vuln::report`] builds structured scan reports with severity counts
//!
//! ## Vulnerability database
//!
//! Vulnerability scanning requires a local SQLite database. Use
//! [`pipeline::default_db_path()`] to get the default location
//! (`$XDG_DATA_HOME/inspektr/vuln.db` or `~/.local/share/inspektr/vuln.db`).
//!
//! The database can be pulled from an OCI registry using [`oci::pull::pull_artifact()`],
//! or built from source data using the `db-admin` feature flag.
//!
//! ## Feature flags
//!
//! | Flag | Effect |
//! |------|--------|
//! | `db-admin` | Enables vulnerability database import modules (OSV, NVD, OVAL, Photon, etc.) |

pub mod cataloger;
pub mod cpe;
pub mod db;
pub mod error;
pub mod models;
pub mod oci;
pub mod pipeline;
pub mod sbom;
pub mod source;
pub mod vuln;

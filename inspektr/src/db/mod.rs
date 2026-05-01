//! Vulnerability database storage, querying, and (with `db-admin`) importing.
//!
//! The database is a binary file compressed with LZ4, containing vulnerability
//! records indexed by (ecosystem, package name). Use [`store::VulnStore`] to
//! open, query, and manage the database.
//!
//! # Downloading the database
//!
//! The pre-built vulnerability database is distributed as an OCI artifact.
//! Two convenience functions handle downloading:
//!
//! - [`download_to_file()`] — pull and save to disk, then open with
//!   [`VulnStore::open()`](store::VulnStore::open)
//! - [`download_to_memory()`] — pull and load directly into a
//!   [`VulnStore`](store::VulnStore) without touching the filesystem
//!
//! ```no_run
//! use inspektr::db;
//! use inspektr::oci::RegistryAuth;
//!
//! // Option 1: download to the default path on disk
//! db::download_to_file(db::DEFAULT_DB_REGISTRY, &RegistryAuth::Anonymous).unwrap();
//! let store = db::store::VulnStore::open(
//!     inspektr::pipeline::default_db_path().to_str().unwrap(),
//! ).unwrap();
//!
//! // Option 2: download straight into memory
//! let store = db::download_to_memory(
//!     db::DEFAULT_DB_REGISTRY,
//!     &RegistryAuth::Anonymous,
//! ).unwrap();
//! ```
//!
//! # Importing data (requires `db-admin` feature)
//!
//! With the `db-admin` feature enabled, additional modules provide importers
//! for various vulnerability data sources:
//!
//! - `osv` — OSV bulk downloads for language and OS ecosystems
//! - `nvd` — NVD API (with incremental updates)
//! - `oracle` — Oracle OVAL feeds
//! - `azure_linux` — Azure Linux / CBL-Mariner OVAL feeds
//! - `bottlerocket` — Bottlerocket updateinfo
//!
//! Each importer implements the `VulnSource` trait.

pub mod store;

use crate::error::InspektrError;
use crate::oci::RegistryAuth;

/// The default OCI registry reference for the pre-built vulnerability database.
pub const DEFAULT_DB_REGISTRY: &str = "rc1405/inspektr-db:latest";

/// Download the vulnerability database to the default file path.
///
/// Pulls the database from the given OCI registry reference, creates the
/// parent directory if needed, and writes the file to
/// [`pipeline::default_db_path()`](crate::pipeline::default_db_path).
///
/// After calling this, open the database with
/// [`VulnStore::open()`](store::VulnStore::open).
///
/// ```no_run
/// use inspektr::db;
/// use inspektr::oci::RegistryAuth;
///
/// db::download_to_file(db::DEFAULT_DB_REGISTRY, &RegistryAuth::Anonymous).unwrap();
/// ```
pub fn download_to_file(
    registry: &str,
    auth: &RegistryAuth,
) -> Result<std::path::PathBuf, InspektrError> {
    let db_path = crate::pipeline::default_db_path();

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(crate::error::SourceError::Io)?;
    }

    crate::oci::pull::pull_artifact(registry, &db_path, auth)?;

    Ok(db_path)
}

/// Download the vulnerability database directly into memory.
///
/// Pulls the database from the given OCI registry reference and returns a
/// ready-to-query [`VulnStore`](store::VulnStore) without writing anything
/// to disk.
///
/// This is useful for serverless or ephemeral environments where filesystem
/// access is undesirable, or when you want to avoid managing the database
/// file lifecycle.
///
/// ```no_run
/// use inspektr::db;
/// use inspektr::oci::RegistryAuth;
///
/// let store = db::download_to_memory(
///     db::DEFAULT_DB_REGISTRY,
///     &RegistryAuth::Anonymous,
/// ).unwrap();
///
/// let results = store.query("Go", "github.com/example/pkg").unwrap();
/// ```
pub fn download_to_memory(
    registry: &str,
    auth: &RegistryAuth,
) -> Result<store::VulnStore, InspektrError> {
    let bytes = crate::oci::pull::pull_artifact_bytes(registry, auth)?;
    let store = store::VulnStore::from_bytes(&bytes)?;
    Ok(store)
}

#[cfg(feature = "db-admin")]
pub mod osv;

#[cfg(feature = "db-admin")]
pub mod nvd;

#[cfg(feature = "db-admin")]
#[cfg(feature = "db-admin")]
pub mod oval;

#[cfg(feature = "db-admin")]
pub mod oracle;

#[cfg(feature = "db-admin")]
pub mod azure_linux;

#[cfg(feature = "db-admin")]
pub mod bottlerocket;

#[cfg(feature = "db-admin")]
use crate::error::DatabaseError;
#[cfg(feature = "db-admin")]
use store::VulnStore;

/// A source of vulnerability data that can import into the store.
///
/// Implement this trait to add support for a new vulnerability data source.
/// Each source downloads and parses data from an external feed and inserts
/// it into the [`VulnStore`].
#[cfg(feature = "db-admin")]
pub trait VulnSource {
    /// The name of this data source (e.g., `"osv"`, `"nvd"`).
    fn name(&self) -> &str;

    /// Import vulnerability data into the store.
    ///
    /// If `ecosystem` is `Some`, only import data for that specific ecosystem.
    /// Returns the number of vulnerabilities imported.
    fn import(
        &self,
        store: &mut VulnStore,
        ecosystem: Option<&str>,
    ) -> Result<usize, DatabaseError>;
}

/// Ecosystems with OSV bulk download availability.
///
/// These names match the ecosystem identifiers used by the
/// [OSV.dev API](https://osv.dev/list).
#[cfg(feature = "db-admin")]
pub const ALL_ECOSYSTEMS: &[&str] = &[
    // Language ecosystems
    "Go",
    "npm",
    "PyPI",
    "Maven",
    "NuGet",
    "Packagist",
    "crates.io",
    "RubyGems",
    "SwiftURL",
    // OS ecosystems (OSV)
    "Alpine",
    "Wolfi",
    "Chainguard",
    "Debian",
    "Ubuntu",
    "Red Hat",
    "Rocky Linux",
    "AlmaLinux",
    "SUSE",
    "Echo",
    "MinimOS",
];

/// Additional ecosystem names accepted for --ecosystem filtering.
/// These are handled by distro-native importers, not OSV.
#[cfg(feature = "db-admin")]
const DISTRO_ECOSYSTEMS: &[&str] = &["Oracle", "Azure Linux", "Bottlerocket"];

/// Normalize an ecosystem string to its canonical form (case-insensitive match).
///
/// Accepts both OSV ecosystem names (e.g., `"npm"`, `"PyPI"`) and distro-native
/// ecosystem names (e.g., `"Oracle"`, `"Photon OS"`). Returns `None` for
/// unrecognized inputs.
#[cfg(feature = "db-admin")]
pub fn normalize_ecosystem(input: &str) -> Option<&'static str> {
    ALL_ECOSYSTEMS
        .iter()
        .chain(DISTRO_ECOSYSTEMS.iter())
        .find(|&&canonical| canonical.eq_ignore_ascii_case(input))
        .copied()
}

/// Return all registered vulnerability data source importers.
///
/// Includes OSV, NVD, Oracle OVAL, Azure Linux OVAL, and Bottlerocket.
#[cfg(feature = "db-admin")]
pub fn vuln_sources() -> Vec<Box<dyn VulnSource>> {
    vec![
        Box::new(osv::OsvSource),
        Box::new(nvd::NvdSource::new()),
        Box::new(oracle::OracleSource),
        Box::new(azure_linux::AzureLinuxSource),
        Box::new(bottlerocket::BottlerocketSource),
    ]
}

/// Like [`vuln_sources`] but uses the GitHub NVD mirror instead of the NVD API.
#[cfg(feature = "db-admin")]
pub fn vuln_sources_github_nvd() -> Vec<Box<dyn VulnSource>> {
    vec![
        Box::new(osv::OsvSource),
        Box::new(nvd::NvdGithubSource),
        Box::new(oracle::OracleSource),
        Box::new(azure_linux::AzureLinuxSource),
        Box::new(bottlerocket::BottlerocketSource),
    ]
}

#[cfg(all(test, feature = "db-admin"))]
mod tests {
    #[test]
    fn test_normalize_ecosystem() {
        use super::normalize_ecosystem;
        assert_eq!(normalize_ecosystem("npm"), Some("npm"));
        assert_eq!(normalize_ecosystem("NPM"), Some("npm"));
        assert_eq!(normalize_ecosystem("pypi"), Some("PyPI"));
        assert_eq!(normalize_ecosystem("PyPI"), Some("PyPI"));
        assert_eq!(normalize_ecosystem("go"), Some("Go"));
        assert_eq!(normalize_ecosystem("maven"), Some("Maven"));
        assert_eq!(normalize_ecosystem("unknown"), None);
        // Distro-native ecosystems
        assert_eq!(normalize_ecosystem("oracle"), Some("Oracle"));
        assert_eq!(normalize_ecosystem("azure linux"), Some("Azure Linux"));
        assert_eq!(normalize_ecosystem("bottlerocket"), Some("Bottlerocket"));
    }
}

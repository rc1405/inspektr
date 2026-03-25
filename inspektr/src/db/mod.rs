pub mod store;

#[cfg(feature = "db-admin")]
pub mod osv;

#[cfg(feature = "db-admin")]
pub mod nvd;

#[cfg(feature = "db-admin")]
pub mod photon;

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
#[cfg(feature = "db-admin")]
pub trait VulnSource {
    fn name(&self) -> &str;
    fn import(
        &self,
        store: &mut VulnStore,
        ecosystem: Option<&str>,
    ) -> Result<usize, DatabaseError>;
}

/// Ecosystems with OSV bulk download availability.
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
const DISTRO_ECOSYSTEMS: &[&str] = &[
    "CentOS",
    "Oracle",
    "Photon OS",
    "Azure Linux",
    "Bottlerocket",
];

/// Normalize an ecosystem string to canonical form (case-insensitive match).
/// Accepts both OSV ecosystem names and distro-native ecosystem names.
#[cfg(feature = "db-admin")]
pub fn normalize_ecosystem(input: &str) -> Option<&'static str> {
    ALL_ECOSYSTEMS
        .iter()
        .chain(DISTRO_ECOSYSTEMS.iter())
        .find(|&&canonical| canonical.eq_ignore_ascii_case(input))
        .copied()
}

/// Return all registered vulnerability sources.
#[cfg(feature = "db-admin")]
pub fn vuln_sources() -> Vec<Box<dyn VulnSource>> {
    vec![
        Box::new(osv::OsvSource),
        Box::new(nvd::NvdSource::new()),
        Box::new(photon::PhotonSource),
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
        assert_eq!(normalize_ecosystem("centos"), Some("CentOS"));
        assert_eq!(normalize_ecosystem("oracle"), Some("Oracle"));
        assert_eq!(normalize_ecosystem("photon os"), Some("Photon OS"));
        assert_eq!(normalize_ecosystem("azure linux"), Some("Azure Linux"));
        assert_eq!(normalize_ecosystem("bottlerocket"), Some("Bottlerocket"));
    }
}

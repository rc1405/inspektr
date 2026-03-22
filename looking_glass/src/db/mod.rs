pub mod store;

#[cfg(feature = "db-admin")]
pub mod osv;

#[cfg(feature = "db-admin")]
pub mod nvd;

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

/// All known ecosystem strings (canonical form).
#[cfg(feature = "db-admin")]
pub const ALL_ECOSYSTEMS: &[&str] = &["Go", "npm", "PyPI", "Maven"];

/// Normalize an ecosystem string to canonical form (case-insensitive match).
#[cfg(feature = "db-admin")]
pub fn normalize_ecosystem(input: &str) -> Option<&'static str> {
    ALL_ECOSYSTEMS
        .iter()
        .find(|&&canonical| canonical.eq_ignore_ascii_case(input))
        .copied()
}

/// Return all registered vulnerability sources.
#[cfg(feature = "db-admin")]
pub fn vuln_sources() -> Vec<Box<dyn VulnSource>> {
    vec![
        Box::new(osv::OsvSource),
        Box::new(nvd::NvdSource::new()),
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
    }
}

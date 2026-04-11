//! Azure Linux / CBL-Mariner OVAL data importer.
//!
//! Downloads and parses OVAL feeds for CBL-Mariner 1.0/2.0 and Azure Linux 3.0.
//!
//! Requires the `db-admin` feature.

use crate::db::VulnSource;
use crate::db::oval::parse_oval_xml;
use crate::db::store::VulnStore;
use crate::error::DatabaseError;

/// Azure Linux / CBL-Mariner OVAL vulnerability data source.
pub struct AzureLinuxSource;

impl VulnSource for AzureLinuxSource {
    fn name(&self) -> &str {
        "azurelinux"
    }

    fn import(
        &self,
        store: &mut VulnStore,
        ecosystem: Option<&str>,
    ) -> Result<usize, DatabaseError> {
        if let Some(eco) = ecosystem {
            if !eco.starts_with("Azure Linux") {
                return Ok(0);
            }
        }

        const VERSIONS: &[(&str, &str)] = &[
            (
                "1.0",
                "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/cbl-mariner-1.0-oval.xml",
            ),
            (
                "2.0",
                "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/cbl-mariner-2.0-oval.xml",
            ),
            (
                "3.0",
                "https://raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/azurelinux-3.0-oval.xml",
            ),
        ];

        let mut total = 0;

        for (version, url) in VERSIONS {
            eprintln!("azurelinux: downloading {}...", url);

            let response = reqwest::blocking::get(*url)
                .map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

            let xml = response
                .text()
                .map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

            let records = parse_oval_xml(&xml, "Azure Linux", version)?;
            let count = records.len();
            store.insert_vulnerabilities(&records)?;
            eprintln!(
                "azurelinux: Azure Linux:{} — {} vulnerabilities",
                version, count
            );
            total += count;
        }

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_linux_source_name() {
        let source = AzureLinuxSource;
        assert_eq!(source.name(), "azurelinux");
    }
}

use crate::db::oval::parse_oval_xml;
use crate::db::store::VulnStore;
use crate::db::VulnSource;
use crate::error::DatabaseError;
use bzip2::read::BzDecoder;
use std::io::Read;

pub struct OracleSource;

impl VulnSource for OracleSource {
    fn name(&self) -> &str {
        "oracle"
    }

    fn import(
        &self,
        store: &mut VulnStore,
        ecosystem: Option<&str>,
    ) -> Result<usize, DatabaseError> {
        if let Some(eco) = ecosystem {
            if !eco.starts_with("Oracle") {
                return Ok(0);
            }
        }

        eprintln!("oracle: clearing previous data...");
        store.clear_source("oracle")?;

        const VERSIONS: &[(&str, &str)] = &[
            ("7", "https://linux.oracle.com/security/oval/com.oracle.elsa-ol7.xml.bz2"),
            ("8", "https://linux.oracle.com/security/oval/com.oracle.elsa-ol8.xml.bz2"),
            ("9", "https://linux.oracle.com/security/oval/com.oracle.elsa-ol9.xml.bz2"),
        ];

        let mut total = 0;

        for (version, url) in VERSIONS {
            eprintln!("oracle: downloading {}...", url);

            let response = reqwest::blocking::get(*url)
                .map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

            let compressed = response
                .bytes()
                .map_err(|e| DatabaseError::ImportFailed(e.to_string()))?;

            let mut decoder = BzDecoder::new(&compressed[..]);
            let mut xml = String::new();
            decoder
                .read_to_string(&mut xml)
                .map_err(|e| DatabaseError::ImportFailed(format!("bzip2 decompress error: {}", e)))?;

            let records = parse_oval_xml(&xml, "Oracle", version)?;
            let count = records.len();
            store.insert_vulnerabilities(&records)?;
            eprintln!("oracle: Oracle:{} — {} vulnerabilities", version, count);
            total += count;
        }

        store.set_last_updated("oracle", &crate::sbom::spdx::chrono_now())?;

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_source_name() {
        let source = OracleSource;
        assert_eq!(source.name(), "oracle");
    }
}

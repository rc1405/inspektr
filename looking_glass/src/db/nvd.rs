use std::collections::VecDeque;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use serde::Deserialize;

use crate::cpe;
use crate::db::store::{AffectedPackage, AffectedRange, VulnRecord, VulnStore};
use crate::error::DatabaseError;
use crate::models::Severity;
use super::VulnSource;

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

struct RateLimiter {
    max_requests: u32,
    window: Duration,
    timestamps: VecDeque<Instant>,
}

impl RateLimiter {
    fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
            timestamps: VecDeque::new(),
        }
    }

    fn wait_if_needed(&mut self) {
        let now = Instant::now();
        // Evict timestamps that have aged out of the window.
        while self.timestamps.front().is_some_and(|&t| now.duration_since(t) >= self.window) {
            self.timestamps.pop_front();
        }
        // If we are at capacity, sleep until the oldest slot expires.
        if self.timestamps.len() >= self.max_requests as usize {
            if let Some(&oldest) = self.timestamps.front() {
                let wait = self.window - now.duration_since(oldest);
                if !wait.is_zero() {
                    std::thread::sleep(wait);
                }
                self.timestamps.pop_front();
            }
        }
        self.timestamps.push_back(Instant::now());
    }
}

// ---------------------------------------------------------------------------
// NVD JSON serde types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdResponse {
    pub results_per_page: u32,
    pub start_index: u32,
    pub total_results: u32,
    #[serde(default)]
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCve {
    pub id: String,
    #[serde(default)]
    pub descriptions: Vec<NvdDescription>,
    #[serde(default)]
    pub published: String,
    #[serde(default)]
    pub last_modified: String,
    #[serde(default)]
    pub metrics: NvdMetrics,
    #[serde(default)]
    pub configurations: Vec<NvdConfiguration>,
}

#[derive(Debug, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdMetrics {
    #[serde(default)]
    pub cvss_metric_v31: Vec<NvdCvssV3>,
    #[serde(default)]
    pub cvss_metric_v30: Vec<NvdCvssV3>,
    #[serde(default)]
    pub cvss_metric_v2: Vec<NvdCvssV2>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssV3 {
    pub cvss_data: NvdCvssV3Data,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssV3Data {
    pub base_severity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssV2 {
    #[serde(default)]
    pub base_severity: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdConfiguration {
    #[serde(default)]
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdNode {
    #[serde(default)]
    pub cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

// ---------------------------------------------------------------------------
// Severity extraction helpers
// ---------------------------------------------------------------------------

fn parse_nvd_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::None,
    }
}

fn extract_severity(cve: &NvdCve) -> Severity {
    // Prefer V3.1, fall back to V3.0, then V2.
    if let Some(m) = cve.metrics.cvss_metric_v31.first() {
        return parse_nvd_severity(&m.cvss_data.base_severity);
    }
    if let Some(m) = cve.metrics.cvss_metric_v30.first() {
        return parse_nvd_severity(&m.cvss_data.base_severity);
    }
    if let Some(m) = cve.metrics.cvss_metric_v2.first() {
        return parse_nvd_severity(&m.base_severity);
    }
    Severity::None
}

// ---------------------------------------------------------------------------
// CVE → VulnRecord conversion
// ---------------------------------------------------------------------------

fn cve_to_vuln_records(cve: &NvdCve, ecosystem_filter: Option<&str>) -> Vec<VulnRecord> {
    let summary = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_default();

    let severity = extract_severity(cve);

    // Aggregate all affected ranges per (ecosystem, package_name) pair.
    let mut affected_map: HashMap<(String, String), Vec<AffectedRange>> = HashMap::new();

    for config in &cve.configurations {
        for node in &config.nodes {
            for cpe_match in &node.cpe_match {
                if !cpe_match.vulnerable {
                    continue;
                }

                let resolved = match cpe::resolve_cpe(&cpe_match.criteria) {
                    Some(r) => r,
                    None => continue,
                };

                if let Some(filter) = ecosystem_filter {
                    if resolved.ecosystem != filter {
                        continue;
                    }
                }

                let range = AffectedRange {
                    range_type: "ECOSYSTEM".to_string(),
                    introduced: cpe_match
                        .version_start_including
                        .clone()
                        .or_else(|| cpe_match.version_start_excluding.clone()),
                    fixed: cpe_match
                        .version_end_excluding
                        .clone()
                        .or_else(|| cpe_match.version_end_including.clone()),
                };

                affected_map
                    .entry((resolved.ecosystem, resolved.package_name))
                    .or_default()
                    .push(range);
            }
        }
    }

    if affected_map.is_empty() {
        return Vec::new();
    }

    let affected: Vec<AffectedPackage> = affected_map
        .into_iter()
        .map(|((ecosystem, package_name), ranges)| AffectedPackage {
            ecosystem,
            package_name,
            ranges,
        })
        .collect();

    vec![VulnRecord {
        id: cve.id.clone(),
        summary,
        details: String::new(),
        severity,
        published: cve.published.clone(),
        modified: cve.last_modified.clone(),
        withdrawn: None,
        affected,
    }]
}

// ---------------------------------------------------------------------------
// NVD HTTP client
// ---------------------------------------------------------------------------

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

pub struct NvdClient {
    http: reqwest::blocking::Client,
    api_key: Option<String>,
    rate_limiter: RateLimiter,
}

impl NvdClient {
    pub fn new() -> Self {
        let api_key = std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty());
        let max_requests = if api_key.is_some() {
            50
        } else {
            eprintln!("nvd: NVD_API_KEY not set, using slower rate limit (5 req/30s)");
            5
        };
        Self {
            http: reqwest::blocking::Client::new(),
            api_key,
            rate_limiter: RateLimiter::new(max_requests, 30),
        }
    }

    fn fetch_page(&mut self, start_index: u32) -> Result<NvdResponse, DatabaseError> {
        self.rate_limiter.wait_if_needed();

        let mut request = self
            .http
            .get(NVD_API_BASE)
            .query(&[
                ("startIndex", start_index.to_string()),
                ("resultsPerPage", self.results_per_page().to_string()),
            ]);

        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().map_err(|e| {
            DatabaseError::ImportFailed(format!("NVD API request failed: {}", e))
        })?;

        if response.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(DatabaseError::ImportFailed(
                "NVD API key rejected. Check NVD_API_KEY or unset it to use anonymous access."
                    .to_string(),
            ));
        }

        if !response.status().is_success() {
            return Err(DatabaseError::ImportFailed(format!(
                "NVD API returned HTTP {}",
                response.status()
            )));
        }

        response.json::<NvdResponse>().map_err(|e| {
            DatabaseError::ImportFailed(format!("Failed to parse NVD response: {}", e))
        })
    }

    fn results_per_page(&self) -> u32 {
        if self.api_key.is_some() { 2000 } else { 500 }
    }
}

// ---------------------------------------------------------------------------
// VulnSource implementation
// ---------------------------------------------------------------------------

pub struct NvdSource {
    _private: (),
}

impl NvdSource {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl VulnSource for NvdSource {
    fn name(&self) -> &str {
        "nvd"
    }

    fn import(&self, store: &mut VulnStore, ecosystem: Option<&str>) -> Result<usize, DatabaseError> {
        let mut client = NvdClient::new();
        let mut total_imported = 0;
        let mut total_cves = 0;
        let mut start_index = 0u32;

        loop {
            let response = client.fetch_page(start_index)?;
            let total_results = response.total_results;
            let page_size = response.results_per_page;
            let page_num = start_index / page_size + 1;
            let total_pages = (total_results + page_size - 1) / page_size;

            eprintln!("nvd: importing CVEs (page {}/{})...", page_num, total_pages);

            total_cves += response.vulnerabilities.len();

            let mut records = Vec::new();
            for vuln in &response.vulnerabilities {
                records.extend(cve_to_vuln_records(&vuln.cve, ecosystem));
            }

            let count = records.len();
            if !records.is_empty() {
                store.insert_vulnerabilities(&records)?;
            }
            total_imported += count;

            start_index += page_size;
            if start_index >= total_results {
                break;
            }
        }

        let match_rate = if total_cves > 0 {
            (total_imported as f64 / total_cves as f64 * 100.0) as u32
        } else {
            0
        };
        eprintln!(
            "nvd: imported {} vulns from {} CVEs ({}% resolved to known ecosystems)",
            total_imported, total_cves, match_rate
        );

        Ok(total_imported)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "db-admin"))]
mod tests {
    use super::*;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // Rate limiter tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let mut rl = RateLimiter::new(5, 30);
        // Should not block — we are well under the limit.
        for _ in 0..4 {
            rl.wait_if_needed();
        }
        assert!(rl.timestamps.len() <= 5);
    }

    #[test]
    fn test_rate_limiter_tracks_timestamps() {
        let mut rl = RateLimiter::new(10, 30);
        rl.wait_if_needed();
        rl.wait_if_needed();
        rl.wait_if_needed();
        // Three calls → three recorded timestamps.
        assert_eq!(rl.timestamps.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Severity parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nvd_severity_v31() {
        let cve = NvdCve {
            id: "CVE-2023-0001".to_string(),
            descriptions: vec![],
            published: String::new(),
            last_modified: String::new(),
            metrics: NvdMetrics {
                cvss_metric_v31: vec![NvdCvssV3 {
                    cvss_data: NvdCvssV3Data { base_severity: "CRITICAL".to_string() },
                }],
                cvss_metric_v30: vec![],
                cvss_metric_v2: vec![],
            },
            configurations: vec![],
        };
        assert_eq!(extract_severity(&cve), Severity::Critical);
    }

    #[test]
    fn test_parse_nvd_severity_fallback_v2() {
        // No V3.1 or V3.0 — should use V2.
        let cve = NvdCve {
            id: "CVE-2023-0002".to_string(),
            descriptions: vec![],
            published: String::new(),
            last_modified: String::new(),
            metrics: NvdMetrics {
                cvss_metric_v31: vec![],
                cvss_metric_v30: vec![],
                cvss_metric_v2: vec![NvdCvssV2 { base_severity: "HIGH".to_string() }],
            },
            configurations: vec![],
        };
        assert_eq!(extract_severity(&cve), Severity::High);
    }

    #[test]
    fn test_parse_nvd_severity_none() {
        let cve = NvdCve {
            id: "CVE-2023-0003".to_string(),
            descriptions: vec![],
            published: String::new(),
            last_modified: String::new(),
            metrics: NvdMetrics::default(),
            configurations: vec![],
        };
        assert_eq!(extract_severity(&cve), Severity::None);
    }

    // -----------------------------------------------------------------------
    // CVE → VulnRecord conversion tests
    // -----------------------------------------------------------------------

    fn make_minimist_cve() -> NvdCve {
        NvdCve {
            id: "CVE-2021-44906".to_string(),
            descriptions: vec![NvdDescription {
                lang: "en".to_string(),
                value: "Prototype pollution in minimist".to_string(),
            }],
            published: "2022-03-17T00:00:00Z".to_string(),
            last_modified: "2022-04-01T00:00:00Z".to_string(),
            metrics: NvdMetrics {
                cvss_metric_v31: vec![NvdCvssV3 {
                    cvss_data: NvdCvssV3Data { base_severity: "CRITICAL".to_string() },
                }],
                ..Default::default()
            },
            configurations: vec![NvdConfiguration {
                nodes: vec![NvdNode {
                    cpe_match: vec![NvdCpeMatch {
                        vulnerable: true,
                        // minimist with node.js target_sw → resolves to npm/minimist
                        criteria: "cpe:2.3:a:minimist_project:minimist:*:*:*:*:*:node.js:*:*"
                            .to_string(),
                        version_start_including: Some("0.0.1".to_string()),
                        version_start_excluding: None,
                        version_end_including: None,
                        version_end_excluding: Some("1.2.6".to_string()),
                    }],
                }],
            }],
        }
    }

    #[test]
    fn test_cve_to_vuln_records() {
        let cve = make_minimist_cve();
        let records = cve_to_vuln_records(&cve, None);

        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.id, "CVE-2021-44906");
        assert_eq!(rec.severity, Severity::Critical);
        assert_eq!(rec.summary, "Prototype pollution in minimist");

        assert_eq!(rec.affected.len(), 1);
        let pkg = &rec.affected[0];
        assert_eq!(pkg.ecosystem, "npm");
        assert_eq!(pkg.package_name, "minimist");

        assert_eq!(pkg.ranges.len(), 1);
        assert_eq!(pkg.ranges[0].introduced, Some("0.0.1".to_string()));
        assert_eq!(pkg.ranges[0].fixed, Some("1.2.6".to_string()));
    }

    #[test]
    fn test_cve_to_vuln_records_ecosystem_filter() {
        let cve = make_minimist_cve();

        // Filter to npm — should match.
        let npm_records = cve_to_vuln_records(&cve, Some("npm"));
        assert_eq!(npm_records.len(), 1);

        // Filter to PyPI — should not match.
        let pypi_records = cve_to_vuln_records(&cve, Some("PyPI"));
        assert!(pypi_records.is_empty());
    }

    #[test]
    fn test_cve_unresolvable_cpe_skipped() {
        let cve = NvdCve {
            id: "CVE-2023-9999".to_string(),
            descriptions: vec![NvdDescription {
                lang: "en".to_string(),
                value: "Some vulnerability".to_string(),
            }],
            published: String::new(),
            last_modified: String::new(),
            metrics: NvdMetrics::default(),
            configurations: vec![NvdConfiguration {
                nodes: vec![NvdNode {
                    cpe_match: vec![NvdCpeMatch {
                        vulnerable: true,
                        // Completely unknown vendor/target_sw → cannot resolve.
                        criteria: "cpe:2.3:a:unknownvendorxyz:unknowntool:1.0:*:*:*:*:*:*:*"
                            .to_string(),
                        version_start_including: None,
                        version_start_excluding: None,
                        version_end_including: None,
                        version_end_excluding: None,
                    }],
                }],
            }],
        };

        let records = cve_to_vuln_records(&cve, None);
        // Nothing resolvable → no records.
        assert!(records.is_empty());
    }

    // -----------------------------------------------------------------------
    // NvdSource trait test
    // -----------------------------------------------------------------------

    #[test]
    fn test_nvd_source_name() {
        let source = NvdSource::new();
        assert_eq!(source.name(), "nvd");
    }
}

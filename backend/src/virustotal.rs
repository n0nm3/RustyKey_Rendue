// backend/src/virustotal.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const VIRUSTOTAL_API_URL: &str = "https://www.virustotal.com/api/v3";

#[derive(Debug, Clone)]
pub struct VirusTotalClient {
    client: reqwest::Client,
    api_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileReport {
    pub hash: String,
    pub scan_date: Option<String>,
    pub positives: u32,
    pub total: u32,
    pub is_safe: bool,
    pub permalink: Option<String>,
    pub engines: HashMap<String, EngineResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EngineResult {
    pub detected: bool,
    pub result: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VTFileResponse {
    data: Option<VTData>,
    error: Option<VTError>,
}

#[derive(Debug, Deserialize)]
struct VTData {
    attributes: VTAttributes,
    id: String,
}

#[derive(Debug, Deserialize)]
struct VTAttributes {
    last_analysis_stats: VTStats,
    last_analysis_results: HashMap<String, VTScanResult>,
    last_analysis_date: Option<i64>,
    permalink: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VTStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    harmless: u32,
    timeout: u32,
    #[serde(rename = "type-unsupported")]
    type_unsupported: u32,
}

#[derive(Debug, Deserialize)]
struct VTScanResult {
    category: String,
    result: Option<String>,
    engine_name: String,
}

#[derive(Debug, Deserialize)]
struct VTError {
    code: String,
    message: String,
}

impl VirusTotalClient {
    pub fn new(api_key: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self { client, api_key })
    }

    pub async fn check_file_hash(&self, hash: &str) -> Result<FileReport> {
        let url = format!("{}/files/{}", VIRUSTOTAL_API_URL, hash);

        let response = self
            .client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .context("Failed to send request to VirusTotal")?;

        let status = response.status();
        let body = response.text().await?;

        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(FileReport {
                hash: hash.to_string(),
                scan_date: None,
                positives: 0,
                total: 0,
                is_safe: true,
                permalink: None,
                engines: HashMap::new(),
            });
        }

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "VirusTotal API error: {} - {}",
                status,
                body
            ));
        }

        let vt_response: VTFileResponse =
            serde_json::from_str(&body).context("Failed to parse VirusTotal response")?;

        if let Some(error) = vt_response.error {
            return Err(anyhow::anyhow!(
                "VirusTotal error: {} - {}",
                error.code,
                error.message
            ));
        }

        let data = vt_response
            .data
            .ok_or_else(|| anyhow::anyhow!("No data in VirusTotal response"))?;

        let attributes = data.attributes;
        let stats = attributes.last_analysis_stats;

        let positives = stats.malicious + stats.suspicious;
        let total = stats.malicious
            + stats.suspicious
            + stats.undetected
            + stats.harmless
            + stats.timeout
            + stats.type_unsupported;

        let engines: HashMap<String, EngineResult> = attributes
            .last_analysis_results
            .into_iter()
            .map(|(name, result)| {
                (
                    name,
                    EngineResult {
                        detected: result.category == "malicious" || result.category == "suspicious",
                        result: result.result,
                    },
                )
            })
            .collect();

        let scan_date = attributes.last_analysis_date.map(|ts| {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "Unknown".to_string())
        });

        Ok(FileReport {
            hash: hash.to_string(),
            scan_date,
            positives,
            total,
            is_safe: positives == 0,
            permalink: attributes.permalink,
            engines,
        })
    }
}

pub fn get_api_key() -> Option<String> {
    let config_path = std::path::Path::new("/etc/rustykey/config/backend.conf");

    if let Ok(config) = common::config::read_config_file(config_path) {
        config
            .get("VIRUSTOTAL_API_KEY")
            .or_else(|| config.get("RUSTYKEY_VIRUSTOTAL_API_KEY"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        std::env::var("VIRUSTOTAL_API_KEY").ok()
    }
}

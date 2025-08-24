// common/src/config.rs
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const CONFIG_DIR: &str = "/etc/rustykey/config";
pub const CERT_DIR: &str = "/etc/rustykey/certs";
pub const LOG_DIR: &str = "/etc/rustykey/logs";

pub fn read_config_file(path: &Path) -> Result<HashMap<String, String>> {
    let mut config = HashMap::new();

    if !path.exists() {
        return Ok(config);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {path:?}"))?;

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            config.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Ok(config)
}

pub fn get_config_value(
    config: &HashMap<String, String>,
    key: &str,
    default: Option<&str>,
) -> Option<String> {
    std::env::var(key)
        .ok()
        .or_else(|| config.get(key).cloned())
        .or_else(|| default.map(|s| s.to_string()))
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub agent_id: String,
    pub backend_addr: String,
    pub mount_path: String,
    pub log_level: String,
    pub verify_tls: bool,
    pub cert_dir: String,
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let config_path = Path::new("/etc/rustykey/config/agent.conf");
        let config = read_config_file(config_path)?;
        let agent_id = get_config_value(&config, "RUSTYKEY_AGENT_ID", None)
            .or_else(|| std::env::var("AGENT_ID").ok())
            .unwrap_or_else(|| {
                let id = generate_agent_id();
                eprintln!("Warning: No RUSTYKEY_AGENT_ID found in config.");
                eprintln!("Generated new ID: {id}");
                eprintln!("Add this line to /etc/rustykey/config/agent.conf:");
                eprintln!("RUSTYKEY_AGENT_ID={id}");
                id
            });

        Ok(Self {
            agent_id,
            backend_addr: get_config_value(&config, "RUSTYKEY_BACKEND", Some("127.0.0.1:8443"))
                .unwrap(),
            mount_path: get_config_value(&config, "RUSTYKEY_MOUNT_PATH", Some("/tmp/rustykey"))
                .unwrap(),
            log_level: get_config_value(&config, "RUSTYKEY_LOG_LEVEL", Some("info")).unwrap(),
            verify_tls: get_config_value(&config, "RUSTYKEY_VERIFY_TLS", Some("true"))
                .unwrap()
                .parse()
                .unwrap_or(true),
            cert_dir: get_config_value(&config, "RUSTYKEY_CERT_DIR", Some("/etc/rustykey/certs"))
                .unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub bind_addr: String,
    pub audit_log_path: String,
    pub enable_metrics: bool,
    pub cert_dir: String,
    pub virustotal_api_key: Option<String>,
}

impl BackendConfig {
    pub fn load() -> Result<Self> {
        let config_path = Path::new("/etc/rustykey/config/backend.conf");
        let config = read_config_file(config_path)?;

        Ok(Self {
            bind_addr: get_config_value(&config, "RUSTYKEY_BIND_ADDR", Some("0.0.0.0:8443"))
                .unwrap(),
            audit_log_path: get_config_value(
                &config,
                "RUSTYKEY_AUDIT_LOG",
                Some("/etc/rustykey/logs/audit.log"),
            )
            .unwrap(),
            enable_metrics: get_config_value(&config, "RUSTYKEY_ENABLE_METRICS", Some("false"))
                .unwrap()
                .parse()
                .unwrap_or(false),
            cert_dir: get_config_value(&config, "RUSTYKEY_CERT_DIR", Some("/etc/rustykey/certs"))
                .unwrap(),
            virustotal_api_key: get_config_value(&config, "VIRUSTOTAL_API_KEY", None)
                .or_else(|| get_config_value(&config, "RUSTYKEY_VIRUSTOTAL_API_KEY", None))
                .filter(|s| !s.is_empty()),
        })
    }
}

pub fn generate_agent_id() -> String {
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    let machine_id = machine_uid::get().unwrap_or_else(|_| "unknown-machine".to_string());

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let combined = format!("{machine_id}-{timestamp}");

    let mut hasher = Sha256::new();
    hasher.update(combined);
    format!("{:x}", hasher.finalize())
}

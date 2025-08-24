// agent/src/network_client.rs
use anyhow::{Context, Result};
use common::{Command, DeviceInfo, FileManifest, Response};
use sha2::{Digest, Sha256};
use std::fs;

pub struct SecureClient {
    pub client: reqwest::Client,
    pub base_url: String,
    pub agent_id: String,
    pub session_id: Option<uuid::Uuid>,
    pub bucket_id: Option<uuid::Uuid>,
    pub banned_extensions: Vec<String>,
}

impl SecureClient {
    pub async fn connect(addr: &str, agent_id: String) -> Result<Self> {
        let cert_dir = "/etc/rustykey/certs";
        let p12_data =
            fs::read(format!("{cert_dir}/agent.p12")).context("Failed to read agent.p12")?;
        let identity = reqwest::Identity::from_pkcs12_der(&p12_data, "rustykey")
            .context("Failed to load PKCS12 identity")?;
        let ca_cert = fs::read(format!("{cert_dir}/ca-cert.pem"))?;
        let ca = reqwest::Certificate::from_pem(&ca_cert)?;

        let client = reqwest::Client::builder()
            .add_root_certificate(ca)
            .identity(identity)
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_hostnames(true)
            .build()?;

        let base_url = format!("https://{addr}");

        Ok(Self {
            client,
            base_url,
            agent_id,
            session_id: None,
            bucket_id: None,
            banned_extensions: Vec::new(),
        })
    }

    pub async fn register_with_description(&mut self, description: Option<String>) -> Result<()> {
        if self.agent_id.is_empty() {
            let machine_id = machine_uid::get().unwrap_or_default();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string();
            let value = format!("{machine_id}{timestamp}");
            let mut hasher = Sha256::new();
            hasher.update(value);
            self.agent_id = format!("{:x}", hasher.finalize());
        }

        let payload = serde_json::json!({
            "agent_id": self.agent_id,
            "description": description,
        });

        let resp = self
            .client
            .post(format!("{}/agent/register", self.base_url))
            .json(&payload)
            .send()
            .await
            .context("Failed to send registration request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Agent registration failed: {} - {}",
                status,
                text
            ));
        }

        Ok(())
    }

    pub async fn authenticate(
        &mut self,
        device_info: DeviceInfo,
    ) -> Result<(uuid::Uuid, uuid::Uuid, Vec<String>)> {
        let payload = serde_json::json!({
            "agent_id": self.agent_id,
            "device_info": device_info,
        });

        let resp = self
            .client
            .post(format!("{}/agent/connect", self.base_url))
            .json(&payload)
            .send()
            .await
            .context("Failed to send authentication request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Authentication failed: {} - {}",
                status,
                text
            ));
        }

        let json: serde_json::Value = resp.json().await?;
        let session_id = json["session_id"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid session_id"))?;
        let bucket_id = json["bucket_id"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid bucket_id"))?;

        let banned_extensions = json["banned_extensions"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        self.session_id = Some(session_id);
        self.bucket_id = Some(bucket_id);
        self.banned_extensions = banned_extensions.clone();

        Ok((session_id, bucket_id, banned_extensions))
    }

    pub async fn check_policy_updates(&mut self) -> Result<Option<Vec<String>>> {
        let payload = serde_json::json!({
            "agent_id": self.agent_id,
        });

        let resp = self
            .client
            .post(format!("{}/agent/policy", self.base_url))
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(None);
        }

        let json: serde_json::Value = resp.json().await?;

        if let Some(extensions) = json["banned_extensions"].as_array() {
            let new_extensions: Vec<String> = extensions
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();

            if let Some(request_new_manifest) = json["request_new_manifest"].as_bool() {
                if request_new_manifest {
                    self.banned_extensions = new_extensions.clone();
                    return Ok(Some(new_extensions));
                }
            }
        }

        Ok(None)
    }

    pub async fn send_manifest(&mut self, mut manifest: FileManifest) -> Result<()> {
        if let Some(session_id) = self.session_id {
            manifest.session_id = session_id;
        } else {
            return Err(anyhow::anyhow!("Not authenticated"));
        }

        let resp = self
            .client
            .post(format!("{}/agent/manifest", self.base_url))
            .json(&manifest)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to send manifest: {} - {}",
                status,
                text
            ));
        }

        Ok(())
    }

    pub async fn notify_disconnection(&mut self, serial: String) -> Result<()> {
        let payload = serde_json::json!({
            "agent_id": self.agent_id,
            "serial": serial,
        });

        let resp = self
            .client
            .post(format!("{}/agent/disconnect", self.base_url))
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to notify disconnection: {} - {}",
                status,
                text
            ));
        }

        Ok(())
    }

    pub async fn send_command(&mut self, command: Command) -> Result<Response> {
        let resp = self
            .client
            .post(format!("{}/agent/command", self.base_url))
            .json(&command)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Command failed: {} - {}", status, text));
        }

        let response: Response = resp.json().await?;
        Ok(response)
    }

    pub async fn get_staged_file(&mut self, bucket_id: &uuid::Uuid, path: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}/agent/staged/{}/{}",
            self.base_url,
            bucket_id,
            path.trim_start_matches('/')
        );

        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to get staged file: {} - {}",
                status,
                text
            ));
        }

        let content = resp.bytes().await?;
        Ok(content.to_vec())
    }

    pub async fn confirm_write(
        &mut self,
        bucket_id: &uuid::Uuid,
        path: &str,
        success: bool,
        error: Option<String>,
    ) -> Result<()> {
        let payload = serde_json::json!({
            "bucket_id": bucket_id,
            "path": path,
            "success": success,
            "error": error,
        });

        let resp = self
            .client
            .post(format!("{}/agent/confirm_write", self.base_url))
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to confirm write: {} - {}",
                status,
                text
            ));
        }

        Ok(())
    }

    pub async fn handle_read_file(
        &mut self,
        mount_point: &std::path::Path,
        path: &str,
        offset: u64,
        length: u64,
        request_id: String,
    ) -> Result<()> {
        let full_path = mount_point.join(path);

        if !full_path.exists() {
            return self.send_file_error(&request_id, "File not found").await;
        }

        let canonical_path = full_path.canonicalize()?;
        let canonical_mount = mount_point.canonicalize()?;

        if !canonical_path.starts_with(&canonical_mount) {
            return self.send_file_error(&request_id, "Invalid path").await;
        }

        let content = tokio::fs::read(&canonical_path).await?;

        let final_content = if offset > 0 || length != u64::MAX {
            let start = offset.min(content.len() as u64) as usize;
            let end = if length == u64::MAX {
                content.len()
            } else {
                ((offset + length).min(content.len() as u64)) as usize
            };
            content[start..end].to_vec()
        } else {
            content
        };

        use sha2::{Digest, Sha256};
        let hash = format!("{:x}", Sha256::digest(&final_content));

        self.send_file_content(request_id, final_content, hash)
            .await
    }

    async fn send_file_content(
        &mut self,
        request_id: String,
        content: Vec<u8>,
        hash: String,
    ) -> Result<()> {
        let size = content.len() as u64;

        let response = Response::FileContent {
            request_id: request_id.clone(),
            content,
            size,
            hash,
        };

        let resp = self
            .client
            .post(format!("{}/agent/file-response", self.base_url))
            .header("X-Agent-Id", &self.agent_id)
            .body(bincode::serde::encode_to_vec(
                &response,
                bincode::config::standard(),
            )?)
            .header("Content-Type", "application/octet-stream")
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to send file content: {} - {}",
                status,
                text
            ));
        }

        Ok(())
    }

    async fn send_file_error(&mut self, request_id: &str, error: &str) -> Result<()> {
        let response = Response::Error(format!("ReadFile failed: {}", error));

        self.client
            .post(format!("{}/agent/file-response", self.base_url))
            .header("X-Agent-Id", &self.agent_id)
            .body(bincode::serde::encode_to_vec(
                &response,
                bincode::config::standard(),
            )?)
            .header("Content-Type", "application/octet-stream")
            .send()
            .await?;

        Ok(())
    }
}

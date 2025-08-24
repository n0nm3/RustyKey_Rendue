// agent/src/command_poller.rs
use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::time::{Duration, interval};
use uuid::Uuid;

use crate::network_client::SecureClient;
use common::{Command, Response};

pub struct CommandPoller {
    mount_point: PathBuf,
    bucket_id: Uuid,
    backend_addr: String,
    agent_id: String,
    client: reqwest::Client,
}

impl CommandPoller {
    pub fn new(
        mount_point: &Path,
        bucket_id: Uuid,
        backend_addr: String,
        agent_id: String,
    ) -> Result<Self> {
        let cert_dir = "/etc/rustykey/certs";
        let p12_data = std::fs::read(format!("{}/agent.p12", cert_dir))?;
        let identity = reqwest::Identity::from_pkcs12_der(&p12_data, "rustykey")?;
        let ca_cert = std::fs::read(format!("{}/ca-cert.pem", cert_dir))?;
        let ca = reqwest::Certificate::from_pem(&ca_cert)?;

        let client = reqwest::Client::builder()
            .add_root_certificate(ca)
            .identity(identity)
            .danger_accept_invalid_hostnames(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        Ok(Self {
            mount_point: mount_point.to_path_buf(),
            bucket_id,
            backend_addr,
            agent_id,
            client,
        })
    }

    pub async fn run(self) -> Result<()> {
        let mut poll_interval = interval(Duration::from_secs(2));

        loop {
            poll_interval.tick().await;

            if !self.mount_point.exists() {
                break;
            }

            if let Err(e) = self.poll_and_execute().await {
                if e.to_string().contains("404") {
                    continue;
                }
                eprintln!("Error polling commands: {}", e);
            }
        }

        Ok(())
    }

    async fn poll_and_execute(&self) -> Result<()> {
        let url = format!(
            "https://{}/agent/poll-commands/{}",
            self.backend_addr, self.bucket_id
        );

        let resp = self
            .client
            .get(&url)
            .header("X-Agent-Id", &self.agent_id)
            .send()
            .await?;

        if resp.status() == 404 {
            return Ok(());
        }

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("Failed to poll: {}", resp.status()));
        }

        let body = resp.bytes().await?;
        let (command, _): (Command, _) =
            bincode::serde::decode_from_slice(&body, bincode::config::standard())?;

        match command {
            Command::ReadFile {
                path,
                offset,
                length,
                request_id,
            } => {
                let mut client =
                    SecureClient::connect(&self.backend_addr, self.agent_id.clone()).await?;
                client
                    .handle_read_file(&self.mount_point, &path, offset, length, request_id)
                    .await?;
            }
            _ => {}
        }

        Ok(())
    }
}

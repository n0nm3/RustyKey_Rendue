// agent/src/sync.rs
use anyhow::{Context, Result};
use std::path::Path;
use tokio::fs;
use uuid::Uuid;

use crate::network_client::SecureClient;
use common::{Command, PendingWrite, Response};

pub struct SyncManager {
    mount_point: std::path::PathBuf,
    bucket_id: Uuid,
    client: SecureClient,
}

impl SyncManager {
    pub fn new(mount_point: &Path, bucket_id: Uuid, client: SecureClient) -> Self {
        Self {
            mount_point: mount_point.to_path_buf(),
            bucket_id,
            client,
        }
    }

    pub async fn sync_all(&mut self) -> Result<SyncStats> {
        if !self.mount_point.exists() {
            return Err(anyhow::anyhow!(
                "Mount point does not exist: {:?}",
                self.mount_point
            ));
        }

        let mut stats = SyncStats::default();
        let pending_writes = self.get_pending_writes().await?;

        if pending_writes.is_empty() {
            return Ok(stats);
        }

        stats.total_files = pending_writes.len();

        for pending in pending_writes {
            match self.sync_file(&pending).await {
                Ok(bytes_written) => {
                    stats.successful_files += 1;
                    stats.total_bytes += bytes_written;
                }
                Err(e) => {
                    stats.failed_files += 1;
                    eprintln!("Failed to sync {}: {}", pending.path, e);
                    let _ = self
                        .confirm_write(&pending.path, false, Some(e.to_string()))
                        .await;
                }
            }
        }

        Ok(stats)
    }

    async fn get_pending_writes(&mut self) -> Result<Vec<PendingWrite>> {
        let response = self
            .client
            .send_command(Command::GetPendingWrites {
                bucket_id: self.bucket_id,
            })
            .await?;

        match response {
            Response::PendingWrites(writes) => Ok(writes),
            _ => Err(anyhow::anyhow!("Unexpected response from backend")),
        }
    }

    async fn sync_file(&mut self, pending: &PendingWrite) -> Result<u64> {
        if pending.hash == "DELETE" && pending.size == 0 {
            return self.sync_delete(&pending).await;
        }

        let content = self
            .client
            .get_staged_file(&self.bucket_id, &pending.path)
            .await
            .context("Failed to retrieve staged file content")?;

        use sha2::Digest;
        let computed_hash = format!("{:x}", sha2::Sha256::digest(&content));
        if computed_hash != pending.hash && pending.hash != "DELETE" {
            return Err(anyhow::anyhow!(
                "Hash mismatch: expected {}, got {}",
                pending.hash,
                computed_hash
            ));
        }

        let target_path = self.mount_point.join(&pending.path);

        if !self.mount_point.exists() {
            return Err(anyhow::anyhow!(
                "Mount point does not exist: {:?}",
                self.mount_point
            ));
        }

        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)
                .await
                .context("Failed to create parent directories")?;
        }

        let content_clone = content.clone();
        let target_path_clone = target_path.clone();

        let write_result = tokio::task::spawn_blocking(move || -> Result<()> {
            use std::fs::OpenOptions;
            use std::io::Write;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&target_path_clone)
                .context("Failed to open file for writing")?;
            file.write_all(&content_clone)
                .context("Failed to write content")?;
            file.flush().context("Failed to flush file")?;
            file.sync_all().context("Failed to sync file to disk")?;
            drop(file);

            let metadata = std::fs::metadata(&target_path_clone)
                .context("Failed to get file metadata after write")?;
            if metadata.len() == 0 && !content_clone.is_empty() {
                return Err(anyhow::anyhow!("File was created but is empty!"));
            }

            Ok(())
        })
        .await
        .context("Blocking task panicked")?;

        write_result?;

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        let _ = tokio::process::Command::new("sync").output().await;

        let written_content = fs::read(&target_path)
            .await
            .context("Failed to read back written file")?;

        if written_content.is_empty() && !content.is_empty() {
            let dd_result = tokio::process::Command::new("dd")
                .arg(format!("if=/dev/stdin"))
                .arg(format!("of={}", target_path.display()))
                .arg("bs=1024")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .context("Failed to spawn dd")?
                .wait_with_output()
                .await
                .context("Failed to run dd")?;

            if !dd_result.status.success() {
                let stderr = String::from_utf8_lossy(&dd_result.stderr);
                return Err(anyhow::anyhow!("dd failed: {}", stderr));
            }

            let written_content = fs::read(&target_path).await?;
            if written_content.is_empty() {
                return Err(anyhow::anyhow!(
                    "File remains empty after multiple write attempts"
                ));
            }
        }

        let written_hash = format!("{:x}", sha2::Sha256::digest(&written_content));
        if written_hash != pending.hash {
            let _ = fs::remove_file(&target_path).await;
            return Err(anyhow::anyhow!("Written file hash mismatch"));
        }

        self.confirm_write(&pending.path, true, None).await?;
        Ok(content.len() as u64)
    }

    async fn confirm_write(
        &mut self,
        path: &str,
        success: bool,
        error: Option<String>,
    ) -> Result<()> {
        self.client
            .confirm_write(&self.bucket_id, path, success, error)
            .await
    }

    async fn sync_delete(&mut self, pending: &PendingWrite) -> Result<u64> {
        let target_path = self.mount_point.join(&pending.path);

        match tokio::fs::remove_file(&target_path).await {
            Ok(_) => {
                self.confirm_write(&pending.path, true, None).await?;
                Ok(0)
            }
            Err(e) => {
                match std::fs::remove_file(&target_path) {
                    Ok(_) => {
                        self.confirm_write(&pending.path, true, None).await?;
                        return Ok(0);
                    }
                    Err(_) => {}
                }

                self.confirm_write(&pending.path, false, Some(e.to_string()))
                    .await?;
                Err(anyhow::anyhow!("Failed to delete file: {}", e))
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct SyncStats {
    pub total_files: usize,
    pub successful_files: usize,
    pub failed_files: usize,
    pub total_bytes: u64,
}

pub struct SyncService {
    mount_point: std::path::PathBuf,
    bucket_id: Uuid,
    backend_addr: String,
    agent_id: String,
}

impl SyncService {
    pub fn new(
        mount_point: &Path,
        bucket_id: Uuid,
        backend_addr: String,
        agent_id: String,
    ) -> Self {
        Self {
            mount_point: mount_point.to_path_buf(),
            bucket_id,
            backend_addr,
            agent_id,
        }
    }

    pub async fn run(self) -> Result<()> {
        if !self.mount_point.exists() {
            return Err(anyhow::anyhow!("Mount point does not exist"));
        }

        if let Err(e) = self.sync_once().await {
            eprintln!("Initial sync failed: {e}");
        }

        let sync_time = 30;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(sync_time));

        loop {
            interval.tick().await;

            if let Err(e) = self.sync_once().await {
                eprintln!("Periodic sync failed: {e}");
            }
        }
    }

    async fn sync_once(&self) -> Result<()> {
        let client =
            crate::network_client::SecureClient::connect(&self.backend_addr, self.agent_id.clone())
                .await?;

        let mut sync_manager = SyncManager::new(&self.mount_point, self.bucket_id, client);

        match sync_manager.sync_all().await {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Sync failed: {e}");
                Err(e)
            }
        }
    }
}

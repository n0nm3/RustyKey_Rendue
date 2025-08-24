// backend/src/staging.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::encryption::EncryptionManager;
use common::PendingWrite;

#[derive(Debug, Clone)]
pub struct StagedFile {
    pub path: String,
    pub content: Vec<u8>,
    pub hash: String,
    pub size: u64,
    pub queued_at: DateTime<Utc>,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub confirmed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct StagedFileMetadata {
    path: String,
    hash: String,
    size: u64,
    queued_at: DateTime<Utc>,
    attempts: u32,
    last_error: Option<String>,
    is_delete: bool,
    encrypted: bool,
}

pub struct StagingManager {
    staged_files: Arc<RwLock<HashMap<Uuid, HashMap<String, StagedFile>>>>,
    staging_dir: PathBuf,
    encryption: Option<EncryptionManager>,
}

impl StagingManager {
    pub async fn new(staging_dir: impl AsRef<Path>) -> Result<Self> {
        let staging_dir = staging_dir.as_ref().to_path_buf();

        fs::create_dir_all(&staging_dir)
            .await
            .context("Failed to create staging directory")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&staging_dir).await?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&staging_dir, perms).await?;
        }

        let encryption = if std::env::var("RUSTYKEY_DISABLE_ENCRYPTION").is_ok() {
            eprintln!("⚠️  WARNING: Encryption at rest is DISABLED!");
            None
        } else {
            match EncryptionManager::init() {
                Ok(mgr) => Some(mgr),
                Err(e) => {
                    eprintln!("❌ Failed to initialize encryption: {}", e);
                    eprintln!("   Continuing without encryption (NOT RECOMMENDED)");
                    None
                }
            }
        };

        Ok(Self {
            staged_files: Arc::new(RwLock::new(HashMap::new())),
            staging_dir,
            encryption,
        })
    }

    pub async fn stage_file(
        &self,
        bucket_id: Uuid,
        path: String,
        content: Vec<u8>,
        hash: String,
    ) -> Result<()> {
        let staged_file = StagedFile {
            path: path.clone(),
            size: content.len() as u64,
            hash: hash.clone(),
            content: content.clone(),
            queued_at: Utc::now(),
            attempts: 0,
            last_error: None,
            confirmed: false,
        };

        self.persist_staged_file(&bucket_id, &staged_file, false)
            .await?;

        let mut staged = self.staged_files.write().await;
        staged
            .entry(bucket_id)
            .or_insert_with(HashMap::new)
            .insert(path, staged_file);

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn stage_delete(&self, bucket_id: Uuid, path: String) -> Result<()> {
        let staged_file = StagedFile {
            path: path.clone(),
            size: 0,
            hash: String::new(),
            content: vec![],
            queued_at: Utc::now(),
            attempts: 0,
            last_error: None,
            confirmed: false,
        };

        self.persist_staged_file(&bucket_id, &staged_file, true)
            .await?;

        let mut staged = self.staged_files.write().await;
        staged
            .entry(bucket_id)
            .or_insert_with(HashMap::new)
            .insert(path, staged_file);

        Ok(())
    }

    async fn persist_staged_file(
        &self,
        bucket_id: &Uuid,
        file: &StagedFile,
        is_delete: bool,
    ) -> Result<()> {
        let file_path = self.get_staged_file_path(bucket_id, &file.path);

        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut is_encrypted = false;

        if is_delete {
            let delete_marker = file_path.with_extension("delete");
            fs::write(&delete_marker, b"").await?;
        } else {
            let data_to_write = if let Some(enc) = &self.encryption {
                let encrypted = enc.encrypt(&file.content)?;
                is_encrypted = true;

                serde_json::to_vec(&serde_json::json!({
                    "ciphertext": base64::encode(&encrypted.ciphertext),
                    "nonce": base64::encode(&encrypted.nonce),
                    "metadata": encrypted.metadata,
                }))?
            } else {
                file.content.clone()
            };

            fs::write(&file_path, &data_to_write)
                .await
                .context("Failed to write staged file")?;
        }

        let metadata = StagedFileMetadata {
            path: file.path.clone(),
            hash: file.hash.clone(),
            size: file.size,
            queued_at: file.queued_at,
            attempts: file.attempts,
            last_error: file.last_error.clone(),
            is_delete,
            encrypted: is_encrypted,
        };

        let meta_path = file_path.with_extension("meta.json");
        let meta_content = serde_json::to_string_pretty(&metadata)?;
        fs::write(&meta_path, meta_content).await?;

        Ok(())
    }

    pub async fn get_pending_writes(&self, bucket_id: &Uuid) -> Vec<PendingWrite> {
        let staged = self.staged_files.read().await;

        if let Some(bucket_files) = staged.get(bucket_id) {
            bucket_files
                .values()
                .filter(|f| !f.confirmed)
                .map(|f| PendingWrite {
                    path: f.path.clone(),
                    size: f.size,
                    hash: f.hash.clone(),
                    queued_at: f.queued_at.timestamp() as u64,
                    attempts: f.attempts,
                    last_error: f.last_error.clone(),
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub async fn get_staged_content(
        &self,
        bucket_id: &Uuid,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let staged = self.staged_files.read().await;
        if let Some(bucket_files) = staged.get(bucket_id) {
            if let Some(file) = bucket_files.get(path) {
                return Ok(Some(file.content.clone()));
            }
        }
        drop(staged);

        let file_path = self.get_staged_file_path(bucket_id, path);
        if file_path.exists() {
            let meta_path = file_path.with_extension("meta.json");
            let is_encrypted = if meta_path.exists() {
                let meta_content = fs::read_to_string(&meta_path).await?;
                let metadata: StagedFileMetadata = serde_json::from_str(&meta_content)?;
                metadata.encrypted
            } else {
                false
            };

            let data = fs::read(&file_path).await?;

            let content = if is_encrypted {
                if let Some(enc) = &self.encryption {
                    let encrypted_data: serde_json::Value = serde_json::from_slice(&data)?;

                    use crate::encryption::EncryptedData;
                    let encrypted = EncryptedData {
                        ciphertext: base64::decode(encrypted_data["ciphertext"].as_str().unwrap())?,
                        nonce: base64::decode(encrypted_data["nonce"].as_str().unwrap())?,
                        metadata: serde_json::from_value(encrypted_data["metadata"].clone())?,
                    };

                    enc.decrypt(&encrypted)?
                } else {
                    return Err(anyhow::anyhow!(
                        "File is encrypted but encryption is disabled"
                    ));
                }
            } else {
                data
            };

            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    pub async fn confirm_write(
        &self,
        bucket_id: &Uuid,
        path: &str,
        success: bool,
        error: Option<String>,
    ) -> Result<()> {
        let mut staged = self.staged_files.write().await;

        if let Some(bucket_files) = staged.get_mut(bucket_id) {
            if let Some(file) = bucket_files.get_mut(path) {
                if success {
                    file.confirmed = true;
                    self.cleanup_staged_file(bucket_id, path).await?;
                } else {
                    file.attempts += 1;
                    file.last_error = error;
                    self.persist_staged_file(bucket_id, file, false).await?;
                }
            }
        }

        if success {
            if let Some(bucket_files) = staged.get_mut(bucket_id) {
                bucket_files.remove(path);
            }
        }

        Ok(())
    }

    async fn cleanup_staged_file(&self, bucket_id: &Uuid, path: &str) -> Result<()> {
        let file_path = self.get_staged_file_path(bucket_id, path);
        let meta_path = file_path.with_extension("meta.json");
        let delete_marker = file_path.with_extension("delete");

        let _ = fs::remove_file(&file_path).await;
        let _ = fs::remove_file(&meta_path).await;
        let _ = fs::remove_file(&delete_marker).await;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn cleanup_confirmed(&self, bucket_id: &Uuid) -> Result<()> {
        let mut staged = self.staged_files.write().await;

        if let Some(bucket_files) = staged.get_mut(bucket_id) {
            bucket_files.retain(|_, file| !file.confirmed);
        }

        Ok(())
    }

    pub async fn load_from_disk(&self) -> Result<()> {
        if !self.staging_dir.exists() {
            return Ok(());
        }

        let mut buckets_loaded = 0;
        let mut files_loaded = 0;

        let mut entries = fs::read_dir(&self.staging_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }

            let bucket_name = entry.file_name();
            if let Some(bucket_str) = bucket_name.to_str() {
                if let Ok(bucket_id) = Uuid::parse_str(bucket_str) {
                    let loaded = self.load_bucket_files(bucket_id).await?;
                    if loaded > 0 {
                        buckets_loaded += 1;
                        files_loaded += loaded;
                    }
                }
            }
        }

        Ok(())
    }

    async fn load_bucket_files(&self, bucket_id: Uuid) -> Result<usize> {
        let bucket_dir = self.staging_dir.join(bucket_id.to_string());
        if !bucket_dir.exists() {
            return Ok(0);
        }

        let mut loaded_count = 0;
        let mut entries = fs::read_dir(&bucket_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            match path.extension().and_then(|s| s.to_str()) {
                Some("json") | Some("delete") => continue,
                _ => {}
            }

            let meta_path = path.with_extension("meta.json");
            if !meta_path.exists() {
                continue;
            }

            let meta_content = fs::read_to_string(&meta_path).await?;
            let metadata: StagedFileMetadata = serde_json::from_str(&meta_content)?;

            let content = if metadata.is_delete {
                vec![]
            } else if path.exists() {
                let data = fs::read(&path).await?;

                if metadata.encrypted {
                    if let Some(enc) = &self.encryption {
                        let encrypted_data: serde_json::Value = serde_json::from_slice(&data)?;

                        use crate::encryption::EncryptedData;
                        let encrypted = EncryptedData {
                            ciphertext: base64::decode(
                                encrypted_data["ciphertext"].as_str().unwrap(),
                            )?,
                            nonce: base64::decode(encrypted_data["nonce"].as_str().unwrap())?,
                            metadata: serde_json::from_value(encrypted_data["metadata"].clone())?,
                        };

                        enc.decrypt(&encrypted)?
                    } else {
                        eprintln!(
                            "Warning: Skipping encrypted file {} (encryption disabled)",
                            metadata.path
                        );
                        continue;
                    }
                } else {
                    data
                }
            } else {
                continue;
            };

            let staged_file = StagedFile {
                path: metadata.path.clone(),
                content,
                hash: metadata.hash,
                size: metadata.size,
                queued_at: metadata.queued_at,
                attempts: metadata.attempts,
                last_error: metadata.last_error,
                confirmed: false,
            };

            let mut staged = self.staged_files.write().await;
            staged
                .entry(bucket_id)
                .or_insert_with(HashMap::new)
                .insert(metadata.path, staged_file);

            loaded_count += 1;
        }

        Ok(loaded_count)
    }

    fn get_staged_file_path(&self, bucket_id: &Uuid, path: &str) -> PathBuf {
        let safe_path = path.replace("..", "_").replace("/", "_").replace("\\", "_");

        self.staging_dir
            .join(bucket_id.to_string())
            .join(format!("{safe_path}.staged"))
    }

    #[allow(dead_code)]
    pub async fn get_stats(&self) -> StagingStats {
        let staged = self.staged_files.read().await;

        let mut stats = StagingStats::default();

        for (_, bucket_files) in staged.iter() {
            stats.total_buckets += 1;
            for (_, file) in bucket_files.iter() {
                stats.total_files += 1;
                stats.total_bytes += file.size;
                if file.confirmed {
                    stats.confirmed_files += 1;
                } else if file.attempts > 0 {
                    stats.failed_files += 1;
                } else {
                    stats.pending_files += 1;
                }
            }
        }
        stats
    }

    pub async fn remove_staged_file(&self, bucket_id: &Uuid, path: &str) -> Result<()> {
        let mut staged = self.staged_files.write().await;
        let mut removed = false;

        if let Some(bucket_files) = staged.get_mut(bucket_id) {
            if bucket_files.remove(path).is_some() {
                removed = true;
            }
        }
        drop(staged);

        if removed {
            self.cleanup_staged_file(bucket_id, path).await?;
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct StagingStats {
    pub total_buckets: usize,
    pub total_files: usize,
    pub pending_files: usize,
    pub confirmed_files: usize,
    pub failed_files: usize,
    pub total_bytes: u64,
}

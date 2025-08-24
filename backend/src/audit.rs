// backend/src/audit.rs
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub details: Option<serde_json::Value>,
}

pub struct AuditLogger {
    file: Mutex<tokio::fs::File>,
}

impl AuditLogger {
    pub fn new(path: &str) -> Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            file: Mutex::new(tokio::fs::File::from_std(file)),
        })
    }

    pub async fn log_event(&self, event: AuditEvent) -> Result<()> {
        let json = serde_json::to_string(&event)?;
        let mut file = self.file.lock().await;
        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }

    pub async fn log_unauthorized(
        &self,
        user_id: Uuid,
        action: &str,
        resource: &str,
    ) -> Result<()> {
        self.log_event(AuditEvent {
            timestamp: Utc::now(),
            user_id,
            session_id: Uuid::nil(),
            action: action.to_string(),
            resource: resource.to_string(),
            result: "unauthorized".to_string(),
            details: None,
        })
        .await
    }
}

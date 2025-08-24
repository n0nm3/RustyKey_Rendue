// common/src/lib.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub mod config;
pub use config::{AgentConfig, BackendConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub agent_id: String,
    pub description: String,
    pub active_buckets: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_online: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterAgentRequest {
    pub agent_id: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAgentRequest {
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub user_id: Uuid,
    pub perms: Vec<Bucket>,
    pub is_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bucket {
    pub id: Uuid,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileManifest {
    pub device_id: String,
    pub files: Vec<FileInfo>,
    pub session_id: Uuid,
    pub agent_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub hash: String,
    pub modified: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    Authenticate {
        agent_id: String,
        device_info: DeviceInfo,
    },
    SendManifest(FileManifest),
    ReadFile {
        path: String,
        offset: u64,
        length: u64,
        request_id: String,
    },
    WriteFile {
        path: String,
        data: Vec<u8>,
        offset: u64,
    },
    GetPendingWrites {
        bucket_id: Uuid,
    },
    ConfirmWrite {
        bucket_id: Uuid,
        path: String,
        success: bool,
        error: Option<String>,
    },
    SyncRequest {
        bucket_id: Uuid,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: String,
    pub capacity: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Response {
    Authenticated {
        session_id: Uuid,
        bucket_id: Uuid,
        banned_extensions: Vec<String>,
    },
    FileContent {
        request_id: String,
        content: Vec<u8>,
        size: u64,
        hash: String,
    },
    PolicyUpdate {
        banned_extensions: Vec<String>,
        request_new_manifest: bool,
    },
    PermissionDenied,
    Success,
    Error(String),
    Data(Vec<u8>),
    PendingWrites(Vec<PendingWrite>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PendingWrite {
    pub path: String,
    pub size: u64,
    pub hash: String,
    pub queued_at: u64,
    pub attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FileOperation {
    Write,
    Delete,
}

impl User {
    pub fn has_permission(&self, bucket_id: &Uuid, operation: Operation) -> bool {
        self.perms.iter().any(|bucket| {
            bucket.id == *bucket_id
                && match operation {
                    Operation::Read => bucket.read,
                    Operation::Write => bucket.write,
                    Operation::Delete => bucket.delete,
                }
        })
    }

    pub fn list_perm(&self, bucket_id: Option<Uuid>) -> Result<Vec<Bucket>, String> {
        match bucket_id {
            Some(id) => {
                if let Some(bucket) = self.perms.iter().find(|b| b.id == id) {
                    Ok(vec![bucket.clone()])
                } else {
                    Err("Bucket not found".to_string())
                }
            }
            None => Ok(self.perms.clone()),
        }
    }

    pub fn change_perm(
        &mut self,
        bucket_id: &Uuid,
        permission: &str,
        value: bool,
    ) -> Result<(), String> {
        if !self.perms.iter().any(|b| b.id == *bucket_id) {
            self.perms.push(Bucket {
                id: *bucket_id,
                read: false,
                write: false,
                delete: false,
            });
        }

        if let Some(bucket) = self.perms.iter_mut().find(|b| b.id == *bucket_id) {
            match permission {
                "read" => bucket.read = value,
                "write" => bucket.write = value,
                "delete" => bucket.delete = value,
                _ => return Err("Permission invalide".to_string()),
            }

            if !bucket.read && !bucket.write && !bucket.delete {
                self.perms.retain(|b| b.id != *bucket_id);
            }

            Ok(())
        } else {
            Err("Bucket non trouvé".to_string())
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Operation {
    Read,
    Write,
    Delete,
}

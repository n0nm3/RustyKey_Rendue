// backend/src/models.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug)]
pub struct BucketData {
    pub id: Uuid,
    pub device_id: String,
    pub serial: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_online: bool,
    pub objects: HashMap<String, ObjectData>,
}

#[derive(Debug, Clone)]
pub struct ObjectData {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub last_modified: DateTime<Utc>,
    pub content: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub is_staged: bool,
}

#[derive(Debug)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub bucket_id: Uuid,
    pub agent_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ListBucketsResponse {
    pub buckets: Vec<BucketInfo>,
}

#[derive(Serialize)]
pub struct BucketInfo {
    pub name: String,
    pub creation_date: String,
    pub is_online: bool,
    pub last_seen: String,
}

#[derive(Serialize)]
pub struct ListObjectsResponse {
    pub contents: Vec<ObjectInfo>,
    pub is_truncated: bool,
    pub max_keys: i32,
}

#[derive(Serialize)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub last_modified: String,
}

#[derive(Deserialize)]
pub struct ListObjectsQuery {
    pub prefix: Option<String>,
    pub max_keys: Option<i32>,
    pub marker: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    pub is_admin: bool,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub user_id: Uuid,
    pub name: String,
    pub is_admin: bool,
    pub permissions_count: usize,
}

#[derive(Deserialize)]
pub struct SetPermissionsRequest {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

#[derive(Serialize)]
pub struct PermissionResponse {
    pub bucket_id: Uuid,
    pub bucket_name: String,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub is_online: bool,
}

impl BucketData {
    pub fn new(device_serial: String, created_by: Uuid) -> Self {
        let bucket_id = Uuid::new_v4();
        Self {
            id: bucket_id,
            device_id: device_serial.clone(),
            serial: device_serial,
            created_by,
            created_at: Utc::now(),
            last_seen: Utc::now(),
            is_online: true,
            objects: HashMap::new(),
        }
    }

    pub fn mark_online(&mut self) {
        self.is_online = true;
        self.last_seen = Utc::now();
    }

    pub fn mark_offline(&mut self) {
        self.is_online = false;
        self.last_seen = Utc::now();
    }

    pub fn to_bucket_info(&self) -> BucketInfo {
        BucketInfo {
            name: format!("usb-{}", self.id),
            creation_date: self.created_at.to_rfc3339(),
            is_online: self.is_online,
            last_seen: self.last_seen.to_rfc3339(),
        }
    }
}

impl ObjectData {
    pub fn new(key: String, content: Vec<u8>, etag: String) -> Self {
        Self {
            key: key.clone(),
            size: content.len() as u64,
            etag,
            last_modified: Utc::now(),
            content,
            metadata: HashMap::new(),
            is_staged: false,
        }
    }

    pub fn new_staged(key: String, size: u64, etag: String) -> Self {
        Self {
            key,
            size,
            etag,
            last_modified: Utc::now(),
            content: vec![],
            metadata: HashMap::new(),
            is_staged: true,
        }
    }

    pub fn to_object_info(&self) -> ObjectInfo {
        ObjectInfo {
            key: self.key.clone(),
            size: self.size,
            etag: self.etag.clone(),
            last_modified: self.last_modified.to_rfc3339(),
        }
    }
}

pub fn format_bucket_name(bucket_id: &Uuid) -> String {
    format!("usb-{bucket_id}")
}

pub fn parse_bucket_name(bucket_name: &str) -> Option<Uuid> {
    bucket_name
        .strip_prefix("usb-")
        .and_then(|id| Uuid::parse_str(id).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_name_formatting() {
        let id = Uuid::new_v4();
        let name = format_bucket_name(&id);
        assert_eq!(parse_bucket_name(&name), Some(id));
    }

    #[test]
    fn test_bucket_lifecycle() {
        let mut bucket = BucketData::new("TEST123".to_string(), Uuid::new_v4());
        assert!(bucket.is_online);

        bucket.mark_offline();
        assert!(!bucket.is_online);

        bucket.mark_online();
        assert!(bucket.is_online);
    }
}

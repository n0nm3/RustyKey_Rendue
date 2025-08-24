// backend/src/policy.rs
use anyhow::Result;
use bytes::Bytes;
use common::DeviceInfo;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct PolicyEngine {
    allowed_vendors: Vec<u16>,
    blocked_serials: Vec<String>,
    max_file_size: u64,
    content_patterns: Vec<Regex>,
    pub banned_extensions: Arc<RwLock<HashSet<String>>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let default_banned = vec![
            ".exe".to_string(),
            ".bat".to_string(),
            ".cmd".to_string(),
            ".com".to_string(),
            ".scr".to_string(),
            ".vbs".to_string(),
            ".vbe".to_string(),
            ".js".to_string(),
            ".jse".to_string(),
            ".wsf".to_string(),
            ".wsh".to_string(),
            ".ps1".to_string(),
            ".dll".to_string(),
        ];

        Self {
            allowed_vendors: vec![0x1234, 0x5678],
            blocked_serials: vec!["BLOCKED123".to_string()],
            max_file_size: 100_000_000,
            content_patterns: vec![
                Regex::new(r"(?i)confidential").unwrap(),
                Regex::new(r"\b(?:\d{4}[\s-]?){3}\d{4}\b").unwrap(),
            ],
            banned_extensions: Arc::new(RwLock::new(default_banned.into_iter().collect())),
        }
    }

    pub async fn is_device_allowed(&self, device: &DeviceInfo) -> Result<bool> {
        if !self.allowed_vendors.contains(&device.vendor_id) {
            return Ok(false);
        }

        if self.blocked_serials.contains(&device.serial) {
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn scan_content(&self, content: &Bytes) -> Result<()> {
        if content.len() as u64 > self.max_file_size {
            return Err(anyhow::anyhow!("File too large"));
        }

        if let Ok(text) = std::str::from_utf8(content) {
            for pattern in &self.content_patterns {
                if pattern.is_match(text) {
                    return Err(anyhow::anyhow!("Content contains prohibited pattern"));
                }
            }
        }

        Ok(())
    }

    pub async fn is_file_allowed(&self, filename: &str) -> bool {
        let banned = self.banned_extensions.read().await;
        let filename_lower = filename.to_lowercase();

        for ext in banned.iter() {
            if filename_lower.contains(ext) {
                return false;
            }
        }

        true
    }

    pub async fn add_banned_extension(&self, extension: String) -> Result<bool> {
        let mut ext = extension.to_lowercase();

        if !ext.starts_with('.') {
            ext = format!(".{ext}");
        }

        let mut banned = self.banned_extensions.write().await;
        Ok(banned.insert(ext))
    }

    pub async fn remove_banned_extension(&self, extension: &str) -> Result<bool> {
        let mut ext = extension.to_lowercase();

        if !ext.starts_with('.') {
            ext = format!(".{ext}");
        }

        let mut banned = self.banned_extensions.write().await;
        Ok(banned.remove(&ext))
    }

    pub async fn get_banned_extensions(&self) -> Vec<String> {
        let banned = self.banned_extensions.read().await;
        let mut extensions: Vec<String> = banned.iter().cloned().collect();
        extensions.sort();
        extensions
    }

    pub async fn set_banned_extensions(&self, extensions: Vec<String>) -> Result<()> {
        let mut normalized: HashSet<String> = HashSet::new();

        for ext in extensions {
            let mut normalized_ext = ext.to_lowercase();
            if !normalized_ext.starts_with('.') {
                normalized_ext = format!(".{normalized_ext}");
            }
            normalized.insert(normalized_ext);
        }

        let mut banned = self.banned_extensions.write().await;
        *banned = normalized;
        Ok(())
    }

    pub async fn is_extension_banned(&self, extension: &str) -> bool {
        let mut ext = extension.to_lowercase();
        if !ext.starts_with('.') {
            ext = format!(".{ext}");
        }

        let banned = self.banned_extensions.read().await;
        banned.contains(&ext)
    }
}

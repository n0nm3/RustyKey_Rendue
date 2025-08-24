// backend/src/main.rs
use anyhow::{Context, Result};
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

mod audit;
mod command_queue;
mod encryption;
mod extractors;
mod models;
mod policy;
mod routes;
mod staging;
mod virustotal;

use command_queue::CommandQueue;
use common::{Agent, BackendConfig, User};

use models::*;
use staging::StagingManager;

#[derive(Clone)]
pub struct AppState {
    pub users: Arc<RwLock<HashMap<Uuid, User>>>,
    pub buckets: Arc<RwLock<HashMap<Uuid, BucketData>>>,
    pub sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
    pub agents: Arc<RwLock<HashMap<String, Agent>>>,
    pub audit_log: Arc<audit::AuditLogger>,
    pub policy_engine: Arc<policy::PolicyEngine>,
    pub staging_manager: Arc<StagingManager>,
    pub config: BackendConfig,
    pub command_queue: Arc<CommandQueue>,
}

impl AppState {
    async fn new(config: BackendConfig, audit_log_path: &str) -> Result<Self> {
        let staging_dir = std::path::Path::new(&config.audit_log_path)
            .parent()
            .unwrap_or(std::path::Path::new("/var/lib/rustykey"))
            .join("staging");

        let staging_manager = Arc::new(
            StagingManager::new(staging_dir)
                .await
                .context("Failed to create staging manager")?,
        );

        staging_manager
            .load_from_disk()
            .await
            .context("Failed to load staged files")?;

        Ok(Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            buckets: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            agents: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(audit::AuditLogger::new(audit_log_path)?),
            policy_engine: Arc::new(policy::PolicyEngine::new()),
            staging_manager,
            config,
            command_queue: Arc::new(CommandQueue::new()),
        })
    }

    async fn create_demo_users(&self) {
        let admin = self.add_user("admin".to_string(), true).await.unwrap();
        println!("Admin User ID: {}", admin.user_id);
    }

    pub async fn add_user(&self, name: String, is_admin: bool) -> Result<User> {
        let mut users = self.users.write().await;
        let user_id = Uuid::new_v4();

        let user = User {
            name: name.clone(),
            user_id,
            perms: vec![],
            is_admin,
        };

        users.insert(user_id, user.clone());
        Ok(user)
    }

    pub async fn del_user(&self, user_id: Uuid, admin_id: Uuid) -> Result<()> {
        if admin_id == user_id {
            return Err(anyhow::anyhow!("Cannot delete yourself"));
        }

        let mut users = self.users.write().await;
        let user = users
            .get(&user_id)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        if user.is_admin {
            let admin_count = users.values().filter(|u| u.is_admin).count();
            if admin_count <= 1 {
                return Err(anyhow::anyhow!("Cannot delete the last admin"));
            }
        }

        users.remove(&user_id);
        Ok(())
    }

    pub async fn update_perms(
        &self,
        user_id: Uuid,
        bucket_id: Uuid,
        permission: &str,
        value: bool,
    ) -> Result<()> {
        let mut users = self.users.write().await;
        match users.get_mut(&user_id) {
            Some(user) => {
                user.change_perm(&bucket_id, permission, value)
                    .map_err(anyhow::Error::msg)?;
                Ok(())
            }
            None => Err(anyhow::anyhow!("User not found")),
        }
    }

    pub async fn authenticate_session(
        &self,
        agent_id: String,
        device_info: common::DeviceInfo,
        user_id: Uuid,
    ) -> Result<(Uuid, Uuid)> {
        use chrono::Utc;

        if !self.policy_engine.is_device_allowed(&device_info).await? {
            return Err(anyhow::anyhow!("Device not allowed by policy"));
        }

        let session_id = Uuid::new_v4();
        let mut buckets = self.buckets.write().await;

        let bucket_id = if let Some(existing_bucket) = buckets
            .values_mut()
            .find(|b| b.serial == device_info.serial)
        {
            existing_bucket.mark_online();
            let bucket_id = existing_bucket.id;
            drop(buckets);

            let pending = self.staging_manager.get_pending_writes(&bucket_id).await;
            bucket_id
        } else {
            let bucket = BucketData::new(device_info.serial.clone(), user_id);
            let bucket_id = bucket.id;
            buckets.insert(bucket_id, bucket);

            let mut users = self.users.write().await;
            if let Some(user) = users.get_mut(&user_id) {
                user.change_perm(&bucket_id, "read", true).ok();
                user.change_perm(&bucket_id, "write", true).ok();
                user.change_perm(&bucket_id, "delete", true).ok();
            }
            drop(users);
            bucket_id
        };

        self.sessions.write().await.insert(
            session_id,
            Session {
                id: session_id,
                user_id,
                bucket_id,
                agent_id,
                created_at: Utc::now(),
            },
        );

        extractors::log_success(
            self,
            user_id,
            "device_connected",
            &format!("device:{}", device_info.serial),
            Some(serde_json::to_value(&device_info).ok().unwrap_or_default()),
        )
        .await?;

        Ok((session_id, bucket_id))
    }
}

mod tls;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let config = BackendConfig::load().context("Failed to load backend configuration")?;

    unsafe {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    if let Some(parent) = std::path::Path::new(&config.audit_log_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let state = Arc::new(AppState::new(config.clone(), &config.audit_log_path).await?);
    state.create_demo_users().await;

    let app = routes::configure_routes(state);

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        format!("{}/server-cert.pem", config.cert_dir),
        format!("{}/server-key.pem", config.cert_dir),
    )
    .await?;

    axum_server::bind_rustls(config.bind_addr.parse()?, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

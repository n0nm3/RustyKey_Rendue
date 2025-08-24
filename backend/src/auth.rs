use anyhow::Result;
use uuid::Uuid;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

pub struct AuthManager {
    tokens: Arc<RwLock<HashMap<String, Uuid>>>, // token -> user_id
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_token(&self, user_id: Uuid) -> String {
        let token = Uuid::new_v4().to_string();
        self.tokens.write().await.insert(token.clone(), user_id);
        token
    }

    pub async fn validate_token(&self, token: &str) -> Option<Uuid> {
        self.tokens.read().await.get(token).copied()
    }

    pub async fn revoke_token(&self, token: &str) {
        self.tokens.write().await.remove(token);
    }
}

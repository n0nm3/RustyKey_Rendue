// backend/src/command_queue.rs
use anyhow::Result;
use common::{Command, Response};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, oneshot};
use uuid::Uuid;

pub struct CommandQueue {
    pending_commands: Arc<RwLock<HashMap<Uuid, Vec<PendingCommand>>>>,
    pending_responses: Arc<Mutex<HashMap<String, oneshot::Sender<Response>>>>,
}

pub enum CommandError {
    Timeout,
    FileNotFound,
    PermissionDenied,
    AgentOffline,
}

struct PendingCommand {
    command: Command,
    request_id: String,
}

impl CommandQueue {
    pub fn new() -> Self {
        Self {
            pending_commands: Arc::new(RwLock::new(HashMap::new())),
            pending_responses: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn send_command_and_wait(
        &self,
        bucket_id: Uuid,
        command: Command,
        request_id: String,
        timeout: std::time::Duration,
    ) -> Result<Response> {
        let (tx, rx) = oneshot::channel();

        {
            let mut responses = self.pending_responses.lock().await;
            responses.insert(request_id.clone(), tx);
        }

        {
            let mut commands = self.pending_commands.write().await;
            let pending = PendingCommand {
                command,
                request_id: request_id.clone(),
            };
            commands
                .entry(bucket_id)
                .or_insert_with(Vec::new)
                .push(pending);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(anyhow::anyhow!("Response channel closed")),
            Err(_) => {
                let mut responses = self.pending_responses.lock().await;
                responses.remove(&request_id);
                Err(anyhow::anyhow!("Command timeout"))
            }
        }
    }

    pub async fn get_next_command(&self, bucket_id: &Uuid) -> Option<Command> {
        let mut commands = self.pending_commands.write().await;
        if let Some(bucket_commands) = commands.get_mut(bucket_id) {
            if !bucket_commands.is_empty() {
                let pending = bucket_commands.remove(0);
                return Some(pending.command);
            }
        }
        None
    }

    pub async fn handle_response(&self, response: Response) -> Result<()> {
        match &response {
            Response::FileContent { request_id, .. } => {
                let mut responses = self.pending_responses.lock().await;
                if let Some(sender) = responses.remove(request_id) {
                    let _ = sender.send(response.clone());
                }
            }
            Response::Error(error_msg) => {
                eprintln!("Received error response: {}", error_msg);
            }
            _ => {}
        }
        Ok(())
    }
}

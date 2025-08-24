// backend/src/routes/agent.rs
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, extractors::*, models::*};
use common::{Agent, Command, DeviceInfo, FileManifest, RegisterAgentRequest, Response};

pub async fn register_agent(
    State(state): State<Arc<AppState>>,
    axum::Json(request): axum::Json<RegisterAgentRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let agent_id = request.agent_id.clone();

    let mut agents = state.agents.write().await;
    if agents.contains_key(&agent_id) {
        if let Some(agent) = agents.get_mut(&agent_id) {
            agent.last_seen = Utc::now();
            agent.is_online = true;
        }
        return Ok((
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "status": "already_registered",
                "agent_id": agent_id
            })),
        ));
    }

    let agent = Agent {
        agent_id: agent_id.clone(),
        description: request.description.unwrap_or_default(),
        active_buckets: vec![],
        created_at: Utc::now(),
        last_seen: Utc::now(),
        is_online: true,
    };

    agents.insert(agent_id.clone(), agent.clone());

    log_success(
        &state,
        Uuid::nil(),
        "agent_registered",
        &format_resource("agent", &agent_id),
        Some(serde_json::json!({
            "description": agent.description
        })),
    )
    .await
    .ok();

    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "status": "registered",
            "agent_id": agent_id
        })),
    ))
}

pub async fn handle_agent_connection(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    let agent_id = payload["agent_id"]
        .as_str()
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string();

    let mut agents = state.agents.write().await;
    if !agents.contains_key(&agent_id) {
        eprintln!("Unknown agent: {agent_id}");
        return Err(StatusCode::UNAUTHORIZED);
    }

    if let Some(agent) = agents.get_mut(&agent_id) {
        agent.is_online = true;
        agent.last_seen = Utc::now();
    }
    drop(agents);

    let device_info = if let Some(dev_info) = payload.get("device_info") {
        DeviceInfo {
            vendor_id: dev_info["vendor_id"].as_u64().unwrap_or(0) as u16,
            product_id: dev_info["product_id"].as_u64().unwrap_or(0) as u16,
            serial: dev_info["serial"].as_str().unwrap_or("").to_string(),
            capacity: dev_info["capacity"].as_u64().unwrap_or(0),
        }
    } else {
        DeviceInfo {
            vendor_id: 0x1234,
            product_id: 0x5678,
            serial: "UNKNOWN".to_string(),
            capacity: 0,
        }
    };

    let users = state.users.read().await;
    let user_id = users
        .values()
        .find(|u| u.is_admin)
        .map(|u| u.user_id)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    drop(users);

    match state
        .authenticate_session(agent_id.clone(), device_info, user_id)
        .await
    {
        Ok((session_id, bucket_id)) => {
            let mut agents = state.agents.write().await;
            if let Some(agent) = agents.get_mut(&agent_id) {
                if !agent.active_buckets.contains(&bucket_id) {
                    agent.active_buckets.push(bucket_id);
                }
            }
            drop(agents);

            let mut sessions = state.sessions.write().await;
            sessions.insert(
                session_id,
                Session {
                    id: session_id,
                    user_id,
                    bucket_id,
                    agent_id: agent_id.clone(),
                    created_at: Utc::now(),
                },
            );
            let banned_extensions = state.policy_engine.get_banned_extensions().await;

            Ok(axum::Json(serde_json::json!({
                "session_id": session_id,
                "bucket_id": bucket_id,
                "banned_extensions": banned_extensions,
            })))
        }
        Err(e) => {
            eprintln!("Authentication failed: {e}");
            Err(StatusCode::FORBIDDEN)
        }
    }
}

pub async fn handle_agent_manifest(
    State(state): State<Arc<AppState>>,
    axum::Json(manifest): axum::Json<FileManifest>,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = state.sessions.read().await;
    let session = sessions
        .get(&manifest.session_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let bucket_id = session.bucket_id;
    drop(sessions);

    let mut buckets = state.buckets.write().await;
    if let Some(bucket) = buckets.get_mut(&bucket_id) {
        for file in manifest.files {
            let mut object = ObjectData::new(file.path.clone(), vec![], file.hash.clone());
            object.size = file.size;
            bucket.objects.insert(file.path, object);
        }
        Ok(StatusCode::OK)
    } else {
        eprintln!("Bucket {bucket_id} not found");
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn handle_agent_command(
    State(state): State<Arc<AppState>>,
    axum::Json(command): axum::Json<Command>,
) -> Result<impl IntoResponse, StatusCode> {
    match command {
        Command::GetPendingWrites { bucket_id } => {
            let buckets = state.buckets.read().await;
            let bucket = buckets.get(&bucket_id).ok_or(StatusCode::NOT_FOUND)?;
            if !bucket.is_online {
                return Ok(axum::Json(Response::PendingWrites(vec![])));
            }
            drop(buckets);

            let pending_writes = state.staging_manager.get_pending_writes(&bucket_id).await;

            Ok(axum::Json(Response::PendingWrites(pending_writes)))
        }
        Command::ReadFile { path, .. } => {
            eprintln!("ReadFile not yet implemented for path: {path}");
            Err(StatusCode::NOT_IMPLEMENTED)
        }
        _ => {
            eprintln!("Unhandled command: {command:?}");
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

pub async fn handle_write_confirmation(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    let bucket_id = payload["bucket_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let path = payload["path"].as_str().ok_or(StatusCode::BAD_REQUEST)?;

    let success = payload["success"].as_bool().unwrap_or(false);
    let error = payload["error"].as_str().map(|s| s.to_string());

    state
        .staging_manager
        .confirm_write(&bucket_id, path, success, error.clone())
        .await
        .status_500()?;

    if success {
        let mut buckets = state.buckets.write().await;
        if let Some(bucket) = buckets.get_mut(&bucket_id) {
            if let Some(object) = bucket.objects.get_mut(path) {
                object.is_staged = false;
            }
        }
    }

    Ok(StatusCode::OK)
}

pub async fn handle_get_staged_file(
    State(state): State<Arc<AppState>>,
    Path((bucket_id, path)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let bucket_id = Uuid::parse_str(&bucket_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let content = state
        .staging_manager
        .get_staged_content(&bucket_id, &path)
        .await
        .status_500()?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(content)
}

pub async fn handle_agent_disconnection(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    let serial = payload["serial"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let agent_id = payload["agent_id"]
        .as_str()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let mut buckets = state.buckets.write().await;
    if let Some(bucket) = buckets.values_mut().find(|b| b.serial == serial) {
        bucket.mark_offline();
        let bucket_id = bucket.id;
        let created_by = bucket.created_by;

        let mut agents = state.agents.write().await;
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.active_buckets.retain(|&id| id != bucket_id);
            agent.last_seen = Utc::now();
        }
        drop(agents);

        log_success(
            &state,
            created_by,
            "device_disconnected",
            &format!("device:{serial}"),
            None,
        )
        .await
        .ok();

        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn check_policy_update(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> Result<impl IntoResponse, StatusCode> {
    let agent_id = payload["agent_id"]
        .as_str()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let mut agents = state.agents.write().await;
    match agents.get_mut(agent_id) {
        Some(agent) => {
            agent.last_seen = Utc::now();
            agent.is_online = true;
        }
        None => return Err(StatusCode::UNAUTHORIZED),
    }
    drop(agents);

    let banned_extensions = state.policy_engine.get_banned_extensions().await;

    Ok(axum::Json(common::Response::PolicyUpdate {
        banned_extensions,
        request_new_manifest: false,
    }))
}

pub async fn poll_commands(
    State(state): State<Arc<AppState>>,
    Path(bucket_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let agent_id = headers
        .get("X-Agent-Id")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let agents = state.agents.read().await;
    let _agent = agents
        .values()
        .find(|a| a.agent_id == agent_id && a.active_buckets.contains(&bucket_id))
        .ok_or(StatusCode::FORBIDDEN)?;
    drop(agents);

    if let Some(command) = state.command_queue.get_next_command(&bucket_id).await {
        let body = bincode::serde::encode_to_vec(&command, bincode::config::standard())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok((StatusCode::OK, body))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn file_response(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let agent_id = headers
        .get("X-Agent-Id")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let response: Response = bincode::serde::decode_from_slice(&body, bincode::config::standard())
        .map(|(response, _)| response)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    state
        .command_queue
        .handle_response(response)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

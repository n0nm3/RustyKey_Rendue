// backend/src/routes/admin/agents.rs
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;

use crate::{AppState, extractors::*, models::*};
use common::{Agent, UpdateAgentRequest};

pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin(&state, &headers).await?;

    let agents = state.agents.read().await;
    let agent_list: Vec<Agent> = agents.values().cloned().collect();

    Ok(axum::Json(agent_list))
}

pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin(&state, &headers).await?;

    let agents = state.agents.read().await;
    let agent = agents.get(&agent_id).ok_or(StatusCode::NOT_FOUND)?;

    Ok(axum::Json(agent.clone()))
}

pub async fn update_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<UpdateAgentRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let admin_id = verify_admin(&state, &headers).await?;

    let mut agents = state.agents.write().await;
    let agent = agents.get_mut(&agent_id).ok_or(StatusCode::NOT_FOUND)?;
    agent.description = request.description;

    log_success(
        &state,
        admin_id,
        "update_agent",
        &format_resource("agent", &agent_id),
        Some(serde_json::json!({
            "description": agent.description
        })),
    )
    .await
    .ok();

    Ok(StatusCode::OK)
}

pub async fn delete_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let admin_id = verify_admin(&state, &headers).await?;

    let mut agents = state.agents.write().await;
    if !agents.contains_key(&agent_id) {
        return Err(StatusCode::NOT_FOUND);
    }

    agents.remove(&agent_id);

    log_success(
        &state,
        admin_id,
        "delete_agent",
        &format_resource("agent", &agent_id),
        None,
    )
    .await
    .ok();

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_agent_buckets(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin(&state, &headers).await?;

    let agents = state.agents.read().await;
    let agent = agents.get(&agent_id).ok_or(StatusCode::NOT_FOUND)?;

    let buckets = state.buckets.read().await;
    let active_buckets: Vec<serde_json::Value> = agent
        .active_buckets
        .iter()
        .filter_map(|bucket_id| {
            buckets.get(bucket_id).map(|b| {
                serde_json::json!({
                    "bucket_id": b.id,
                    "name": format_bucket_name(&b.id),
                    "serial": b.serial,
                    "is_online": b.is_online,
                    "last_seen": b.last_seen.to_rfc3339(),
                    "created_at": b.created_at.to_rfc3339(),
                })
            })
        })
        .collect();

    Ok(axum::Json(active_buckets))
}

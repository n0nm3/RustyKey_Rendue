// backend/src/routes/admin/policy.rs
use crate::{AppState, extractors::*};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AddExtensionRequest {
    extension: String,
}

#[derive(Serialize)]
pub struct ExtensionsResponse {
    extensions: Vec<String>,
}

pub async fn list_banned_extensions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;
    if !user.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    drop(users);

    let extensions = state.policy_engine.get_banned_extensions().await;

    log_success(
        &state,
        user_id,
        "list_banned_extensions",
        "policy",
        Some(serde_json::json!({ "count": extensions.len() })),
    )
    .await
    .ok();

    Ok(Json(ExtensionsResponse { extensions }))
}

pub async fn remove_banned_extension(
    State(state): State<Arc<AppState>>,
    Path(extension): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;
    if !user.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    drop(users);

    let removed = state
        .policy_engine
        .remove_banned_extension(&extension)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if removed {
        notify_policy_change(&state).await;
        log_success(
            &state,
            user_id,
            "remove_banned_extension",
            &format!("extension:{extension}"),
            None,
        )
        .await
        .ok();
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn add_banned_extension(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddExtensionRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;
    if !user.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    drop(users);

    let extension = if !req.extension.starts_with('.') {
        format!(".{}", req.extension)
    } else {
        req.extension.clone()
    };

    let added = state
        .policy_engine
        .add_banned_extension(extension.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if added {
        let removed_count = clean_buckets_for_extension(&state, &extension).await;

        notify_policy_change(&state).await;

        log_success(
            &state,
            user_id,
            "add_banned_extension",
            &format!("extension:{}", extension),
            Some(serde_json::json!({
                "removed_objects": removed_count
            })),
        )
        .await
        .ok();

        Ok(Json(serde_json::json!({
            "status": "added",
            "extension": extension,
            "removed_objects": removed_count,
            "message": format!("Extension {} banned. {} objects removed from existing buckets", extension, removed_count)
        })))
    } else {
        Ok(Json(serde_json::json!({
            "status": "already_exists",
            "extension": extension
        })))
    }
}

async fn notify_policy_change(state: &Arc<AppState>) {
    let banned_extensions = state.policy_engine.get_banned_extensions().await;
    let agents = state.agents.read().await;
    let online_agents: Vec<String> = agents
        .values()
        .filter(|a| a.is_online)
        .map(|a| a.agent_id.clone())
        .collect();
    drop(agents);

    let mut buckets = state.buckets.write().await;
    let mut refreshed_count = 0;
    let mut total_removed = 0;

    for (_bucket_id, bucket) in buckets.iter_mut() {
        if bucket.is_online {
            let mut objects_to_remove = Vec::new();

            for (key, _) in &bucket.objects {
                for ext in &banned_extensions {
                    if should_filter_file(key, ext) {
                        objects_to_remove.push(key.clone());
                        break;
                    }
                }
            }

            for key in &objects_to_remove {
                bucket.objects.remove(key);
                total_removed += 1;
            }

            refreshed_count += 1;
        }
    }
}

async fn clean_buckets_for_extension(state: &Arc<AppState>, extension: &str) -> usize {
    let mut total_removed = 0;
    let mut buckets = state.buckets.write().await;

    for (bucket_id, bucket) in buckets.iter_mut() {
        let mut objects_to_remove = Vec::new();

        for (key, _object) in &bucket.objects {
            if should_filter_file(key, extension) {
                objects_to_remove.push(key.clone());
            }
        }

        for key in objects_to_remove {
            bucket.objects.remove(&key);
            total_removed += 1;

            state
                .staging_manager
                .remove_staged_file(bucket_id, &key)
                .await
                .ok();
        }
    }

    total_removed
}

fn should_filter_file(path: &str, extension: &str) -> bool {
    let path_lower = path.to_lowercase();
    let ext_lower = extension.to_lowercase();

    path_lower.contains(&ext_lower) || path_lower.ends_with(&ext_lower)
}

pub async fn clean_all_buckets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;
    if !user.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    drop(users);

    let banned_extensions = state.policy_engine.get_banned_extensions().await;

    let mut total_removed = 0;
    let mut buckets_cleaned = 0;

    {
        let mut buckets = state.buckets.write().await;

        for (bucket_id, bucket) in buckets.iter_mut() {
            let mut objects_to_remove = Vec::new();

            for (key, _) in &bucket.objects {
                for extension in &banned_extensions {
                    if should_filter_file(key, extension) {
                        objects_to_remove.push(key.clone());
                        break;
                    }
                }
            }

            if !objects_to_remove.is_empty() {
                buckets_cleaned += 1;
                for key in objects_to_remove {
                    bucket.objects.remove(&key);
                    total_removed += 1;

                    state
                        .staging_manager
                        .remove_staged_file(&bucket.id, &key)
                        .await
                        .ok();
                }
            }
        }
    }

    if total_removed > 0 {
        notify_policy_change(&state).await;
    }

    log_success(
        &state,
        user_id,
        "clean_all_buckets",
        "policy",
        Some(serde_json::json!({
            "objects_removed": total_removed,
            "buckets_affected": buckets_cleaned
        })),
    )
    .await
    .ok();

    Ok(Json(serde_json::json!({
        "status": "cleaned",
        "objects_removed": total_removed,
        "buckets_affected": buckets_cleaned,
        "banned_extensions": banned_extensions
    })))
}

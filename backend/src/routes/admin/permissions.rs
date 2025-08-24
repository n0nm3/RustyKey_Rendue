// backend/src/routes/admin/permissions.rs
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, extractors::*, models::*};

use crate::extractors::IntoStatus;

pub async fn list_user_permissions(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin(&state, &headers).await?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::NOT_FOUND)?;
    let perms = user
        .list_perm(None)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    drop(users);

    let buckets = state.buckets.read().await;

    let permissions: Vec<PermissionResponse> = perms
        .iter()
        .map(|perm| {
            let bucket_info = buckets.get(&perm.id);
            PermissionResponse {
                bucket_id: perm.id,
                bucket_name: format_bucket_name(&perm.id),
                read: perm.read,
                write: perm.write,
                delete: perm.delete,
                is_online: bucket_info.map(|b| b.is_online).unwrap_or(false),
            }
        })
        .collect();

    Ok(axum::Json(permissions))
}

pub async fn get_user_bucket_permission(
    State(state): State<Arc<AppState>>,
    Path((user_id, bucket_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin(&state, &headers).await?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::NOT_FOUND)?;

    let perms = user
        .list_perm(Some(bucket_id))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let permission = perms.first().ok_or(StatusCode::NOT_FOUND)?;

    let buckets = state.buckets.read().await;
    let bucket_info = buckets.get(&bucket_id);

    Ok(axum::Json(PermissionResponse {
        bucket_id: permission.id,
        bucket_name: format_bucket_name(&permission.id),
        read: permission.read,
        write: permission.write,
        delete: permission.delete,
        is_online: bucket_info.map(|b| b.is_online).unwrap_or(false),
    }))
}

pub async fn set_user_bucket_permission(
    State(state): State<Arc<AppState>>,
    Path((user_id, bucket_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<SetPermissionsRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let admin_id = verify_admin(&state, &headers).await?;

    get_bucket_verified(&state, &bucket_id).await?;

    state
        .update_perms(user_id, bucket_id, "read", request.read)
        .await
        .status_500()?;

    state
        .update_perms(user_id, bucket_id, "write", request.write)
        .await
        .status_500()?;

    state
        .update_perms(user_id, bucket_id, "delete", request.delete)
        .await
        .status_500()?;

    log_success(
        &state,
        admin_id,
        "set_permissions",
        &format!("user:{user_id}/bucket:{bucket_id}"),
        Some(serde_json::json!({
            "read": request.read,
            "write": request.write,
            "delete": request.delete
        })),
    )
    .await
    .ok();

    Ok(StatusCode::OK)
}

pub async fn delete_user_bucket_permission(
    State(state): State<Arc<AppState>>,
    Path((user_id, bucket_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let admin_id = verify_admin(&state, &headers).await?;

    state
        .update_perms(user_id, bucket_id, "read", false)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    state
        .update_perms(user_id, bucket_id, "write", false)
        .await
        .ok();

    state
        .update_perms(user_id, bucket_id, "delete", false)
        .await
        .ok();

    log_success(
        &state,
        admin_id,
        "delete_permissions",
        &format!("user:{user_id}/bucket:{bucket_id}"),
        None,
    )
    .await
    .ok();

    Ok(StatusCode::NO_CONTENT)
}

// backend/src/routes/admin/users.rs
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::extractors::IntoStatus;
use crate::{AppState, extractors::*, models::*};

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let admin_id = verify_admin(&state, &headers).await?;

    let users = state.users.read().await;
    let user_list: Vec<UserResponse> = users
        .values()
        .map(|u| UserResponse {
            user_id: u.user_id,
            name: u.name.clone(),
            is_admin: u.is_admin,
            permissions_count: u.perms.len(),
        })
        .collect();

    log_success(
        &state,
        admin_id,
        "list_users",
        "users",
        Some(serde_json::json!({ "count": user_list.len() })),
    )
    .await
    .ok();

    Ok(axum::Json(user_list))
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<CreateUserRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let admin_id = verify_admin(&state, &headers).await?;

    let new_user = state
        .add_user(request.name.clone(), request.is_admin)
        .await
        .status_500()?;

    log_success(
        &state,
        admin_id,
        "create_user",
        &format_resource("user", &new_user.user_id.to_string()),
        Some(serde_json::json!({
            "name": new_user.name,
            "is_admin": new_user.is_admin
        })),
    )
    .await
    .ok();

    Ok((
        StatusCode::CREATED,
        axum::Json(UserResponse {
            user_id: new_user.user_id,
            name: new_user.name,
            is_admin: new_user.is_admin,
            permissions_count: 0,
        }),
    ))
}

pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin(&state, &headers).await?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::NOT_FOUND)?;

    Ok(axum::Json(UserResponse {
        user_id: user.user_id,
        name: user.name.clone(),
        is_admin: user.is_admin,
        permissions_count: user.perms.len(),
    }))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(target_user_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let admin_id = verify_admin(&state, &headers).await?;

    state
        .del_user(target_user_id, admin_id)
        .await
        .map_err(|e| {
            eprintln!("Failed to delete user: {e}");
            match e.to_string().as_str() {
                "Cannot delete yourself" => StatusCode::FORBIDDEN,
                "Cannot delete the last admin" => StatusCode::FORBIDDEN,
                "User not found" => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        })?;

    log_success(
        &state,
        admin_id,
        "delete_user",
        &format_resource("user", &target_user_id.to_string()),
        None,
    )
    .await
    .ok();

    Ok(StatusCode::NO_CONTENT)
}

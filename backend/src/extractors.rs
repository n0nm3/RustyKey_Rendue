// backend/src/extractors.rs
use crate::{AppState, audit};
use anyhow::Result;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use common::{Operation, User};
use uuid::Uuid;

pub fn extract_user_id(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("X-User-Id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

pub async fn verify_admin(state: &AppState, headers: &HeaderMap) -> Result<Uuid, StatusCode> {
    let user_id = extract_user_id(headers).ok_or(StatusCode::UNAUTHORIZED)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;

    if !user.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(user_id)
}

pub fn parse_bucket_id(bucket_name: &str) -> Result<Uuid, StatusCode> {
    bucket_name
        .strip_prefix("usb-")
        .ok_or(StatusCode::BAD_REQUEST)?
        .parse::<Uuid>()
        .map_err(|_| StatusCode::BAD_REQUEST)
}

pub async fn check_permission(
    state: &AppState,
    user: &User,
    user_id: Uuid,
    bucket_id: &Uuid,
    operation: Operation,
    resource: &str,
) -> Result<(), StatusCode> {
    if user.is_admin {
        return Ok(());
    }

    if !user.has_permission(bucket_id, operation) {
        state
            .audit_log
            .log_unauthorized(user_id, &format!("{operation:?}").to_lowercase(), resource)
            .await
            .ok();
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(())
}

pub async fn log_success(
    state: &AppState,
    user_id: Uuid,
    action: &str,
    resource: &str,
    details: Option<serde_json::Value>,
) -> Result<()> {
    state
        .audit_log
        .log_event(audit::AuditEvent {
            timestamp: Utc::now(),
            user_id,
            session_id: Uuid::nil(),
            action: action.to_string(),
            resource: resource.to_string(),
            result: "success".to_string(),
            details,
        })
        .await
}

pub async fn log_and_error(
    state: &AppState,
    user_id: Uuid,
    action: &str,
    resource: &str,
    error: &str,
    status: StatusCode,
) -> StatusCode {
    state
        .audit_log
        .log_event(audit::AuditEvent {
            timestamp: Utc::now(),
            user_id,
            session_id: Uuid::nil(),
            action: action.to_string(),
            resource: resource.to_string(),
            result: "failed".to_string(),
            details: Some(serde_json::json!({ "error": error })),
        })
        .await
        .ok();

    status
}

pub async fn get_bucket_verified(state: &AppState, bucket_id: &Uuid) -> Result<bool, StatusCode> {
    let buckets = state.buckets.read().await;
    buckets
        .get(bucket_id)
        .map(|b| b.is_online)
        .ok_or(StatusCode::NOT_FOUND)
}

pub fn format_resource(resource_type: &str, id: &str) -> String {
    format!("{resource_type}:{id}")
}

pub fn format_bucket_resource(bucket_id: &Uuid) -> String {
    format!("bucket:usb-{bucket_id}")
}

pub fn format_object_resource(bucket_id: &Uuid, key: &str) -> String {
    format!("bucket:usb-{bucket_id}/object:{key}")
}

pub trait IntoStatus<T> {
    fn status_500(self) -> Result<T, StatusCode>;
}

impl<T, E> IntoStatus<T> for Result<T, E>
where
    E: std::fmt::Debug,
{
    fn status_500(self) -> Result<T, StatusCode> {
        self.map_err(|e| {
            eprintln!("Internal error: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }
}

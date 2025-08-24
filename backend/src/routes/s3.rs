// backend/src/routes/s3.rs
use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json;
use sha2::Digest;
use std::sync::Arc;

use crate::{AppState, extractors::*, models::*};
use common::Operation;

use crate::extractors::IntoStatus;

pub async fn list_buckets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;
    let is_admin = user.is_admin;
    let user_perms = user.perms.clone();
    drop(users);

    let buckets = state.buckets.read().await;

    let bucket_list: Vec<BucketInfo> = if is_admin {
        buckets.values().map(|b| b.to_bucket_info()).collect()
    } else {
        user_perms
            .iter()
            .filter_map(|perm| {
                if perm.read {
                    buckets.get(&perm.id).map(|b| b.to_bucket_info())
                } else {
                    None
                }
            })
            .collect()
    };

    log_success(
        &state,
        user_id,
        "list_buckets",
        "buckets",
        Some(serde_json::json!({ "count": bucket_list.len() })),
    )
    .await
    .ok();

    Ok(axum::Json(ListBucketsResponse {
        buckets: bucket_list,
    }))
}

pub async fn list_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket_name): Path<String>,
    Query(params): Query<ListObjectsQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let bucket_id = parse_bucket_id(&bucket_name)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;

    check_permission(
        &state,
        &user,
        user_id,
        &bucket_id,
        Operation::Read,
        &format_bucket_resource(&bucket_id),
    )
    .await?;
    drop(users);

    let buckets = state.buckets.read().await;
    let bucket = buckets.get(&bucket_id).ok_or(StatusCode::NOT_FOUND)?;

    let max_keys = params.max_keys.unwrap_or(1000).min(1000) as usize;
    let prefix = params.prefix.as_deref().unwrap_or("");

    let objects: Vec<ObjectInfo> = bucket
        .objects
        .values()
        .filter(|obj| obj.key.starts_with(prefix))
        .take(max_keys)
        .map(|obj| obj.to_object_info())
        .collect();

    log_success(
        &state,
        user_id,
        "list_objects",
        &format_bucket_resource(&bucket_id),
        Some(serde_json::json!({ "count": objects.len(), "prefix": prefix })),
    )
    .await
    .ok();

    Ok(axum::Json(ListObjectsResponse {
        contents: objects,
        is_truncated: false,
        max_keys: max_keys as i32,
    }))
}

pub async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let bucket_id = parse_bucket_id(&bucket_name)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;
    check_permission(
        &state,
        &user,
        user_id,
        &bucket_id,
        Operation::Read,
        &format_object_resource(&bucket_id, &key),
    )
    .await?;
    drop(users);

    let buckets = state.buckets.read().await;
    let bucket = buckets.get(&bucket_id).ok_or(StatusCode::NOT_FOUND)?;
    let object = bucket.objects.get(&key).ok_or(StatusCode::NOT_FOUND)?;

    let is_staged = object.is_staged;
    let is_online = bucket.is_online;
    let etag = object.etag.clone();
    let size = object.size;
    drop(buckets);

    let content = if is_staged {
        state
            .staging_manager
            .get_staged_content(&bucket_id, &key)
            .await
            .status_500()?
            .ok_or(StatusCode::NOT_FOUND)?
    } else if is_online {
        let request_id = format!("{}-{}", bucket_id, uuid::Uuid::new_v4());

        let command = common::Command::ReadFile {
            path: key.clone(),
            offset: 0,
            length: u64::MAX,
            request_id: request_id.clone(),
        };

        match state
            .command_queue
            .send_command_and_wait(
                bucket_id,
                command,
                request_id.clone(),
                std::time::Duration::from_secs(30),
            )
            .await
        {
            Ok(common::Response::FileContent {
                content,
                size: file_size,
                hash,
                ..
            }) => content,
            Ok(other) => {
                eprintln!("Unexpected response type: {:?}", other);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
            Err(e) => {
                eprintln!("Failed to get file from agent: {}", e);

                if e.to_string().contains("not found") || e.to_string().contains("File not found") {
                    return Err(StatusCode::NOT_FOUND);
                } else if e.to_string().contains("timeout") {
                    return Err(StatusCode::GATEWAY_TIMEOUT);
                }

                let buckets = state.buckets.read().await;
                if let Some(bucket) = buckets.get(&bucket_id) {
                    if let Some(obj) = bucket.objects.get(&key) {
                        if !obj.content.is_empty() {
                            obj.content.clone()
                        } else {
                            return Err(StatusCode::SERVICE_UNAVAILABLE);
                        }
                    } else {
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    }
                } else {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
            }
        }
    } else {
        eprintln!(
            "Bucket {} is offline and file {} is not staged",
            bucket_id, key
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };

    log_success(
        &state,
        user_id,
        "get_object",
        &format_object_resource(&bucket_id, &key),
        Some(serde_json::json!({
            "size": size,
            "etag": etag,
            "staged": is_staged,
            "from_agent": !is_staged && is_online,
            "actual_size": content.len(),
        })),
    )
    .await
    .ok();

    let mut response_headers = HeaderMap::new();
    response_headers.insert("ETag", etag.parse().unwrap());
    response_headers.insert("Content-Length", content.len().to_string().parse().unwrap());

    Ok((response_headers, content))
}

pub async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let bucket_id = parse_bucket_id(&bucket_name)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;

    check_permission(
        &state,
        &user,
        user_id,
        &bucket_id,
        Operation::Write,
        &format_object_resource(&bucket_id, &key),
    )
    .await?;
    drop(users);

    if let Err(e) = state.policy_engine.scan_content(&body).await {
        return Err(log_and_error(
            &state,
            user_id,
            "put_object",
            &format_object_resource(&bucket_id, &key),
            &e.to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await);
    }

    let etag = format!("{:x}", md5::compute(&body));
    let sha_file = format!("{:x}", sha2::Sha256::digest(&body));

    let is_online = get_bucket_verified(&state, &bucket_id).await?;

    state
        .staging_manager
        .stage_file(bucket_id, key.clone(), body.to_vec(), sha_file.clone())
        .await
        .status_500()?;

    let object = ObjectData::new_staged(key.clone(), body.len() as u64, etag.clone());

    let mut buckets = state.buckets.write().await;
    buckets
        .get_mut(&bucket_id)
        .ok_or(StatusCode::NOT_FOUND)?
        .objects
        .insert(key.clone(), object);
    drop(buckets);

    log_success(
        &state,
        user_id,
        "put_object",
        &format_object_resource(&bucket_id, &key),
        Some(serde_json::json!({
            "size": body.len(),
            "etag": etag,
            "staged": true,
            "device_online": is_online,
        })),
    )
    .await
    .ok();

    let mut response_headers = HeaderMap::new();
    response_headers.insert("ETag", etag.parse().unwrap());

    Ok((StatusCode::OK, response_headers))
}

pub async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let bucket_id = parse_bucket_id(&bucket_name)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;

    check_permission(
        &state,
        &user,
        user_id,
        &bucket_id,
        Operation::Delete,
        &format_object_resource(&bucket_id, &key),
    )
    .await?;
    drop(users);

    let is_online = get_bucket_verified(&state, &bucket_id).await?;

    state
        .staging_manager
        .stage_file(bucket_id, key.clone(), vec![], "DELETE".to_string())
        .await
        .status_500()?;

    let mut buckets = state.buckets.write().await;
    if let Some(bucket) = buckets.get_mut(&bucket_id) {
        if bucket.objects.remove(&key).is_some() {
            drop(buckets);

            log_success(
                &state,
                user_id,
                "delete_object",
                &format_object_resource(&bucket_id, &key),
                Some(serde_json::json!({
                    "staged": true,
                    "device_online": is_online,
                })),
            )
            .await
            .ok();

            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

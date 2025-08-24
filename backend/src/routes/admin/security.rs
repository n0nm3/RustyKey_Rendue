// backend/src/routes/admin/security.rs
use crate::{AppState, extractors::*, virustotal};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct CheckHashRequest {
    hash: String,
}

#[derive(Serialize)]
pub struct HashCheckResponse {
    hash: String,
    is_safe: bool,
    scan_date: Option<String>,
    detection_ratio: String,
    positives: u32,
    total: u32,
    permalink: Option<String>,
    message: String,
}

pub async fn check_file_hash(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CheckHashRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;
    if !user.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    drop(users);

    let api_key = state
        .config
        .virustotal_api_key
        .as_ref()
        .ok_or_else(|| {
            eprintln!("VirusTotal API key not configured in backend.conf");
            eprintln!("Add VIRUSTOTAL_API_KEY=your_key to /etc/rustykey/config/backend.conf");
            StatusCode::SERVICE_UNAVAILABLE
        })?
        .clone();

    let vt_client = virustotal::VirusTotalClient::new(api_key).map_err(|e| {
        eprintln!("Failed to create VirusTotal client: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match vt_client.check_file_hash(&req.hash).await {
        Ok(report) => {
            let message = if report.is_safe {
                if report.total == 0 {
                    "File has never been scanned by VirusTotal".to_string()
                } else {
                    format!("File is SAFE (0/{} detections)", report.total)
                }
            } else {
                format!(
                    "⚠️ File is MALICIOUS ({}/{} detections)",
                    report.positives, report.total
                )
            };

            log_success(
                &state,
                user_id,
                "check_file_hash",
                &format!("hash:{}", req.hash),
                Some(serde_json::json!({
                    "is_safe": report.is_safe,
                    "positives": report.positives,
                    "total": report.total,
                })),
            )
            .await
            .ok();

            Ok(Json(HashCheckResponse {
                hash: report.hash,
                is_safe: report.is_safe,
                scan_date: report.scan_date,
                detection_ratio: format!("{}/{}", report.positives, report.total),
                positives: report.positives,
                total: report.total,
                permalink: report.permalink,
                message,
            }))
        }
        Err(e) => {
            eprintln!("VirusTotal check failed: {}", e);

            if e.to_string().contains("404") || e.to_string().contains("NOT_FOUND") {
                Ok(Json(HashCheckResponse {
                    hash: req.hash.clone(),
                    is_safe: true,
                    scan_date: None,
                    detection_ratio: "0/0".to_string(),
                    positives: 0,
                    total: 0,
                    permalink: None,
                    message: "File not found in VirusTotal database (never scanned)".to_string(),
                }))
            } else {
                Err(StatusCode::BAD_GATEWAY)
            }
        }
    }
}

pub async fn check_object_safety(
    State(state): State<Arc<AppState>>,
    Path((bucket_name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let user_id = extract_user_id(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let bucket_id = crate::extractors::parse_bucket_id(&bucket_name)?;

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or(StatusCode::UNAUTHORIZED)?;

    if !user.is_admin && !user.has_permission(&bucket_id, common::Operation::Read) {
        return Err(StatusCode::FORBIDDEN);
    }
    drop(users);

    let api_key = state
        .config
        .virustotal_api_key
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .clone();

    let buckets = state.buckets.read().await;
    let bucket = buckets.get(&bucket_id).ok_or(StatusCode::NOT_FOUND)?;
    let object = bucket.objects.get(&key).ok_or(StatusCode::NOT_FOUND)?;
    let hash = object.etag.clone();
    drop(buckets);

    let vt_client = virustotal::VirusTotalClient::new(api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match vt_client.check_file_hash(&hash).await {
        Ok(report) => Ok(Json(serde_json::json!({
            "object": key,
            "hash": hash,
            "is_safe": report.is_safe,
            "scan_date": report.scan_date,
            "detections": format!("{}/{}", report.positives, report.total),
            "permalink": report.permalink,
        }))),
        Err(_) => Ok(Json(serde_json::json!({
            "object": key,
            "hash": hash,
            "is_safe": true,
            "message": "Could not verify with VirusTotal",
        }))),
    }
}

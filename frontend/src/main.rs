// frontend/src/main.rs - Version complète avec normalize_bucket_id

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use base64;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

#[derive(Clone)]
struct AppState {
    backend_url: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct ApiRequest {
    user_id: String,
    bucket_id: Option<String>,
    action: String,
    #[serde(flatten)]
    data: serde_json::Value,
}

// Helper function pour normaliser les bucket IDs
fn normalize_bucket_id(bucket_id: &str) -> String {
    if bucket_id.starts_with("usb-") {
        bucket_id.to_string()
    } else {
        format!("usb-{}", bucket_id)
    }
}

#[tokio::main]
async fn main() {
    let backend_url =
        std::env::var("BACKEND_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to create HTTP client");

    let state = Arc::new(AppState {
        backend_url: backend_url.clone(),
        client,
    });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/proxy", post(handle_api_proxy))
        .nest_service(
            "/static",
            ServeDir::new(concat!(env!("CARGO_MANIFEST_DIR"), "/static")),
        )
        .layer(CorsLayer::permissive())
        .with_state(state);

    println!("🚀 RustyKey Frontend starting on http://localhost:3000");
    println!("📡 Backend URL: {backend_url}");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn serve_index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn handle_api_proxy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ApiRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    println!(
        "📥 API Request: action={}, user_id={}, bucket_id={:?}",
        req.action, req.user_id, req.bucket_id
    );

    let result = match req.action.as_str() {
        // === S3 OPERATIONS ===
        "list_buckets" => {
            state
                .client
                .get(format!("{}/s3", state.backend_url))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        "list_objects" => {
            let bucket = req.bucket_id.ok_or(StatusCode::BAD_REQUEST)?;
            let normalized_bucket = normalize_bucket_id(&bucket);
            println!("  Normalized bucket: {}", normalized_bucket);

            state
                .client
                .get(format!("{}/s3/{}", state.backend_url, normalized_bucket))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        "get_object" => {
            let bucket = req.bucket_id.ok_or(StatusCode::BAD_REQUEST)?;
            let normalized_bucket = normalize_bucket_id(&bucket);
            let key = req.data["key"].as_str().ok_or(StatusCode::BAD_REQUEST)?;

            let response = state
                .client
                .get(format!(
                    "{}/s3/{}/{}",
                    state.backend_url, normalized_bucket, key
                ))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            if response.status().is_success() {
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let base64_content = base64::encode(&bytes);

                return Ok(Json(serde_json::json!({
                    "content": base64_content,
                    "size": bytes.len()
                })));
            } else {
                return Err(StatusCode::from_u16(response.status().as_u16())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
            }
        }
        "delete_object" => {
            let bucket = req.bucket_id.ok_or(StatusCode::BAD_REQUEST)?;
            let normalized_bucket = normalize_bucket_id(&bucket);
            let key = req.data["key"].as_str().ok_or(StatusCode::BAD_REQUEST)?;

            state
                .client
                .delete(format!(
                    "{}/s3/{}/{}",
                    state.backend_url, normalized_bucket, key
                ))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        "put_object" => {
            let bucket = req.bucket_id.ok_or(StatusCode::BAD_REQUEST)?;
            let normalized_bucket = normalize_bucket_id(&bucket);
            let key = req.data["key"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
            let content = req.data["content"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;
            let is_base64 = req.data["base64"].as_bool().unwrap_or(false);

            let bytes = if is_base64 {
                base64::decode(content).map_err(|_| StatusCode::BAD_REQUEST)?
            } else {
                content.as_bytes().to_vec()
            };

            state
                .client
                .put(format!(
                    "{}/s3/{}/{}",
                    state.backend_url, normalized_bucket, key
                ))
                .header("X-User-Id", &req.user_id)
                .header("Content-Type", "application/octet-stream")
                .body(bytes)
                .send()
                .await
        }

        // === USER MANAGEMENT ===
        "list_users" => {
            state
                .client
                .get(format!("{}/admin/users", state.backend_url))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        "create_user" => {
            let name = req.data["name"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
            let is_admin = req.data["is_admin"].as_bool().unwrap_or(false);

            state
                .client
                .post(format!("{}/admin/users", state.backend_url))
                .header("X-User-Id", &req.user_id)
                .json(&serde_json::json!({
                    "name": name,
                    "is_admin": is_admin
                }))
                .send()
                .await
        }
        "delete_user" => {
            let target_user = req.data["target_user_id"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;

            state
                .client
                .delete(format!("{}/admin/users/{}", state.backend_url, target_user))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }

        // === PERMISSIONS (avec normalize pour les buckets) ===
        "list_permissions" => {
            let target_user = req.data["target_user_id"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;
            state
                .client
                .get(format!(
                    "{}/admin/users/{}/permissions",
                    state.backend_url, target_user
                ))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        "set_permissions" => {
            let target_user = req.data["target_user_id"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;
            let target_bucket = req.data["target_bucket_id"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;

            // Normaliser seulement l'ID, pas pour l'API admin
            let target_bucket_clean = target_bucket.strip_prefix("usb-").unwrap_or(target_bucket);

            let perms = serde_json::json!({
                "read": req.data["read"].as_bool().unwrap_or(false),
                "write": req.data["write"].as_bool().unwrap_or(false),
                "delete": req.data["delete"].as_bool().unwrap_or(false),
            });

            state
                .client
                .put(format!(
                    "{}/admin/users/{}/permissions/{}",
                    state.backend_url, target_user, target_bucket_clean
                ))
                .header("X-User-Id", &req.user_id)
                .json(&perms)
                .send()
                .await
        }
        "revoke_permission" => {
            let target_user = req.data["target_user_id"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;
            let target_bucket = req.data["target_bucket_id"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;

            // Normaliser seulement l'ID, pas pour l'API admin
            let target_bucket_clean = target_bucket.strip_prefix("usb-").unwrap_or(target_bucket);

            state
                .client
                .delete(format!(
                    "{}/admin/users/{}/permissions/{}",
                    state.backend_url, target_user, target_bucket_clean
                ))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }

        // === AGENTS ===
        "list_agents" => {
            state
                .client
                .get(format!("{}/admin/agents", state.backend_url))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }

        // === POLICY (EXTENSIONS) ===
        "list_banned_extensions" => {
            state
                .client
                .get(format!("{}/admin/policy/extensions", state.backend_url))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        "add_banned_extension" => {
            let extension = req.data["extension"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;

            state
                .client
                .post(format!("{}/admin/policy/extensions", state.backend_url))
                .header("X-User-Id", &req.user_id)
                .json(&serde_json::json!({ "extension": extension }))
                .send()
                .await
        }
        "remove_banned_extension" => {
            let extension = req.data["extension"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;

            let ext_clean = extension.trim_start_matches('.');

            state
                .client
                .delete(format!(
                    "{}/admin/policy/extensions/{}",
                    state.backend_url, ext_clean
                ))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        // === VIRUSTOTAL ===
        "check_file_hash" => {
            let hash = req.data["hash"].as_str().ok_or(StatusCode::BAD_REQUEST)?;

            state
                .client
                .post(format!("{}/admin/security/check-hash", state.backend_url))
                .header("X-User-Id", &req.user_id)
                .json(&serde_json::json!({ "hash": hash }))
                .send()
                .await
        }
        "check_object_safety" => {
            let bucket = req.data["bucket_id"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;
            let normalized_bucket = normalize_bucket_id(bucket);
            let object_key = req.data["object_key"]
                .as_str()
                .ok_or(StatusCode::BAD_REQUEST)?;

            state
                .client
                .get(format!(
                    "{}/admin/security/check-object/{}/{}",
                    state.backend_url, normalized_bucket, object_key
                ))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        "clean_buckets" => {
            state
                .client
                .post(format!("{}/admin/policy/clean", state.backend_url))
                .header("X-User-Id", &req.user_id)
                .send()
                .await
        }
        _ => {
            eprintln!("❌ Unknown action: {}", req.action);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Log le résultat sans causer d'erreur de type
    if result.is_ok() {
        println!("✅ Backend request sent successfully");
    } else {
        eprintln!("❌ Request to backend failed");
    }

    match result {
        Ok(response) => {
            if response.status().is_success() {
                let data = response
                    .json::<serde_json::Value>()
                    .await
                    .unwrap_or(serde_json::json!({"status": "ok"}));
                Ok(Json(data))
            } else {
                Err(StatusCode::from_u16(response.status().as_u16()).unwrap())
            }
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

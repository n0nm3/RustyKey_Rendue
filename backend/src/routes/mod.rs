// backend/src/routes/mod.rs
use crate::AppState;
use admin::policy::*;
use axum::{
    Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;

pub mod admin;
pub mod agent;
pub mod s3;

use crate::routes::admin::security::check_file_hash;
use crate::routes::admin::security::check_object_safety;

pub fn configure_routes(state: Arc<AppState>) -> Router {
    let s3_routes = Router::new()
        .route("/", get(s3::list_buckets))
        .route("/{bucket}", get(s3::list_objects))
        .route("/{bucket}/{key}", get(s3::get_object))
        .route("/{bucket}/{key}", put(s3::put_object))
        .route("/{bucket}/{key}", delete(s3::delete_object));

    let admin_routes = Router::new()
        .route("/users", get(admin::users::list_users))
        .route("/users", post(admin::users::create_user))
        .route("/users/{user_id}", get(admin::users::get_user))
        .route("/users/{user_id}", delete(admin::users::delete_user))
        .route(
            "/users/{user_id}/permissions",
            get(admin::permissions::list_user_permissions),
        )
        .route(
            "/users/{user_id}/permissions/{bucket_id}",
            get(admin::permissions::get_user_bucket_permission),
        )
        .route(
            "/users/{user_id}/permissions/{bucket_id}",
            put(admin::permissions::set_user_bucket_permission),
        )
        .route(
            "/users/{user_id}/permissions/{bucket_id}",
            delete(admin::permissions::delete_user_bucket_permission),
        )
        .route("/agents", get(admin::agents::list_agents))
        .route("/agents/{agent_id}", get(admin::agents::get_agent))
        .route("/agents/{agent_id}", put(admin::agents::update_agent))
        .route("/agents/{agent_id}", delete(admin::agents::delete_agent))
        .route(
            "/agents/{agent_id}/buckets",
            get(admin::agents::list_agent_buckets),
        );

    Router::new()
        .nest("/s3", s3_routes)
        .nest("/admin", admin_routes)
        .route("/agent/register", post(agent::register_agent))
        .route("/agent/connect", post(agent::handle_agent_connection))
        .route("/agent/manifest", post(agent::handle_agent_manifest))
        .route("/agent/disconnect", post(agent::handle_agent_disconnection))
        .route("/agent/command", post(agent::handle_agent_command))
        .route(
            "/agent/confirm_write",
            post(agent::handle_write_confirmation),
        )
        .route(
            "/agent/staged/{bucket_id}/{*path}",
            get(agent::handle_get_staged_file),
        )
        .route("/agent/policy", post(agent::check_policy_update))
        .route("/admin/policy/extensions", get(list_banned_extensions))
        .route("/admin/policy/extensions", post(add_banned_extension))
        .route(
            "/admin/policy/extensions/{ext}",
            delete(remove_banned_extension),
        )
        .route("/admin/policy/clean", post(clean_all_buckets))
        .route("/admin/security/check-hash", post(check_file_hash))
        .route(
            "/admin/security/check-object/{bucket}/{key}",
            get(check_object_safety),
        )
        .route(
            "/agent/poll-commands/{bucket_id}",
            get(agent::poll_commands),
        )
        .route("/agent/file-response", post(agent::file_response))
        .with_state(state)
}

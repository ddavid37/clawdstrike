//! HTTP API for the package registry.

pub mod attestation;
pub mod audit;
pub mod checkpoint;
pub mod download;
pub mod health;
pub mod index;
pub mod info;
pub mod org;
pub mod proof;
pub mod publish;
pub mod search;
pub mod yank;

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::auth::require_publish_auth;
use crate::state::AppState;

/// Create the top-level router for the registry.
pub fn create_router(state: AppState) -> Router {
    let max_upload = state.config.max_upload_bytes;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no auth required).
    let public_routes = Router::new()
        .route("/health", get(health::health))
        .route("/api/v1/packages/{name}", get(info::package_info))
        .route("/api/v1/packages/{name}/{version}", get(info::version_info))
        .route(
            "/api/v1/packages/{name}/{version}/download",
            get(download::download),
        )
        .route("/api/v1/search", get(search::search))
        .route("/api/v1/index/{name}", get(index::sparse_index))
        .route(
            "/api/v1/packages/{name}/{version}/attestation",
            get(attestation::get_attestation),
        )
        .route(
            "/api/v1/packages/{name}/{version}/proof",
            get(proof::get_proof),
        )
        .route(
            "/api/v1/transparency/checkpoint",
            get(checkpoint::get_checkpoint),
        )
        .route("/api/v1/audit/{name}", get(audit::get_audit))
        // Organization public endpoints.
        .route("/api/v1/orgs/{name}", get(org::get_org))
        .route("/api/v1/orgs/{name}/packages", get(org::list_org_packages));

    // Authenticated routes (publish, yank, org management).
    let auth_routes = Router::new()
        .route("/api/v1/packages", post(publish::publish))
        .route("/api/v1/packages/{name}/{version}", delete(yank::yank))
        .route("/api/v1/orgs", post(org::create_org))
        .route(
            "/api/v1/orgs/{name}/members",
            get(org::list_members).post(org::invite_member),
        )
        .route(
            "/api/v1/orgs/{name}/members/{key}",
            delete(org::remove_member),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_publish_auth,
        ));

    Router::new()
        .merge(public_routes)
        .merge(auth_routes)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(max_upload))
        .with_state(state)
}

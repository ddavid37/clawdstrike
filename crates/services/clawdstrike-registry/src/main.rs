#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::net::SocketAddr;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod attestation;
mod auth;
mod config;
mod db;
mod error;
mod index;
mod keys;
mod state;
mod storage;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clawdstrike_registry=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    let port = config.port;
    let host = config.host.clone();

    let state = AppState::new(config)?;

    let app = api::create_router(state);

    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    tracing::info!(%addr, "Starting clawdstrike-registry");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

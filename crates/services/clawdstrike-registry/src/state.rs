//! Shared application state for the registry service.

use std::sync::{Arc, Mutex};

use hush_core::Keypair;

use crate::config::Config;
use crate::db::RegistryDb;
use crate::error::RegistryError;
use crate::keys::RegistryKeyManager;
use crate::storage::BlobStorage;

/// Shared application state, cheaply cloneable via `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<Mutex<RegistryDb>>,
    pub blobs: Arc<BlobStorage>,
    pub registry_keypair: Arc<Keypair>,
    pub key_manager: Arc<Mutex<RegistryKeyManager>>,
}

impl AppState {
    /// Initialize application state from config.
    ///
    /// Creates directories, opens the database, and loads or generates the
    /// registry Ed25519 keypair.
    pub fn new(config: Config) -> anyhow::Result<Self> {
        // Ensure directories exist.
        std::fs::create_dir_all(config.data_dir.clone())?;
        std::fs::create_dir_all(config.index_dir())?;
        std::fs::create_dir_all(config.keys_dir())?;

        // Open database.
        let db = RegistryDb::open(&config.db_path())?;

        // Open blob storage.
        let blobs = BlobStorage::new(config.blob_dir())?;

        // Load or generate registry keypair.
        let keypair = load_or_generate_keypair(&config)?;
        tracing::info!(
            public_key = %keypair.public_key().to_hex(),
            "Registry keypair loaded"
        );

        // Initialize key manager with the loaded keypair.
        let key_manager = RegistryKeyManager::new(keypair.clone());

        // Ensure the initial key is recorded in the database.
        let key_info = key_manager.current_key();
        db.upsert_registry_key(key_info)?;

        Ok(Self {
            config: Arc::new(config),
            db: Arc::new(Mutex::new(db)),
            blobs: Arc::new(blobs),
            registry_keypair: Arc::new(keypair),
            key_manager: Arc::new(Mutex::new(key_manager)),
        })
    }
}

/// Load the registry keypair from disk, or generate a new one.
fn load_or_generate_keypair(config: &Config) -> anyhow::Result<Keypair> {
    let key_path = config.keys_dir().join("registry.key");
    let pub_path = config.keys_dir().join("registry.pub");

    if key_path.exists() {
        let hex = std::fs::read_to_string(&key_path)?.trim().to_string();
        let keypair = Keypair::from_hex(&hex)
            .map_err(|e| RegistryError::Internal(format!("failed to load registry key: {e}")))?;
        Ok(keypair)
    } else {
        let keypair = Keypair::generate();
        std::fs::write(&key_path, keypair.to_hex())?;
        std::fs::write(&pub_path, keypair.public_key().to_hex())?;
        tracing::info!("Generated new registry keypair");
        Ok(keypair)
    }
}

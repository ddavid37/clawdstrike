//! Shared application state for the registry service.

use std::sync::{Arc, Mutex};

use clawdstrike::pkg::merkle::{LeafData, MerkleTree};
use hush_core::Keypair;

use crate::config::Config;
use crate::db::RegistryDb;
use crate::error::RegistryError;
use crate::keys::RegistryKeyManager;
use crate::oidc::JwksCache;
use crate::storage::BlobStorage;

/// Shared application state, cheaply cloneable via `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<Mutex<RegistryDb>>,
    pub blobs: Arc<BlobStorage>,
    pub registry_keypair: Arc<Keypair>,
    pub key_manager: Arc<Mutex<RegistryKeyManager>>,
    pub merkle_tree: Arc<Mutex<MerkleTree>>,
    pub jwks_cache: Arc<Mutex<JwksCache>>,
}

impl AppState {
    /// Initialize application state from config.
    ///
    /// Creates directories, opens the database, and loads or generates the
    /// registry Ed25519 keypair. Rebuilds the Merkle tree from existing
    /// version rows.
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

        // Rebuild the Merkle tree from existing version rows.
        let mut tree = MerkleTree::new();
        let versions = db.list_all_versions_ordered()?;
        for v in &versions {
            let leaf_data = LeafData {
                package_name: v.name.clone(),
                version: v.version.clone(),
                content_hash: v.checksum.clone(),
                publisher_key: v.publisher_key.clone(),
                timestamp: v.published_at.clone(),
            };
            let leaf_hash = leaf_data.leaf_hash().map_err(|e| {
                RegistryError::Internal(format!("failed to compute leaf hash on rebuild: {e}"))
            })?;
            tree.append_hash(leaf_hash);
        }
        tracing::info!(
            tree_size = tree.tree_size(),
            "Merkle tree rebuilt from existing versions"
        );

        Ok(Self {
            config: Arc::new(config),
            db: Arc::new(Mutex::new(db)),
            blobs: Arc::new(blobs),
            registry_keypair: Arc::new(keypair),
            key_manager: Arc::new(Mutex::new(key_manager)),
            merkle_tree: Arc::new(Mutex::new(tree)),
            jwks_cache: Arc::new(Mutex::new(JwksCache::new())),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(dir: &std::path::Path) -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 0,
            data_dir: dir.to_path_buf(),
            api_key: String::new(),
            max_upload_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn app_state_new_creates_dirs_and_keypair() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path());
        let state = AppState::new(cfg).unwrap();
        assert!(state.config.db_path().exists());
        assert!(state.config.blob_dir().exists());
        assert!(state.config.index_dir().exists());
        assert!(state.config.keys_dir().join("registry.key").exists());
        assert!(state.config.keys_dir().join("registry.pub").exists());
        assert_eq!(state.merkle_tree.lock().unwrap().tree_size(), 0);
    }

    #[test]
    fn load_or_generate_keypair_is_stable_across_reloads() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path());
        std::fs::create_dir_all(cfg.keys_dir()).unwrap();
        let first = load_or_generate_keypair(&cfg).unwrap();
        let second = load_or_generate_keypair(&cfg).unwrap();
        assert_eq!(first.public_key().to_hex(), second.public_key().to_hex());
    }
}

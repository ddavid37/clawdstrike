//! GET /api/v1/transparency/checkpoint
//!
//! Returns the latest transparency log checkpoint: Merkle root, tree size,
//! and registry signature over the checkpoint data.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::error::RegistryError;
use crate::state::AppState;

/// Transparency log checkpoint.
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointResponse {
    /// Hex-encoded Merkle root hash.
    pub root: String,
    /// Number of leaves in the tree.
    pub tree_size: u64,
    /// ISO-8601 timestamp of the checkpoint.
    pub timestamp: String,
    /// Hex-encoded registry Ed25519 signature over `root || tree_size || timestamp`.
    pub registry_sig: String,
    /// Hex-encoded registry public key for verification.
    pub registry_key: String,
}

/// GET /api/v1/transparency/checkpoint
///
/// Returns the latest checkpoint. The Merkle tree integration is built by
/// Stream 1. For now, this returns a signed checkpoint with an empty tree.
/// During synthesis, this will be wired to the actual Merkle tree state.
pub async fn get_checkpoint(
    State(state): State<AppState>,
) -> Result<Json<CheckpointResponse>, RegistryError> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let tree_size: u64 = 0;

    // Build the checkpoint message: root || tree_size || timestamp
    // For an empty tree, the root is the zero hash.
    let root_hex = "0".repeat(64);
    let checkpoint_msg = format!("{root_hex}{tree_size}{timestamp}");

    let signature = state.registry_keypair.sign(checkpoint_msg.as_bytes());
    let sig_hex = signature.to_hex();
    let key_hex = state.registry_keypair.public_key().to_hex();

    Ok(Json(CheckpointResponse {
        root: root_hex,
        tree_size,
        timestamp,
        registry_sig: sig_hex,
        registry_key: key_hex,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_response_serializes() {
        let resp = CheckpointResponse {
            root: "a".repeat(64),
            tree_size: 100,
            timestamp: "2026-02-25T10:00:00Z".into(),
            registry_sig: "sig_hex".into(),
            registry_key: "key_hex".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["tree_size"], 100);
        assert!(json["root"].as_str().unwrap().len() == 64);
    }
}

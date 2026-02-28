//! GET /api/v1/packages/{name}/{version}/proof
//!
//! Returns the Merkle inclusion proof for a specific package version.
//! The proof can be verified against the transparency log checkpoint.

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;

use crate::error::RegistryError;
use crate::state::AppState;

fn checkpoint_signature_message(root: &str, tree_size: u64, timestamp: &str) -> String {
    format!("clawdstrike-checkpoint:v1:{root}:{tree_size}:{timestamp}")
}

/// Merkle inclusion proof for a published package version.
#[derive(Clone, Debug, Serialize)]
pub struct InclusionProofResponse {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Index of the leaf in the Merkle tree.
    pub leaf_index: u64,
    /// Size of the tree at the time of inclusion.
    pub tree_size: u64,
    /// Sibling hashes for the Merkle path (hex-encoded).
    pub hashes: Vec<String>,
    /// Hex-encoded Merkle root for `tree_size`.
    pub root: String,
    /// RFC-3339 checkpoint timestamp for `root` and `tree_size`.
    pub checkpoint_timestamp: String,
    /// Registry signature over `clawdstrike-checkpoint:v1:{root}:{tree_size}:{checkpoint_timestamp}`.
    pub checkpoint_sig: String,
    /// Registry public key used for `checkpoint_sig`.
    pub checkpoint_key: String,
}

/// GET /api/v1/packages/{name}/{version}/proof
///
/// Returns a Merkle inclusion proof if the package version has been included
/// in the transparency log. Returns 404 if the proof is not yet available.
pub async fn get_proof(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<InclusionProofResponse>, RegistryError> {
    // Look up the version and its leaf_index.
    let leaf_index = {
        let db = state
            .db
            .lock()
            .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

        let v = db.get_version(&name, &version)?.ok_or_else(|| {
            RegistryError::NotFound(format!("version {version} of {name} not found"))
        })?;

        v.leaf_index.ok_or_else(|| {
            RegistryError::NotFound(format!(
                "inclusion proof for {name}@{version} not yet available (legacy version)"
            ))
        })?
    };

    // Generate the inclusion proof from the Merkle tree.
    let tree = state
        .merkle_tree
        .lock()
        .map_err(|e| RegistryError::Internal(format!("merkle_tree lock poisoned: {e}")))?;

    let proof = tree
        .generate_inclusion_proof(leaf_index)
        .map_err(|e| RegistryError::Internal(format!("failed to generate inclusion proof: {e}")))?;
    let root = tree
        .root()
        .map_err(|e| RegistryError::Internal(format!("failed to compute merkle root: {e}")))?;
    drop(tree);

    let checkpoint_timestamp = chrono::Utc::now().to_rfc3339();
    let checkpoint_message =
        checkpoint_signature_message(&root, proof.tree_size, &checkpoint_timestamp);
    let checkpoint_sig = state
        .registry_keypair
        .sign(checkpoint_message.as_bytes())
        .to_hex();
    let checkpoint_key = state.registry_keypair.public_key().to_hex();

    Ok(Json(InclusionProofResponse {
        name,
        version,
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        hashes: proof.proof_path,
        root,
        checkpoint_timestamp,
        checkpoint_sig,
        checkpoint_key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusion_proof_serializes() {
        let proof = InclusionProofResponse {
            name: "@acme/guard".into(),
            version: "1.0.0".into(),
            leaf_index: 42,
            tree_size: 100,
            hashes: vec!["aabb".into(), "ccdd".into()],
            root: "a".repeat(64),
            checkpoint_timestamp: "2026-02-28T00:00:00Z".into(),
            checkpoint_sig: "sig".into(),
            checkpoint_key: "key".into(),
        };
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(json["leaf_index"], 42);
        assert_eq!(json["hashes"].as_array().unwrap().len(), 2);
        assert_eq!(json["root"].as_str().unwrap().len(), 64);
    }
}

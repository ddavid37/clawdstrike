//! GET /api/v1/packages/{name}/{version}/proof
//!
//! Returns the Merkle inclusion proof for a specific package version.
//! The proof can be verified against the transparency log checkpoint.

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;

use crate::error::RegistryError;
use crate::state::AppState;

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
}

/// GET /api/v1/packages/{name}/{version}/proof
///
/// Returns a Merkle inclusion proof if the package version has been included
/// in the transparency log. Returns 404 if the proof is not yet available.
pub async fn get_proof(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<InclusionProofResponse>, RegistryError> {
    // First verify the package version exists.
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let _v = db
        .get_version(&name, &version)?
        .ok_or_else(|| RegistryError::NotFound(format!("version {version} of {name} not found")))?;

    // The transparency log integration is built by Stream 1 (merkle-agent).
    // For now, return a placeholder that indicates the proof is not yet available.
    // During synthesis, this will be wired to the actual Merkle tree.
    Err(RegistryError::NotFound(format!(
        "inclusion proof for {name}@{version} not yet available"
    )))
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
        };
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(json["leaf_index"], 42);
        assert_eq!(json["hashes"].as_array().unwrap().len(), 2);
    }
}

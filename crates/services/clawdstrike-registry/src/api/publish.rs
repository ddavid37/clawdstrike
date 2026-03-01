//! POST /api/v1/packages — publish a new package version.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use clawdstrike::pkg::merkle::LeafData;
use hush_core::{PublicKey, Signature};

use crate::attestation;
use crate::db::VersionRow;
use crate::error::RegistryError;
use crate::index;
use crate::state::AppState;

/// Extract the OIDC provider hint from request headers.
fn extract_oidc_provider(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("X-Clawdstrike-Oidc-Provider")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[derive(Deserialize)]
pub struct PublishRequest {
    /// Base64-encoded .cpkg archive bytes.
    pub archive_base64: String,
    /// Hex-encoded Ed25519 publisher public key.
    pub publisher_key: String,
    /// Hex-encoded Ed25519 signature over the SHA-256 hash of the archive.
    pub publisher_sig: String,
    /// Raw TOML manifest content (`clawdstrike-pkg.toml`).
    pub manifest_toml: String,
}

#[derive(Debug, Serialize)]
pub struct PublishResponse {
    pub name: String,
    pub version: String,
    pub checksum: String,
    pub registry_sig: String,
    pub registry_key: String,
    pub attestation_hash: Option<String>,
    pub key_id: Option<String>,
}

fn extract_embedded_manifest_toml(archive_bytes: &[u8]) -> Result<String, RegistryError> {
    let scratch = tempfile::Builder::new()
        .prefix("clawdstrike_registry_publish_")
        .tempdir()
        .map_err(|e| {
            RegistryError::Internal(format!("failed to create publish scratch dir: {e}"))
        })?;

    let archive_path = scratch.path().join("upload.cpkg");
    std::fs::write(&archive_path, archive_bytes).map_err(|e| {
        RegistryError::BadRequest(format!("failed to stage uploaded archive bytes: {e}"))
    })?;

    let unpack_dir = scratch.path().join("unpacked");
    clawdstrike::pkg::archive::unpack(&archive_path, &unpack_dir)
        .map_err(|e| RegistryError::BadRequest(format!("invalid .cpkg archive payload: {e}")))?;

    let manifest_path = unpack_dir.join("clawdstrike-pkg.toml");
    std::fs::read_to_string(&manifest_path).map_err(|e| {
        RegistryError::BadRequest(format!(
            "uploaded archive missing clawdstrike-pkg.toml ({}): {e}",
            manifest_path.display()
        ))
    })
}

fn manifests_match(
    request_manifest: &clawdstrike::pkg::manifest::PkgManifest,
    embedded_manifest: &clawdstrike::pkg::manifest::PkgManifest,
) -> Result<bool, RegistryError> {
    let req = serde_json::to_value(request_manifest).map_err(|e| {
        RegistryError::Internal(format!("failed to serialize request manifest: {e}"))
    })?;
    let emb = serde_json::to_value(embedded_manifest).map_err(|e| {
        RegistryError::Internal(format!("failed to serialize embedded manifest: {e}"))
    })?;
    Ok(req == emb)
}

/// POST /api/v1/packages
pub async fn publish(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, RegistryError> {
    // 1. Decode archive bytes.
    use base64::Engine as _;
    let archive_bytes = base64::engine::general_purpose::STANDARD
        .decode(&req.archive_base64)
        .map_err(|e| RegistryError::BadRequest(format!("invalid base64 archive: {e}")))?;

    // 2. Parse and validate both the request-body manifest and the embedded
    // archive manifest, then enforce semantic equality.
    let request_manifest = clawdstrike::pkg::manifest::parse_pkg_manifest_toml(&req.manifest_toml)
        .map_err(|e| RegistryError::BadRequest(format!("invalid request manifest: {e}")))?;
    let embedded_manifest_toml = extract_embedded_manifest_toml(&archive_bytes)?;
    let embedded_manifest =
        clawdstrike::pkg::manifest::parse_pkg_manifest_toml(&embedded_manifest_toml)
            .map_err(|e| RegistryError::BadRequest(format!("invalid archive manifest: {e}")))?;
    if !manifests_match(&request_manifest, &embedded_manifest)? {
        return Err(RegistryError::BadRequest(
            "request manifest does not match embedded archive manifest".into(),
        ));
    }
    let manifest = embedded_manifest;

    let name = manifest.package.name.clone();
    let version = manifest.package.version.clone();

    // 1a. OIDC trusted publisher validation (when using CI/CD identity tokens).
    let is_oidc = headers
        .get("X-Clawdstrike-Auth-Type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("oidc"))
        .unwrap_or(false);

    if is_oidc {
        let oidc_token = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|h| {
                if h.len() > 7 && h[..7].eq_ignore_ascii_case("Bearer ") {
                    Some(h[7..].to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                RegistryError::Unauthorized("missing bearer token for OIDC auth".into())
            })?;

        let provider = extract_oidc_provider(&headers).unwrap_or_else(|| "github".to_string());

        let claims = crate::oidc::validate_oidc_token(&oidc_token, &provider, &state.jwks_cache)?;

        let db = state
            .db
            .lock()
            .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;
        let trusted_publishers = db.get_trusted_publishers(&name)?;
        drop(db);

        let matched = crate::oidc::match_trusted_publisher(&claims, &trusted_publishers)?;

        tracing::info!(
            package = %name,
            provider = %claims.provider(),
            repository = %claims.repository(),
            publisher_id = matched.id,
            "OIDC trusted publisher matched"
        );
    }

    // 1b. Package authorization (for non-OIDC publishes).
    //
    // - Scoped packages: caller must be org owner/maintainer for @scope.
    // - Unscoped packages:
    //   - First publish (package does not exist yet): allowed.
    //   - Existing package: caller must be an existing package publisher.
    if !is_oidc {
        let db = state
            .db
            .lock()
            .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

        if let Some((scope, _basename)) = crate::auth::parse_package_scope(&name) {
            crate::auth::authorize_scoped_publish(&db, &scope, &req.publisher_key)?;
        } else if db.get_package(&name)?.is_some() {
            crate::auth::authorize_unscoped_package_admin(&db, &name, &req.publisher_key)?;
        }

        drop(db);
    }

    // 3. Compute SHA-256 of the archive.
    let checksum = hush_core::sha256_hex(&archive_bytes);

    // 4. Verify publisher signature.
    let publisher_key = PublicKey::from_hex(&req.publisher_key)
        .map_err(|e| RegistryError::BadRequest(format!("invalid publisher key: {e}")))?;
    let publisher_sig = Signature::from_hex(&req.publisher_sig)
        .map_err(|e| RegistryError::BadRequest(format!("invalid publisher signature: {e}")))?;

    let hash = hush_core::sha256(&archive_bytes);
    if !publisher_key.verify(hash.as_bytes(), &publisher_sig) {
        return Err(RegistryError::Integrity(
            "publisher signature verification failed".into(),
        ));
    }

    // 5. Counter-sign with registry keypair.
    let registry_sig = state.registry_keypair.sign(hash.as_bytes());
    let registry_sig_hex = registry_sig.to_hex();
    let registry_key_hex = state.registry_keypair.public_key().to_hex();

    // 6. Store blob.
    state.blobs.store_with_hash(&archive_bytes, &checksum)?;

    // 7. Serialize dependencies JSON.
    let deps_json = serde_json::to_string(&manifest.dependencies)
        .map_err(|e| RegistryError::Internal(format!("failed to serialize deps: {e}")))?;

    let now = chrono::Utc::now().to_rfc3339();

    let leaf_data = LeafData {
        package_name: name.clone(),
        version: version.clone(),
        content_hash: checksum.clone(),
        publisher_key: req.publisher_key.clone(),
        timestamp: now.clone(),
    };
    let leaf_hash = leaf_data
        .leaf_hash()
        .map_err(|e| RegistryError::Internal(format!("failed to compute leaf hash: {e}")))?;

    // Serialize publishes on the DB mutex so leaf index reservation stays
    // deterministic without holding the Merkle tree lock across DB I/O.
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let leaf_index = {
        let tree = state
            .merkle_tree
            .lock()
            .map_err(|e| RegistryError::Internal(format!("merkle_tree lock poisoned: {e}")))?;
        tree.tree_size()
    };

    // 8a. Create publish attestation with reserved leaf_index.
    let (attestation_hash, key_id) = {
        let key_mgr = state
            .key_manager
            .lock()
            .map_err(|e| RegistryError::Internal(format!("key_manager lock poisoned: {e}")))?;

        let current = key_mgr.current_key();
        let current_keypair = key_mgr.current_keypair();
        let kid = current.key_id.clone();

        let att = attestation::create_publish_attestation(&attestation::AttestationInput {
            package_name: &name,
            version: &version,
            publisher_key: &req.publisher_key,
            publisher_signature: &req.publisher_sig,
            content_hash: &checksum,
            registry_signature: &registry_sig_hex,
            leaf_index: Some(leaf_index),
            timestamp: &now,
        });

        let signed = attestation::sign_attestation(&att, current_keypair, &kid)?;
        let att_hash = signed.attestation.hash()?;
        (att_hash, kid)
    };

    // 9. Upsert package + insert version (under lock). If this fails, no tree
    // append occurs, preserving DB/log consistency.
    db.upsert_package(&name, manifest.package.description.as_deref(), &now)?;

    db.insert_version(&VersionRow {
        name: name.clone(),
        version: version.clone(),
        pkg_type: manifest.package.pkg_type.to_string(),
        checksum: checksum.clone(),
        manifest_toml: embedded_manifest_toml,
        publisher_key: req.publisher_key.clone(),
        publisher_sig: req.publisher_sig.clone(),
        registry_sig: Some(registry_sig_hex.clone()),
        dependencies_json: deps_json,
        yanked: false,
        published_at: now,
        attestation_hash: Some(attestation_hash.clone()),
        key_id: Some(key_id.clone()),
        leaf_index: Some(leaf_index),
        download_count: 0,
    })?;

    // 10. Update sparse index.
    index::update_index(&db, &state.config.index_dir(), &name)?;

    // 11. Append to Merkle tree only after DB + index commit succeeds.
    let appended_index = {
        let mut tree = state
            .merkle_tree
            .lock()
            .map_err(|e| RegistryError::Internal(format!("merkle_tree lock poisoned: {e}")))?;
        tree.append_hash(leaf_hash)
    };
    if appended_index != leaf_index {
        return Err(RegistryError::Internal(format!(
            "reserved leaf index mismatch: expected {leaf_index}, got {appended_index}"
        )));
    }

    tracing::info!(name = %name, version = %version, checksum = %checksum, leaf_index = leaf_index, "Package published");

    Ok(Json(PublishResponse {
        name,
        version,
        checksum,
        registry_sig: registry_sig_hex,
        registry_key: registry_key_hex,
        attestation_hash: Some(attestation_hash),
        key_id: Some(key_id),
    }))
}

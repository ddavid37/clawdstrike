//! API key validation middleware for publish/yank operations.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use hush_core::{PublicKey, Signature};

use crate::db::RegistryDb;
use crate::error::RegistryError;
use crate::state::AppState;

const CALLER_KEY_HEADER: &str = "X-Clawdstrike-Caller-Key";
const CALLER_SIG_HEADER: &str = "X-Clawdstrike-Caller-Sig";
const CALLER_TS_HEADER: &str = "X-Clawdstrike-Caller-Ts";
const MAX_CALLER_CLOCK_SKEW_SECS: i64 = 300;

/// Extract bearer token from the Authorization header.
fn extract_bearer_token(req: &Request<Body>) -> Option<String> {
    let header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())?;

    if header.len() > 7 {
        let prefix = &header[..7];
        if prefix.eq_ignore_ascii_case("Bearer ") {
            return Some(header[7..].to_string());
        }
    }

    None
}

/// Check whether the request uses OIDC authentication.
pub fn is_oidc_auth(req: &Request<Body>) -> bool {
    req.headers()
        .get("X-Clawdstrike-Auth-Type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("oidc"))
        .unwrap_or(false)
}

/// Build canonical bytes for caller-auth signatures.
pub fn caller_signature_message(payload: &str, timestamp_rfc3339: &str) -> String {
    format!("clawdstrike-registry-auth:v1:{payload}:{timestamp_rfc3339}")
}

/// Verify signed caller headers and return the caller public key hex.
///
/// Callers must send:
/// - `X-Clawdstrike-Caller-Key`: Ed25519 public key hex
/// - `X-Clawdstrike-Caller-Sig`: Ed25519 signature hex over canonical message
/// - `X-Clawdstrike-Caller-Ts`: RFC-3339 timestamp used in canonical message
pub fn verify_signed_caller(headers: &HeaderMap, payload: &str) -> Result<String, RegistryError> {
    let caller_key_hex = headers
        .get(CALLER_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| RegistryError::Unauthorized("missing caller key header".into()))?;
    let caller_sig_hex = headers
        .get(CALLER_SIG_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| RegistryError::Unauthorized("missing caller signature header".into()))?;
    let caller_ts = headers
        .get(CALLER_TS_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| RegistryError::Unauthorized("missing caller timestamp header".into()))?;

    let ts = chrono::DateTime::parse_from_rfc3339(caller_ts).map_err(|e| {
        RegistryError::Unauthorized(format!("invalid caller timestamp (RFC-3339 required): {e}"))
    })?;
    let now = Utc::now();
    let skew = (now - ts.with_timezone(&Utc)).num_seconds().abs();
    if skew > MAX_CALLER_CLOCK_SKEW_SECS {
        return Err(RegistryError::Unauthorized(
            "caller signature timestamp outside allowed clock skew".into(),
        ));
    }

    let caller_key = PublicKey::from_hex(caller_key_hex)
        .map_err(|e| RegistryError::Unauthorized(format!("invalid caller key hex: {e}")))?;
    let caller_sig = Signature::from_hex(caller_sig_hex)
        .map_err(|e| RegistryError::Unauthorized(format!("invalid caller signature hex: {e}")))?;

    let msg = caller_signature_message(payload, caller_ts);
    if !caller_key.verify(msg.as_bytes(), &caller_sig) {
        return Err(RegistryError::Unauthorized(
            "caller signature verification failed".into(),
        ));
    }

    Ok(caller_key_hex.to_string())
}

/// Middleware that validates a bearer token against the configured API key.
///
/// If no API key is configured (empty string), all requests are allowed through.
/// OIDC-authenticated requests are passed through without API key validation;
/// the OIDC token is validated later in the publish handler where the package
/// name is available for trusted-publisher matching.
pub async fn require_publish_auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth if no API key is configured.
    if state.config.api_key.is_empty() {
        return Ok(next.run(req).await);
    }

    // OIDC requests carry a CI/CD identity token instead of an API key.
    // The token will be validated in the publish handler itself.
    if is_oidc_auth(&req) {
        // Still require a bearer token to be present.
        let _token = extract_bearer_token(&req).ok_or(StatusCode::UNAUTHORIZED)?;
        return Ok(next.run(req).await);
    }

    let token = extract_bearer_token(&req).ok_or(StatusCode::UNAUTHORIZED)?;

    // Constant-time comparison via SHA-256 hash to avoid timing attacks.
    let token_hash = hush_core::sha256_hex(token.as_bytes());
    let expected_hash = hush_core::sha256_hex(state.config.api_key.as_bytes());

    if token_hash != expected_hash {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

/// Parse a scoped package name like `@scope/name` into `(scope, basename)`.
/// Returns `None` for unscoped package names.
pub fn parse_package_scope(name: &str) -> Option<(String, String)> {
    let stripped = name.strip_prefix('@')?;
    let (scope, basename) = stripped.split_once('/')?;
    if scope.is_empty() || basename.is_empty() {
        return None;
    }
    Some((scope.to_string(), basename.to_string()))
}

/// Authorize a scoped publish: the publisher must be an `owner` or `maintainer`
/// of the organization that owns the scope.
pub fn authorize_scoped_publish(
    db: &RegistryDb,
    scope: &str,
    publisher_key: &str,
) -> Result<(), RegistryError> {
    let org = db
        .get_organization(scope)?
        .ok_or_else(|| RegistryError::NotFound(format!("organization '{}' not found", scope)))?;

    let role = db.get_member_role(org.id, publisher_key)?;

    match role.as_deref() {
        Some("owner" | "maintainer") => Ok(()),
        Some(_) => Err(RegistryError::Unauthorized(format!(
            "publisher does not have publish permission in @{}",
            scope
        ))),
        None => Err(RegistryError::Unauthorized(format!(
            "publisher is not a member of @{}",
            scope
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;
    use hush_core::Keypair;

    fn make_request(auth: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder();
        if let Some(val) = auth {
            builder = builder.header(header::AUTHORIZATION, val);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn extract_valid_bearer() {
        let req = make_request(Some("Bearer my-key"));
        assert_eq!(extract_bearer_token(&req).as_deref(), Some("my-key"));
    }

    #[test]
    fn extract_case_insensitive() {
        let req = make_request(Some("bearer my-key"));
        assert_eq!(extract_bearer_token(&req).as_deref(), Some("my-key"));
    }

    #[test]
    fn extract_missing_header() {
        let req = make_request(None);
        assert!(extract_bearer_token(&req).is_none());
    }

    #[test]
    fn extract_wrong_scheme() {
        let req = make_request(Some("Basic abc123"));
        assert!(extract_bearer_token(&req).is_none());
    }

    #[test]
    fn verify_signed_caller_accepts_valid_signature() {
        let kp = Keypair::from_seed(&[9u8; 32]);
        let ts = Utc::now().to_rfc3339();
        let payload = "org:invite:acme:member-key:member";
        let msg = caller_signature_message(payload, &ts);
        let sig = kp.sign(msg.as_bytes()).to_hex();

        let mut headers = HeaderMap::new();
        headers.insert(CALLER_KEY_HEADER, kp.public_key().to_hex().parse().unwrap());
        headers.insert(CALLER_SIG_HEADER, sig.parse().unwrap());
        headers.insert(CALLER_TS_HEADER, ts.parse().unwrap());

        let caller = verify_signed_caller(&headers, payload).unwrap();
        assert_eq!(caller, kp.public_key().to_hex());
    }

    #[test]
    fn verify_signed_caller_rejects_bad_signature() {
        let kp = Keypair::from_seed(&[9u8; 32]);
        let ts = Utc::now().to_rfc3339();
        let payload = "org:invite:acme:member-key:member";
        let mut headers = HeaderMap::new();
        headers.insert(CALLER_KEY_HEADER, kp.public_key().to_hex().parse().unwrap());
        headers.insert(CALLER_SIG_HEADER, "00".parse().unwrap());
        headers.insert(CALLER_TS_HEADER, ts.parse().unwrap());
        let err = verify_signed_caller(&headers, payload).unwrap_err();
        assert!(err.to_string().contains("invalid caller signature hex"));
    }

    // Scope parsing tests.

    #[test]
    fn parse_scoped_package() {
        let result = parse_package_scope("@acme/my-guard");
        assert_eq!(result, Some(("acme".to_string(), "my-guard".to_string())));
    }

    #[test]
    fn parse_unscoped_package() {
        assert!(parse_package_scope("my-guard").is_none());
    }

    #[test]
    fn parse_empty_scope() {
        assert!(parse_package_scope("@/my-guard").is_none());
    }

    #[test]
    fn parse_empty_basename() {
        assert!(parse_package_scope("@acme/").is_none());
    }

    #[test]
    fn parse_no_at_with_slash() {
        assert!(parse_package_scope("acme/my-guard").is_none());
    }

    // Authorization tests.

    #[test]
    fn authorize_owner_can_publish() {
        let db = crate::db::RegistryDb::open_in_memory().unwrap();
        db.create_organization("acme", None, "owner_key").unwrap();

        authorize_scoped_publish(&db, "acme", "owner_key").unwrap();
    }

    #[test]
    fn authorize_maintainer_can_publish() {
        let db = crate::db::RegistryDb::open_in_memory().unwrap();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();
        db.add_org_member(org_id, "maintainer_key", "maintainer", Some("owner_key"))
            .unwrap();

        authorize_scoped_publish(&db, "acme", "maintainer_key").unwrap();
    }

    #[test]
    fn authorize_member_cannot_publish() {
        let db = crate::db::RegistryDb::open_in_memory().unwrap();
        let org_id = db.create_organization("acme", None, "owner_key").unwrap();
        db.add_org_member(org_id, "member_key", "member", Some("owner_key"))
            .unwrap();

        let err = authorize_scoped_publish(&db, "acme", "member_key").unwrap_err();
        assert!(err.to_string().contains("publish permission"));
    }

    #[test]
    fn authorize_nonmember_rejected() {
        let db = crate::db::RegistryDb::open_in_memory().unwrap();
        db.create_organization("acme", None, "owner_key").unwrap();

        let err = authorize_scoped_publish(&db, "acme", "stranger_key").unwrap_err();
        assert!(err.to_string().contains("not a member"));
    }

    #[test]
    fn authorize_nonexistent_org_rejected() {
        let db = crate::db::RegistryDb::open_in_memory().unwrap();

        let err = authorize_scoped_publish(&db, "nonexistent", "some_key").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    // OIDC auth detection tests.

    #[test]
    fn is_oidc_auth_true() {
        let req = Request::builder()
            .header("X-Clawdstrike-Auth-Type", "oidc")
            .body(Body::empty())
            .unwrap();
        assert!(is_oidc_auth(&req));
    }

    #[test]
    fn is_oidc_auth_case_insensitive() {
        let req = Request::builder()
            .header("X-Clawdstrike-Auth-Type", "OIDC")
            .body(Body::empty())
            .unwrap();
        assert!(is_oidc_auth(&req));
    }

    #[test]
    fn is_oidc_auth_false_missing() {
        let req = Request::builder().body(Body::empty()).unwrap();
        assert!(!is_oidc_auth(&req));
    }

    #[test]
    fn is_oidc_auth_false_other_value() {
        let req = Request::builder()
            .header("X-Clawdstrike-Auth-Type", "api-key")
            .body(Body::empty())
            .unwrap();
        assert!(!is_oidc_auth(&req));
    }
}

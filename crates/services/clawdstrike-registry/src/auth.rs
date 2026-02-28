//! API key validation middleware for publish/yank operations.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::db::RegistryDb;
use crate::error::RegistryError;
use crate::state::AppState;

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

/// Middleware that validates a bearer token against the configured API key.
///
/// If no API key is configured (empty string), all requests are allowed through.
pub async fn require_publish_auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth if no API key is configured.
    if state.config.api_key.is_empty() {
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
}

//! OIDC token validation for trusted publishing from CI/CD environments.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::db::TrustedPublisher;
use crate::error::RegistryError;

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const GITLAB_ISSUER: &str = "https://gitlab.com";
const GITLAB_JWKS_URL: &str = "https://gitlab.com/-/jwks";
const JWKS_CACHE_DURATION_SECS: u64 = 3600;
const DEFAULT_OIDC_AUDIENCE: &str = "clawdstrike-registry";

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubClaims {
    pub sub: String,
    pub repository: String,
    pub repository_owner: String,
    #[serde(default)]
    pub workflow_ref: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    pub iss: String,
    #[serde(default)]
    pub aud: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabClaims {
    pub sub: String,
    pub project_path: String,
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    pub iss: String,
    #[serde(default)]
    pub aud: String,
}

#[derive(Debug, Clone)]
pub enum OidcClaims {
    GitHub(GitHubClaims),
    GitLab(GitLabClaims),
}

impl OidcClaims {
    pub fn repository(&self) -> &str {
        match self {
            OidcClaims::GitHub(c) => &c.repository,
            OidcClaims::GitLab(c) => &c.project_path,
        }
    }

    pub fn provider(&self) -> &str {
        match self {
            OidcClaims::GitHub(_) => "github",
            OidcClaims::GitLab(_) => "gitlab",
        }
    }

    pub fn workflow(&self) -> Option<&str> {
        match self {
            OidcClaims::GitHub(c) => c.workflow_ref.as_deref(),
            OidcClaims::GitLab(c) => c.git_ref.as_deref(),
        }
    }

    pub fn environment(&self) -> Option<&str> {
        match self {
            OidcClaims::GitHub(c) => c.environment.as_deref(),
            OidcClaims::GitLab(c) => c.environment.as_deref(),
        }
    }

    #[allow(dead_code)]
    pub fn subject(&self) -> &str {
        match self {
            OidcClaims::GitHub(c) => &c.sub,
            OidcClaims::GitLab(c) => &c.sub,
        }
    }
}

// ---------------------------------------------------------------------------
// JWKS Cache
// ---------------------------------------------------------------------------

/// Per-provider cached JWKS entry.
struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

/// JWKS cache keyed by provider name to avoid serving the wrong JWKS
/// when validating tokens from different providers (e.g. GitHub vs GitLab).
pub struct JwksCache {
    entries: HashMap<String, CachedJwks>,
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn get_or_fetch(&mut self, provider: &str, jwks_url: &str) -> Result<JwkSet, RegistryError> {
        let is_valid = self
            .entries
            .get(provider)
            .map(|e| e.fetched_at.elapsed().as_secs() <= JWKS_CACHE_DURATION_SECS)
            .unwrap_or(false);

        if !is_valid {
            let fetched = fetch_jwks(jwks_url)?;
            self.entries.insert(
                provider.to_string(),
                CachedJwks {
                    jwks: fetched,
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(self.entries[provider].jwks.clone())
    }
}

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

/// Validate an OIDC token from a CI/CD provider.
///
/// Uses the `provider` hint (`"github"` or `"gitlab"`) to select the correct
/// issuer and JWKS URL.  Falls back to inspecting the token's `iss` claim
/// when no explicit provider is given.
pub fn validate_oidc_token(
    token: &str,
    provider: &str,
    jwks_cache: &Mutex<JwksCache>,
) -> Result<OidcClaims, RegistryError> {
    let (issuer, jwks_url) = match provider.to_ascii_lowercase().as_str() {
        "github" => (GITHUB_ISSUER, GITHUB_JWKS_URL),
        "gitlab" => (GITLAB_ISSUER, GITLAB_JWKS_URL),
        _ => {
            return Err(RegistryError::BadRequest(format!(
                "unsupported OIDC provider: {provider}"
            )));
        }
    };

    // Fetch or use cached JWKS (keyed by provider to avoid cross-provider confusion).
    let jwks = {
        let mut cache = jwks_cache
            .lock()
            .map_err(|e| RegistryError::Internal(format!("jwks cache lock poisoned: {e}")))?;
        cache.get_or_fetch(provider, jwks_url)?
    };

    // Decode the JWT header to find the key ID.
    let header = decode_header(token)
        .map_err(|e| RegistryError::Unauthorized(format!("invalid JWT header: {e}")))?;

    let kid = header
        .kid
        .as_ref()
        .ok_or_else(|| RegistryError::Unauthorized("JWT header missing kid".into()))?;

    // Find the matching key in the JWKS.
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid.as_str()))
        .ok_or_else(|| {
            RegistryError::Unauthorized(format!("no matching key found for kid '{kid}'"))
        })?;

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| RegistryError::Unauthorized(format!("failed to build decoding key: {e}")))?;

    let algorithm = header.alg;
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    let allowed_audiences = configured_allowed_audiences(provider);
    let allowed_refs: Vec<&str> = allowed_audiences.iter().map(String::as_str).collect();
    validation.set_audience(&allowed_refs);

    match provider.to_ascii_lowercase().as_str() {
        "github" => {
            let token_data = decode::<GitHubClaims>(token, &decoding_key, &validation)
                .map_err(|e| RegistryError::Unauthorized(format!("JWT validation failed: {e}")))?;
            Ok(OidcClaims::GitHub(token_data.claims))
        }
        "gitlab" => {
            let token_data = decode::<GitLabClaims>(token, &decoding_key, &validation)
                .map_err(|e| RegistryError::Unauthorized(format!("JWT validation failed: {e}")))?;
            Ok(OidcClaims::GitLab(token_data.claims))
        }
        _ => Err(RegistryError::BadRequest(format!(
            "unsupported OIDC provider: {provider}"
        ))),
    }
}

fn configured_allowed_audiences(provider: &str) -> Vec<String> {
    let provider_env = format!(
        "CLAWDSTRIKE_OIDC_{}_AUDIENCES",
        provider.to_ascii_uppercase()
    );
    let raw = std::env::var(&provider_env)
        .ok()
        .or_else(|| std::env::var("CLAWDSTRIKE_OIDC_ALLOWED_AUDIENCES").ok())
        .unwrap_or_else(|| DEFAULT_OIDC_AUDIENCE.to_string());

    parse_allowed_audiences(&raw)
}

fn parse_allowed_audiences(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Fetch JWKS from a remote URL.
fn fetch_jwks(url: &str) -> Result<JwkSet, RegistryError> {
    let resp = reqwest::blocking::get(url)
        .map_err(|e| RegistryError::Internal(format!("failed to fetch JWKS from {url}: {e}")))?;

    if !resp.status().is_success() {
        return Err(RegistryError::Internal(format!(
            "JWKS endpoint returned HTTP {}",
            resp.status()
        )));
    }

    let jwks: JwkSet = resp
        .json()
        .map_err(|e| RegistryError::Internal(format!("failed to parse JWKS response: {e}")))?;

    Ok(jwks)
}

// ---------------------------------------------------------------------------
// Publisher matching
// ---------------------------------------------------------------------------

/// Match OIDC claims against a list of trusted publishers.
///
/// Returns the first matching publisher, or an error if none match.
pub fn match_trusted_publisher<'a>(
    claims: &OidcClaims,
    publishers: &'a [TrustedPublisher],
) -> Result<&'a TrustedPublisher, RegistryError> {
    for publisher in publishers {
        // Provider must match.
        if !publisher.provider.eq_ignore_ascii_case(claims.provider()) {
            continue;
        }

        // Repository must match (case-insensitive).
        if !publisher
            .repository
            .eq_ignore_ascii_case(claims.repository())
        {
            continue;
        }

        // If the publisher specifies a workflow, it must match.
        // GitHub workflow_ref looks like "owner/repo/.github/workflows/release.yml@refs/heads/main".
        // We strip the ref suffix and check that the path ends with the required workflow
        // at a path boundary to prevent partial-name attacks (e.g., "pre-release.yml"
        // should not match a requirement of "release.yml").
        if let Some(ref required_workflow) = publisher.workflow {
            match claims.workflow() {
                Some(actual) => {
                    let workflow_path = actual.split('@').next().unwrap_or(actual);
                    let matches = workflow_path == required_workflow.as_str()
                        || workflow_path.ends_with(&format!("/{}", required_workflow));
                    if !matches {
                        continue;
                    }
                }
                None => continue,
            }
        }

        // If the publisher specifies an environment, it must match.
        if let Some(ref required_env) = publisher.environment {
            match claims.environment() {
                Some(actual) => {
                    if !actual.eq_ignore_ascii_case(required_env) {
                        continue;
                    }
                }
                None => continue,
            }
        }

        return Ok(publisher);
    }

    Err(RegistryError::Unauthorized(
        "no trusted publisher matches the OIDC token claims".into(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_github_claims(repo: &str, workflow: Option<&str>, env: Option<&str>) -> OidcClaims {
        OidcClaims::GitHub(GitHubClaims {
            sub: format!("repo:{repo}:ref:refs/heads/main"),
            repository: repo.to_string(),
            repository_owner: repo.split('/').next().unwrap_or("").to_string(),
            workflow_ref: workflow.map(String::from),
            environment: env.map(String::from),
            iss: GITHUB_ISSUER.to_string(),
            aud: "clawdstrike-registry".to_string(),
        })
    }

    fn make_gitlab_claims(project: &str, git_ref: Option<&str>, env: Option<&str>) -> OidcClaims {
        OidcClaims::GitLab(GitLabClaims {
            sub: format!("project_path:{project}:ref_type:branch:ref:main"),
            project_path: project.to_string(),
            git_ref: git_ref.map(String::from),
            environment: env.map(String::from),
            iss: GITLAB_ISSUER.to_string(),
            aud: "clawdstrike-registry".to_string(),
        })
    }

    fn make_publisher(
        provider: &str,
        repo: &str,
        workflow: Option<&str>,
        env: Option<&str>,
    ) -> TrustedPublisher {
        TrustedPublisher {
            id: 1,
            package_name: "test-pkg".to_string(),
            provider: provider.to_string(),
            repository: repo.to_string(),
            workflow: workflow.map(String::from),
            environment: env.map(String::from),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            created_by: "test".to_string(),
        }
    }

    #[test]
    fn match_github_repo_only() {
        let claims = make_github_claims("acme/my-guard", None, None);
        let publishers = [make_publisher("github", "acme/my-guard", None, None)];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn match_github_with_workflow() {
        let claims = make_github_claims(
            "acme/my-guard",
            Some("acme/my-guard/.github/workflows/release.yml@refs/heads/main"),
            None,
        );
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            Some("release.yml"),
            None,
        )];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn match_github_with_environment() {
        let claims = make_github_claims("acme/my-guard", None, Some("production"));
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            None,
            Some("production"),
        )];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn no_match_wrong_repo() {
        let claims = make_github_claims("other/repo", None, None);
        let publishers = [make_publisher("github", "acme/my-guard", None, None)];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn no_match_wrong_provider() {
        let claims = make_github_claims("acme/my-guard", None, None);
        let publishers = [make_publisher("gitlab", "acme/my-guard", None, None)];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn no_match_missing_workflow() {
        let claims = make_github_claims("acme/my-guard", None, None);
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            Some("release.yml"),
            None,
        )];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn no_match_wrong_environment() {
        let claims = make_github_claims("acme/my-guard", None, Some("staging"));
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            None,
            Some("production"),
        )];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn match_gitlab_repo() {
        let claims = make_gitlab_claims("acme/my-guard", None, None);
        let publishers = [make_publisher("gitlab", "acme/my-guard", None, None)];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn claims_accessors() {
        let gh = make_github_claims("acme/guard", Some("wf.yml"), Some("prod"));
        assert_eq!(gh.repository(), "acme/guard");
        assert_eq!(gh.provider(), "github");
        assert_eq!(gh.workflow(), Some("wf.yml"));
        assert_eq!(gh.environment(), Some("prod"));
        assert_eq!(gh.subject(), "repo:acme/guard:ref:refs/heads/main");

        let gl = make_gitlab_claims("acme/guard", Some("main"), Some("staging"));
        assert_eq!(gl.repository(), "acme/guard");
        assert_eq!(gl.provider(), "gitlab");
        assert_eq!(gl.workflow(), Some("main"));
        assert_eq!(gl.environment(), Some("staging"));
    }

    #[test]
    fn no_match_partial_workflow_name() {
        // "pre-release.yml" should NOT match a requirement of "release.yml"
        let claims = make_github_claims(
            "acme/my-guard",
            Some("acme/my-guard/.github/workflows/pre-release.yml@refs/heads/main"),
            None,
        );
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            Some("release.yml"),
            None,
        )];
        let err = match_trusted_publisher(&claims, &publishers).unwrap_err();
        assert!(err.to_string().contains("no trusted publisher"));
    }

    #[test]
    fn match_full_workflow_path() {
        // Full path should match when specified
        let claims = make_github_claims(
            "acme/my-guard",
            Some("acme/my-guard/.github/workflows/release.yml@refs/heads/main"),
            None,
        );
        let publishers = [make_publisher(
            "github",
            "acme/my-guard",
            Some(".github/workflows/release.yml"),
            None,
        )];
        let matched = match_trusted_publisher(&claims, &publishers).unwrap();
        assert_eq!(matched.repository, "acme/my-guard");
    }

    #[test]
    fn parse_allowed_audiences_splits_and_trims() {
        let parsed = super::parse_allowed_audiences("  clawdstrike-registry, ci-release , ,prod ");
        assert_eq!(
            parsed,
            vec![
                "clawdstrike-registry".to_string(),
                "ci-release".to_string(),
                "prod".to_string()
            ]
        );
    }
}

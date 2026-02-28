//! Resolves `pkg:` references to installed packages.
//!
//! Format: `pkg:@scope/name@version` or `pkg:name@version`
//! Optional sub-path: `pkg:@scope/name@version/path/to/policy.yaml`

use std::path::Path;

use crate::error::{Error, Result};
use crate::policy::{LocalPolicyResolver, PolicyLocation, PolicyResolver, ResolvedPolicySource};

use super::store::PackageStore;

/// Default policy file path within a policy-pack package.
const DEFAULT_POLICY_PATH: &str = "policies/main.yaml";

/// Resolves `pkg:` references to installed packages.
///
/// Non-`pkg:` references are delegated to an inner `LocalPolicyResolver`.
pub struct PackagePolicyResolver {
    store: PackageStore,
    local: LocalPolicyResolver,
}

impl PackagePolicyResolver {
    /// Create a new resolver backed by the given package store.
    pub fn new(store: PackageStore) -> Self {
        Self {
            store,
            local: LocalPolicyResolver::new(),
        }
    }
}

/// Parsed components of a `pkg:` reference.
#[derive(Debug, PartialEq, Eq)]
struct PkgRef {
    name: String,
    version: String,
    sub_path: Option<String>,
}

/// Parse a `pkg:` reference string.
///
/// Supported formats:
/// - `pkg:name@version`
/// - `pkg:@scope/name@version`
/// - `pkg:name@version/sub/path.yaml`
/// - `pkg:@scope/name@version/sub/path.yaml`
fn parse_pkg_ref(reference: &str) -> Result<PkgRef> {
    let body = reference
        .strip_prefix("pkg:")
        .ok_or_else(|| Error::PkgError(format!("not a pkg: reference: {reference}")))?;

    if body.is_empty() {
        return Err(Error::PkgError("empty pkg: reference".to_string()));
    }

    if body.starts_with('@') {
        // Scoped: @scope/name@version[/sub/path]
        let after_scope = body
            .find('/')
            .ok_or_else(|| Error::PkgError(format!("invalid scoped pkg reference: {reference}")))?;

        let version_at = body[after_scope..]
            .find('@')
            .map(|i| i + after_scope)
            .ok_or_else(|| {
                Error::PkgError(format!("pkg reference missing version: {reference}"))
            })?;

        let name = &body[..version_at];
        let rest = &body[version_at + 1..];

        if name.is_empty() || rest.is_empty() {
            return Err(Error::PkgError(format!(
                "pkg reference has empty name or version: {reference}"
            )));
        }

        let (version, sub_path) = match rest.find('/') {
            Some(slash) => {
                let v = &rest[..slash];
                let p = &rest[slash + 1..];
                if v.is_empty() {
                    return Err(Error::PkgError(format!(
                        "pkg reference has empty version: {reference}"
                    )));
                }
                (v, Some(p.to_string()))
            }
            None => (rest, None),
        };

        Ok(PkgRef {
            name: name.to_string(),
            version: version.to_string(),
            sub_path,
        })
    } else {
        // Unscoped: name@version[/sub/path]
        let at_pos = body.find('@').ok_or_else(|| {
            Error::PkgError(format!("pkg reference missing version: {reference}"))
        })?;

        let name = &body[..at_pos];
        let rest = &body[at_pos + 1..];

        if name.is_empty() || rest.is_empty() {
            return Err(Error::PkgError(format!(
                "pkg reference has empty name or version: {reference}"
            )));
        }

        let (version, sub_path) = match rest.find('/') {
            Some(slash) => {
                let v = &rest[..slash];
                let p = &rest[slash + 1..];
                if v.is_empty() {
                    return Err(Error::PkgError(format!(
                        "pkg reference has empty version: {reference}"
                    )));
                }
                (v, Some(p.to_string()))
            }
            None => (rest, None),
        };

        Ok(PkgRef {
            name: name.to_string(),
            version: version.to_string(),
            sub_path,
        })
    }
}

/// Find the policy YAML file within a package directory.
///
/// If a sub-path is given, use that directly. Otherwise, look for:
/// 1. `policies/main.yaml`
/// 2. The first `.yaml` file in `policies/`
fn find_policy_file(pkg_dir: &Path, sub_path: Option<&str>) -> Result<std::path::PathBuf> {
    if let Some(sub) = sub_path {
        let path = pkg_dir.join(sub);
        if !path.exists() {
            return Err(Error::PkgError(format!(
                "policy sub-path not found: {}",
                path.display()
            )));
        }
        // Canonicalize both paths and verify the resolved path stays within
        // pkg_dir to prevent path traversal via `..` components.
        let canonical = path.canonicalize().map_err(|e| {
            Error::PkgError(format!(
                "failed to canonicalize sub-path {}: {e}",
                path.display()
            ))
        })?;
        let canonical_base = pkg_dir.canonicalize().map_err(|e| {
            Error::PkgError(format!(
                "failed to canonicalize package dir {}: {e}",
                pkg_dir.display()
            ))
        })?;
        if !canonical.starts_with(&canonical_base) {
            return Err(Error::PkgError(format!(
                "path traversal detected in package reference: {sub}"
            )));
        }
        return Ok(canonical);
    }

    // Default: policies/main.yaml
    let default_path = pkg_dir.join(DEFAULT_POLICY_PATH);
    if default_path.exists() {
        return Ok(default_path);
    }

    // Fallback: first .yaml in policies/
    let policies_dir = pkg_dir.join("policies");
    if policies_dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(&policies_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());
        if let Some(first) = entries.into_iter().next() {
            return Ok(first.path());
        }
    }

    Err(Error::PkgError(format!(
        "no policy YAML found in package at {}",
        pkg_dir.display()
    )))
}

impl PolicyResolver for PackagePolicyResolver {
    fn resolve(&self, reference: &str, from: &PolicyLocation) -> Result<ResolvedPolicySource> {
        if !reference.starts_with("pkg:") {
            return self.local.resolve(reference, from);
        }

        let pkg_ref = parse_pkg_ref(reference)?;

        let installed = self
            .store
            .get(&pkg_ref.name, &pkg_ref.version)?
            .ok_or_else(|| {
                Error::PkgError(format!(
                    "package not installed: {}@{}",
                    pkg_ref.name, pkg_ref.version
                ))
            })?;

        let policy_path = find_policy_file(&installed.path, pkg_ref.sub_path.as_deref())?;
        let yaml = std::fs::read_to_string(&policy_path)?;

        Ok(ResolvedPolicySource {
            key: format!("pkg:{}@{}", pkg_ref.name, pkg_ref.version),
            yaml,
            location: PolicyLocation::Package {
                name: pkg_ref.name,
                version: pkg_ref.version,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    // -----------------------------------------------------------------------
    // Test helper: simulate an installed package in the store's on-disk layout.
    //
    // The store normalizes scoped names (`@scope/name` -> `scope--name`) and
    // expects a `.pkg-meta.json` metadata file in each version directory.
    // -----------------------------------------------------------------------

    /// Normalize a package name for the filesystem (mirrors store::normalize_name).
    fn normalize_name(name: &str) -> String {
        if let Some(rest) = name.strip_prefix('@') {
            rest.replace('/', "--")
        } else {
            name.to_string()
        }
    }

    /// Simulate an installed package by creating the expected directory layout
    /// with a valid `.pkg-meta.json` metadata file. Returns the package directory.
    fn fake_install(store_root: &Path, name: &str, version: &str) -> PathBuf {
        let dir_name = normalize_name(name);
        let pkg_dir = store_root.join(&dir_name).join(version);
        std::fs::create_dir_all(&pkg_dir).unwrap();

        // Write metadata in the format PackageStore::get() expects.
        let hash = hush_core::sha256(b"fake-archive");
        let meta = serde_json::json!({
            "content_hash": hash.to_hex(),
            "installed_at": "2026-01-01T00:00:00Z"
        });
        std::fs::write(
            pkg_dir.join(".pkg-meta.json"),
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();

        pkg_dir
    }

    // -----------------------------------------------------------------------
    // parse_pkg_ref tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_scoped_ref() {
        let r = parse_pkg_ref("pkg:@scope/name@1.0.0").unwrap();
        assert_eq!(r.name, "@scope/name");
        assert_eq!(r.version, "1.0.0");
        assert!(r.sub_path.is_none());
    }

    #[test]
    fn parse_unscoped_ref() {
        let r = parse_pkg_ref("pkg:simple-name@2.1.0").unwrap();
        assert_eq!(r.name, "simple-name");
        assert_eq!(r.version, "2.1.0");
        assert!(r.sub_path.is_none());
    }

    #[test]
    fn parse_scoped_ref_with_subpath() {
        let r = parse_pkg_ref("pkg:@scope/name@1.0.0/custom/path.yaml").unwrap();
        assert_eq!(r.name, "@scope/name");
        assert_eq!(r.version, "1.0.0");
        assert_eq!(r.sub_path.as_deref(), Some("custom/path.yaml"));
    }

    #[test]
    fn parse_unscoped_ref_with_subpath() {
        let r = parse_pkg_ref("pkg:my-pack@3.0.0/policies/strict.yaml").unwrap();
        assert_eq!(r.name, "my-pack");
        assert_eq!(r.version, "3.0.0");
        assert_eq!(r.sub_path.as_deref(), Some("policies/strict.yaml"));
    }

    #[test]
    fn rejects_missing_version() {
        let err = parse_pkg_ref("pkg:some-name").unwrap_err();
        assert!(err.to_string().contains("missing version"));
    }

    #[test]
    fn rejects_empty_name() {
        let err = parse_pkg_ref("pkg:@1.0.0").unwrap_err();
        assert!(err.to_string().contains("invalid scoped pkg reference"));
    }

    #[test]
    fn rejects_empty_body() {
        let err = parse_pkg_ref("pkg:").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_not_pkg_prefix() {
        let err = parse_pkg_ref("http://example.com").unwrap_err();
        assert!(err.to_string().contains("not a pkg:"));
    }

    #[test]
    fn rejects_empty_version_scoped() {
        let err = parse_pkg_ref("pkg:@scope/name@").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_empty_version_unscoped() {
        let err = parse_pkg_ref("pkg:name@").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    // -----------------------------------------------------------------------
    // Non-pkg references fall through to local resolver
    // -----------------------------------------------------------------------

    #[test]
    fn non_pkg_reference_delegates_to_local() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
        let resolver = PackagePolicyResolver::new(store);

        // "strict" is a built-in ruleset
        let result = resolver.resolve("strict", &PolicyLocation::None);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.key.starts_with("ruleset:"));
    }

    // -----------------------------------------------------------------------
    // Integration tests: install a fake policy-pack and resolve it
    // -----------------------------------------------------------------------

    #[test]
    fn resolves_installed_policy_pack() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("store");
        let store = PackageStore::with_root(store_root.clone()).unwrap();

        let pkg_dir = fake_install(&store_root, "test-pack", "1.0.0");
        let policies_dir = pkg_dir.join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();
        std::fs::write(
            policies_dir.join("main.yaml"),
            "version: \"1.2.0\"\nname: test-pack\n",
        )
        .unwrap();

        let resolver = PackagePolicyResolver::new(store);
        let resolved = resolver
            .resolve("pkg:test-pack@1.0.0", &PolicyLocation::None)
            .unwrap();

        assert_eq!(resolved.key, "pkg:test-pack@1.0.0");
        assert!(resolved.yaml.contains("name: test-pack"));
        assert_eq!(
            resolved.location,
            PolicyLocation::Package {
                name: "test-pack".to_string(),
                version: "1.0.0".to_string(),
            }
        );
    }

    #[test]
    fn resolves_with_subpath() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("store");
        let store = PackageStore::with_root(store_root.clone()).unwrap();

        let pkg_dir = fake_install(&store_root, "@acme/policies", "2.0.0");
        let custom_dir = pkg_dir.join("rulesets");
        std::fs::create_dir_all(&custom_dir).unwrap();
        std::fs::write(
            custom_dir.join("strict.yaml"),
            "version: \"1.2.0\"\nname: acme-strict\n",
        )
        .unwrap();

        let resolver = PackagePolicyResolver::new(store);
        let resolved = resolver
            .resolve(
                "pkg:@acme/policies@2.0.0/rulesets/strict.yaml",
                &PolicyLocation::None,
            )
            .unwrap();

        assert_eq!(resolved.key, "pkg:@acme/policies@2.0.0");
        assert!(resolved.yaml.contains("name: acme-strict"));
    }

    #[test]
    fn resolves_fallback_first_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("store");
        let store = PackageStore::with_root(store_root.clone()).unwrap();

        let pkg_dir = fake_install(&store_root, "fb-pack", "0.1.0");
        let policies_dir = pkg_dir.join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();
        std::fs::write(
            policies_dir.join("alpha.yaml"),
            "version: \"1.2.0\"\nname: alpha\n",
        )
        .unwrap();

        let resolver = PackagePolicyResolver::new(store);
        let resolved = resolver
            .resolve("pkg:fb-pack@0.1.0", &PolicyLocation::None)
            .unwrap();

        assert!(resolved.yaml.contains("name: alpha"));
    }

    #[test]
    fn errors_on_missing_package() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
        let resolver = PackagePolicyResolver::new(store);

        let err = resolver
            .resolve("pkg:not-installed@1.0.0", &PolicyLocation::None)
            .unwrap_err();
        assert!(err.to_string().contains("not installed"));
    }

    #[test]
    fn errors_on_missing_policy_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("store");
        let store = PackageStore::with_root(store_root.clone()).unwrap();

        // Create package dir with metadata but no policies/
        let _pkg_dir = fake_install(&store_root, "empty-pkg", "1.0.0");

        let resolver = PackagePolicyResolver::new(store);
        let err = resolver
            .resolve("pkg:empty-pkg@1.0.0", &PolicyLocation::None)
            .unwrap_err();
        assert!(err.to_string().contains("no policy YAML found"));
    }
}

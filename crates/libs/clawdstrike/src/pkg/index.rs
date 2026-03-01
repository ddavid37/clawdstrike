//! Sparse registry index client for fetching package metadata.
//!
//! Follows a pattern similar to `remote_extends.rs` for content-addressed HTTP
//! caching with ETag-based revalidation.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::manifest::PkgType;
use super::{encode_url_path_segment, normalize_package_name};
use crate::error::{Error, Result};

/// Default registry base URL.
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.clawdstrike.dev";

/// A sparse-index client that fetches and caches package metadata from a remote
/// registry.
#[derive(Clone, Debug)]
pub struct RegistryIndex {
    /// Registry base URL (e.g. `https://registry.clawdstrike.dev`).
    base_url: String,
    /// Local cache directory for index entries.
    cache_dir: PathBuf,
}

/// All known versions for a single package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIndexEntry {
    /// Package name.
    pub name: String,
    /// Available versions in chronological order.
    pub versions: Vec<IndexVersion>,
}

/// A single version record within a package index entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexVersion {
    /// Semver version string.
    pub version: String,
    /// Content-address checksum (`sha256:<hex>`).
    pub checksum: String,
    /// Dependencies: name -> version constraint string.
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    /// Whether this version has been yanked.
    #[serde(default)]
    pub yanked: bool,
    /// Package type.
    pub pkg_type: PkgType,
}

/// Cached ETag metadata for a given index entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheMetadata {
    etag: Option<String>,
}

impl RegistryIndex {
    /// Create a new index client with default cache directory
    /// (`~/.clawdstrike/registry-cache/index/`).
    pub fn new(base_url: &str) -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::PkgError("cannot determine home directory".to_string()))?;
        let cache_dir = home
            .join(".clawdstrike")
            .join("registry-cache")
            .join("index");
        Self::with_cache_dir(base_url, cache_dir)
    }

    /// Create an index client with a custom cache directory.
    pub fn with_cache_dir(base_url: &str, cache_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            cache_dir,
        })
    }

    /// Return the base URL of the registry.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch (or return cached) version information for a package.
    ///
    /// The index follows a sparse layout where package metadata lives at:
    /// `{base_url}/api/v1/index/{normalized_name}`
    ///
    /// HTTP ETag headers are used for cache revalidation.
    pub fn fetch_package_versions(&self, name: &str) -> Result<PackageIndexEntry> {
        let normalized = normalize_package_name(name);
        let cache_path = self.cache_dir.join(format!("{normalized}.json"));
        let meta_path = self.cache_dir.join(format!("{normalized}.meta.json"));

        // Read cached ETag if available.
        let cached_etag = fs::read_to_string(&meta_path)
            .ok()
            .and_then(|s| serde_json::from_str::<CacheMetadata>(&s).ok())
            .and_then(|m| m.etag);

        let url = format!(
            "{}/api/v1/index/{}",
            self.base_url,
            encode_url_path_segment(name)
        );
        let package_name = name.to_string();

        let (status, etag, body) = run_blocking_http(move || {
            let client = build_blocking_client()?;
            let mut request = client.get(&url);
            if let Some(etag) = cached_etag.as_deref() {
                request = request.header("If-None-Match", etag);
            }

            let response = request.send().map_err(|e| {
                Error::PkgError(format!(
                    "failed to fetch index for '{}': {}",
                    package_name, e
                ))
            })?;

            let status = response.status();
            let etag = response
                .headers()
                .get("etag")
                .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
                .map(String::from);

            let body = if status == reqwest::StatusCode::NOT_MODIFIED {
                None
            } else {
                Some(response.text().map_err(|e| {
                    Error::PkgError(format!(
                        "failed to read index body for '{}': {}",
                        package_name, e
                    ))
                })?)
            };

            Ok((status, etag, body))
        })?;

        // 304 Not Modified — use cached version.
        if status == reqwest::StatusCode::NOT_MODIFIED {
            let cached = fs::read_to_string(&cache_path).map_err(|e| {
                Error::PkgError(format!(
                    "cache hit (304) but failed to read cached index for '{}': {}",
                    name, e
                ))
            })?;
            let entry: PackageIndexEntry = serde_json::from_str(&cached)?;
            return Ok(entry);
        }

        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::PkgError(format!(
                "package '{}' not found in registry",
                name
            )));
        }

        if !status.is_success() {
            return Err(Error::PkgError(format!(
                "registry returned HTTP {} for package '{}'",
                status, name
            )));
        }

        let body = body.ok_or_else(|| {
            Error::PkgError(format!(
                "registry returned success without body for package '{}'",
                name
            ))
        })?;

        // Validate JSON before caching.
        let entry: PackageIndexEntry = serde_json::from_str(&body)
            .map_err(|e| Error::PkgError(format!("invalid index JSON for '{}': {}", name, e)))?;

        // Write cache.
        fs::write(&cache_path, &body)?;
        let meta = CacheMetadata { etag };
        let meta_json = serde_json::to_string(&meta)
            .map_err(|e| Error::PkgError(format!("failed to serialize cache metadata: {}", e)))?;
        fs::write(&meta_path, meta_json)?;

        Ok(entry)
    }

    /// Invalidate the cached index entry for a package.
    pub fn invalidate_cache(&self, name: &str) -> Result<()> {
        let normalized = normalize_package_name(name);
        let cache_path = self.cache_dir.join(format!("{normalized}.json"));
        let meta_path = self.cache_dir.join(format!("{normalized}.meta.json"));
        let _ = fs::remove_file(&cache_path);
        let _ = fs::remove_file(&meta_path);
        Ok(())
    }
}

/// Build a blocking HTTP client suitable for registry communication.
fn build_blocking_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("clawdstrike-pkg/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::PkgError(format!("failed to build HTTP client: {}", e)))
}

fn run_blocking_http<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::spawn(f)
            .join()
            .map_err(|_| Error::PkgError("blocking HTTP worker panicked".to_string()))?
    } else {
        f()
    }
}

// ---------------------------------------------------------------------------
// In-memory mock for testing
// ---------------------------------------------------------------------------

/// An in-memory index for testing that doesn't require network access.
#[derive(Clone, Debug, Default)]
pub struct MockRegistryIndex {
    entries: BTreeMap<String, PackageIndexEntry>,
}

impl MockRegistryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a package with its versions.
    pub fn add_entry(&mut self, entry: PackageIndexEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Add a single version to a package (creates the entry if needed).
    pub fn add_version(
        &mut self,
        name: &str,
        version: &str,
        checksum: &str,
        pkg_type: PkgType,
        dependencies: BTreeMap<String, String>,
        yanked: bool,
    ) {
        let entry = self
            .entries
            .entry(name.to_string())
            .or_insert_with(|| PackageIndexEntry {
                name: name.to_string(),
                versions: Vec::new(),
            });
        entry.versions.push(IndexVersion {
            version: version.to_string(),
            checksum: checksum.to_string(),
            dependencies,
            yanked,
            pkg_type,
        });
    }

    /// Look up a package's index entry.
    pub fn fetch_package_versions(&self, name: &str) -> Result<PackageIndexEntry> {
        self.entries
            .get(name)
            .cloned()
            .ok_or_else(|| Error::PkgError(format!("package '{}' not found in index", name)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_index_add_and_fetch() {
        let mut index = MockRegistryIndex::new();
        index.add_version(
            "my-guard",
            "1.0.0",
            "sha256:aabb",
            PkgType::Guard,
            BTreeMap::new(),
            false,
        );
        index.add_version(
            "my-guard",
            "1.1.0",
            "sha256:ccdd",
            PkgType::Guard,
            BTreeMap::new(),
            false,
        );

        let entry = index.fetch_package_versions("my-guard").unwrap();
        assert_eq!(entry.name, "my-guard");
        assert_eq!(entry.versions.len(), 2);
        assert_eq!(entry.versions[0].version, "1.0.0");
        assert_eq!(entry.versions[1].version, "1.1.0");
    }

    #[test]
    fn mock_index_not_found() {
        let index = MockRegistryIndex::new();
        let err = index.fetch_package_versions("missing").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn mock_index_with_dependencies() {
        let mut index = MockRegistryIndex::new();
        let mut deps = BTreeMap::new();
        deps.insert("base-guard".to_string(), "^1.0.0".to_string());

        index.add_version(
            "my-guard",
            "2.0.0",
            "sha256:eeff",
            PkgType::Guard,
            deps,
            false,
        );

        let entry = index.fetch_package_versions("my-guard").unwrap();
        let v = &entry.versions[0];
        assert_eq!(v.dependencies.len(), 1);
        assert_eq!(v.dependencies["base-guard"], "^1.0.0");
    }

    #[test]
    fn mock_index_yanked() {
        let mut index = MockRegistryIndex::new();
        index.add_version(
            "old-pkg",
            "1.0.0",
            "sha256:1111",
            PkgType::Guard,
            BTreeMap::new(),
            true,
        );

        let entry = index.fetch_package_versions("old-pkg").unwrap();
        assert!(entry.versions[0].yanked);
    }

    #[test]
    fn normalize_scoped_name() {
        assert_eq!(
            normalize_package_name("@acme/firewall"),
            "s--acme--firewall"
        );
        assert_eq!(normalize_package_name("simple-name"), "u--simple-name");
        assert_ne!(
            normalize_package_name("@acme/foo"),
            normalize_package_name("acme--foo")
        );
    }

    #[test]
    fn index_version_serde_roundtrip() {
        let mut deps = BTreeMap::new();
        deps.insert("dep-a".to_string(), "^1.0".to_string());

        let iv = IndexVersion {
            version: "1.2.3".to_string(),
            checksum: "sha256:abcdef".to_string(),
            dependencies: deps,
            yanked: false,
            pkg_type: PkgType::Guard,
        };

        let json = serde_json::to_string(&iv).unwrap();
        let parsed: IndexVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, iv);
    }

    #[test]
    fn package_index_entry_serde_roundtrip() {
        let entry = PackageIndexEntry {
            name: "test-pkg".to_string(),
            versions: vec![IndexVersion {
                version: "0.1.0".to_string(),
                checksum: "sha256:000".to_string(),
                dependencies: BTreeMap::new(),
                yanked: false,
                pkg_type: PkgType::PolicyPack,
            }],
        };

        let json = serde_json::to_string_pretty(&entry).unwrap();
        let parsed: PackageIndexEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, entry);
    }
}

//! Local package store — manages installed `.cpkg` packages on disk.

use std::fs;
use std::path::{Path, PathBuf};

use hush_core::Hash;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::archive;
use super::manifest::parse_pkg_manifest_toml;
use super::normalize_package_name;

/// An installed package record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub content_hash: Hash,
}

/// Metadata persisted alongside an installed package (`.pkg-meta.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreMetadata {
    pub content_hash: Hash,
    pub installed_at: String,
    /// Original package name (including scope if any). Used to avoid
    /// ambiguity when denormalizing directory names that contain `--`.
    #[serde(default)]
    pub name: Option<String>,
}

/// Local package store rooted at `~/.clawdstrike/packages/` by default.
pub struct PackageStore {
    root: PathBuf,
}

/// Reverse the directory name back to a package name (**legacy fallback**).
///
/// New installs always persist the original name in [`StoreMetadata`],
/// so [`PackageStore::list`] prefers that authoritative value and only
/// calls this function for old metadata that lacks the `name` field.
///
/// Because the `scope--name` encoding is inherently ambiguous (an
/// unscoped package called `my--pkg` is indistinguishable from a
/// scoped `@my/pkg` after normalization), this function simply returns
/// the directory name unchanged.  Callers that need the display name
/// should use `StoreMetadata::name` instead.
fn denormalize_name(dir_name: &str) -> String {
    dir_name.to_string()
}

impl PackageStore {
    /// Create a store at the default location (`~/.clawdstrike/packages/`).
    pub fn new() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::PkgError("cannot determine home directory".to_string()))?;
        let root = home.join(".clawdstrike").join("packages");
        Self::with_root(root)
    }

    /// Create a store at a custom root (useful for testing).
    pub fn with_root(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Return the directory path for a given package name and version.
    pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
        self.root.join(normalize_package_name(name)).join(version)
    }

    /// Install a package from a `.cpkg` archive file.
    ///
    /// Atomically unpacks to a temp dir, validates the manifest, then moves
    /// to `<root>/<normalized_name>/<version>/`.
    pub fn install_from_file(&self, archive_path: &Path) -> Result<InstalledPackage> {
        // Unpack to a temp directory first (atomic install).
        // Use a guard so the temp dir is cleaned up on any error path.
        let tmp_name = format!(".tmp-{}", uuid::Uuid::new_v4());
        let tmp_dir = self.root.join(&tmp_name);
        fs::create_dir_all(&tmp_dir)?;

        // Guard that removes the temp directory when dropped, unless
        // explicitly disarmed after a successful rename.
        struct TmpGuard {
            path: PathBuf,
            disarmed: bool,
        }
        impl Drop for TmpGuard {
            fn drop(&mut self) {
                if !self.disarmed {
                    let _ = fs::remove_dir_all(&self.path);
                }
            }
        }
        let mut guard = TmpGuard {
            path: tmp_dir.clone(),
            disarmed: false,
        };

        let content_hash = archive::unpack(archive_path, &tmp_dir)?;

        // Read and validate manifest.
        let manifest_path = tmp_dir.join("clawdstrike-pkg.toml");
        let manifest_content = fs::read_to_string(&manifest_path)
            .map_err(|e| Error::PkgError(format!("package missing clawdstrike-pkg.toml: {e}")))?;
        let manifest = parse_pkg_manifest_toml(&manifest_content)?;

        let name = &manifest.package.name;
        let version = &manifest.package.version;
        let dir_name = normalize_package_name(name);
        let target = self.root.join(&dir_name).join(version);

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        // Preserve existing install until the replacement is safely in place.
        let mut backup: Option<PathBuf> = None;
        if target.exists() {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let backup_path = target.with_extension(format!("bak.{nonce:x}"));
            fs::rename(&target, &backup_path)?;
            backup = Some(backup_path);
        }

        // Atomic rename (same filesystem). If this fails, restore backup.
        if let Err(e) = fs::rename(&tmp_dir, &target) {
            if let Some(ref backup_path) = backup {
                let _ = fs::rename(backup_path, &target);
            }
            return Err(e.into());
        }

        // Remove old backup only after successful replacement.
        if let Some(backup_path) = backup {
            let _ = fs::remove_dir_all(backup_path);
        }

        // Disarm the guard — the temp dir no longer exists (it was renamed).
        guard.disarmed = true;

        // Write metadata file.
        let meta = StoreMetadata {
            content_hash,
            installed_at: chrono::Utc::now().to_rfc3339(),
            name: Some(name.clone()),
        };
        let meta_path = target.join(".pkg-meta.json");
        let meta_json = serde_json::to_string_pretty(&meta)?;
        fs::write(&meta_path, meta_json)?;

        Ok(InstalledPackage {
            name: name.clone(),
            version: version.clone(),
            path: target,
            content_hash,
        })
    }

    /// Look up an installed package by name and version.
    pub fn get(&self, name: &str, version: &str) -> Result<Option<InstalledPackage>> {
        let dir_name = normalize_package_name(name);
        let pkg_dir = self.root.join(&dir_name).join(version);
        if !pkg_dir.exists() {
            return Ok(None);
        }

        let meta_path = pkg_dir.join(".pkg-meta.json");
        let meta_content = fs::read_to_string(&meta_path)
            .map_err(|e| Error::PkgError(format!("missing metadata for {name}@{version}: {e}")))?;
        let meta: StoreMetadata = serde_json::from_str(&meta_content)?;

        Ok(Some(InstalledPackage {
            name: name.to_string(),
            version: version.to_string(),
            path: pkg_dir,
            content_hash: meta.content_hash,
        }))
    }

    /// List all installed packages.
    pub fn list(&self) -> Result<Vec<InstalledPackage>> {
        let mut packages = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(_) => return Ok(packages),
        };

        for entry in entries {
            let entry = entry?;
            let pkg_dir = entry.path();
            if !pkg_dir.is_dir() {
                continue;
            }

            let dir_name = entry.file_name().to_string_lossy().to_string();

            // Each package dir contains version subdirs.
            let version_entries = match fs::read_dir(&pkg_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for ver_entry in version_entries {
                let ver_entry = ver_entry?;
                let ver_dir = ver_entry.path();
                if !ver_dir.is_dir() {
                    continue;
                }

                let meta_path = ver_dir.join(".pkg-meta.json");
                if !meta_path.exists() {
                    continue;
                }

                let meta_content = match fs::read_to_string(&meta_path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let meta: StoreMetadata = match serde_json::from_str(&meta_content) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                // Prefer the original name stored in metadata (avoids
                // double-dash ambiguity); fall back to heuristic
                // denormalization for older metadata without the field.
                let name = meta
                    .name
                    .clone()
                    .unwrap_or_else(|| denormalize_name(&dir_name));
                let version = ver_entry.file_name().to_string_lossy().to_string();

                packages.push(InstalledPackage {
                    name,
                    version,
                    path: ver_dir,
                    content_hash: meta.content_hash,
                });
            }
        }

        packages.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
        Ok(packages)
    }

    /// Remove an installed package.
    pub fn remove(&self, name: &str, version: &str) -> Result<()> {
        let dir_name = normalize_package_name(name);
        let pkg_dir = self.root.join(&dir_name).join(version);
        if !pkg_dir.exists() {
            return Err(Error::PkgError(format!(
                "package {name}@{version} is not installed"
            )));
        }
        fs::remove_dir_all(&pkg_dir)?;

        // Clean up parent dir if empty.
        let parent = self.root.join(&dir_name);
        if parent.exists() {
            let is_empty = fs::read_dir(&parent)?.next().is_none();
            if is_empty {
                fs::remove_dir(&parent)?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a minimal package directory with a manifest and pack it.
    fn create_test_package(
        tmp: &Path,
        name: &str,
        version: &str,
        pkg_type: &str,
        suffix: &str,
    ) -> PathBuf {
        let src = tmp.join(format!("pkg-src-{suffix}"));
        fs::create_dir_all(&src).unwrap();

        let manifest = format!(
            r#"[package]
name = "{name}"
version = "{version}"
pkg_type = "{pkg_type}"

[trust]
level = "trusted"
sandbox = "native"
"#
        );
        fs::write(src.join("clawdstrike-pkg.toml"), &manifest).unwrap();
        fs::write(src.join("guard.wasm"), b"fake wasm").unwrap();

        let archive_path = tmp.join(format!("{suffix}.cpkg"));
        archive::pack(&src, &archive_path).unwrap();
        archive_path
    }

    #[test]
    fn install_and_get() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive = create_test_package(tmp.path(), "my-guard", "1.0.0", "guard", "a");
        let installed = store.install_from_file(&archive).unwrap();

        assert_eq!(installed.name, "my-guard");
        assert_eq!(installed.version, "1.0.0");
        assert!(installed.path.exists());

        let got = store.get("my-guard", "1.0.0").unwrap().unwrap();
        assert_eq!(got.name, "my-guard");
        assert_eq!(got.content_hash, installed.content_hash);
    }

    #[test]
    fn install_scoped_package() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive =
            create_test_package(tmp.path(), "@acme/firewall", "0.1.0", "policy-pack", "b");
        let installed = store.install_from_file(&archive).unwrap();

        assert_eq!(installed.name, "@acme/firewall");
        assert!(installed.path.to_string_lossy().contains("acme--firewall"));

        let got = store.get("@acme/firewall", "0.1.0").unwrap().unwrap();
        assert_eq!(got.name, "@acme/firewall");
    }

    #[test]
    fn list_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let a1 = create_test_package(tmp.path(), "alpha", "1.0.0", "guard", "c");
        let a2 = create_test_package(tmp.path(), "beta", "2.0.0", "adapter", "d");

        store.install_from_file(&a1).unwrap();
        store.install_from_file(&a2).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "alpha");
        assert_eq!(list[1].name, "beta");
    }

    #[test]
    fn remove_package() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive = create_test_package(tmp.path(), "removable", "1.0.0", "guard", "e");
        store.install_from_file(&archive).unwrap();
        assert!(store.get("removable", "1.0.0").unwrap().is_some());

        store.remove("removable", "1.0.0").unwrap();
        assert!(store.get("removable", "1.0.0").unwrap().is_none());
    }

    #[test]
    fn remove_nonexistent_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let err = store.remove("nope", "1.0.0").unwrap_err();
        assert!(err.to_string().contains("not installed"));
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        assert!(store.get("nope", "1.0.0").unwrap().is_none());
    }

    #[test]
    fn reinstall_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive = create_test_package(tmp.path(), "my-guard", "1.0.0", "guard", "f");
        let first = store.install_from_file(&archive).unwrap();
        let second = store.install_from_file(&archive).unwrap();

        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn denormalize_returns_dir_name_unchanged() {
        // `denormalize_name` is a legacy fallback that no longer attempts
        // to reverse `--` into scoped names because the mapping is
        // ambiguous.  New installs store the original name in metadata.
        assert_eq!(denormalize_name("acme--firewall"), "acme--firewall");
        assert_eq!(denormalize_name("my--pkg"), "my--pkg");
        assert_eq!(denormalize_name("a--b--c"), "a--b--c");
        assert_eq!(denormalize_name("simple-guard"), "simple-guard");
        assert_eq!(denormalize_name("--name"), "--name");
    }

    #[test]
    fn list_uses_metadata_name_for_scoped_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive =
            create_test_package(tmp.path(), "@acme/firewall", "0.1.0", "policy-pack", "g");
        store.install_from_file(&archive).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        // The original scoped name is preserved via StoreMetadata.name,
        // NOT via denormalize_name heuristics.
        assert_eq!(list[0].name, "@acme/firewall");
    }
}

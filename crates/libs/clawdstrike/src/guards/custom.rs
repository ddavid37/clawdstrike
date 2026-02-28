use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::pkg::manifest::{PkgManifest, PkgType};

use super::Guard;

pub trait CustomGuardFactory: Send + Sync {
    fn id(&self) -> &str;
    fn build(&self, config: Value) -> Result<Box<dyn Guard>>;
}

#[derive(Clone, Default)]
pub struct CustomGuardRegistry {
    factories: HashMap<String, Arc<dyn CustomGuardFactory>>,
}

impl std::fmt::Debug for CustomGuardRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomGuardRegistry")
            .field("count", &self.factories.len())
            .finish()
    }
}

impl CustomGuardRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<F>(&mut self, factory: F) -> &mut Self
    where
        F: CustomGuardFactory + 'static,
    {
        self.factories
            .insert(factory.id().to_string(), Arc::new(factory));
        self
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn CustomGuardFactory>> {
        self.factories.get(id)
    }

    pub fn build(&self, id: &str, config: Value) -> Result<Box<dyn Guard>> {
        let factory = self.factories.get(id).ok_or_else(|| {
            Error::ConfigError(format!("Custom guard factory not found for id: {}", id))
        })?;
        factory.build(config)
    }

    /// Register all guard factories from an installed package's manifest.
    ///
    /// For guard packages, this scans the install directory for a
    /// `clawdstrike.plugin.toml` plugin manifest, discovers guard entries,
    /// loads their WASM entrypoints, and registers `WasmGuardFactory`
    /// instances in the registry.
    ///
    /// Non-guard packages are silently ignored (returns `Ok(())`).
    pub fn register_from_package(
        &mut self,
        manifest: &PkgManifest,
        install_path: &Path,
    ) -> Result<()> {
        if manifest.package.pkg_type != PkgType::Guard {
            return Ok(()); // Only guard packages register factories
        }

        self.register_guards_from_package_impl(manifest, install_path)
    }

    #[cfg(not(feature = "wasm-plugin-runtime"))]
    fn register_guards_from_package_impl(
        &mut self,
        manifest: &PkgManifest,
        _install_path: &Path,
    ) -> Result<()> {
        tracing::warn!(
            package = %manifest.package.name,
            version = %manifest.package.version,
            "Guard package requires wasm-plugin-runtime feature; skipping"
        );
        Ok(())
    }

    #[cfg(feature = "wasm-plugin-runtime")]
    fn register_guards_from_package_impl(
        &mut self,
        pkg_manifest: &PkgManifest,
        install_path: &Path,
    ) -> Result<()> {
        use crate::plugins::{parse_plugin_manifest_toml, WasmGuardFactory};

        let plugin_manifest_path = install_path.join("clawdstrike.plugin.toml");
        let plugin_manifest_content =
            std::fs::read_to_string(&plugin_manifest_path).map_err(|e| {
                Error::ConfigError(format!(
                    "guard package {} missing clawdstrike.plugin.toml at {}: {}",
                    pkg_manifest.package.name,
                    plugin_manifest_path.display(),
                    e
                ))
            })?;

        let plugin_manifest = parse_plugin_manifest_toml(&plugin_manifest_content)?;

        for guard_entry in &plugin_manifest.guards {
            let entrypoint = guard_entry.entrypoint.as_deref().unwrap_or("guard.wasm");
            let entry_rel = std::path::Path::new(entrypoint);
            if entry_rel.is_absolute() {
                return Err(Error::ConfigError(format!(
                    "guard entrypoint must be relative: {}",
                    entrypoint
                )));
            }

            // Lexically normalize to reject traversal attempts up-front.
            let mut normalized_rel = std::path::PathBuf::new();
            for component in entry_rel.components() {
                match component {
                    std::path::Component::CurDir => {}
                    std::path::Component::ParentDir => {
                        if !normalized_rel.pop() {
                            return Err(Error::ConfigError(format!(
                                "guard entrypoint escapes package root: {}",
                                entrypoint
                            )));
                        }
                    }
                    std::path::Component::Normal(seg) => normalized_rel.push(seg),
                    _ => {
                        return Err(Error::ConfigError(format!(
                            "invalid guard entrypoint path: {}",
                            entrypoint
                        )));
                    }
                }
            }

            let wasm_path = install_path.join(&normalized_rel);
            let canonical_install = install_path.canonicalize().map_err(|e| {
                Error::ConfigError(format!(
                    "failed to canonicalize guard install path {}: {}",
                    install_path.display(),
                    e
                ))
            })?;
            let canonical_wasm = wasm_path.canonicalize().map_err(|e| {
                Error::ConfigError(format!(
                    "failed to resolve WASM entrypoint for guard {}: {} ({})",
                    guard_entry.name,
                    wasm_path.display(),
                    e
                ))
            })?;
            if !canonical_wasm.starts_with(&canonical_install) {
                return Err(Error::ConfigError(format!(
                    "guard entrypoint escapes package root: {}",
                    entrypoint
                )));
            }
            let wasm_bytes = std::fs::read(&canonical_wasm).map_err(|e| {
                Error::ConfigError(format!(
                    "failed to read WASM entrypoint for guard {}: {} ({})",
                    guard_entry.name,
                    canonical_wasm.display(),
                    e
                ))
            })?;

            let factory = WasmGuardFactory::new(
                guard_entry.name.clone(),
                wasm_bytes,
                guard_entry.handles.clone(),
                plugin_manifest.capabilities.clone(),
                plugin_manifest.resources.clone(),
            );

            tracing::info!(
                package = %pkg_manifest.package.name,
                guard = %guard_entry.name,
                entrypoint = %entrypoint,
                "Registered WASM guard factory from package"
            );

            self.register(factory);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "wasm-plugin-runtime"))]
mod tests {
    use super::*;
    use crate::pkg::manifest::{PackageSection, PkgManifest};
    use crate::plugins::{PluginCapabilities, PluginResourceLimits, PluginTrust};

    /// Compile a minimal WASM guard that always denies.
    fn deny_guard_wasm() -> Vec<u8> {
        // {"allowed":false,"severity":"high","message":"Denied by wasm"} = 62 bytes
        wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":false,\"severity\":\"high\",\"message\":\"Denied by wasm\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 64
                  i32.const 62
                  call $set_output
                  drop
                  i32.const 0)
            )"#,
        )
        .expect("valid WAT")
    }

    fn make_pkg_manifest(name: &str, version: &str, pkg_type: PkgType) -> PkgManifest {
        PkgManifest {
            package: PackageSection {
                name: name.to_string(),
                version: version.to_string(),
                pkg_type,
                description: None,
                authors: vec![],
                license: None,
                repository: None,
                keywords: vec![],
                readme: None,
            },
            clawdstrike: None,
            capabilities: PluginCapabilities::default(),
            resources: PluginResourceLimits::default(),
            trust: PluginTrust::default(),
            dependencies: Default::default(),
            build: None,
        }
    }

    /// Set up a mock package directory with a plugin manifest and WASM file.
    fn setup_mock_package(
        dir: &std::path::Path,
        plugin_toml: &str,
        wasm_filename: &str,
        wasm_bytes: &[u8],
    ) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("clawdstrike.plugin.toml"), plugin_toml).unwrap();
        std::fs::write(dir.join(wasm_filename), wasm_bytes).unwrap();
    }

    #[test]
    fn register_from_package_loads_wasm_guard() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wasm = deny_guard_wasm();

        setup_mock_package(
            tmp.path(),
            r#"
[plugin]
version = "1.0.0"
name = "acme-deny"

[[guards]]
name = "acme.deny"
entrypoint = "guard.wasm"

[trust]
level = "trusted"
sandbox = "wasm"
"#,
            "guard.wasm",
            &wasm,
        );

        let pkg_manifest = make_pkg_manifest("acme-deny", "1.0.0", PkgType::Guard);
        let mut registry = CustomGuardRegistry::new();
        registry
            .register_from_package(&pkg_manifest, tmp.path())
            .expect("register_from_package");

        assert!(
            registry.get("acme.deny").is_some(),
            "guard factory should be registered"
        );
    }

    #[tokio::test]
    async fn register_from_package_guard_produces_correct_result() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wasm = deny_guard_wasm();

        setup_mock_package(
            tmp.path(),
            r#"
[plugin]
version = "1.0.0"
name = "acme-deny"

[[guards]]
name = "acme.deny"
entrypoint = "guard.wasm"

[trust]
level = "trusted"
sandbox = "wasm"
"#,
            "guard.wasm",
            &wasm,
        );

        let pkg_manifest = make_pkg_manifest("acme-deny", "1.0.0", PkgType::Guard);
        let mut registry = CustomGuardRegistry::new();
        registry
            .register_from_package(&pkg_manifest, tmp.path())
            .expect("register_from_package");

        let guard = registry
            .build("acme.deny", serde_json::json!({}))
            .expect("build");
        let ctx = crate::guards::GuardContext::new();
        let result = guard
            .check(&crate::guards::GuardAction::FileAccess("/tmp/test"), &ctx)
            .await;
        assert!(!result.allowed, "guard should deny");
        assert_eq!(result.guard, "acme.deny");
    }

    #[test]
    fn register_from_package_ignores_non_guard_packages() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pkg_manifest = make_pkg_manifest("my-policy", "1.0.0", PkgType::PolicyPack);
        let mut registry = CustomGuardRegistry::new();
        registry
            .register_from_package(&pkg_manifest, tmp.path())
            .expect("should succeed for non-guard");
        assert!(
            registry.get("anything").is_none(),
            "no factories registered for non-guard package"
        );
    }

    #[test]
    fn register_from_package_multiple_guards() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let wasm = deny_guard_wasm();

        // Write the same WASM under two different filenames
        std::fs::create_dir_all(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike.plugin.toml"),
            r#"
[plugin]
version = "1.0.0"
name = "acme-multi"

[[guards]]
name = "acme.guard-a"
entrypoint = "a.wasm"

[[guards]]
name = "acme.guard-b"
entrypoint = "b.wasm"

[trust]
level = "trusted"
sandbox = "wasm"
"#,
        )
        .unwrap();
        std::fs::write(tmp.path().join("a.wasm"), &wasm).unwrap();
        std::fs::write(tmp.path().join("b.wasm"), &wasm).unwrap();

        let pkg_manifest = make_pkg_manifest("acme-multi", "1.0.0", PkgType::Guard);
        let mut registry = CustomGuardRegistry::new();
        registry
            .register_from_package(&pkg_manifest, tmp.path())
            .expect("register_from_package");

        assert!(registry.get("acme.guard-a").is_some());
        assert!(registry.get("acme.guard-b").is_some());
    }

    #[test]
    fn register_from_package_missing_plugin_manifest_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pkg_manifest = make_pkg_manifest("acme-missing", "1.0.0", PkgType::Guard);
        let mut registry = CustomGuardRegistry::new();
        let err = registry
            .register_from_package(&pkg_manifest, tmp.path())
            .expect_err("should fail without plugin manifest");
        assert!(err.to_string().contains("clawdstrike.plugin.toml"));
    }

    #[test]
    fn register_from_package_missing_wasm_entrypoint_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Plugin manifest references guard.wasm but we don't create it
        std::fs::write(
            tmp.path().join("clawdstrike.plugin.toml"),
            r#"
[plugin]
version = "1.0.0"
name = "acme-missing-wasm"

[[guards]]
name = "acme.missing"
entrypoint = "guard.wasm"

[trust]
level = "trusted"
sandbox = "wasm"
"#,
        )
        .unwrap();

        let pkg_manifest = make_pkg_manifest("acme-missing-wasm", "1.0.0", PkgType::Guard);
        let mut registry = CustomGuardRegistry::new();
        let err = registry
            .register_from_package(&pkg_manifest, tmp.path())
            .expect_err("should fail without WASM file");
        assert!(err.to_string().contains("failed to read WASM entrypoint"));
    }
}

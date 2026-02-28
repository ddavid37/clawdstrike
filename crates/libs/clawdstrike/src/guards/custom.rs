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
    /// For Phase 0, this is a placeholder that validates the manifest
    /// and records the package as a source of guards.
    /// WASM guard loading will be implemented in Phase 1.
    pub fn register_from_package(
        &mut self,
        manifest: &PkgManifest,
        _install_path: &Path,
    ) -> Result<()> {
        if manifest.package.pkg_type != PkgType::Guard {
            return Ok(()); // Only guard packages register factories
        }
        tracing::info!(
            package = %manifest.package.name,
            version = %manifest.package.version,
            "Registered guard package (WASM loading deferred to Phase 1)"
        );
        Ok(())
    }
}

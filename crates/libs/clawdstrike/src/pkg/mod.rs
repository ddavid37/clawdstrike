//! Package manager core library for `.cpkg` packages.
//!
//! Provides manifest parsing, archive creation/extraction, a local package
//! store, lockfile management, and cryptographic integrity verification.

pub mod archive;
pub mod index;
pub mod integrity;
pub mod lockfile;
pub mod manifest;
pub mod merkle;
pub mod resolver;
pub mod resolver_deps;
pub mod store;
#[cfg(feature = "wasm-plugin-runtime")]
pub mod test_runner;
pub mod trust;
pub mod version;

pub use archive::{content_hash, pack, unpack};
pub use index::{
    IndexVersion, MockRegistryIndex, PackageIndexEntry, RegistryIndex, DEFAULT_REGISTRY_URL,
};
pub use integrity::{sign_package, verify_package, PackageSignature};
pub use lockfile::{LockedDependency, LockedPackage, Lockfile};
pub use manifest::{parse_pkg_manifest_toml, PkgManifest, PkgType};
pub use resolver::PackagePolicyResolver;
pub use resolver_deps::{
    lockfile_from_resolution, DependencyResolver, PkgId, ResolvedPackage, ResolverError,
};
pub use store::{InstalledPackage, PackageStore, StoreMetadata};
#[cfg(feature = "wasm-plugin-runtime")]
pub use test_runner::{
    parse_guard_test_file, parse_guard_test_suite, run_guard_tests, GuardTestFixture,
    GuardTestResult, GuardTestSuite,
};
pub use trust::{check_trust, compute_trust_level, TrustError, TrustLevel, TrustRequirement};
pub use version::{parse_version, parse_version_req, VersionReq};

//! Package manager core library for `.cpkg` packages.
//!
//! Provides manifest parsing, archive creation/extraction, a local package
//! store, lockfile management, and cryptographic integrity verification.

pub mod archive;
pub mod integrity;
pub mod lockfile;
pub mod manifest;
pub mod resolver;
pub mod store;
#[cfg(feature = "wasm-plugin-runtime")]
pub mod test_runner;

pub use archive::{content_hash, pack, unpack};
pub use integrity::{sign_package, verify_package, PackageSignature};
pub use lockfile::{LockedDependency, LockedPackage, Lockfile};
pub use manifest::{parse_pkg_manifest_toml, PkgManifest, PkgType};
pub use resolver::PackagePolicyResolver;
pub use store::{InstalledPackage, PackageStore, StoreMetadata};
#[cfg(feature = "wasm-plugin-runtime")]
pub use test_runner::{
    parse_guard_test_file, parse_guard_test_suite, run_guard_tests, GuardTestFixture,
    GuardTestResult, GuardTestSuite,
};

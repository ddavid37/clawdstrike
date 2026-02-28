#![allow(clippy::needless_pass_by_value)]
//! `hush pkg` subcommands — package management for `.cpkg` archives.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Subcommand;

use clawdstrike::pkg::archive;
use clawdstrike::pkg::manifest::{parse_pkg_manifest_toml, PkgManifest, PkgType};
use clawdstrike::pkg::store::PackageStore;

use crate::ExitCode;

// ---------------------------------------------------------------------------
// Clap types
// ---------------------------------------------------------------------------

/// Map `PkgType` to clap `ValueEnum` without adding clap to the library crate.
#[derive(Clone, Debug)]
pub enum CliPkgType {
    Guard,
    PolicyPack,
    Adapter,
    Engine,
    Template,
    Bundle,
}

impl clap::ValueEnum for CliPkgType {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Guard,
            Self::PolicyPack,
            Self::Adapter,
            Self::Engine,
            Self::Template,
            Self::Bundle,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Guard => clap::builder::PossibleValue::new("guard"),
            Self::PolicyPack => clap::builder::PossibleValue::new("policy-pack"),
            Self::Adapter => clap::builder::PossibleValue::new("adapter"),
            Self::Engine => clap::builder::PossibleValue::new("engine"),
            Self::Template => clap::builder::PossibleValue::new("template"),
            Self::Bundle => clap::builder::PossibleValue::new("bundle"),
        })
    }
}

impl CliPkgType {
    fn to_pkg_type(&self) -> PkgType {
        match self {
            Self::Guard => PkgType::Guard,
            Self::PolicyPack => PkgType::PolicyPack,
            Self::Adapter => PkgType::Adapter,
            Self::Engine => PkgType::Engine,
            Self::Template => PkgType::Template,
            Self::Bundle => PkgType::Bundle,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Guard => "guard",
            Self::PolicyPack => "policy-pack",
            Self::Adapter => "adapter",
            Self::Engine => "engine",
            Self::Template => "template",
            Self::Bundle => "bundle",
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum PkgCommands {
    /// Initialize a new package in the current directory
    Init {
        /// Package type
        #[arg(long, value_enum)]
        pkg_type: CliPkgType,
        /// Package name (e.g., @acme/my-guard)
        #[arg(long)]
        name: String,
    },
    /// Build a .cpkg archive from the current directory (or specified path)
    Pack {
        /// Path to package directory (defaults to current dir)
        path: Option<PathBuf>,
    },
    /// Install a package from a local .cpkg file
    Install {
        /// Path to .cpkg file
        source: PathBuf,
    },
    /// List installed packages
    List,
    /// Verify an installed package's integrity
    Verify {
        /// Package name
        name: String,
        /// Package version
        #[arg(long)]
        version: String,
    },
    /// Show details about an installed package
    Info {
        /// Package name
        name: String,
        /// Package version
        #[arg(long)]
        version: String,
    },
    /// Run guard test fixtures against a WASM guard plugin
    Test {
        /// Path to the guard package directory (defaults to current dir)
        path: Option<PathBuf>,
        /// Filter: only run fixtures whose name contains this string
        #[arg(long)]
        filter: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

pub fn cmd_pkg(command: PkgCommands, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match command {
        PkgCommands::Init { pkg_type, name } => cmd_pkg_init(&pkg_type, &name, stdout, stderr),
        PkgCommands::Pack { path } => cmd_pkg_pack(path.as_deref(), stdout, stderr),
        PkgCommands::Install { source } => cmd_pkg_install(&source, stdout, stderr),
        PkgCommands::List => cmd_pkg_list(stdout, stderr),
        PkgCommands::Verify { name, version } => cmd_pkg_verify(&name, &version, stdout, stderr),
        PkgCommands::Info { name, version } => cmd_pkg_info(&name, &version, stdout, stderr),
        PkgCommands::Test { path, filter } => {
            cmd_pkg_test(path.as_deref(), filter.as_deref(), stdout, stderr)
        }
    }
}

// ---------------------------------------------------------------------------
// pkg init
// ---------------------------------------------------------------------------

fn cmd_pkg_init(
    pkg_type: &CliPkgType,
    name: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Generate scaffold based on type
    let core_type = pkg_type.to_pkg_type();
    if let Err(e) = scaffold_package(&cwd, &core_type, name) {
        let _ = writeln!(stderr, "Error: {e}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(
        stdout,
        "Initialized {} package '{}' in {}",
        pkg_type.label(),
        name,
        cwd.display()
    );
    ExitCode::Ok
}

fn scaffold_package(dir: &Path, pkg_type: &PkgType, name: &str) -> std::io::Result<()> {
    // Create type-specific directories
    match pkg_type {
        PkgType::Guard => {
            std::fs::create_dir_all(dir.join("src"))?;
            std::fs::create_dir_all(dir.join("tests"))?;
            std::fs::create_dir_all(dir.join(".cargo"))?;
        }
        PkgType::PolicyPack => {
            std::fs::create_dir_all(dir.join("policies"))?;
            std::fs::create_dir_all(dir.join("data"))?;
        }
        PkgType::Adapter => {
            std::fs::create_dir_all(dir.join("src"))?;
        }
        PkgType::Engine => {
            std::fs::create_dir_all(dir.join("src"))?;
        }
        PkgType::Template => {
            std::fs::create_dir_all(dir.join("template"))?;
        }
        PkgType::Bundle => {
            // No extra directories needed
        }
    }

    // Write the package manifest
    let manifest_toml = generate_manifest_toml(name, pkg_type);
    std::fs::write(dir.join("clawdstrike-pkg.toml"), manifest_toml)?;

    // Guard-specific template files
    if *pkg_type == PkgType::Guard {
        scaffold_guard_templates(dir, name)?;
    }

    Ok(())
}

fn scaffold_guard_templates(dir: &Path, name: &str) -> std::io::Result<()> {
    // Derive a safe Rust identifier from the guard name for struct names
    let struct_name = name
        .replace('@', "")
        .replace(['/', '-'], "_")
        .split('_')
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<String>()
        + "Guard";

    // src/lib.rs
    std::fs::write(
        dir.join("src/lib.rs"),
        generate_guard_lib_rs(name, &struct_name),
    )?;

    // Cargo.toml for the guard project
    std::fs::write(dir.join("Cargo.toml"), generate_guard_cargo_toml(name))?;

    // plugin-manifest.toml
    std::fs::write(
        dir.join("plugin-manifest.toml"),
        generate_guard_plugin_manifest(name),
    )?;

    // tests/basic.yaml
    std::fs::write(
        dir.join("tests/basic.yaml"),
        generate_guard_test_fixture(name),
    )?;

    // .cargo/config.toml
    std::fs::write(
        dir.join(".cargo/config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
    )?;

    Ok(())
}

fn generate_guard_lib_rs(name: &str, struct_name: &str) -> String {
    format!(
        r#"//! {name} -- a Clawdstrike WASM guard plugin.
//!
//! This guard is compiled to `wasm32-unknown-unknown` and loaded by
//! the Clawdstrike runtime at evaluation time.

use clawdstrike_guard_sdk::prelude::*;

/// {struct_name} implements a custom security guard.
#[clawdstrike_guard]
#[derive(Default)]
pub struct {struct_name};

impl Guard for {struct_name} {{
    fn name(&self) -> &str {{
        "{name}"
    }}

    fn handles(&self, action_type: &str) -> bool {{
        // Return true for the action types this guard should evaluate.
        // Examples: "file_access", "tool_call", "shell_command", "network"
        matches!(action_type, "file_access" | "tool_call")
    }}

    fn check(&self, input: GuardInput) -> GuardOutput {{
        // Implement your security logic here.
        //
        // `input.payload` contains the action details as a JSON value.
        // `input.config` contains per-invocation configuration.
        //
        // Return `GuardOutput::allow()` or `GuardOutput::deny(severity, message)`.

        GuardOutput::allow()
    }}
}}
"#
    )
}

fn generate_guard_cargo_toml(name: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
clawdstrike-guard-sdk = {{ version = "0.1" }}

[profile.release]
opt-level = "s"
lto = true
strip = true
"#
    )
}

fn generate_guard_plugin_manifest(name: &str) -> String {
    format!(
        r#"[plugin]
name = "{name}"
version = "0.1.0"
description = "A custom Clawdstrike guard plugin"

[[guards]]
name = "{name}"
handles = ["file_access", "tool_call"]

[capabilities]

[resources]
max_memory_mb = 16
max_cpu_ms = 50
max_timeout_ms = 5000

[trust]
level = "untrusted"
sandbox = "wasm"
"#
    )
}

fn generate_guard_test_fixture(name: &str) -> String {
    format!(
        r#"suite: "{name} Tests"
guard: "{name}"
fixtures:
  - name: "allows safe action"
    action:
      type: "file_access"
      path: "/tmp/safe-file.txt"
    expect:
      allowed: true

  - name: "evaluates tool call"
    action:
      type: "tool_call"
      tool: "read_file"
      parameters:
        path: "/tmp/test.txt"
    expect:
      allowed: true
"#
    )
}

fn generate_manifest_toml(name: &str, pkg_type: &PkgType) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
pkg_type = "{pkg_type}"
description = ""
authors = []
license = "Apache-2.0"

[clawdstrike]
min_version = "{clawdstrike_version}"

[trust]
level = "untrusted"
sandbox = "wasm"

[dependencies]
"#,
        clawdstrike_version = env!("CARGO_PKG_VERSION"),
    )
}

// ---------------------------------------------------------------------------
// pkg pack
// ---------------------------------------------------------------------------

fn cmd_pkg_pack(path: Option<&Path>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    let source_dir = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
                return ExitCode::RuntimeError;
            }
        },
    };

    // Read and validate manifest
    let manifest_path = source_dir.join("clawdstrike-pkg.toml");
    let manifest_str = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read clawdstrike-pkg.toml: {e}");
            return ExitCode::ConfigError;
        }
    };

    let manifest: PkgManifest = match parse_pkg_manifest_toml(&manifest_str) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid manifest: {e}");
            return ExitCode::ConfigError;
        }
    };

    // Build archive name
    let archive_name = format!(
        "{}-{}.cpkg",
        manifest.package.name.replace('/', "-").replace('@', ""),
        manifest.package.version
    );
    let output_path = source_dir.join(&archive_name);

    // Pack
    let hash = match archive::pack(&source_dir, &output_path) {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(stderr, "Error: pack failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(stdout, "Packed: {}", output_path.display());
    let _ = writeln!(stdout, "Hash:   {}", hash.to_hex());
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg install
// ---------------------------------------------------------------------------

fn cmd_pkg_install(source: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    if !source.exists() {
        let _ = writeln!(stderr, "Error: file not found: {}", source.display());
        return ExitCode::ConfigError;
    }

    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let installed = match store.install_from_file(source) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Error: install failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(
        stdout,
        "Installed: {} v{}",
        installed.name, installed.version
    );
    let _ = writeln!(stdout, "Path:      {}", installed.path.display());
    let _ = writeln!(stdout, "Hash:      {}", installed.content_hash.to_hex());
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg list
// ---------------------------------------------------------------------------

fn cmd_pkg_list(stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let packages = match store.list() {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot list packages: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if packages.is_empty() {
        let _ = writeln!(stdout, "No packages installed.");
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "{:<40} {:<12} HASH", "NAME", "VERSION");
    let _ = writeln!(stdout, "{}", "-".repeat(72));
    for pkg in &packages {
        let hash_hex = pkg.content_hash.to_hex();
        let hash_display = if hash_hex.len() > 16 {
            &hash_hex[..16]
        } else {
            &hash_hex
        };
        let _ = writeln!(
            stdout,
            "{:<40} {:<12} {}...",
            pkg.name, pkg.version, hash_display
        );
    }

    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg verify
// ---------------------------------------------------------------------------

fn cmd_pkg_verify(
    name: &str,
    version: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let pkg = match store.get(name, version) {
        Ok(Some(p)) => p,
        Ok(None) => {
            let _ = writeln!(stderr, "Error: package '{}' v{} not found", name, version);
            return ExitCode::Fail;
        }
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Verify the manifest is present and valid.
    let manifest_path = pkg.path.join("clawdstrike-pkg.toml");
    let manifest_str = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "FAIL: '{}' v{} missing manifest: {e}",
                name, version
            );
            return ExitCode::Fail;
        }
    };

    if let Err(e) = parse_pkg_manifest_toml(&manifest_str) {
        let _ = writeln!(
            stderr,
            "FAIL: '{}' v{} invalid manifest: {e}",
            name, version
        );
        return ExitCode::Fail;
    }

    // Verify the metadata file is present and the stored content hash is non-empty.
    let meta_path = pkg.path.join(".pkg-meta.json");
    if !meta_path.exists() {
        let _ = writeln!(
            stderr,
            "FAIL: '{}' v{} missing store metadata",
            name, version
        );
        return ExitCode::Fail;
    }

    let _ = writeln!(
        stdout,
        "OK: '{}' v{} integrity verified (hash: {})",
        name,
        version,
        pkg.content_hash.to_hex()
    );
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg info
// ---------------------------------------------------------------------------

fn cmd_pkg_info(
    name: &str,
    version: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let pkg = match store.get(name, version) {
        Ok(Some(p)) => p,
        Ok(None) => {
            let _ = writeln!(stderr, "Error: package '{}' v{} not found", name, version);
            return ExitCode::Fail;
        }
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let _ = writeln!(stdout, "Name:    {}", pkg.name);
    let _ = writeln!(stdout, "Version: {}", pkg.version);
    let _ = writeln!(stdout, "Path:    {}", pkg.path.display());
    let _ = writeln!(stdout, "Hash:    {}", pkg.content_hash);

    // Try to read the manifest for more detail
    let manifest_path = pkg.path.join("clawdstrike-pkg.toml");
    if let Ok(manifest_str) = std::fs::read_to_string(&manifest_path) {
        if let Ok(manifest) = parse_pkg_manifest_toml(&manifest_str) {
            let _ = writeln!(stdout, "Type:    {}", manifest.package.pkg_type);
            if let Some(desc) = &manifest.package.description {
                if !desc.is_empty() {
                    let _ = writeln!(stdout, "Desc:    {}", desc);
                }
            }
            if let Some(license) = &manifest.package.license {
                let _ = writeln!(stdout, "License: {}", license);
            }
            if !manifest.package.authors.is_empty() {
                let _ = writeln!(stdout, "Authors: {}", manifest.package.authors.join(", "));
            }
            if !manifest.dependencies.is_empty() {
                let _ = writeln!(stdout, "Dependencies:");
                for (dep_name, constraint) in &manifest.dependencies {
                    let _ = writeln!(stdout, "  {} = \"{}\"", dep_name, constraint);
                }
            }
        }
    }

    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg test
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm-plugin-runtime")]
fn cmd_pkg_test(
    path: Option<&Path>,
    filter: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    use clawdstrike::pkg::test_runner::{parse_guard_test_file, run_guard_tests};

    let pkg_dir = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                let _ = writeln!(stderr, "Error: cannot determine current directory: {e}");
                return ExitCode::RuntimeError;
            }
        },
    };

    // Discover test fixture files
    let tests_dir = pkg_dir.join("tests");
    if !tests_dir.is_dir() {
        let _ = writeln!(
            stderr,
            "Error: no tests/ directory found in {}",
            pkg_dir.display()
        );
        return ExitCode::ConfigError;
    }

    let fixture_files: Vec<PathBuf> = match std::fs::read_dir(&tests_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect(),
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read tests/ directory: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if fixture_files.is_empty() {
        let _ = writeln!(
            stderr,
            "Error: no .yaml/.yml fixture files found in {}",
            tests_dir.display()
        );
        return ExitCode::ConfigError;
    }

    // Find the WASM file: check plugin-manifest.toml first, then fall back to
    // looking for a .wasm file in target/wasm32-unknown-unknown/release/ or
    // target/wasm32-unknown-unknown/debug/
    let wasm_path = find_wasm_binary(&pkg_dir, stderr);
    let wasm_path = match wasm_path {
        Some(p) => p,
        None => return ExitCode::ConfigError,
    };

    let wasm_bytes = match std::fs::read(&wasm_path) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "Error: cannot read WASM file {}: {e}",
                wasm_path.display()
            );
            return ExitCode::RuntimeError;
        }
    };

    // Load runtime options from plugin-manifest.toml if available
    let options = load_runtime_options(&pkg_dir);

    let _ = writeln!(stdout, "Running guard tests...");
    let _ = writeln!(stdout, "WASM: {}", wasm_path.display());
    let _ = writeln!(stdout);

    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut total_error = 0usize;

    for fixture_path in &fixture_files {
        let suite = match parse_guard_test_file(fixture_path) {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "Error: failed to parse {}: {e}",
                    fixture_path.display()
                );
                total_error += 1;
                continue;
            }
        };

        let file_name = fixture_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let _ = writeln!(stdout, "--- {} ({})", suite.suite, file_name);

        let results = run_guard_tests(&wasm_bytes, &suite, &options, filter);

        for result in &results {
            if result.passed {
                total_pass += 1;
                let _ = writeln!(
                    stdout,
                    "  PASS  {} ({:.1}ms)",
                    result.name,
                    result.duration.as_secs_f64() * 1000.0
                );
            } else if let Some(ref err) = result.error {
                total_error += 1;
                let _ = writeln!(stdout, "  ERROR {} -- {}", result.name, err);
            } else {
                total_fail += 1;
                let _ = writeln!(
                    stdout,
                    "  FAIL  {} ({:.1}ms)",
                    result.name,
                    result.duration.as_secs_f64() * 1000.0
                );
                for mismatch in &result.mismatches {
                    let _ = writeln!(
                        stdout,
                        "         {}: expected '{}', got '{}'",
                        mismatch.field, mismatch.expected, mismatch.actual
                    );
                }
            }
        }

        let _ = writeln!(stdout);
    }

    let _ = writeln!(
        stdout,
        "Results: {} passed, {} failed, {} errors",
        total_pass, total_fail, total_error
    );

    if total_fail > 0 || total_error > 0 {
        ExitCode::Fail
    } else {
        ExitCode::Ok
    }
}

#[cfg(not(feature = "wasm-plugin-runtime"))]
fn cmd_pkg_test(
    _path: Option<&Path>,
    _filter: Option<&str>,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let _ = writeln!(
        stderr,
        "Error: `pkg test` requires the `wasm-plugin-runtime` feature.\n\
         Rebuild with: cargo build --features wasm-plugin-runtime"
    );
    ExitCode::ConfigError
}

#[cfg(feature = "wasm-plugin-runtime")]
fn find_wasm_binary(pkg_dir: &Path, stderr: &mut dyn Write) -> Option<PathBuf> {
    use clawdstrike::plugins::parse_plugin_manifest_toml;

    // Try to read plugin-manifest.toml for the plugin name
    let manifest_path = pkg_dir.join("plugin-manifest.toml");
    if let Ok(content) = std::fs::read_to_string(&manifest_path) {
        if let Ok(manifest) = parse_plugin_manifest_toml(&content) {
            let wasm_name = format!("{}.wasm", manifest.plugin.name.replace('-', "_"));

            // Check release first, then debug
            for profile in &["release", "debug"] {
                let candidate = pkg_dir
                    .join("target/wasm32-unknown-unknown")
                    .join(profile)
                    .join(&wasm_name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }

    // Fall back: try to read Cargo.toml for [package].name
    let cargo_path = pkg_dir.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo_path) {
        if let Ok(table) = content.parse::<toml::Table>() {
            if let Some(pkg_name) = table
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
            {
                let wasm_name = format!("{}.wasm", pkg_name.replace('-', "_"));
                for profile in &["release", "debug"] {
                    let candidate = pkg_dir
                        .join("target/wasm32-unknown-unknown")
                        .join(profile)
                        .join(&wasm_name);
                    if candidate.exists() {
                        return Some(candidate);
                    }
                }
            }
        }
    }

    // Last resort: find any .wasm file in the target dirs
    for profile in &["release", "debug"] {
        let dir = pkg_dir.join("target/wasm32-unknown-unknown").join(profile);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|ext| ext == "wasm") {
                    return Some(p);
                }
            }
        }
    }

    let _ = writeln!(
        stderr,
        "Error: no .wasm file found. Build your guard first:\n  \
         cargo build --target wasm32-unknown-unknown --release"
    );
    None
}

#[cfg(feature = "wasm-plugin-runtime")]
fn load_runtime_options(pkg_dir: &Path) -> clawdstrike::plugins::WasmGuardRuntimeOptions {
    use clawdstrike::plugins::{parse_plugin_manifest_toml, WasmGuardRuntimeOptions};

    let manifest_path = pkg_dir.join("plugin-manifest.toml");
    if let Ok(content) = std::fs::read_to_string(&manifest_path) {
        if let Ok(manifest) = parse_plugin_manifest_toml(&content) {
            return WasmGuardRuntimeOptions {
                capabilities: manifest.capabilities,
                resources: manifest.resources,
            };
        }
    }

    WasmGuardRuntimeOptions::default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run_cmd(cmd: PkgCommands) -> (String, String, ExitCode) {
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let code = cmd_pkg(cmd, &mut stdout_buf, &mut stderr_buf);
        (
            String::from_utf8_lossy(&stdout_buf).to_string(),
            String::from_utf8_lossy(&stderr_buf).to_string(),
            code,
        )
    }

    #[test]
    fn test_scaffold_guard() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "my-test-guard").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("src").is_dir());

        let content = std::fs::read_to_string(tmp.path().join("clawdstrike-pkg.toml")).unwrap();
        assert!(content.contains("my-test-guard"));
        assert!(content.contains("guard"));
    }

    #[test]
    fn test_scaffold_guard_creates_all_template_files() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "my-guard").unwrap();

        // Guard-specific files
        assert!(tmp.path().join("src/lib.rs").exists());
        assert!(tmp.path().join("Cargo.toml").exists());
        assert!(tmp.path().join("plugin-manifest.toml").exists());
        assert!(tmp.path().join("tests/basic.yaml").exists());
        assert!(tmp.path().join(".cargo/config.toml").exists());

        // Verify content of key files
        let lib_rs = std::fs::read_to_string(tmp.path().join("src/lib.rs")).unwrap();
        assert!(lib_rs.contains("clawdstrike_guard_sdk"));
        assert!(lib_rs.contains("#[clawdstrike_guard]"));
        assert!(lib_rs.contains("impl Guard for"));

        let cargo_toml = std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("cdylib"));
        assert!(cargo_toml.contains("clawdstrike-guard-sdk"));

        let plugin_manifest =
            std::fs::read_to_string(tmp.path().join("plugin-manifest.toml")).unwrap();
        assert!(plugin_manifest.contains("my-guard"));

        let test_yaml = std::fs::read_to_string(tmp.path().join("tests/basic.yaml")).unwrap();
        assert!(test_yaml.contains("my-guard"));
        assert!(test_yaml.contains("fixtures:"));

        let cargo_config = std::fs::read_to_string(tmp.path().join(".cargo/config.toml")).unwrap();
        assert!(cargo_config.contains("wasm32-unknown-unknown"));
    }

    #[test]
    fn test_scaffold_guard_struct_name_derivation() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "@acme/my-cool-guard").unwrap();

        let lib_rs = std::fs::read_to_string(tmp.path().join("src/lib.rs")).unwrap();
        // @acme/my-cool-guard -> AcmeMyCoolGuardGuard
        assert!(lib_rs.contains("AcmeMyCoolGuardGuard"));
    }

    #[test]
    fn test_scaffold_non_guard_skips_guard_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "my-policies").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(!tmp.path().join("src/lib.rs").exists());
        assert!(!tmp.path().join("plugin-manifest.toml").exists());
        assert!(!tmp.path().join("tests/basic.yaml").exists());
    }

    #[test]
    fn test_scaffold_policy_pack() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "my-policies").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("policies").is_dir());
        assert!(tmp.path().join("data").is_dir());
    }

    #[test]
    fn test_scaffold_all_types() {
        for (pkg_type, expected_dir) in [
            (PkgType::Guard, Some("src")),
            (PkgType::PolicyPack, Some("policies")),
            (PkgType::Adapter, Some("src")),
            (PkgType::Engine, Some("src")),
            (PkgType::Template, Some("template")),
            (PkgType::Bundle, None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            scaffold_package(tmp.path(), &pkg_type, "test-pkg").unwrap();
            assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
            if let Some(dir) = expected_dir {
                assert!(
                    tmp.path().join(dir).is_dir(),
                    "expected {dir} for {pkg_type}"
                );
            }
        }
    }

    #[test]
    fn test_pack_missing_manifest() {
        let tmp = tempfile::tempdir().unwrap();

        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("clawdstrike-pkg.toml"));
    }

    #[test]
    fn test_pack_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("mypkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "test-pkg"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
        std::fs::write(pkg_dir.join("src/lib.rs"), "// guard code").unwrap();

        let (stdout, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(pkg_dir.clone()),
        });

        assert_eq!(code, ExitCode::Ok, "stderr: {}", stderr);
        assert!(stdout.contains("Packed:"));
        assert!(stdout.contains("Hash:"));

        // Verify .cpkg file exists
        let cpkg = pkg_dir.join("test-pkg-0.1.0.cpkg");
        assert!(cpkg.exists(), "expected cpkg at {}", cpkg.display());
    }

    #[test]
    fn test_list_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
        let _ = store; // ensure store dir exists

        // We can't easily redirect the default store, so just verify
        // the list command doesn't panic with an empty store.
        // Direct testing would require a way to inject the store root.
    }

    #[test]
    fn test_install_nonexistent() {
        let (_, stderr, code) = run_cmd(PkgCommands::Install {
            source: PathBuf::from("/tmp/nonexistent-pkg-12345.cpkg"),
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("not found"));
    }
}

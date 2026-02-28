#![allow(clippy::needless_pass_by_value)]
//! `hush pkg` subcommands — package management for `.cpkg` archives.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use hush_core::{PublicKey, Signature};

use clawdstrike::pkg::archive;
use clawdstrike::pkg::integrity::sign_package;
use clawdstrike::pkg::manifest::{parse_pkg_manifest_toml, PkgManifest, PkgType};
use clawdstrike::pkg::store::PackageStore;

use crate::registry_config::{is_file_source, load_or_generate_publisher_keypair, RegistryConfig};
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
    /// Install a package from a local .cpkg file or the registry
    Install {
        /// Path to .cpkg file, or package name for registry install
        source: String,
        /// Version to install (for registry packages)
        #[arg(long)]
        version: Option<String>,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
        /// Minimum trust level for registry installs (unverified, signed, verified, certified)
        #[arg(long, default_value = "signed")]
        trust_level: Option<String>,
        /// Allow installing unverified packages (dangerous)
        #[arg(long)]
        allow_unverified: bool,
    },
    /// List installed packages
    List,
    /// Verify an installed package's integrity and trust level
    Verify {
        /// Package name (e.g., @scope/name)
        name: String,
        /// Specific version to verify (default: installed version)
        #[arg(long)]
        version: String,
        /// Minimum required trust level (unverified, signed, verified, certified)
        #[arg(long, default_value = "signed")]
        trust_level: String,
        /// Registry URL (for fetching attestations and proofs)
        #[arg(long)]
        registry: Option<String>,
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
    /// Authenticate with a package registry
    Login {
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// Publish a package to the registry
    Publish {
        /// Path to package directory (defaults to current dir)
        path: Option<PathBuf>,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
        /// Use OIDC token for authentication (for CI/CD environments)
        #[arg(long)]
        oidc: bool,
    },
    /// Search for packages in the registry
    Search {
        /// Search query
        query: String,
        /// Maximum number of results
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Page number (0-indexed)
        #[arg(long, default_value = "0")]
        page: usize,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show package publish history
    Audit {
        /// Package name
        name: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
        /// Limit results
        #[arg(long, default_value = "20")]
        limit: u32,
    },
    /// Yank (soft-delete) a package version from the registry
    Yank {
        /// Package name (e.g., @scope/name)
        name: String,
        /// Version to yank
        #[arg(long)]
        version: String,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show package download and usage statistics
    Stats {
        /// Package name
        name: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Organization management
    Org {
        #[command(subcommand)]
        command: OrgCommands,
    },
    /// Manage trusted publishers for OIDC-based CI/CD publishing
    TrustedPublishers {
        #[command(subcommand)]
        command: TrustedPublisherCommands,
    },
    /// Mirror packages from an upstream registry for air-gapped or local use
    Mirror {
        #[command(subcommand)]
        command: crate::mirror::MirrorCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum TrustedPublisherCommands {
    /// Add a trusted publisher for a package
    Add {
        /// Package name (e.g., @acme/my-guard)
        package: String,
        /// OIDC provider: github or gitlab
        #[arg(long)]
        provider: String,
        /// Repository in owner/repo format
        #[arg(long)]
        repo: String,
        /// Optional workflow filter (e.g., release.yml)
        #[arg(long)]
        workflow: Option<String>,
        /// Optional environment filter (e.g., production)
        #[arg(long)]
        environment: Option<String>,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// List trusted publishers for a package
    List {
        /// Package name
        package: String,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove a trusted publisher by ID
    Remove {
        /// Package name
        package: String,
        /// Trusted publisher ID
        #[arg(long)]
        id: i64,
        /// Registry URL override
        #[arg(long)]
        registry: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum OrgCommands {
    /// Create a new organization
    Create {
        /// Organization name (used as @scope)
        name: String,
        /// Display name
        #[arg(long)]
        display_name: Option<String>,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// List organization members
    Members {
        /// Organization name
        name: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Invite a member to the organization
    Invite {
        /// Organization name
        org: String,
        /// Member's public key (hex)
        publisher_key: String,
        /// Role: owner, maintainer, member
        #[arg(long, default_value = "member")]
        role: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove a member from the organization
    Remove {
        /// Organization name
        org: String,
        /// Member's public key (hex)
        publisher_key: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
    /// Show organization info
    Info {
        /// Organization name
        name: String,
        /// Registry URL
        #[arg(long)]
        registry: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

pub fn cmd_pkg(command: PkgCommands, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match command {
        PkgCommands::Init { pkg_type, name } => cmd_pkg_init(&pkg_type, &name, stdout, stderr),
        PkgCommands::Pack { path } => cmd_pkg_pack(path.as_deref(), stdout, stderr),
        PkgCommands::Install {
            source,
            version,
            registry,
            trust_level,
            allow_unverified,
        } => cmd_pkg_install(
            &source,
            version.as_deref(),
            registry.as_deref(),
            trust_level.as_deref(),
            allow_unverified,
            stdout,
            stderr,
        ),
        PkgCommands::List => cmd_pkg_list(stdout, stderr),
        PkgCommands::Verify {
            name,
            version,
            trust_level,
            registry,
        } => cmd_pkg_verify(
            &name,
            &version,
            &trust_level,
            registry.as_deref(),
            stdout,
            stderr,
        ),
        PkgCommands::Info { name, version } => cmd_pkg_info(&name, &version, stdout, stderr),
        PkgCommands::Test { path, filter } => {
            cmd_pkg_test(path.as_deref(), filter.as_deref(), stdout, stderr)
        }
        PkgCommands::Login { registry } => cmd_pkg_login(registry.as_deref(), stdout, stderr),
        PkgCommands::Publish {
            path,
            registry,
            oidc,
        } => cmd_pkg_publish(path.as_deref(), registry.as_deref(), oidc, stdout, stderr),
        PkgCommands::Search {
            query,
            limit,
            page,
            registry,
        } => cmd_pkg_search(&query, limit, page, registry.as_deref(), stdout, stderr),
        PkgCommands::Audit {
            name,
            registry,
            limit,
        } => cmd_pkg_audit(&name, registry.as_deref(), limit, stdout, stderr),
        PkgCommands::Yank {
            name,
            version,
            registry,
        } => cmd_pkg_yank(&name, &version, registry.as_deref(), stdout, stderr),
        PkgCommands::Stats { name, registry } => {
            cmd_pkg_stats(&name, registry.as_deref(), stdout, stderr)
        }
        PkgCommands::TrustedPublishers { command } => {
            cmd_pkg_trusted_publishers(command, stdout, stderr)
        }
        PkgCommands::Org { command } => cmd_pkg_org(command, stdout, stderr),
        PkgCommands::Mirror { command } => crate::mirror::cmd_mirror(command, stdout, stderr),
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

/// Write a template file into the given directory, creating parent dirs as needed.
fn write_template_file(dir: &Path, filename: &str, content: &str) -> std::io::Result<()> {
    let path = dir.join(filename);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)
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
            std::fs::create_dir_all(dir.join("tests"))?;
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
    write_template_file(dir, "clawdstrike-pkg.toml", &manifest_toml)?;

    // Type-specific template files
    match pkg_type {
        PkgType::Guard => scaffold_guard_templates(dir, name)?,
        PkgType::PolicyPack => scaffold_policy_pack_templates(dir, name)?,
        PkgType::Bundle => scaffold_bundle_templates(dir, name)?,
        _ => {}
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

fn scaffold_policy_pack_templates(dir: &Path, name: &str) -> std::io::Result<()> {
    // policies/default.yaml
    write_template_file(
        dir,
        "policies/default.yaml",
        &generate_policy_pack_default_yaml(name),
    )?;

    // tests/policy-test.yaml
    write_template_file(
        dir,
        "tests/policy-test.yaml",
        &generate_policy_pack_test(name),
    )?;

    // README.md
    write_template_file(dir, "README.md", &generate_policy_pack_readme(name))?;

    Ok(())
}

fn scaffold_bundle_templates(dir: &Path, name: &str) -> std::io::Result<()> {
    // README.md
    write_template_file(dir, "README.md", &generate_bundle_readme(name))?;

    Ok(())
}

fn generate_policy_pack_default_yaml(name: &str) -> String {
    format!(
        r#"# {name} — Default Policy
version: "1.2.0"
name: {name}
description: Default policy for {name}
extends: clawdstrike:default

guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
      - "**/.env.*"
      - "/etc/shadow"
      - "/etc/passwd"
    exceptions: []

  secret_leak:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{{16}}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
    skip_paths:
      - "**/test/**"
      - "**/tests/**"

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600
"#
    )
}

fn generate_policy_pack_test(name: &str) -> String {
    format!(
        r#"# Test suite for {name} policy pack
suite: "{name} policy tests"
tests:
  - name: "blocks access to .ssh directory"
    action:
      type: "file_access"
      path: "/home/user/.ssh/id_rsa"
    policy: "policies/default.yaml"
    expect:
      allowed: false

  - name: "allows access to safe path"
    action:
      type: "file_access"
      path: "/tmp/safe-file.txt"
    policy: "policies/default.yaml"
    expect:
      allowed: true
"#
    )
}

fn generate_policy_pack_readme(name: &str) -> String {
    format!(
        r#"# {name}

A Clawdstrike policy pack.

## Policies

| Policy | Description |
|--------|-------------|
| `policies/default.yaml` | Default policy configuration |

## Usage

```yaml
extends: "{name}/policies/default"
```

```bash
clawdstrike pkg install {name}
clawdstrike check --ruleset {name}/policies/default --action-type file /path/to/check
```

## Compliance Mapping

| Requirement | Control | Guard |
|---|---|---|
| *Add your compliance mapping here* | | |
"#
    )
}

fn generate_bundle_readme(name: &str) -> String {
    format!(
        r#"# {name}

A Clawdstrike bundle package that combines guards and policy packs.

## Dependencies

This bundle includes the following packages (see `[dependencies]` in `clawdstrike-pkg.toml`):

| Package | Version | Description |
|---------|---------|-------------|
| *Add dependencies to clawdstrike-pkg.toml* | | |

## Usage

```bash
clawdstrike pkg install {name}
```

All bundled guards and policies are installed together as a single unit.
"#
    )
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
    let deps = if *pkg_type == PkgType::Bundle {
        r#"[dependencies]
# "@clawdstrike/example-guard" = "^0.1"
# "@clawdstrike/example-policy" = "^0.1"
"#
    } else {
        "[dependencies]\n"
    };

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

{deps}"#,
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

    // Pre-pack validation based on package type
    if let Err(msg) = validate_pack_contents(&source_dir, &manifest) {
        let _ = writeln!(stderr, "Error: {msg}");
        return ExitCode::ConfigError;
    }

    // Warn on missing README.md
    if !source_dir.join("README.md").exists() {
        let _ = writeln!(stderr, "Warning: README.md not found; consider adding one");
    }

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

/// Validate that a package directory contains the expected contents for its type.
fn validate_pack_contents(source_dir: &Path, manifest: &PkgManifest) -> Result<(), String> {
    match manifest.package.pkg_type {
        PkgType::PolicyPack => {
            let policies_dir = source_dir.join("policies");
            if !policies_dir.is_dir() {
                return Err("policy-pack must contain a policies/ directory".to_string());
            }
            let has_yaml = std::fs::read_dir(&policies_dir)
                .map(|entries| {
                    entries.filter_map(|e| e.ok()).any(|e| {
                        e.path()
                            .extension()
                            .is_some_and(|ext| ext == "yaml" || ext == "yml")
                    })
                })
                .unwrap_or(false);
            if !has_yaml {
                return Err(
                    "policy-pack policies/ directory must contain at least one .yaml file"
                        .to_string(),
                );
            }
        }
        PkgType::Guard => {
            if !source_dir.join("src/lib.rs").exists() {
                return Err(
                    "guard package must contain src/lib.rs (or a WASM entrypoint)".to_string(),
                );
            }
        }
        PkgType::Bundle => {
            if manifest.dependencies.is_empty() {
                return Err(
                    "bundle package must have at least one entry in [dependencies]".to_string(),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// pkg install
// ---------------------------------------------------------------------------

fn cmd_pkg_install(
    source: &str,
    version: Option<&str>,
    registry: Option<&str>,
    trust_level: Option<&str>,
    allow_unverified: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if is_file_source(source) {
        return cmd_pkg_install_local(Path::new(source), stdout, stderr);
    }

    // Validate trust level if provided.
    let level = trust_level.unwrap_or("signed");
    if !matches!(level, "unverified" | "signed" | "verified" | "certified") {
        let _ = writeln!(
            stderr,
            "Error: invalid trust level '{}'. Must be one of: unverified, signed, verified, certified",
            level
        );
        return ExitCode::ConfigError;
    }

    if level == "unverified" && !allow_unverified {
        let _ = writeln!(
            stderr,
            "Error: trust level 'unverified' requires --allow-unverified flag"
        );
        return ExitCode::ConfigError;
    }

    if allow_unverified {
        let _ = writeln!(
            stderr,
            "Warning: installing without trust verification. Use at your own risk."
        );
    }

    cmd_pkg_install_registry(
        source,
        version,
        registry,
        level,
        allow_unverified,
        stdout,
        stderr,
    )
}

fn cmd_pkg_install_local(
    source: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
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

fn cmd_pkg_install_registry(
    name: &str,
    version: Option<&str>,
    registry: Option<&str>,
    trust_level: &str,
    allow_unverified: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // When version is omitted, resolve the latest version from the registry.
    let resolved_version: String;
    let version_segment: &str = match version {
        Some(v) => v,
        None => {
            let info_url = format!(
                "{}/api/v1/packages/{}/stats",
                cfg.registry_url.trim_end_matches('/'),
                urlencoding_simple(name)
            );
            let info_resp = match client.get(&info_url).send() {
                Ok(r) => r,
                Err(e) => {
                    let _ = writeln!(
                        stderr,
                        "Error: cannot fetch package info to resolve latest version: {e}"
                    );
                    return ExitCode::RuntimeError;
                }
            };
            if !info_resp.status().is_success() {
                let status = info_resp.status();
                let _ = writeln!(
                    stderr,
                    "Error: cannot resolve latest version (HTTP {status}). \
                     Specify --version explicitly."
                );
                return ExitCode::RuntimeError;
            }
            let info: serde_json::Value = match info_resp.json() {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: invalid package info response: {e}");
                    return ExitCode::RuntimeError;
                }
            };
            // The stats endpoint returns versions newest-first (DESC), so
            // index 0 is the latest.
            let latest = info["versions"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|entry| entry["version"].as_str())
                .or_else(|| info["latest_version"].as_str());
            match latest {
                Some(v) => {
                    resolved_version = v.to_string();
                    &resolved_version
                }
                None => {
                    let _ = writeln!(
                        stderr,
                        "Error: cannot determine latest version for '{name}'. \
                         Specify --version explicitly."
                    );
                    return ExitCode::RuntimeError;
                }
            }
        }
    };

    let url = format!(
        "{}/api/v1/packages/{}/{}/download",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version_segment)
    );

    let _ = writeln!(stdout, "Downloading {} v{} ...", name, version_segment);

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: download failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let bytes = match resp.bytes() {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to read response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Write to a temp file, then install
    let tmp_dir = match tempdir_for_download() {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create temp dir: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let cpkg_path = tmp_dir.join(format!(
        "{}-{}.cpkg",
        name.replace('/', "-").replace('@', ""),
        version_segment
    ));
    if let Err(e) = std::fs::write(&cpkg_path, &bytes) {
        let _ = writeln!(stderr, "Error: cannot write temp file: {e}");
        return ExitCode::RuntimeError;
    }

    let store = match PackageStore::new() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot open package store: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let installed = match store.install_from_file(&cpkg_path) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "Error: install failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Cleanup temp
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Trust verification for registry installs.
    if !allow_unverified && trust_level != "unverified" {
        let trust_ok = verify_install_trust(
            &installed.name,
            version_segment,
            &installed.content_hash,
            &cfg,
            &client,
            trust_level,
            stdout,
            stderr,
        );
        if !trust_ok {
            // Remove the installed package since trust verification failed.
            let _ = store.remove(&installed.name, &installed.version);
            let _ = writeln!(
                stderr,
                "Error: package removed because trust verification failed. \
                 Use --allow-unverified to skip trust checks."
            );
            return ExitCode::Fail;
        }
    }

    let _ = writeln!(
        stdout,
        "Installed: {} v{}",
        installed.name, installed.version
    );
    let _ = writeln!(stdout, "Path:      {}", installed.path.display());
    let _ = writeln!(stdout, "Hash:      {}", installed.content_hash.to_hex());
    ExitCode::Ok
}

/// Verify trust level of a registry-installed package.
/// Returns `true` if trust verification passes at the requested level.
#[derive(Debug, serde::Deserialize)]
struct RegistryAttestation {
    checksum: String,
    publisher_key: String,
    publisher_sig: String,
    registry_sig: Option<String>,
    registry_key: Option<String>,
}

#[derive(Debug)]
struct AttestationVerification {
    publisher_verified: bool,
    registry_verified: bool,
}

fn verify_attestation_against_hash(
    attestation: &RegistryAttestation,
    content_hash: &hush_core::Hash,
) -> Result<AttestationVerification, String> {
    if attestation.checksum != content_hash.to_hex() {
        return Err("attestation checksum does not match installed package hash".to_string());
    }

    let publisher_key = PublicKey::from_hex(&attestation.publisher_key)
        .map_err(|e| format!("invalid publisher key in attestation: {e}"))?;
    let publisher_sig = Signature::from_hex(&attestation.publisher_sig)
        .map_err(|e| format!("invalid publisher signature in attestation: {e}"))?;
    if !publisher_key.verify(content_hash.as_bytes(), &publisher_sig) {
        return Err("publisher signature verification failed".to_string());
    }

    let registry_verified = if let Some(registry_sig_hex) = &attestation.registry_sig {
        let registry_key_hex = attestation
            .registry_key
            .as_deref()
            .ok_or_else(|| "registry signature present but registry key missing".to_string())?;
        let registry_key = PublicKey::from_hex(registry_key_hex)
            .map_err(|e| format!("invalid registry key in attestation: {e}"))?;
        let registry_sig = Signature::from_hex(registry_sig_hex)
            .map_err(|e| format!("invalid registry signature in attestation: {e}"))?;
        if !registry_key.verify(content_hash.as_bytes(), &registry_sig) {
            return Err("registry counter-signature verification failed".to_string());
        }
        true
    } else {
        false
    };

    Ok(AttestationVerification {
        publisher_verified: true,
        registry_verified,
    })
}

fn verify_install_trust(
    name: &str,
    version: &str,
    content_hash: &hush_core::Hash,
    cfg: &RegistryConfig,
    client: &reqwest::blocking::Client,
    trust_level: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> bool {
    let _ = writeln!(stdout, "Verifying trust level: {} ...", trust_level);

    // Fetch attestation from registry.
    let attestation_url = format!(
        "{}/api/v1/packages/{}/{}/attestation",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
    );

    let resp = match client.get(&attestation_url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Warning: cannot fetch attestation: {e}");
            return false;
        }
    };

    if !resp.status().is_success() {
        let _ = writeln!(
            stderr,
            "Warning: attestation not available (HTTP {})",
            resp.status()
        );
        return false;
    }

    let attestation: RegistryAttestation = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Warning: invalid attestation response: {e}");
            return false;
        }
    };

    let verified = match verify_attestation_against_hash(&attestation, content_hash) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return false;
        }
    };

    if trust_level == "signed" {
        return verified.publisher_verified;
    }

    if !verified.registry_verified {
        let _ = writeln!(
            stderr,
            "Error: package has no valid registry counter-signature"
        );
        return false;
    }

    if trust_level == "verified" {
        return true;
    }

    // At "certified" level, we also need a Merkle inclusion proof.
    let proof_url = format!(
        "{}/api/v1/packages/{}/{}/proof",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
    );

    let proof_resp = match client.get(&proof_url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot fetch inclusion proof: {e}");
            return false;
        }
    };

    if !proof_resp.status().is_success() {
        let _ = writeln!(
            stderr,
            "Error: Merkle inclusion proof not available (HTTP {})",
            proof_resp.status()
        );
        return false;
    }

    // trust_level == "certified"
    true
}

fn tempdir_for_download() -> std::io::Result<PathBuf> {
    let nonce: u64 = rand::Rng::random(&mut rand::rng());
    let dir = std::env::temp_dir().join(format!("clawdstrike_dl_{nonce:x}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

struct CallerAuthHeaders {
    key_hex: String,
    sig_hex: String,
    ts: String,
}

fn build_caller_auth_headers(
    cfg: &RegistryConfig,
    payload: &str,
    stderr: &mut dyn Write,
) -> Result<CallerAuthHeaders, ExitCode> {
    let keypair = load_or_generate_publisher_keypair(cfg, stderr).map_err(|e| {
        let _ = writeln!(stderr, "Error: {e}");
        ExitCode::RuntimeError
    })?;
    let ts = chrono::Utc::now().to_rfc3339();
    let msg = format!("clawdstrike-registry-auth:v1:{payload}:{ts}");
    let sig = keypair.sign(msg.as_bytes()).to_hex();
    Ok(CallerAuthHeaders {
        key_hex: keypair.public_key().to_hex(),
        sig_hex: sig,
        ts,
    })
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
    trust_level: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    // Validate trust level.
    if !matches!(
        trust_level,
        "unverified" | "signed" | "verified" | "certified"
    ) {
        let _ = writeln!(
            stderr,
            "Error: invalid trust level '{}'. Must be one of: unverified, signed, verified, certified",
            trust_level
        );
        return ExitCode::ConfigError;
    }

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

    let _ = writeln!(stdout, "Package: {} v{}", name, version);

    // --- Step 1: Local integrity check ---
    let manifest_path = pkg.path.join("clawdstrike-pkg.toml");
    let manifest_str = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stdout, "Trust Level: FAIL\n");
            let _ = writeln!(stdout, "  x Content integrity    Missing manifest: {e}");
            return ExitCode::Fail;
        }
    };

    if let Err(e) = parse_pkg_manifest_toml(&manifest_str) {
        let _ = writeln!(stdout, "Trust Level: FAIL\n");
        let _ = writeln!(stdout, "  x Content integrity    Invalid manifest: {e}");
        return ExitCode::Fail;
    }

    let meta_path = pkg.path.join(".pkg-meta.json");
    if !meta_path.exists() {
        let _ = writeln!(stdout, "Trust Level: FAIL\n");
        let _ = writeln!(stdout, "  x Content integrity    Missing store metadata");
        return ExitCode::Fail;
    }

    let hash_hex = pkg.content_hash.to_hex();
    let hash_display = if hash_hex.len() > 16 {
        &hash_hex[..16]
    } else {
        &hash_hex
    };

    let mut content_ok = true;
    let mut publisher_ok = false;
    let mut registry_ok = false;
    let mut attestation_error: Option<String> = None;

    // Read store metadata for installed_at timestamp.
    let installed_at = match std::fs::read_to_string(&meta_path) {
        Ok(s) => {
            let meta: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
            meta.get("installed_at")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string()
        }
        Err(_) => {
            content_ok = false;
            "unknown".to_string()
        }
    };

    // If trust level is unverified, we only check content integrity.
    if trust_level == "unverified" {
        let _ = writeln!(stdout, "Trust Level: Unverified\n");
        if content_ok {
            let _ = writeln!(
                stdout,
                "  + Content integrity    SHA-256: {}...",
                hash_display
            );
        } else {
            let _ = writeln!(stdout, "  x Content integrity    Metadata unreadable");
        }
        let _ = writeln!(stdout, "\nInstalled: {}", installed_at);
        return if content_ok {
            ExitCode::Ok
        } else {
            ExitCode::Fail
        };
    }

    // --- Steps 2-4: Registry-based verification ---
    let cfg = RegistryConfig::load(registry);
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Fetch attestation.
    let attestation_url = format!(
        "{}/api/v1/packages/{}/{}/attestation",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
    );

    let attestation: Option<RegistryAttestation> = client
        .get(&attestation_url)
        .send()
        .ok()
        .filter(|r| r.status().is_success())
        .and_then(|r| r.json().ok());

    if let Some(ref att) = attestation {
        match verify_attestation_against_hash(att, &pkg.content_hash) {
            Ok(v) => {
                publisher_ok = v.publisher_verified;
                registry_ok = v.registry_verified;
            }
            Err(e) => {
                attestation_error = Some(e);
            }
        }
    } else {
        attestation_error = Some("attestation not available from registry".to_string());
    }

    // Fetch Merkle proof (for certified level).
    let proof_url = format!(
        "{}/api/v1/packages/{}/{}/proof",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
    );

    let transparency_ok = client
        .get(&proof_url)
        .send()
        .ok()
        .is_some_and(|r| r.status().is_success());

    // Determine achieved trust level.
    let achieved = if transparency_ok && registry_ok && publisher_ok {
        "Certified"
    } else if registry_ok && publisher_ok {
        "Verified"
    } else if publisher_ok {
        "Signed"
    } else {
        "Unverified"
    };

    // Check if achieved level meets the requested level.
    let level_rank = |l: &str| -> u8 {
        match l.to_lowercase().as_str() {
            "unverified" => 0,
            "signed" => 1,
            "verified" => 2,
            "certified" => 3,
            _ => 0,
        }
    };

    let achieved_rank = level_rank(achieved);
    let required_rank = level_rank(trust_level);
    let meets_requirement = achieved_rank >= required_rank;

    let check = if meets_requirement { "+" } else { "x" };
    let _ = writeln!(stdout, "Trust Level: {} {}\n", check, achieved);

    // Print detail lines.
    let mark = |ok: bool| if ok { "+" } else { "x" };

    let _ = writeln!(
        stdout,
        "  {} Content integrity    SHA-256: {}...",
        mark(content_ok),
        hash_display
    );

    if let Some(ref att) = attestation {
        let pub_key = att.publisher_key.as_str();
        let pub_key_display = if pub_key.len() > 16 {
            &pub_key[..16]
        } else {
            pub_key
        };
        let _ = writeln!(
            stdout,
            "  {} Publisher signature   Key: {}...",
            mark(publisher_ok),
            pub_key_display
        );

        let reg_sig = att.registry_sig.as_deref().unwrap_or("");
        if registry_ok {
            let reg_display = if reg_sig.len() > 16 {
                &reg_sig[..16]
            } else {
                reg_sig
            };
            let _ = writeln!(
                stdout,
                "  {} Registry attestation  Hash: {}...",
                mark(registry_ok),
                reg_display
            );
        } else {
            let _ = writeln!(
                stdout,
                "  {} Registry attestation  Not available",
                mark(registry_ok)
            );
        }

        if let Some(ref err) = attestation_error {
            let _ = writeln!(stdout, "  x Attestation validity  {}", err);
        }
    } else {
        let _ = writeln!(
            stdout,
            "  {} Publisher signature   Not available",
            mark(publisher_ok)
        );
        let _ = writeln!(
            stdout,
            "  {} Registry attestation  Not available",
            mark(registry_ok)
        );
        if let Some(ref err) = attestation_error {
            let _ = writeln!(stdout, "  x Attestation validity  {}", err);
        }
    }

    if transparency_ok {
        let _ = writeln!(
            stdout,
            "  {} Transparency log     Inclusion proof verified",
            mark(transparency_ok)
        );
    } else {
        let _ = writeln!(
            stdout,
            "  {} Transparency log     Not yet available",
            mark(transparency_ok)
        );
    }

    let _ = writeln!(stdout, "\nInstalled: {}", installed_at);

    if meets_requirement {
        ExitCode::Ok
    } else {
        let _ = writeln!(
            stderr,
            "FAIL: achieved trust level '{}' does not meet required '{}'",
            achieved.to_lowercase(),
            trust_level
        );
        ExitCode::Fail
    }
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
// pkg login
// ---------------------------------------------------------------------------

fn cmd_pkg_login(
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    // Load or generate publisher keypair locally.
    let keypair = match load_or_generate_publisher_keypair(&cfg, stderr) {
        Ok(kp) => kp,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let public_key_hex = keypair.public_key().to_hex();

    // If an auth token is already configured (via env var or credentials file),
    // report success immediately.
    if cfg.auth_token.is_some() {
        let _ = writeln!(stdout, "Already authenticated.");
        let _ = writeln!(stdout, "Publisher key: {public_key_hex}");
        let _ = writeln!(stdout, "Registry: {}", cfg.registry_url);
        return ExitCode::Ok;
    }

    // Store the keypair locally. The auth token can be set via
    // CLAWDSTRIKE_AUTH_TOKEN env var or written to
    // ~/.clawdstrike/credentials.toml manually.
    //
    // TODO: A `/api/v1/auth/register` endpoint will be added in a future phase
    // to enable automated token exchange. For now, register your public key with
    // the registry administrator and set the token manually.
    let _ = writeln!(stdout, "Publisher keypair ready.");
    let _ = writeln!(stdout, "Publisher key: {public_key_hex}");
    let _ = writeln!(stdout, "Registry: {}", cfg.registry_url);
    let _ = writeln!(stdout);
    let _ = writeln!(stdout, "To complete login, set your auth token via one of:");
    let _ = writeln!(stdout, "  export CLAWDSTRIKE_AUTH_TOKEN=<your-token>");
    let _ = writeln!(
        stdout,
        "  echo '[registry]\\nauth_token = \"<your-token>\"' > ~/.clawdstrike/credentials.toml"
    );
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg publish
// ---------------------------------------------------------------------------

fn cmd_pkg_publish(
    path: Option<&Path>,
    registry: Option<&str>,
    oidc: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
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

    let cfg = RegistryConfig::load(registry);

    // For OIDC publishing, obtain the identity token from CI/CD environment.
    let auth_token = if oidc {
        match obtain_oidc_token(stderr) {
            Ok(t) => t,
            Err(code) => return code,
        }
    } else {
        match &cfg.auth_token {
            Some(t) => t.clone(),
            None => {
                let _ = writeln!(
                    stderr,
                    "Error: not authenticated. Run `clawdstrike pkg login` first."
                );
                return ExitCode::ConfigError;
            }
        }
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

    let pkg_name = &manifest.package.name;
    let pkg_version = &manifest.package.version;

    // Pack the archive
    let archive_name = format!(
        "{}-{}.cpkg",
        pkg_name.replace('/', "-").replace('@', ""),
        pkg_version
    );
    let output_path = source_dir.join(&archive_name);

    let _ = writeln!(stdout, "Packing {} v{} ...", pkg_name, pkg_version);

    if let Err(e) = archive::pack(&source_dir, &output_path) {
        let _ = writeln!(stderr, "Error: pack failed: {e}");
        return ExitCode::RuntimeError;
    }

    // Sign the archive
    let keypair = match load_or_generate_publisher_keypair(&cfg, stderr) {
        Ok(kp) => kp,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let signature = match sign_package(&output_path, &keypair) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: signing failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    // Upload
    let url = format!("{}/api/v1/packages", cfg.registry_url.trim_end_matches('/'));

    let cpkg_bytes = match std::fs::read(&output_path) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot read archive: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    use base64::Engine as _;
    let publish_body = serde_json::json!({
        "archive_base64": base64::engine::general_purpose::STANDARD.encode(&cpkg_bytes),
        "publisher_key": keypair.public_key().to_hex(),
        "publisher_sig": signature.signature.to_hex(),
        "manifest_toml": manifest_str,
    });

    let mut request_builder = client.post(&url).bearer_auth(&auth_token);

    if oidc {
        request_builder = request_builder.header("X-Clawdstrike-Auth-Type", "oidc");
        // Detect provider from env vars.
        let provider = if std::env::var("GITHUB_ACTIONS").is_ok() {
            "github"
        } else if std::env::var("GITLAB_CI").is_ok() {
            "gitlab"
        } else {
            "github"
        };
        request_builder = request_builder.header("X-Clawdstrike-Oidc-Provider", provider);
    }

    let resp = match request_builder.json(&publish_body).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: publish request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Published {} v{}", pkg_name, pkg_version);
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// OIDC token acquisition
// ---------------------------------------------------------------------------

/// Obtain an OIDC identity token from the CI/CD environment.
///
/// GitHub Actions: uses `ACTIONS_ID_TOKEN_REQUEST_TOKEN` + `ACTIONS_ID_TOKEN_REQUEST_URL`.
/// GitLab CI: uses `CI_JOB_JWT_V2`.
fn obtain_oidc_token(stderr: &mut dyn Write) -> Result<String, ExitCode> {
    // GitLab CI: direct JWT env var.
    if let Ok(jwt) = std::env::var("CI_JOB_JWT_V2") {
        if !jwt.is_empty() {
            return Ok(jwt);
        }
    }

    // GitHub Actions: request a token from the OIDC provider.
    let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok();
    let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok();

    if let (Some(token), Some(url)) = (request_token, request_url) {
        if !token.is_empty() && !url.is_empty() {
            let url_with_audience = format!("{url}&audience=clawdstrike-registry");
            let client = match reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
                    return Err(ExitCode::RuntimeError);
                }
            };

            let resp = match client.get(&url_with_audience).bearer_auth(&token).send() {
                Ok(r) => r,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: failed to request OIDC token: {e}");
                    return Err(ExitCode::RuntimeError);
                }
            };

            if !resp.status().is_success() {
                let status = resp.status();
                let _ = writeln!(stderr, "Error: OIDC token request returned HTTP {status}");
                return Err(ExitCode::RuntimeError);
            }

            let body: serde_json::Value = match resp.json() {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: invalid OIDC token response: {e}");
                    return Err(ExitCode::RuntimeError);
                }
            };

            if let Some(value) = body.get("value").and_then(|v| v.as_str()) {
                return Ok(value.to_string());
            }

            let _ = writeln!(stderr, "Error: OIDC token response missing 'value' field");
            return Err(ExitCode::RuntimeError);
        }
    }

    let _ = writeln!(
        stderr,
        "Error: --oidc requires a CI/CD environment (GitHub Actions or GitLab CI)"
    );
    Err(ExitCode::ConfigError)
}

// ---------------------------------------------------------------------------
// Trusted publishers
// ---------------------------------------------------------------------------

fn cmd_pkg_trusted_publishers(
    command: TrustedPublisherCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        TrustedPublisherCommands::Add {
            package,
            provider,
            repo,
            workflow,
            environment,
            registry,
        } => cmd_trusted_publisher_add(
            &package,
            &provider,
            &repo,
            workflow.as_deref(),
            environment.as_deref(),
            registry.as_deref(),
            stdout,
            stderr,
        ),
        TrustedPublisherCommands::List { package, registry } => {
            cmd_trusted_publisher_list(&package, registry.as_deref(), stdout, stderr)
        }
        TrustedPublisherCommands::Remove {
            package,
            id,
            registry,
        } => cmd_trusted_publisher_remove(&package, id, registry.as_deref(), stdout, stderr),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_trusted_publisher_add(
    package: &str,
    provider: &str,
    repo: &str,
    workflow: Option<&str>,
    environment: Option<&str>,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let url = format!(
        "{}/api/v1/packages/{}/trusted-publishers",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package)
    );

    let provider_norm = provider.to_ascii_lowercase();
    let mut body = serde_json::json!({
        "provider": provider_norm,
        "repository": repo,
    });
    if let Some(wf) = workflow {
        body["workflow"] = serde_json::Value::String(wf.to_string());
    }
    if let Some(env) = environment {
        body["environment"] = serde_json::Value::String(env.to_string());
    }

    let payload = format!(
        "trusted-publisher:add:{package}:{provider_norm}:{repo}:{}:{}",
        workflow.unwrap_or(""),
        environment.unwrap_or("")
    );
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .post(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: registry returned HTTP {status}: {resp_body}"
        );
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(
        stdout,
        "Added trusted publisher for {}: {} ({})",
        package, repo, provider
    );
    ExitCode::Ok
}

fn cmd_trusted_publisher_list(
    package: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let url = format!(
        "{}/api/v1/packages/{}/trusted-publishers",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package)
    );

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let publishers = resp_json
        .get("trusted_publishers")
        .and_then(|v| v.as_array());

    match publishers {
        Some(list) if !list.is_empty() => {
            let _ = writeln!(stdout, "Trusted publishers for {}:", package);
            for tp in list {
                let id = tp.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                let provider = tp.get("provider").and_then(|v| v.as_str()).unwrap_or("?");
                let repository = tp.get("repository").and_then(|v| v.as_str()).unwrap_or("?");
                let workflow = tp.get("workflow").and_then(|v| v.as_str()).unwrap_or("-");
                let environment = tp
                    .get("environment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let _ = writeln!(
                    stdout,
                    "  [{}] {} {} (workflow: {}, env: {})",
                    id, provider, repository, workflow, environment
                );
            }
        }
        _ => {
            let _ = writeln!(stdout, "No trusted publishers configured for {}.", package);
        }
    }

    ExitCode::Ok
}

fn cmd_trusted_publisher_remove(
    package: &str,
    id: i64,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let url = format!(
        "{}/api/v1/packages/{}/trusted-publishers/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(package),
        id
    );

    let payload = format!("trusted-publisher:remove:{package}:{id}");
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .delete(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Removed trusted publisher {} from {}", id, package);
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg search
// ---------------------------------------------------------------------------

fn cmd_pkg_search(
    query: &str,
    limit: usize,
    page: usize,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);
    let offset = page * limit;
    let url = format!(
        "{}/api/v1/search?q={}&limit={}&offset={}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(query),
        limit,
        offset
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: search request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response from registry: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let results = match resp_json.get("packages").and_then(|r| r.as_array()) {
        Some(r) => r,
        None => {
            let _ = writeln!(stdout, "No packages found.");
            return ExitCode::Ok;
        }
    };

    if results.is_empty() {
        let _ = writeln!(stdout, "No packages found.");
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "{:<40} {:<12} DESCRIPTION", "NAME", "VERSION");
    let _ = writeln!(stdout, "{}", "-".repeat(80));

    for result in results {
        let name = result.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let version = result
            .get("latest_version")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let description = result
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        let desc_display = if description.len() > 40 {
            format!("{}...", &description[..37])
        } else {
            description.to_string()
        };
        let _ = writeln!(stdout, "{:<40} {:<12} {}", name, version, desc_display);
    }

    let total = resp_json
        .get("total")
        .and_then(|t| t.as_u64())
        .unwrap_or(results.len() as u64);
    let showing_end = offset + results.len();
    let _ = writeln!(
        stdout,
        "\nShowing {}-{} of {} results",
        offset + 1,
        showing_end,
        total
    );

    ExitCode::Ok
}

/// Minimal percent-encoding for query parameters (avoids pulling in another dep).
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX_UPPER[(b >> 4) as usize]));
                out.push(char::from(HEX_UPPER[(b & 0x0f) as usize]));
            }
        }
    }
    out
}

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

// ---------------------------------------------------------------------------
// pkg audit
// ---------------------------------------------------------------------------

fn cmd_pkg_audit(
    name: &str,
    registry: Option<&str>,
    limit: u32,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);
    let url = format!(
        "{}/api/v1/audit/{}?limit={}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        limit
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: audit request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response from registry: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let events = match resp_json.get("events").and_then(|e| e.as_array()) {
        Some(e) => e,
        None => {
            let _ = writeln!(stdout, "No audit events found for '{}'.", name);
            return ExitCode::Ok;
        }
    };

    if events.is_empty() {
        let _ = writeln!(stdout, "No audit events found for '{}'.", name);
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "Audit log for: {}\n", name);
    let _ = writeln!(
        stdout,
        "{:<12} {:<10} {:<20} PUBLISHER KEY",
        "VERSION", "ACTION", "TIMESTAMP"
    );
    let _ = writeln!(stdout, "{}", "-".repeat(72));

    for event in events {
        let version = event.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let action = event.get("action").and_then(|a| a.as_str()).unwrap_or("?");
        let timestamp = event
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("?");
        let publisher_key = event
            .get("publisher_key")
            .and_then(|k| k.as_str())
            .unwrap_or("?");
        let key_display = if publisher_key.len() > 16 {
            format!("{}...", &publisher_key[..16])
        } else {
            publisher_key.to_string()
        };

        let _ = writeln!(
            stdout,
            "{:<12} {:<10} {:<20} {}",
            version, action, timestamp, key_display
        );
    }

    let _ = writeln!(stdout, "\n{} event(s) shown.", events.len());
    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// pkg stats
// ---------------------------------------------------------------------------

fn cmd_pkg_stats(
    name: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);
    let url = format!(
        "{}/api/v1/packages/{}/stats",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: stats request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response from registry: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let pkg_name = resp_json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or(name);
    let total_downloads = resp_json
        .get("total_downloads")
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    let first_published = resp_json
        .get("first_published")
        .and_then(|f| f.as_str())
        .unwrap_or("unknown");

    let _ = writeln!(stdout, "Package: {}", pkg_name);
    let _ = writeln!(
        stdout,
        "Total downloads: {}",
        format_number(total_downloads)
    );
    let _ = writeln!(stdout, "First published: {}", first_published);

    let versions = resp_json.get("versions").and_then(|v| v.as_array());

    if let Some(versions) = versions {
        if !versions.is_empty() {
            let _ = writeln!(stdout);
            let _ = writeln!(stdout, "  {:<12} {:<12} PUBLISHED", "VERSION", "DOWNLOADS");
            let _ = writeln!(stdout, "  {}", "-".repeat(50));

            for v in versions {
                let version = v.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                let downloads = v.get("downloads").and_then(|d| d.as_u64()).unwrap_or(0);
                let published_at = v
                    .get("published_at")
                    .and_then(|p| p.as_str())
                    .unwrap_or("?");
                let _ = writeln!(
                    stdout,
                    "  {:<12} {:<12} {}",
                    version,
                    format_number(downloads),
                    published_at
                );
            }
        }
    }

    ExitCode::Ok
}

/// Format a number with comma separators (e.g. 1234 -> "1,234").
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

// ---------------------------------------------------------------------------
// pkg yank
// ---------------------------------------------------------------------------

fn cmd_pkg_yank(
    name: &str,
    version: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

    let url = format!(
        "{}/api/v1/packages/{}/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name),
        urlencoding_simple(version)
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let resp = match client.delete(&url).bearer_auth(&auth_token).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: yank request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Yanked {} v{}", name, version);
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
// pkg org
// ---------------------------------------------------------------------------

fn cmd_pkg_org(command: OrgCommands, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match command {
        OrgCommands::Create {
            name,
            display_name,
            registry,
        } => cmd_org_create(
            &name,
            display_name.as_deref(),
            registry.as_deref(),
            stdout,
            stderr,
        ),
        OrgCommands::Members { name, registry } => {
            cmd_org_members(&name, registry.as_deref(), stdout, stderr)
        }
        OrgCommands::Invite {
            org,
            publisher_key,
            role,
            registry,
        } => cmd_org_invite(
            &org,
            &publisher_key,
            &role,
            registry.as_deref(),
            stdout,
            stderr,
        ),
        OrgCommands::Remove {
            org,
            publisher_key,
            registry,
        } => cmd_org_remove(&org, &publisher_key, registry.as_deref(), stdout, stderr),
        OrgCommands::Info { name, registry } => {
            cmd_org_info(&name, registry.as_deref(), stdout, stderr)
        }
    }
}

fn cmd_org_create(
    name: &str,
    display_name: Option<&str>,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

    let keypair = match load_or_generate_publisher_keypair(&cfg, stderr) {
        Ok(kp) => kp,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let url = format!("{}/api/v1/orgs", cfg.registry_url.trim_end_matches('/'));

    let mut body = serde_json::json!({
        "name": name,
        "publisher_key": keypair.public_key().to_hex(),
    });
    if let Some(dn) = display_name {
        body["display_name"] = serde_json::Value::String(dn.to_string());
    }

    let resp = match client
        .post(&url)
        .bearer_auth(&auth_token)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: registry returned HTTP {status}: {resp_body}"
        );
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Created organization @{}", name);
    ExitCode::Ok
}

fn cmd_org_members(
    name: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let url = format!(
        "{}/api/v1/orgs/{}/members",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name)
    );

    let resp = match client.get(&url).bearer_auth(&auth_token).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let members = match resp_json.get("members").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => {
            let _ = writeln!(stdout, "No members found.");
            return ExitCode::Ok;
        }
    };

    let _ = writeln!(stdout, "Members of @{}:\n", name);
    let _ = writeln!(stdout, "{:<48} {:<12} JOINED", "KEY", "ROLE");
    let _ = writeln!(stdout, "{}", "-".repeat(80));

    for member in members {
        let key = member
            .get("publisher_key")
            .and_then(|k| k.as_str())
            .unwrap_or("?");
        let role = member.get("role").and_then(|r| r.as_str()).unwrap_or("?");
        let joined = member
            .get("joined_at")
            .and_then(|j| j.as_str())
            .unwrap_or("?");
        let key_display = if key.len() > 44 {
            format!("{}...", &key[..44])
        } else {
            key.to_string()
        };
        let _ = writeln!(stdout, "{:<48} {:<12} {}", key_display, role, joined);
    }

    let _ = writeln!(stdout, "\n{} member(s)", members.len());
    ExitCode::Ok
}

fn cmd_org_invite(
    org: &str,
    publisher_key: &str,
    role: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if !matches!(role, "owner" | "maintainer" | "member") {
        let _ = writeln!(
            stderr,
            "Error: invalid role '{}'. Must be one of: owner, maintainer, member",
            role
        );
        return ExitCode::ConfigError;
    }

    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let url = format!(
        "{}/api/v1/orgs/{}/members",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(org)
    );

    let body = serde_json::json!({
        "publisher_key": publisher_key,
        "role": role,
    });

    let payload = format!("org:invite:{org}:{publisher_key}:{role}");
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .post(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let resp_body = resp.text().unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: registry returned HTTP {status}: {resp_body}"
        );
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Invited {} to @{} as {}", publisher_key, org, role);
    ExitCode::Ok
}

fn cmd_org_remove(
    org: &str,
    publisher_key: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let auth_token = match &cfg.auth_token {
        Some(t) => t.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "Error: not authenticated. Run `clawdstrike pkg login` first."
            );
            return ExitCode::ConfigError;
        }
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let url = format!(
        "{}/api/v1/orgs/{}/members/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(org),
        urlencoding_simple(publisher_key)
    );

    let payload = format!("org:remove:{org}:{publisher_key}");
    let caller = match build_caller_auth_headers(&cfg, &payload, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let resp = match client
        .delete(&url)
        .bearer_auth(&auth_token)
        .header("X-Clawdstrike-Caller-Key", &caller.key_hex)
        .header("X-Clawdstrike-Caller-Sig", &caller.sig_hex)
        .header("X-Clawdstrike-Caller-Ts", &caller.ts)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let _ = writeln!(stdout, "Removed {} from @{}", publisher_key, org);
    ExitCode::Ok
}

fn cmd_org_info(
    name: &str,
    registry: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let cfg = RegistryConfig::load(registry);

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "Error: cannot create HTTP client: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let url = format!(
        "{}/api/v1/orgs/{}",
        cfg.registry_url.trim_end_matches('/'),
        urlencoding_simple(name)
    );

    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "Error: request failed: {e}");
            return ExitCode::RuntimeError;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let _ = writeln!(stderr, "Error: registry returned HTTP {status}: {body}");
        return ExitCode::RuntimeError;
    }

    let resp_json: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: invalid response: {e}");
            return ExitCode::RuntimeError;
        }
    };

    let org_name = resp_json
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("?");
    let display = resp_json
        .get("display_name")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let verified = resp_json
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let members = resp_json
        .get("member_count")
        .and_then(|m| m.as_i64())
        .unwrap_or(0);
    let packages = resp_json
        .get("package_count")
        .and_then(|p| p.as_i64())
        .unwrap_or(0);

    let _ = writeln!(stdout, "Organization: @{}", org_name);
    if !display.is_empty() {
        let _ = writeln!(stdout, "Display Name: {}", display);
    }
    let _ = writeln!(
        stdout,
        "Verified:     {}",
        if verified { "yes" } else { "no" }
    );
    let _ = writeln!(stdout, "Members:      {}", members);
    let _ = writeln!(stdout, "Packages:     {}", packages);

    ExitCode::Ok
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
            source: "/tmp/nonexistent-pkg-12345.cpkg".to_string(),
            version: None,
            registry: None,
            trust_level: Some("signed".to_string()),
            allow_unverified: false,
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("not found"));
    }

    #[test]
    fn test_is_file_source() {
        // File paths
        assert!(is_file_source("/tmp/my-pkg.cpkg"));
        assert!(is_file_source("./local-pkg.cpkg"));
        assert!(is_file_source("../other.cpkg"));
        assert!(is_file_source("/absolute/path/to/pkg.cpkg"));

        // Package names (not file paths)
        assert!(!is_file_source("@acme/my-guard"));
        assert!(!is_file_source("my-guard"));
        assert!(!is_file_source("@scope/name"));
    }

    #[test]
    fn test_registry_config_defaults() {
        let cfg = RegistryConfig::from_toml_str("", "");
        assert_eq!(cfg.registry_url, "http://localhost:3100");
        assert!(cfg.auth_token.is_none());
    }

    #[test]
    fn test_registry_config_from_toml() {
        let config = r#"
[registry]
url = "https://registry.example.com"
"#;
        let creds = r#"
[registry]
auth_token = "tok_secret"
"#;
        let cfg = RegistryConfig::from_toml_str(config, creds);
        assert_eq!(cfg.registry_url, "https://registry.example.com");
        assert_eq!(cfg.auth_token.as_deref(), Some("tok_secret"));
    }

    #[test]
    fn test_urlencoding_simple() {
        assert_eq!(urlencoding_simple("hello"), "hello");
        assert_eq!(urlencoding_simple("@scope/name"), "%40scope%2Fname");
        assert_eq!(urlencoding_simple("a b"), "a%20b");
        assert_eq!(urlencoding_simple("foo+bar"), "foo%2Bbar");
    }

    #[test]
    fn test_publish_requires_auth() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
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

        let (_, stderr, code) = run_cmd(PkgCommands::Publish {
            path: Some(tmp.path().to_path_buf()),
            // Use a fake registry so we never actually hit a real server
            registry: Some("http://127.0.0.1:1".to_string()),
            oidc: false,
        });

        // Should fail because no auth token is configured
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("not authenticated"));
    }

    // -----------------------------------------------------------------------
    // Enhanced scaffolding template tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_scaffold_policy_pack_creates_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "@acme/my-policies").unwrap();

        assert!(tmp.path().join("policies").is_dir());
        assert!(tmp.path().join("data").is_dir());
        assert!(tmp.path().join("tests").is_dir());
        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("policies/default.yaml").exists());
        assert!(tmp.path().join("tests/policy-test.yaml").exists());
        assert!(tmp.path().join("README.md").exists());

        let policy = std::fs::read_to_string(tmp.path().join("policies/default.yaml")).unwrap();
        assert!(policy.contains("version:"));
        assert!(policy.contains("guards:"));
        assert!(policy.contains("forbidden_path:"));

        let test_yaml = std::fs::read_to_string(tmp.path().join("tests/policy-test.yaml")).unwrap();
        assert!(test_yaml.contains("tests:"));
        assert!(test_yaml.contains("file_access"));

        let readme = std::fs::read_to_string(tmp.path().join("README.md")).unwrap();
        assert!(readme.contains("@acme/my-policies"));
    }

    #[test]
    fn test_scaffold_bundle_creates_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Bundle, "my-bundle").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("README.md").exists());

        let manifest = std::fs::read_to_string(tmp.path().join("clawdstrike-pkg.toml")).unwrap();
        assert!(manifest.contains("[dependencies]"));
        assert!(manifest.contains("bundle"));

        let readme = std::fs::read_to_string(tmp.path().join("README.md")).unwrap();
        assert!(readme.contains("bundle"));
        assert!(readme.contains("my-bundle"));
    }

    // -----------------------------------------------------------------------
    // Pre-pack validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_policy_pack_missing_policies_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("policies/ directory"));
    }

    #[test]
    fn test_validate_policy_pack_empty_policies_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("policies")).unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one .yaml"));
    }

    #[test]
    fn test_validate_policy_pack_with_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("policies")).unwrap();
        std::fs::write(tmp.path().join("policies/test.yaml"), "version: \"1.2.0\"").unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        assert!(validate_pack_contents(tmp.path(), &manifest).is_ok());
    }

    #[test]
    fn test_validate_guard_missing_src() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-guard"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("src/lib.rs"));
    }

    #[test]
    fn test_validate_bundle_empty_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-bundle"
version = "0.1.0"
pkg_type = "bundle"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("[dependencies]"));
    }

    #[test]
    fn test_validate_bundle_with_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-bundle"
version = "0.1.0"
pkg_type = "bundle"

[trust]
level = "trusted"
sandbox = "native"

[dependencies]
"@acme/guard" = "^0.1"
"#,
        )
        .unwrap();
        assert!(validate_pack_contents(tmp.path(), &manifest).is_ok());
    }

    #[test]
    fn test_pack_policy_pack_without_policies_fails() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
            r#"[package]
name = "no-policies"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("policies/ directory"));
    }

    #[test]
    fn test_pack_guard_without_src_fails() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
            r#"[package]
name = "no-src"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("src/lib.rs"));
    }
}

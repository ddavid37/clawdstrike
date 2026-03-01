//! Direct package scanning — scan MCP servers from package registries.
//!
//! Supports `npm:<pkg>`, `pypi:<pkg>`, and `oci:<image>` specs. Each spec is
//! converted into a [`ServerConfig::Stdio`] and fed to
//! [`mcp_client::introspect_server`].

use crate::mcp_client::{self, McpError};
use crate::models::{ScanError, ServerConfig, ServerScanResult, StdioServer};

// ---------------------------------------------------------------------------
// McpError → ScanError conversion
// ---------------------------------------------------------------------------

impl From<McpError> for ScanError {
    fn from(e: McpError) -> Self {
        match e {
            McpError::Timeout(secs) => {
                ScanError::server_startup(format!("connection timeout ({secs}s)"), None)
            }
            McpError::ServerStartup {
                message,
                server_output,
            } => ScanError::server_startup(message, server_output),
            McpError::AllAttemptsFailed { errors } => ScanError::server_http_error(
                format!("all connection attempts failed: {}", errors.join("; ")),
                None,
            ),
            other => ScanError::server_startup(other.to_string(), None),
        }
    }
}

// ---------------------------------------------------------------------------
// Package spec types
// ---------------------------------------------------------------------------

/// Supported package registries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageRegistry {
    Npm,
    Pypi,
    Oci,
}

/// A parsed package specification.
#[derive(Debug, Clone)]
pub struct PackageSpec {
    pub registry: PackageRegistry,
    pub name: String,
}

/// Parse a `"registry:name"` string into a [`PackageSpec`].
///
/// Accepted prefixes: `npm:`, `pypi:`, `oci:`.
pub fn parse_package_spec(spec: &str) -> Result<PackageSpec, String> {
    if let Some(name) = spec.strip_prefix("npm:") {
        if name.is_empty() {
            return Err("npm package name cannot be empty".to_string());
        }
        Ok(PackageSpec {
            registry: PackageRegistry::Npm,
            name: name.to_string(),
        })
    } else if let Some(name) = spec.strip_prefix("pypi:") {
        if name.is_empty() {
            return Err("pypi package name cannot be empty".to_string());
        }
        Ok(PackageSpec {
            registry: PackageRegistry::Pypi,
            name: name.to_string(),
        })
    } else if let Some(name) = spec.strip_prefix("oci:") {
        if name.is_empty() {
            return Err("oci image name cannot be empty".to_string());
        }
        Ok(PackageSpec {
            registry: PackageRegistry::Oci,
            name: name.to_string(),
        })
    } else {
        Err(format!(
            "unknown package prefix in '{spec}': expected npm:, pypi:, or oci:"
        ))
    }
}

/// Generate a [`ServerConfig::Stdio`] for the given package spec.
pub fn generate_server_config(spec: &PackageSpec) -> ServerConfig {
    match spec.registry {
        PackageRegistry::Npm => ServerConfig::Stdio(StdioServer {
            command: "npx".to_string(),
            args: Some(vec!["-y".to_string(), spec.name.clone()]),
            server_type: Some("stdio".to_string()),
            env: None,
            binary_identifier: None,
        }),
        PackageRegistry::Pypi => ServerConfig::Stdio(StdioServer {
            command: "uvx".to_string(),
            args: Some(vec![spec.name.clone()]),
            server_type: Some("stdio".to_string()),
            env: None,
            binary_identifier: None,
        }),
        PackageRegistry::Oci => ServerConfig::Stdio(StdioServer {
            command: "docker".to_string(),
            args: Some(vec![
                "run".to_string(),
                "-i".to_string(),
                "--rm".to_string(),
                spec.name.clone(),
            ]),
            server_type: Some("stdio".to_string()),
            env: None,
            binary_identifier: None,
        }),
    }
}

/// Scan a single package by generating a server config and introspecting it.
pub async fn scan_package(spec: &PackageSpec, timeout: u64) -> ServerScanResult {
    let config = generate_server_config(spec);
    let display_name = format!("{}:{}", registry_prefix(&spec.registry), spec.name);

    match mcp_client::introspect_server(&config, timeout).await {
        Ok(sig) => ServerScanResult {
            name: Some(display_name),
            server: config,
            signature: Some(sig),
            error: None,
        },
        Err(e) => ServerScanResult {
            name: Some(display_name),
            server: config,
            signature: None,
            error: Some(ScanError::from(e)),
        },
    }
}

fn registry_prefix(reg: &PackageRegistry) -> &'static str {
    match reg {
        PackageRegistry::Npm => "npm",
        PackageRegistry::Pypi => "pypi",
        PackageRegistry::Oci => "oci",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_npm_spec() {
        let spec = parse_package_spec("npm:@modelcontextprotocol/server-everything").unwrap();
        assert_eq!(spec.registry, PackageRegistry::Npm);
        assert_eq!(spec.name, "@modelcontextprotocol/server-everything");
    }

    #[test]
    fn test_parse_pypi_spec() {
        let spec = parse_package_spec("pypi:mcp-server-fetch").unwrap();
        assert_eq!(spec.registry, PackageRegistry::Pypi);
        assert_eq!(spec.name, "mcp-server-fetch");
    }

    #[test]
    fn test_parse_oci_spec() {
        let spec = parse_package_spec("oci:ghcr.io/example/mcp:latest").unwrap();
        assert_eq!(spec.registry, PackageRegistry::Oci);
        assert_eq!(spec.name, "ghcr.io/example/mcp:latest");
    }

    #[test]
    fn test_parse_unknown_prefix() {
        let result = parse_package_spec("cargo:some-crate");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown package prefix"));
    }

    #[test]
    fn test_parse_empty_name() {
        assert!(parse_package_spec("npm:").is_err());
        assert!(parse_package_spec("pypi:").is_err());
        assert!(parse_package_spec("oci:").is_err());
    }

    #[test]
    fn test_generate_npm_config() {
        let spec = PackageSpec {
            registry: PackageRegistry::Npm,
            name: "my-server".into(),
        };
        let config = generate_server_config(&spec);
        match config {
            ServerConfig::Stdio(s) => {
                assert_eq!(s.command, "npx");
                assert_eq!(s.args, Some(vec!["-y".into(), "my-server".into()]));
            }
            _ => panic!("expected Stdio"),
        }
    }

    #[test]
    fn test_generate_pypi_config() {
        let spec = PackageSpec {
            registry: PackageRegistry::Pypi,
            name: "mcp-server".into(),
        };
        let config = generate_server_config(&spec);
        match config {
            ServerConfig::Stdio(s) => {
                assert_eq!(s.command, "uvx");
                assert_eq!(s.args, Some(vec!["mcp-server".into()]));
            }
            _ => panic!("expected Stdio"),
        }
    }

    #[test]
    fn test_generate_oci_config() {
        let spec = PackageSpec {
            registry: PackageRegistry::Oci,
            name: "my-image:latest".into(),
        };
        let config = generate_server_config(&spec);
        match config {
            ServerConfig::Stdio(s) => {
                assert_eq!(s.command, "docker");
                assert_eq!(
                    s.args,
                    Some(vec![
                        "run".into(),
                        "-i".into(),
                        "--rm".into(),
                        "my-image:latest".into()
                    ])
                );
            }
            _ => panic!("expected Stdio"),
        }
    }

    #[test]
    fn test_mcp_error_to_scan_error_timeout() {
        let err = McpError::Timeout(30);
        let scan_err = ScanError::from(err);
        assert!(scan_err.is_failure);
        assert!(scan_err.message.as_deref().unwrap().contains("timeout"));
    }

    #[test]
    fn test_mcp_error_to_scan_error_startup() {
        let err = McpError::ServerStartup {
            message: "spawn failed".into(),
            server_output: Some("stderr output".into()),
        };
        let scan_err = ScanError::from(err);
        assert!(scan_err.is_failure);
        assert_eq!(scan_err.server_output.as_deref(), Some("stderr output"));
    }

    #[test]
    fn test_mcp_error_to_scan_error_all_attempts() {
        let err = McpError::AllAttemptsFailed {
            errors: vec!["err1".into(), "err2".into()],
        };
        let scan_err = ScanError::from(err);
        assert!(scan_err.is_failure);
        assert!(scan_err.message.as_deref().unwrap().contains("err1"));
    }
}

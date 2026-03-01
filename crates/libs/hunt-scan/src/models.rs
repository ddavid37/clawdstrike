//! Data models for the hunt scan subsystem.
//!
//! Contains all serde-serializable structs, enums, and type aliases used by
//! the scanner, covering MCP server configs, entity types, scan results,
//! error handling, and API request/response types.

use chrono::{DateTime, Utc};
use md5::{Digest, Md5};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

/// Categorised scan error types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    FileNotFound,
    UnknownConfig,
    ParseError,
    ServerStartup,
    ServerHttpError,
    AnalysisError,
    SkillScanError,
}

impl ErrorCategory {
    /// Returns `true` when this category represents a real failure (not just
    /// a missing or unrecognised config).
    pub fn is_failure(&self) -> bool {
        !matches!(self, Self::FileNotFound | Self::UnknownConfig)
    }
}

/// Serde default helper that returns `true`.
fn default_true() -> bool {
    true
}

/// A scan error with optional category, message, and captured server output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceback: Option<String>,
    #[serde(default = "default_true")]
    pub is_failure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<ErrorCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_output: Option<String>,
}

impl ScanError {
    /// Create a non-failure error for a missing config file.
    pub fn file_not_found(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            exception: Some("FileNotFoundConfig".into()),
            traceback: None,
            is_failure: false,
            category: Some(ErrorCategory::FileNotFound),
            server_output: None,
        }
    }

    /// Create a non-failure error for an unrecognised config format.
    pub fn unknown_config(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            exception: Some("UnknownConfigFormat".into()),
            traceback: None,
            is_failure: false,
            category: Some(ErrorCategory::UnknownConfig),
            server_output: None,
        }
    }

    /// Create a failure error for a config that could not be parsed.
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            exception: Some("CouldNotParseMCPConfig".into()),
            traceback: None,
            is_failure: true,
            category: Some(ErrorCategory::ParseError),
            server_output: None,
        }
    }

    /// Create a failure error for a server that failed to start.
    pub fn server_startup(message: impl Into<String>, server_output: Option<String>) -> Self {
        Self {
            message: Some(message.into()),
            exception: Some("ServerStartupError".into()),
            traceback: None,
            is_failure: true,
            category: Some(ErrorCategory::ServerStartup),
            server_output,
        }
    }

    /// Create a failure error for an HTTP server error.
    pub fn server_http_error(message: impl Into<String>, server_output: Option<String>) -> Self {
        Self {
            message: Some(message.into()),
            exception: Some("ServerHTTPError".into()),
            traceback: None,
            is_failure: true,
            category: Some(ErrorCategory::ServerHttpError),
            server_output,
        }
    }

    /// Create a failure error for an analysis error.
    pub fn analysis_error(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            exception: Some("AnalysisError".into()),
            traceback: None,
            is_failure: true,
            category: Some(ErrorCategory::AnalysisError),
            server_output: None,
        }
    }

    /// Create a failure error for a skill scan error.
    pub fn skill_scan_error(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            exception: Some("SkillScanError".into()),
            traceback: None,
            is_failure: true,
            category: Some(ErrorCategory::SkillScanError),
            server_output: None,
        }
    }
}

// ---------------------------------------------------------------------------
// MCP entity types
// ---------------------------------------------------------------------------

/// An MCP tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

/// An argument for an MCP prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// An MCP prompt definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub arguments: Vec<PromptArgument>,
}

/// An MCP resource definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// An MCP resource template definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTemplate {
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// A completion entity (placeholder — included for forward-compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Union of all MCP entity types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Entity {
    #[serde(rename = "prompt")]
    Prompt(Prompt),
    #[serde(rename = "resource")]
    Resource(Resource),
    #[serde(rename = "tool")]
    Tool(Tool),
    #[serde(rename = "resource_template")]
    ResourceTemplate(ResourceTemplate),
    #[serde(rename = "completion")]
    Completion(Completion),
}

/// Map entity variant to a human-readable type string.
pub fn entity_type_to_str(entity: &Entity) -> &'static str {
    match entity {
        Entity::Prompt(_) => "prompt",
        Entity::Resource(_) => "resource",
        Entity::Tool(_) => "tool",
        Entity::ResourceTemplate(_) => "resource template",
        Entity::Completion(_) => "completion",
    }
}

/// Compute an MD5 hash of the entity description for change detection.
///
/// Uses `"no description available"` when the description is `None`.
pub fn hash_entity(description: Option<&str>) -> String {
    let text = description.unwrap_or("no description available");
    let mut hasher = Md5::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// A stored entity record for change detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedEntity {
    pub hash: String,
    #[serde(rename = "type")]
    pub entity_type: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Map of all known entities, keyed by `"{server_name}.{entity_type}.{entity_name}"`.
pub type ScannedEntities = HashMap<String, ScannedEntity>;

// ---------------------------------------------------------------------------
// Server config types
// ---------------------------------------------------------------------------

/// A process-spawning (stdio) MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioServer {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_identifier: Option<String>,
}

/// An HTTP or SSE MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteServer {
    pub url: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

/// A skills directory reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillServer {
    pub path: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
}

/// A synthetic server with pre-defined tool signatures (used for built-in IDE tools).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticToolsServer {
    pub name: String,
    pub signature: Vec<Tool>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
}

/// Discriminated union of all MCP server config types.
///
/// Deserialization uses a custom implementation that handles missing or null
/// `type` fields by inferring the variant from field presence:
/// - `command` field present -> `Stdio`
/// - `url` field present -> `Http` (default for remote)
/// - `path` field (with no command/url) -> `Skill`
/// - `signature` field -> `Tools`
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum ServerConfig {
    #[serde(rename = "stdio")]
    Stdio(StdioServer),
    #[serde(rename = "sse")]
    Sse(RemoteServer),
    #[serde(rename = "http")]
    Http(RemoteServer),
    #[serde(rename = "skill")]
    Skill(SkillServer),
    #[serde(rename = "tools")]
    Tools(StaticToolsServer),
}

impl<'de> Deserialize<'de> for ServerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let obj = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("expected a JSON object for ServerConfig"))?;

        // Check the explicit type field first.
        let type_str = obj
            .get("type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());

        match type_str.as_deref() {
            Some("stdio") => {
                let mut s: StdioServer =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                let (cmd, args) = rebalance_command_args(&s.command, s.args.as_deref());
                s.command = cmd;
                s.args = Some(args);
                Ok(ServerConfig::Stdio(s))
            }
            Some("sse") => {
                let s: RemoteServer =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(ServerConfig::Sse(s))
            }
            Some("http") => {
                let s: RemoteServer =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(ServerConfig::Http(s))
            }
            Some("skill") => {
                let s: SkillServer =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(ServerConfig::Skill(s))
            }
            Some("tools") => {
                let s: StaticToolsServer =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                Ok(ServerConfig::Tools(s))
            }
            Some(other) => Err(serde::de::Error::custom(format!(
                "unknown server type: {other}"
            ))),
            // type is null or missing — infer from fields
            None => {
                if obj.contains_key("command") {
                    let mut s: StdioServer =
                        serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                    let (cmd, args) = rebalance_command_args(&s.command, s.args.as_deref());
                    s.command = cmd;
                    s.args = Some(args);
                    Ok(ServerConfig::Stdio(s))
                } else if obj.contains_key("url") {
                    let s: RemoteServer =
                        serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                    Ok(ServerConfig::Http(s))
                } else if obj.contains_key("signature") {
                    let s: StaticToolsServer =
                        serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                    Ok(ServerConfig::Tools(s))
                } else if obj.contains_key("path") {
                    let s: SkillServer =
                        serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                    Ok(ServerConfig::Skill(s))
                } else {
                    Err(serde::de::Error::custom(
                        "cannot infer server type: no type, command, url, signature, or path field",
                    ))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command rebalancing
// ---------------------------------------------------------------------------

/// Split a compound `command` string into `(command, args)`.
///
/// For example, `command: "npx -y some-server"` becomes
/// `command: "npx"`, `args: ["-y", "some-server", ...existing_args]`.
pub fn rebalance_command_args(
    command: &str,
    existing_args: Option<&[String]>,
) -> (String, Vec<String>) {
    let mut existing: Vec<String> = existing_args.map(|a| a.to_vec()).unwrap_or_default();

    // Try to split the command string using shell-words.
    let parts = match shell_words::split(command) {
        Ok(p) if !p.is_empty() => p,
        _ => {
            // If parsing fails or produces nothing, keep command as-is.
            return (command.to_string(), existing);
        }
    };

    if parts.len() == 1 {
        // Single token — no rebalancing needed.
        return (parts[0].clone(), existing);
    }

    // First token is the command, rest are prepended to existing args.
    let cmd = parts[0].clone();
    let mut new_args = parts[1..].to_vec();
    new_args.append(&mut existing);
    (cmd, new_args)
}

// ---------------------------------------------------------------------------
// Scan result types
// ---------------------------------------------------------------------------

/// The complete output of a successful server introspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSignature {
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub prompts: Vec<serde_json::Value>,
    #[serde(default)]
    pub resources: Vec<serde_json::Value>,
    #[serde(default)]
    pub resource_templates: Vec<serde_json::Value>,
    #[serde(default)]
    pub tools: Vec<Tool>,
}

impl ServerSignature {
    /// Return all entities as a flat list.
    pub fn entities(&self) -> Vec<Entity> {
        let mut result = Vec::new();
        for t in &self.tools {
            result.push(Entity::Tool(t.clone()));
        }
        for p in &self.prompts {
            if let Ok(prompt) = serde_json::from_value::<Prompt>(p.clone()) {
                result.push(Entity::Prompt(prompt));
            }
        }
        for r in &self.resources {
            if let Ok(resource) = serde_json::from_value::<Resource>(r.clone()) {
                result.push(Entity::Resource(resource));
            }
        }
        for rt in &self.resource_templates {
            if let Ok(tmpl) = serde_json::from_value::<ResourceTemplate>(rt.clone()) {
                result.push(Entity::ResourceTemplate(tmpl));
            }
        }
        result
    }
}

/// Per-tool risk labels assigned by the analysis API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalarToolLabels {
    pub is_public_sink: f64,
    pub destructive: f64,
    pub untrusted_content: f64,
    pub private_data: f64,
}

/// A vulnerability finding with severity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub code: String,
    pub message: String,
    /// `(server_index, entity_index)` — server-level when entity is `None`,
    /// global when both are `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<(usize, Option<usize>)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_data: Option<HashMap<String, serde_json::Value>>,
}

/// One per MCP server within a config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerScanResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub server: ServerConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ServerSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ScanError>,
}

/// Top-level result per config file path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPathResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<ServerScanResult>>,
    #[serde(default)]
    pub issues: Vec<Issue>,
    #[serde(default)]
    pub labels: Vec<Vec<ScalarToolLabels>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_violations: Vec<crate::analysis::PolicyViolation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ScanError>,
}

// ---------------------------------------------------------------------------
// Config file models
// ---------------------------------------------------------------------------

/// Trait implemented by all MCP config file formats.
pub trait MCPConfig {
    /// Extract all server configurations from this config.
    fn get_servers(&self) -> HashMap<String, ServerConfig>;
    /// Replace the server configurations in this config.
    fn set_servers(&mut self, servers: HashMap<String, ServerConfig>);
}

/// `{ "mcpServers": { "<name>": ServerConfig } }`
///
/// Used by: Claude Desktop, Cursor, most clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeConfigFile {
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: HashMap<String, ServerConfig>,
}

impl MCPConfig for ClaudeConfigFile {
    fn get_servers(&self) -> HashMap<String, ServerConfig> {
        self.mcp_servers.clone()
    }
    fn set_servers(&mut self, servers: HashMap<String, ServerConfig>) {
        self.mcp_servers = servers;
    }
}

/// `{ "projects": { "<key>": ClaudeConfigFile } }`
///
/// Used by: Claude Code (`.claude.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeCodeConfigFile {
    #[serde(default)]
    pub projects: HashMap<String, ClaudeConfigFile>,
}

impl MCPConfig for ClaudeCodeConfigFile {
    fn get_servers(&self) -> HashMap<String, ServerConfig> {
        let mut all = HashMap::new();
        for cfg in self.projects.values() {
            all.extend(cfg.get_servers());
        }
        all
    }
    fn set_servers(&mut self, servers: HashMap<String, ServerConfig>) {
        // Apply to all projects
        for cfg in self.projects.values_mut() {
            cfg.set_servers(servers.clone());
        }
    }
}

/// `{ "inputs": [...], "servers": { "<name>": ServerConfig } }`
///
/// Used by: VS Code `.vscode/mcp.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeMCPConfig {
    #[serde(default)]
    pub inputs: Vec<serde_json::Value>,
    #[serde(default)]
    pub servers: HashMap<String, ServerConfig>,
}

impl MCPConfig for VSCodeMCPConfig {
    fn get_servers(&self) -> HashMap<String, ServerConfig> {
        self.servers.clone()
    }
    fn set_servers(&mut self, servers: HashMap<String, ServerConfig>) {
        self.servers = servers;
    }
}

/// `{ "mcp": { "inputs": [...], "servers": { ... } } }`
///
/// Used by: VS Code `settings.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeConfigFile {
    pub mcp: VSCodeMCPConfig,
}

impl MCPConfig for VSCodeConfigFile {
    fn get_servers(&self) -> HashMap<String, ServerConfig> {
        self.mcp.get_servers()
    }
    fn set_servers(&mut self, servers: HashMap<String, ServerConfig>) {
        self.mcp.set_servers(servers);
    }
}

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

/// User identity for the verification API request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUserInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymous_identifier: Option<String>,
}

/// Request and response body for the verification API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPathResultsCreate {
    pub scan_path_results: Vec<ScanPathResult>,
    pub scan_user_info: ScanUserInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_metadata: Option<HashMap<String, serde_json::Value>>,
}

// ---------------------------------------------------------------------------
// Discovery types
// ---------------------------------------------------------------------------

/// A candidate AI-agent client discovered on the system.
#[derive(Debug, Clone)]
pub struct CandidateClient {
    pub name: String,
    pub config_paths: Vec<PathBuf>,
    pub skills_dirs: Vec<PathBuf>,
    pub client_exists_paths: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rebalance_single_command() {
        let (cmd, args) = rebalance_command_args("npx", None);
        assert_eq!(cmd, "npx");
        assert!(args.is_empty());
    }

    #[test]
    fn test_rebalance_compound_command() {
        let (cmd, args) = rebalance_command_args("npx -y some-server", None);
        assert_eq!(cmd, "npx");
        assert_eq!(args, vec!["-y", "some-server"]);
    }

    #[test]
    fn test_rebalance_with_existing_args() {
        let existing = vec!["--port".to_string(), "3000".to_string()];
        let (cmd, args) = rebalance_command_args("npx -y some-server", Some(&existing));
        assert_eq!(cmd, "npx");
        assert_eq!(args, vec!["-y", "some-server", "--port", "3000"]);
    }

    #[test]
    fn test_rebalance_quoted_args() {
        let (cmd, args) = rebalance_command_args(r#"node "my script.js""#, None);
        assert_eq!(cmd, "node");
        assert_eq!(args, vec!["my script.js"]);
    }

    #[test]
    fn test_hash_entity_with_description() {
        let h = hash_entity(Some("A test description"));
        assert!(!h.is_empty());
        assert_eq!(h.len(), 32); // MD5 hex length
    }

    #[test]
    fn test_hash_entity_without_description() {
        let h = hash_entity(None);
        let h2 = hash_entity(Some("no description available"));
        assert_eq!(h, h2);
    }

    #[test]
    fn test_error_category_is_failure() {
        assert!(!ErrorCategory::FileNotFound.is_failure());
        assert!(!ErrorCategory::UnknownConfig.is_failure());
        assert!(ErrorCategory::ParseError.is_failure());
        assert!(ErrorCategory::ServerStartup.is_failure());
        assert!(ErrorCategory::ServerHttpError.is_failure());
        assert!(ErrorCategory::AnalysisError.is_failure());
        assert!(ErrorCategory::SkillScanError.is_failure());
    }

    #[test]
    fn test_server_config_deserialize_stdio_explicit() {
        let json = r#"{"type": "stdio", "command": "node server.js"}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg {
            ServerConfig::Stdio(s) => {
                assert_eq!(s.command, "node");
                assert_eq!(s.args, Some(vec!["server.js".to_string()]));
            }
            _ => panic!("expected Stdio variant"),
        }
    }

    #[test]
    fn test_server_config_deserialize_missing_type_with_command() {
        let json = r#"{"command": "npx -y @modelcontextprotocol/server-everything"}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg {
            ServerConfig::Stdio(s) => {
                assert_eq!(s.command, "npx");
                assert_eq!(
                    s.args,
                    Some(vec![
                        "-y".to_string(),
                        "@modelcontextprotocol/server-everything".to_string()
                    ])
                );
            }
            _ => panic!("expected Stdio variant"),
        }
    }

    #[test]
    fn test_server_config_deserialize_null_type_with_url() {
        let json = r#"{"type": null, "url": "https://example.com/mcp"}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg {
            ServerConfig::Http(s) => {
                assert_eq!(s.url, "https://example.com/mcp");
            }
            _ => panic!("expected Http variant"),
        }
    }

    #[test]
    fn test_server_config_deserialize_sse() {
        let json = r#"{"type": "sse", "url": "https://example.com/sse"}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg {
            ServerConfig::Sse(s) => {
                assert_eq!(s.url, "https://example.com/sse");
            }
            _ => panic!("expected Sse variant"),
        }
    }

    #[test]
    fn test_claude_config_file_deserialize() {
        let json = r#"{
            "mcpServers": {
                "test": {"type": "stdio", "command": "node test.js"}
            }
        }"#;
        let cfg: ClaudeConfigFile = serde_json::from_str(json).unwrap();
        assert!(cfg.mcp_servers.contains_key("test"));
    }

    #[test]
    fn test_entity_type_to_str_values() {
        let tool = Entity::Tool(Tool {
            name: "t".into(),
            description: None,
            input_schema: None,
        });
        assert_eq!(entity_type_to_str(&tool), "tool");

        let prompt = Entity::Prompt(Prompt {
            name: "p".into(),
            description: None,
            arguments: vec![],
        });
        assert_eq!(entity_type_to_str(&prompt), "prompt");

        let resource = Entity::Resource(Resource {
            uri: "file:///test".into(),
            name: "r".into(),
            description: None,
            mime_type: None,
        });
        assert_eq!(entity_type_to_str(&resource), "resource");

        let tmpl = Entity::ResourceTemplate(ResourceTemplate {
            uri_template: "file:///{path}".into(),
            name: "rt".into(),
            description: None,
            mime_type: None,
        });
        assert_eq!(entity_type_to_str(&tmpl), "resource template");

        let comp = Entity::Completion(Completion {
            name: "c".into(),
            description: None,
        });
        assert_eq!(entity_type_to_str(&comp), "completion");
    }

    // -- Serde round-trip tests -----------------------------------------------

    #[test]
    fn test_scan_path_result_serde_roundtrip() {
        let result = ScanPathResult {
            client: Some("cursor".into()),
            path: "/test/path.json".into(),
            servers: Some(vec![ServerScanResult {
                name: Some("test-server".into()),
                server: ServerConfig::Stdio(StdioServer {
                    command: "node".into(),
                    args: Some(vec!["server.js".into()]),
                    server_type: Some("stdio".into()),
                    env: None,
                    binary_identifier: None,
                }),
                signature: Some(ServerSignature {
                    metadata: serde_json::json!({"protocolVersion": "2025-03-26"}),
                    prompts: vec![],
                    resources: vec![],
                    resource_templates: vec![],
                    tools: vec![Tool {
                        name: "test_tool".into(),
                        description: Some("A test tool".into()),
                        input_schema: None,
                    }],
                }),
                error: None,
            }]),
            issues: vec![Issue {
                code: "TEST".into(),
                message: "test issue".into(),
                reference: Some((0, Some(1))),
                extra_data: None,
            }],
            labels: vec![],
            policy_violations: vec![],
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let restored: ScanPathResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.client.as_deref(), Some("cursor"));
        assert_eq!(restored.path, "/test/path.json");
        assert_eq!(restored.issues.len(), 1);
        assert_eq!(restored.issues[0].code, "TEST");
        let servers = restored.servers.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name.as_deref(), Some("test-server"));
    }

    #[test]
    fn test_server_signature_serde_roundtrip() {
        let sig = ServerSignature {
            metadata: serde_json::json!({"test": true}),
            prompts: vec![serde_json::json!({"name": "p1"})],
            resources: vec![],
            resource_templates: vec![],
            tools: vec![Tool {
                name: "tool1".into(),
                description: Some("desc".into()),
                input_schema: Some(serde_json::json!({"type": "object"})),
            }],
        };

        let json = serde_json::to_string(&sig).unwrap();
        let restored: ServerSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tools.len(), 1);
        assert_eq!(restored.tools[0].name, "tool1");
        assert_eq!(restored.prompts.len(), 1);
    }

    #[test]
    fn test_server_signature_entities() {
        let sig = ServerSignature {
            metadata: serde_json::json!({}),
            prompts: vec![serde_json::json!({"name": "p1"})],
            resources: vec![serde_json::json!({
                "uri": "file:///test",
                "name": "r1"
            })],
            resource_templates: vec![serde_json::json!({
                "uriTemplate": "file:///{path}",
                "name": "rt1"
            })],
            tools: vec![Tool {
                name: "t1".into(),
                description: None,
                input_schema: None,
            }],
        };

        let entities = sig.entities();
        assert_eq!(entities.len(), 4);
    }

    // -- ServerConfig deserialization variants ---------------------------------

    #[test]
    fn test_server_config_deserialize_http_explicit() {
        let json = r#"{"type": "http", "url": "https://example.com/mcp"}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg {
            ServerConfig::Http(s) => assert_eq!(s.url, "https://example.com/mcp"),
            _ => panic!("expected Http variant"),
        }
    }

    #[test]
    fn test_server_config_deserialize_skill() {
        let json = r#"{"type": "skill", "path": "/skills/my-skill"}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg {
            ServerConfig::Skill(s) => assert_eq!(s.path, "/skills/my-skill"),
            _ => panic!("expected Skill variant"),
        }
    }

    #[test]
    fn test_server_config_deserialize_tools() {
        let json = r#"{"type": "tools", "name": "test", "signature": [{"name": "t1"}]}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg {
            ServerConfig::Tools(s) => {
                assert_eq!(s.name, "test");
                assert_eq!(s.signature.len(), 1);
            }
            _ => panic!("expected Tools variant"),
        }
    }

    #[test]
    fn test_server_config_infer_skill_from_path() {
        let json = r#"{"path": "/skills/my-skill"}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(cfg, ServerConfig::Skill(_)));
    }

    #[test]
    fn test_server_config_infer_tools_from_signature() {
        let json = r#"{"name": "tools", "signature": []}"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(cfg, ServerConfig::Tools(_)));
    }

    #[test]
    fn test_server_config_unknown_type_error() {
        let json = r#"{"type": "grpc", "url": "localhost:50051"}"#;
        let result = serde_json::from_str::<ServerConfig>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_config_no_fields_error() {
        let json = r#"{"foo": "bar"}"#;
        let result = serde_json::from_str::<ServerConfig>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_config_stdio_with_env() {
        let json = r#"{
            "type": "stdio",
            "command": "node server.js",
            "env": {"API_KEY": "secret", "PORT": "3000"}
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg {
            ServerConfig::Stdio(s) => {
                assert!(s.env.is_some());
                let env = s.env.unwrap();
                assert_eq!(env.get("API_KEY").unwrap(), "secret");
                assert_eq!(env.get("PORT").unwrap(), "3000");
            }
            _ => panic!("expected Stdio variant"),
        }
    }

    // -- Config file format tests ---------------------------------------------

    #[test]
    fn test_claude_code_config_file_deserialize() {
        let json = r#"{
            "projects": {
                "~/project": {
                    "mcpServers": {
                        "server1": {"command": "node s.js"}
                    }
                }
            }
        }"#;
        let cfg: ClaudeCodeConfigFile = serde_json::from_str(json).unwrap();
        let servers = cfg.get_servers();
        assert!(servers.contains_key("server1"));
    }

    #[test]
    fn test_vscode_mcp_config_deserialize() {
        let json = r#"{
            "inputs": [],
            "servers": {
                "my-server": {"type": "stdio", "command": "node s.js"}
            }
        }"#;
        let cfg: VSCodeMCPConfig = serde_json::from_str(json).unwrap();
        let servers = cfg.get_servers();
        assert!(servers.contains_key("my-server"));
    }

    #[test]
    fn test_vscode_config_file_deserialize() {
        let json = r#"{
            "mcp": {
                "inputs": [],
                "servers": {
                    "vsc-server": {"type": "stdio", "command": "python s.py"}
                }
            }
        }"#;
        let cfg: VSCodeConfigFile = serde_json::from_str(json).unwrap();
        let servers = cfg.get_servers();
        assert!(servers.contains_key("vsc-server"));
    }

    #[test]
    fn test_claude_code_config_merges_projects() {
        let json = r#"{
            "projects": {
                "~/p1": {
                    "mcpServers": {
                        "s1": {"command": "node s1.js"}
                    }
                },
                "~/p2": {
                    "mcpServers": {
                        "s2": {"command": "node s2.js"}
                    }
                }
            }
        }"#;
        let cfg: ClaudeCodeConfigFile = serde_json::from_str(json).unwrap();
        let servers = cfg.get_servers();
        assert!(servers.contains_key("s1"));
        assert!(servers.contains_key("s2"));
    }

    // -- ScanError constructors -----------------------------------------------

    #[test]
    fn test_scan_error_constructors() {
        let e1 = ScanError::file_not_found("missing");
        assert!(!e1.is_failure);
        assert_eq!(e1.category, Some(ErrorCategory::FileNotFound));

        let e2 = ScanError::unknown_config("bad format");
        assert!(!e2.is_failure);
        assert_eq!(e2.category, Some(ErrorCategory::UnknownConfig));

        let e3 = ScanError::parse_error("invalid json");
        assert!(e3.is_failure);
        assert_eq!(e3.category, Some(ErrorCategory::ParseError));

        let e4 = ScanError::server_startup("spawn failed", Some("stderr output".into()));
        assert!(e4.is_failure);
        assert_eq!(e4.server_output.as_deref(), Some("stderr output"));

        let e5 = ScanError::server_http_error("404", None);
        assert!(e5.is_failure);
        assert_eq!(e5.category, Some(ErrorCategory::ServerHttpError));

        let e6 = ScanError::analysis_error("api down");
        assert!(e6.is_failure);

        let e7 = ScanError::skill_scan_error("dir missing");
        assert!(e7.is_failure);
    }

    #[test]
    fn test_scan_error_serde_roundtrip() {
        let error = ScanError::server_startup("test error", Some("output".into()));
        let json = serde_json::to_string(&error).unwrap();
        let restored: ScanError = serde_json::from_str(&json).unwrap();
        assert!(restored.is_failure);
        assert_eq!(restored.message.as_deref(), Some("test error"));
        assert_eq!(restored.server_output.as_deref(), Some("output"));
    }

    // -- ScanUserInfo ---------------------------------------------------------

    #[test]
    fn test_scan_user_info_serde() {
        let info = ScanUserInfo {
            hostname: Some("test-host".into()),
            username: Some("testuser".into()),
            identifier: None,
            ip_address: None,
            anonymous_identifier: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let restored: ScanUserInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.hostname.as_deref(), Some("test-host"));
        assert_eq!(restored.username.as_deref(), Some("testuser"));
    }
}

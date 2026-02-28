# Models Reference

Data model reference for the `hunt scan` subsystem. This documents all structs, enums, and type aliases needed for the Rust implementation, mapped back to their Python origins in the `agent-scan` codebase.

## Core scan result types

### ScanPathResult

Top-level result per config file path. One `ScanPathResult` per discovered config.

**Origin:** `models.py:359`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPathResult {
    pub client: Option<String>,
    pub path: String,
    pub servers: Option<Vec<ServerScanResult>>,
    #[serde(default)]
    pub issues: Vec<Issue>,
    #[serde(default)]
    pub labels: Vec<Vec<ScalarToolLabels>>,
    pub error: Option<ScanError>,
}
```

`servers` is `None` when the config file is missing or unparseable. `issues` and `labels` are populated by the analysis stage and may be backfilled from the verification API response.

### ServerScanResult

One per MCP server within a config file.

**Origin:** `models.py:327`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerScanResult {
    pub name: Option<String>,
    pub server: ServerConfig,
    pub signature: Option<ServerSignature>,
    pub error: Option<ScanError>,
}
```

### ServerSignature

The complete output of a successful server introspection. Contains the `initialize` response and all list call results.

**Origin:** `models.py:315`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSignature {
    pub metadata: serde_json::Value, // MCP InitializeResult
    #[serde(default)]
    pub prompts: Vec<serde_json::Value>,
    #[serde(default)]
    pub resources: Vec<serde_json::Value>,
    #[serde(default)]
    pub resource_templates: Vec<serde_json::Value>,
    #[serde(default)]
    pub tools: Vec<Tool>,
}
```

The `metadata` field holds the server's `InitializeResult` from the MCP `initialize` call. For built-in tools, `metadata.protocolVersion` is `"built-in"`.

An `.entities()` method should return the concatenation of all four lists (matching the Python `@property`).

### Issue

A vulnerability finding with severity.

**Origin:** `models.py:303`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub code: String,
    pub message: String,
    /// (server_index, entity_index) -- server-level when entity is None, global when both None
    pub reference: Option<(usize, Option<usize>)>,
    pub extra_data: Option<HashMap<String, serde_json::Value>>,
}
```

### ScalarToolLabels

Per-tool risk labels assigned by the analysis API.

**Origin:** `models.py:136`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalarToolLabels {
    pub is_public_sink: f64,
    pub destructive: f64,
    pub untrusted_content: f64,
    pub private_data: f64,
}
```

## Server config types

### StdioServer

A process-spawning MCP server.

**Origin:** `models.py:153`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioServer {
    pub command: String,
    pub args: Option<Vec<String>>,
    #[serde(rename = "type", default)]
    pub server_type: Option<String>, // "stdio"
    pub env: Option<HashMap<String, String>>,
    pub binary_identifier: Option<String>,
}
```

A `model_validator` in the Python code calls `rebalance_command_args` on construction (see [Command rebalancing](#command-rebalancing) below).

### RemoteServer

An HTTP or SSE MCP server.

**Origin:** `models.py:146`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteServer {
    pub url: String,
    #[serde(rename = "type")]
    pub server_type: Option<String>, // "sse" | "http"
    #[serde(default)]
    pub headers: HashMap<String, String>,
}
```

### SkillServer

A skills directory reference.

**Origin:** `models.py:168`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillServer {
    pub path: String,
    #[serde(rename = "type", default)]
    pub server_type: Option<String>, // "skill"
}
```

### StaticToolsServer

A synthetic server with pre-defined tool signatures (used for built-in IDE tools).

**Origin:** `models.py:174`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticToolsServer {
    pub name: String,
    pub signature: Vec<Tool>,
    #[serde(rename = "type", default)]
    pub server_type: Option<String>, // "tools"
}
```

### ServerConfig (discriminated union)

The server config union type, discriminated by the `type` field.

**Origin:** Python union `StdioServer | RemoteServer | StaticToolsServer | SkillServer`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
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
```

Note: some servers have `type = None` in Python configs. Handle this with a default variant or normalize the field before deserialization. When `type` is absent, discriminate by field presence: `command` implies `StdioServer`, `url` implies `RemoteServer`.

## Entity types

### Entity (tagged enum)

Union of all MCP entity types returned by introspection.

**Origin:** `models.py:37`

```rust
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
```

The MCP SDK entity types serialize without an explicit `type` tag. In practice, you may need `#[serde(untagged)]` and rely on field-shape discrimination, or add a wrapper with an explicit tag.

Helper functions from Python:

- `entity_type_to_str` (`models.py:94`): maps `Prompt -> "prompt"`, `Resource -> "resource"`, `Tool -> "tool"`, `ResourceTemplate -> "resource template"`. `Completion` raises an error.
- `hash_entity` (`models.py:85`): computes `md5(description.encode()).hexdigest()`. Falls back to `"no description available"` when description is `None`.

### ScannedEntity

A stored entity record for change detection.

**Origin:** `models.py:111`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedEntity {
    pub hash: String,
    #[serde(rename = "type")]
    pub entity_type: String,
    pub timestamp: DateTime<Utc>,
    pub description: Option<String>,
}
```

### ScannedEntities

Map of all known entities, keyed by `"{server_name}.{entity_type}.{entity_name}"`.

**Origin:** `models.py:143`

```rust
pub type ScannedEntities = HashMap<String, ScannedEntity>;
```

## Error handling

### ErrorCategory

**Origin:** `models.py:25-33`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn is_failure(&self) -> bool {
        !matches!(self, Self::FileNotFound | Self::UnknownConfig)
    }
}
```

| Category | Is failure | Meaning |
|----------|-----------|---------|
| `file_not_found` | No | Config file does not exist |
| `unknown_config` | No | Unrecognized MCP config format |
| `parse_error` | Yes | Config exists but could not be parsed |
| `server_startup` | Yes | MCP server failed to start |
| `server_http_error` | Yes | MCP server returned HTTP error |
| `analysis_error` | Yes | Could not reach/use analysis server |
| `skill_scan_error` | Yes | Could not scan skill |

### ScanError

**Origin:** `models.py:271`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub message: Option<String>,
    pub exception: Option<String>, // always serialized as string
    pub traceback: Option<String>,
    #[serde(default = "default_true")]
    pub is_failure: bool,
    pub category: Option<ErrorCategory>,
    pub server_output: Option<String>,
}

fn default_true() -> bool { true }
```

The `server_output` field stores captured MCP traffic when a connection fails (useful for debugging).

### Serialized exception variants

Concrete error types for structured serialization. All inherit from `SerializedException` (`models.py:530`).

**Origin:** `models.py:530-567`

| Variant | Category | `is_failure` | Extra fields |
|---------|----------|-------------|--------------|
| `FileNotFoundConfig` | `file_not_found` | `false` | -- |
| `UnknownConfigFormat` | `unknown_config` | `false` | -- |
| `CouldNotParseMCPConfig` | `parse_error` | `true` | -- |
| `ServerStartupError` | `server_startup` | `true` | `server_output: Option<String>` |
| `SkillScannError` | `skill_scan_error` | `true` | -- |
| `ServerHTTPError` | `server_http_error` | `true` | `server_output: Option<String>` |
| `AnalysisError` | `analysis_error` | `true` | -- |

## API types

### ScanUserInfo

User identity for the verification API request.

**Origin:** `models.py:390`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUserInfo {
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub identifier: Option<String>,
    pub ip_address: Option<String>,
    pub anonymous_identifier: Option<String>,
}
```

### ScanPathResultsCreate

Request **and** response body for the verification API. The response merges `issues`, `labels`, and optionally `signature` back into the original `ScanPathResult` objects.

**Origin:** `models.py:466`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPathResultsCreate {
    pub scan_path_results: Vec<ScanPathResult>,
    pub scan_user_info: ScanUserInfo,
    pub scan_metadata: Option<HashMap<String, serde_json::Value>>,
}
```

## Config file models

These models represent the different MCP config file formats that the scanner parses. They are tried in priority order during the discovery stage (see [scan.md](scan.md#config-file-parsing)).

### ClaudeConfigFile

**Origin:** `models.py:202`

```rust
/// { "mcpServers": { "<name>": StdioServer | RemoteServer } }
/// Used by: Claude Desktop, Cursor, most clients
pub struct ClaudeConfigFile {
    #[serde(rename = "mcpServers")]
    pub mcp_servers: HashMap<String, ServerConfig>,
}
```

### ClaudeCodeConfigFile

**Origin:** `models.py:213`

```rust
/// { "projects": { "<key>": ClaudeConfigFile } }
/// Used by: Claude Code (.claude.json)
pub struct ClaudeCodeConfigFile {
    pub projects: HashMap<String, ClaudeConfigFile>,
}
```

### VSCodeMCPConfig

**Origin:** `models.py:227`

```rust
/// { "servers": { "<name>": ... } }
/// Used by: VS Code .vscode/mcp.json
pub struct VSCodeMCPConfig {
    #[serde(default)]
    pub inputs: Vec<serde_json::Value>,
    pub servers: HashMap<String, ServerConfig>,
}
```

### VSCodeConfigFile

**Origin:** `models.py:240`

```rust
/// { "mcp": { "inputs": [...], "servers": { ... } } }
/// Used by: VS Code settings.json
pub struct VSCodeConfigFile {
    pub mcp: VSCodeMCPConfig,
}
```

### UnknownMCPConfig

**Origin:** `models.py:251`

Fallback model that accepts any JSON and returns an empty server set. In Rust, this can be handled as a catch-all branch that produces an empty `HashMap`.

### MCPConfig trait

All config models implement `get_servers() -> HashMap<String, ServerConfig>` and `set_servers()`. In Rust, define a trait:

```rust
pub trait MCPConfig {
    fn get_servers(&self) -> HashMap<String, ServerConfig>;
    fn set_servers(&mut self, servers: HashMap<String, ServerConfig>);
}
```

## Implementation notes

### Command rebalancing

**Origin:** `models.py:49-82`

`StdioServer` splits compound `command` strings into `(command, args)` on construction. For example, `command: "npx -y some-server"` becomes `command: "npx"`, `args: ["-y", "some-server", ...existing_args]`.

The Python implementation uses a Lark grammar that tokenizes respecting single and double quotes. In Rust, use the `shell-words` crate or port the grammar with a PEG parser.

### Entity hashing

**Origin:** `models.py:85-91`

```
hash = md5(entity.description.encode()).hexdigest()
```

If `entity.description` is `None`, uses the string `"no description available"`. Use the `md5` crate in Rust.

### Redaction

**Origin:** `redact.py`

Redaction is applied before sending data to the verification API. All sensitive values are replaced with `"**REDACTED**"`.

| Target | What is redacted |
|--------|-----------------|
| **Absolute paths** | Unix paths (`/dir/...`), home paths (`~/...`), Windows paths (`C:\...`) in tracebacks and server output |
| **CLI args** | `--flag value` pairs (value redacted), `--flag=value` (value redacted), positional file paths |
| **Env vars** | All values in `StdioServer.env` (keys preserved) |
| **HTTP headers** | All values in `RemoteServer.headers` (keys preserved) |
| **URL query params** | All values in `RemoteServer.url` query string (keys preserved) |

In Rust, implement as clone-and-modify or `&mut` in-place modification.

### Datetime parsing

**Origin:** `models.py:111`

`ScannedEntity.timestamp` accepts two formats:
1. ISO 8601 (primary): `chrono::DateTime::parse_from_rfc3339`
2. Legacy format: `"DD/MM/YYYY, HH:MM:SS"` via `NaiveDateTime::parse_from_str("%d/%m/%Y, %H:%M:%S")`

Try ISO 8601 first, fall back to legacy.

### Type field handling

Some server configs have `type = None` in the JSON. The `ServerConfig` enum uses `type` as its serde tag, so a missing or null `type` field needs special handling:

1. Normalize before deserialization: if `type` is missing, infer it from field presence (`command` -> `"stdio"`, `url` -> `"http"`)
2. Or use `#[serde(untagged)]` with field-shape discrimination

### Storage format

**Origin:** `Storage.py`

Scan history is persisted to `~/.agent-scan/scanned_entities.json` for change detection between runs. The file is protected by a file lock (10-second timeout). Entity keys follow the format `"{server_name}.{entity_type}.{entity_name}"`.

Change detection (`check_and_update`): compute the entity hash, compare against stored hash. If different, flag as changed and include the previous description and timestamp in the change message.

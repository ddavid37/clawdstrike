# hunt scan

Discover and audit AI agent configurations, MCP server inventories, and policy compliance across a workstation or cluster environment.

## Purpose

`hunt scan` is the entry point for understanding what agents are running, what tools they have access to, and whether their configurations meet security policy. It implements a three-stage pipeline -- **Discover, Introspect, Analyze** -- that finds agent MCP configs on disk, connects to each server to enumerate its capabilities, then evaluates everything against Clawdstrike's policy engine. The result is a comprehensive inventory with actionable security findings.

## Usage

```bash
clawdstrike hunt scan [OPTIONS] [TARGET...]
```

Targets can be:

- A **client shorthand** (`cursor`, `claude`, `vscode`, `windsurf`) -- expands to platform-specific config paths
- A **file path** to a specific config file (`./mcp.json`, `~/.cursor/mcp.json`)
- A **directory path** (scans for agent configs, MCP manifests, policy files)
- A **package URI** (`npm:@org/mcp-srv`, `pypi:mcp-server`, `oci:image`)
- **Omitted** -- scans all discovered agents on the current machine

When all targets are alphanumeric shorthands (matching `^[A-Za-z0-9_-]+$`), they are expanded via the [client shorthand table](discovery-reference.md#client-shorthand-resolution). Otherwise targets are treated as raw file paths.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--target <name\|path>` | Specific client shorthand or config file path to scan (repeatable) | (all discovered) |
| `--package <uri>` | Scan a package directly: `npm:pkg`, `pypi:pkg`, `oci:image` (repeatable) | (none) |
| `--skills <dir>` | Scan agent skills directories (repeatable) | (none) |
| `--query <text>` | Natural language or keyword filter over results | (none) |
| `--policy <ref>` | Policy file or reference to check agent configs against | `clawdstrike:ai-agent` |
| `--ruleset <name>` | Built-in ruleset to evaluate against | (none) |
| `--timeout <secs>` | MCP server connection timeout in seconds | `10` |
| `--include-builtin` | Include built-in IDE tools (Cursor, Windsurf, VS Code) in results | `false` |
| `--depth <n>` | Directory scan depth | `5` |
| `--sign` | Produce a signed receipt for the scan results | `false` |
| `--key <path>` | Signing key for receipts | `hush.key` |
| `--json` | Machine-readable JSON output | `false` |
| `--output <path>` | Write results to file instead of stdout | (none) |
| `--severity <level>` | Minimum severity to report (`info`, `warning`, `error`, `critical`) | `info` |

## Pipeline stages

### Stage 1: Discover

Find AI agent MCP configurations on disk by checking well-known paths per platform.

The scanner knows about 11 clients across macOS, Linux, and Windows. For each client, it checks whether the client is installed (probing `client_exists_paths`), then reads its MCP config files and skills directories. Config files are parsed with JSON5/JSONC support to handle comments and trailing commas common in editor configs.

Supported clients: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Kiro, OpenCode, Antigravity, Codex, Clawdbot/OpenClaw.

See the [Discovery Reference](discovery-reference.md) for the complete platform path table and built-in tool definitions.

#### Config file parsing

Config files are validated against a model hierarchy (first match wins):

| Priority | Format | Shape | Used by |
|----------|--------|-------|---------|
| 1 | `ClaudeCodeConfigFile` | `{ "projects": { "~": { "mcpServers": {...} } } }` | Claude Code `.claude.json` |
| 2 | `ClaudeConfigFile` | `{ "mcpServers": { "name": { "command": "...", "args": [...] } } }` | Claude Desktop, Cursor, most clients |
| 3 | `VSCodeConfigFile` | `{ "mcp": { "servers": {...} } }` | VS Code `settings.json` |
| 4 | `VSCodeMCPConfig` | `{ "servers": {...} } }` | VS Code `.vscode/mcp.json` |
| 5 | `UnknownMCPConfig` | anything | Fallback (empty server set) |

Within each config, individual server entries are discriminated by field presence:
- Has `command` field -> `StdioServer` (process-spawning)
- Has `url` field -> `RemoteServer` (HTTP/SSE)

### Stage 2: Introspect

Connect to each discovered MCP server and enumerate its capabilities via the MCP protocol.

The introspection client uses JSON-RPC 2.0 over three transports:

| Transport | When used | How it works |
|-----------|-----------|--------------|
| **stdio** | `StdioServer` configs | Spawns the process, communicates via stdin/stdout JSON-RPC |
| **SSE** | `RemoteServer` with `type: "sse"` | HTTP GET for server events, HTTP POST for client requests |
| **Streamable HTTP** | `RemoteServer` with `type: "http"` or unspecified | HTTP POST with streaming response body |

The introspection sequence calls five JSON-RPC methods:

```
Client                          Server
  |                                |
  |  --- initialize ----------->  |
  |  <-- InitializeResult ------  |
  |                                |
  |  --- notifications/initialized (no response)
  |                                |
  |  --- prompts/list ----------> |  (if capabilities.prompts or stdio)
  |  <-- { prompts: [...] } ----  |
  |                                |
  |  --- resources/list --------> |  (if capabilities.resources or stdio)
  |  <-- { resources: [...] } --  |
  |                                |
  |  --- resources/templates/list  |  (if capabilities.resources or stdio)
  |  <-- { resourceTemplates: [] } |
  |                                |
  |  --- tools/list ------------> |  (if capabilities.tools or stdio)
  |  <-- { tools: [...] } ------  |
  |                                |
  |  (connection closed)           |
```

For stdio servers, all list methods are attempted regardless of announced capabilities. For remote servers, only methods matching advertised capabilities are called. Each list call failure is caught independently and results in an empty list -- it does not abort the scan.

#### Remote URL probing

When connecting to a remote server, the scanner generates URL variants and tries them in sequence until one succeeds:

Given a URL, three variants are derived:

| Input URL ends with | `url_with_sse` | `url_with_mcp` | `url_without_end` |
|---------------------|----------------|----------------|--------------------|
| `/sse` | as-is | replace `/sse` with `/mcp` | strip `/sse` |
| `/mcp` | replace `/mcp` with `/sse` | as-is | strip `/mcp` |
| neither | append `/sse` | append `/mcp` | as-is |

The default probing order (preferring streamable HTTP):

```
1. http  + url_with_mcp
2. http  + url_without_end
3. sse   + url_with_mcp
4. sse   + url_without_end
5. http  + url_with_sse
6. sse   + url_with_sse
```

Each attempt is bounded by `--timeout`. If all six fail, an error is reported for that server.

### Stage 3: Analyze

Evaluate discovered tools and configurations against Clawdstrike policy and vulnerability checks.

#### Policy-aware scanning (guard integration)

The key integration point: discovered MCP tools are cross-referenced against the Clawdstrike policy engine using existing guards.

```rust
// Evaluate each tool against the loaded policy
for tool in &signature.tools {
    let action = GuardAction::McpTool(&tool.name, &tool.input_schema);
    let report = engine.evaluate(&action, &context).await;
    // Report which tools would be blocked/warned/allowed
}

// Run PromptInjectionGuard over tool descriptions
for tool in &signature.tools {
    let action = GuardAction::Custom("tool_description", &json!({"text": tool.description}));
    // Check for prompt injection in descriptions
}

// Run SecretLeakGuard over all entity descriptions
for entity in all_entities {
    // Check for leaked secrets in tool/prompt/resource descriptions
}
```

This gives `hunt scan` policy-aware scanning that ties directly into enforcement -- the same guards that protect agents at runtime also audit their configurations at scan time.

#### Vulnerability types

| Code | Severity | Description |
|------|----------|-------------|
| `TOOL_POISONING` | critical | Tool description contains hidden instructions that manipulate the agent |
| `PROMPT_INJECTION` | critical | Prompt or resource description contains injection payloads |
| `TOXIC_FLOW` | high | Tool chain creates a dangerous data flow (e.g., read secrets then send HTTP) |
| `RUG_PULL` | high | Server signature changed since last scan (tool added/modified) |
| `CROSS_ORIGIN_ESCALATION` | high | Tool can access resources outside its declared scope |

#### Additional checks

- Outdated policy schema versions
- Permissive rulesets in production namespaces
- Missing signing keys or unsigned receipts in audit trails
- Egress allowlists that include wildcard domains
- Tools not in the MCP allowlist
- Servers running with overly broad permissions
- Missing authentication on exposed endpoints

## Natural language query

The `--query` flag filters scan results using keyword and fuzzy matching:

```bash
clawdstrike hunt scan --query "tools with file access"
clawdstrike hunt scan --query "servers that can exec"
```

Query processing:

1. Tokenize the query string
2. Fuzzy match tokens against tool names and descriptions
3. Match tokens against guard action categories (`FileAccess`, `NetworkEgress`, `ShellCommand`, `McpTool`)
4. Filter and rank results by relevance score

## Examples

Scan all discovered agents on this machine:

```bash
clawdstrike hunt scan
```

Scan a specific client:

```bash
clawdstrike hunt scan --target cursor
```

Scan a specific config file:

```bash
clawdstrike hunt scan --target ./mcp.json
```

Scan a package directly:

```bash
clawdstrike hunt scan --package npm:@org/mcp-srv
clawdstrike hunt scan --package pypi:mcp-server
```

Scan agent skills directories:

```bash
clawdstrike hunt scan --skills ~/.cursor/skills
```

Scan with policy evaluation against the strict ruleset:

```bash
clawdstrike hunt scan --policy strict.yaml --json
```

Include built-in IDE tools in the scan:

```bash
clawdstrike hunt scan --target cursor --include-builtin
```

Filter results with a natural language query:

```bash
clawdstrike hunt scan --query "tools with network access"
```

Scan with MCP introspection and produce a signed receipt:

```bash
clawdstrike hunt scan --sign --key /etc/clawdstrike/hunt.key
```

Scan and filter to warnings and above:

```bash
clawdstrike hunt scan --severity warning --output scan-results.json --json
```

## Output

Human-readable output groups findings by client and server:

```text
SCAN cursor (~/.cursor/mcp.json)
  SERVER my-server (stdio: npx)
    5 tools, 0 prompts, 2 resources
    CRITICAL  TOOL_POISONING: Tool "read_file" description contains hidden instructions
    ERROR     policy_violation: forbidden_path guard would block McpTool(read_file)
    WARN      tool "shell_exec" not in MCP allowlist

SCAN claude (~/Library/Application Support/Claude/claude_desktop_config.json)
  SERVER api-server (http: https://api.example.com/mcp)
    3 tools, 1 prompt, 0 resources
    OK        all tools pass policy evaluation

Summary: 2 clients scanned, 3 servers found, 8 tools found, 1 issue, 1 policy violation
```

### JSON output

The `--json` flag produces structured output:

```json
{
  "clients": [
    {
      "name": "cursor",
      "config_path": "~/.cursor/mcp.json",
      "servers": [
        {
          "name": "my-server",
          "type": "stdio",
          "command": "npx",
          "tools": 5,
          "prompts": 0,
          "resources": 2,
          "issues": [
            {
              "code": "TOOL_POISONING",
              "severity": "critical",
              "message": "Tool description contains hidden instructions",
              "tool": "read_file"
            }
          ],
          "policy_violations": [
            {
              "guard": "forbidden_path",
              "action": "McpTool(read_file)",
              "allowed": false,
              "message": "Tool can access forbidden paths"
            }
          ]
        }
      ]
    }
  ],
  "summary": {
    "clients_scanned": 3,
    "servers_found": 7,
    "tools_found": 42,
    "issues_found": 2,
    "policy_violations": 5
  }
}
```

JSON output is compatible with SARIF for integration with CI pipelines.

## Signed receipts

When `--sign` is used, the scan produces a `SignedReceipt` attesting to the findings. This receipt includes:

- SHA-256 hash of the scan results
- Policy reference used for evaluation
- Timestamp and issuer identity
- Verdict (`PASS` if no errors, `FAIL` otherwise)

The receipt can be verified with `clawdstrike verify`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no errors found |
| 1 | Scan completed with warnings |
| 2 | Scan completed with errors (policy violations) |
| 3 | Configuration error (invalid policy, bad target) |
| 4 | Runtime error (I/O, network, MCP connection failure) |

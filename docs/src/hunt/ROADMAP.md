# `clawdstrike hunt` Implementation Roadmap

This document describes the phased implementation plan for the `clawdstrike hunt`
CLI command -- a threat-hunting toolkit for AI agent ecosystems.

The command ports and extends the Python `agent-scan` tool into Rust, integrates
with the Spine/NATS attestation infrastructure, and adds correlation, watch-mode,
and IOC capabilities that do not exist in the original Python codebase.

---

## Table of Contents

1. [Overview](#overview)
2. [Source File Index](#source-file-index)
3. [Crate Layout](#crate-layout)
4. [Phase 1 -- Foundation + Scan](#phase-1--foundation--scan)
5. [Phase 2 -- Query + Timeline](#phase-2--query--timeline)
6. [Phase 3 -- Correlate + Watch + IOC](#phase-3--correlate--watch--ioc)
7. [Rust Struct Reference](#rust-struct-reference)
8. [Dependency Map](#dependency-map)
9. [Risk Areas and Open Questions](#risk-areas-and-open-questions)

---

## Overview

### Motivation

AI agent runtimes (Claude Code, Cursor, Windsurf, VSCode Copilot, OpenCode,
Gemini CLI, etc.) expose MCP servers that grant tools filesystem, network, and
shell access. Today the Python `agent-scan` project provides point-in-time
vulnerability scanning. `clawdstrike hunt` extends this into a full threat-hunting
workflow: **scan, query, correlate, watch**.

### Design Principles

- **Fail-closed.** Invalid scan configs or unparseable MCP responses produce
  errors, never silent pass-through.
- **Signed evidence.** Every scan result is wrapped in an Ed25519-signed receipt
  via `hush-core`. Hunt queries against NATS replay produce verifiable evidence
  chains.
- **Offline-first.** Scanning and local querying work without network access.
  NATS connectivity is optional and additive.
- **CLI-native.** Follows the existing `hush` CLI patterns: clap derive API,
  `--json` machine output, stable exit codes (`ExitCode` enum), and the
  `CLI_JSON_VERSION` envelope.

### High-Level Data Flow

```
+------------------------------------------------------------------+
|                      clawdstrike hunt                            |
+------------------------------------------------------------------+
|                                                                  |
|  Phase 1: SCAN                                                   |
|  +-----------+    +-----------+    +----------+    +-----------+ |
|  | Platform  |--->| MCP Client|--->| Vuln     |--->| Signed    | |
|  | Discovery |    | Introspect|    | Analysis |    | Receipt   | |
|  +-----------+    +-----------+    +----------+    +-----------+ |
|   well_known       stdio/SSE/      tool poison,    Ed25519       |
|   clients          HTTP transports  prompt inj,    hush-core     |
|   (per-OS)                          toxic flows                  |
|                                                                  |
|  Phase 2: QUERY + TIMELINE                                       |
|  +-----------+    +----------------+    +-----------+            |
|  | HuntQuery |--->| NATS JetStream |--->| Timeline  |            |
|  | DSL Parse |    | Replay + Filter|    | Renderer  |            |
|  +-----------+    +----------------+    +-----------+            |
|   structured       spine::nats_       merge/sort                 |
|   flags, NL        transport          color-coded                |
|   keywords                            terminal out               |
|                                                                  |
|  Phase 3: CORRELATE + WATCH + IOC                                |
|  +-----------+    +-----------+    +----------+    +-----------+ |
|  | Correlation|--->| Watch     |--->| IOC      |--->| Report    | |
|  | Engine     |    | Mode      |    | Matcher  |    | Generator | |
|  +-----------+    +-----------+    +----------+    +-----------+ |
|   YAML rules       NATS sub,       hash/domain/    Merkle proof  |
|   SIGMA-like        real-time       IP/STIX         evidence     |
|                     streaming                       bundles      |
+------------------------------------------------------------------+
```

---

## Source File Index

All Python source under `standalone/research/research/agent-scan/src/agent_scan/`.
LOC counts and priorities drive the Phase 1 porting order.

| File | LOC | What It Does | Port Priority | Rust Target |
|------|-----|-------------|---------------|-------------|
| `well_known_clients.py` | 419 | Platform-specific agent config discovery | **P0** | `hunt/discovery.rs` |
| `models.py` | 636 | All data structures (Pydantic models) | **P0** | `hunt/models.rs` |
| `mcp_client.py` | 339 | MCP server connection & introspection | **P0** (hardest) | `hunt/mcp.rs` |
| `inspect.py` | 288 | Per-client config parsing & inspection orchestration | **P0** | `hunt/mcp.rs` + `discovery.rs` |
| `pipelines.py` | 173 | Pipeline composition (inspect -> analyze -> push) | **P0** | `lib.rs` orchestration |
| `MCPScanner.py` | 355 | Main scanner orchestrator | **P0** | `lib.rs` orchestration |
| `verify_api.py` | 301 | Verification API client (analysis server) | **P1** | `hunt/analyze.rs` |
| `redact.py` | 203 | Sensitive data redaction before upload | **P1** | `hunt/redact.rs` |
| `skill_client.py` | 151 | SKILL.md parsing & skill directory scanning | **P1** | `hunt/skills.rs` |
| `cli.py` | 665 | CLI args & command routing | -- (reference only) | `hush-cli/src/hunt.rs` |
| `direct_scanner.py` | 154 | Direct package scanning (npm/pypi/oci) | **P2** | `hunt/packages.rs` |
| `Storage.py` | 129 | Persistent scan history & change detection | **P2** | `hunt/storage.rs` |
| `printer.py` | 355 | Rich output formatting | -- (don't port) | Use existing CLI patterns |

**P0 total: ~2,210 LOC** -- core scan pipeline, must ship in Phase 1.
**P1 total: ~655 LOC** -- analysis + redaction + skills, Phase 1.1 or early Phase 2.
**P2 total: ~283 LOC** -- package scanning + storage, can defer.

### Rust Crate Mapping

| Python Dependency | Rust Equivalent | Purpose |
|-------------------|-----------------|---------|
| `mcp==1.25.0` | `rmcp` or custom minimal JSON-RPC client | MCP protocol |
| `pydantic` | `serde` + `serde_json` | Serialization/validation |
| `aiohttp` | `reqwest` (already in workspace) | HTTP client |
| `pyyaml` | `serde_yaml` (already in workspace) | YAML parsing |
| `pyjson5` | `json5` crate | JSON5/JSONC config parsing |
| `lark` | `shell-words` or hand-rolled tokenizer | Command string parsing |
| `rich` | existing CLI output patterns | Terminal output |
| `rapidfuzz` | `strsim` or `fuzzy-matcher` | Fuzzy string matching |
| `psutil` | `sysinfo` crate | System/process info |
| `filelock` | `fs2` or `fd-lock` | File locking |
| `certifi` | `rustls` + `webpki-roots` (already in workspace) | TLS certificate roots |

---

## Crate Layout

Three new library crates under `crates/libs/`, following the existing workspace
convention. Each is a library crate consumed by the CLI binary in
`crates/services/hush-cli`.

```
crates/
  libs/
    hunt-scan/              # Phase 1 -- NEW
      Cargo.toml
      src/
        lib.rs              # pub API: scan(), ScanResult, ScanConfig
        discovery.rs        # Platform-aware client detection (from well_known_clients.py)
        mcp_client.rs       # Async MCP introspection (from mcp_client.py + MCPScanner.py)
        models.rs           # All data structures (from models.py)
        analysis.rs         # Vulnerability detection + verification API (from verify_api.py)
        redact.rs           # Sensitive data redaction (from redact.py)
        skills.rs           # Skill directory scanning (from skill_client.py)
        packages.rs         # Direct package scanning (from direct_scanner.py) -- P2
        storage.rs          # Persistent scan state (from Storage.py) -- P2
        receipt.rs          # Signed scan receipt generation
    hunt-query/             # Phase 2 -- NEW
      Cargo.toml
      src/
        lib.rs              # pub API: query(), Timeline, HuntQuery
        query.rs            # HuntQuery struct + flag parsing
        replay.rs           # NATS JetStream replay with filtering
        timeline.rs         # Multi-source event merge + sort
        render.rs           # Color-coded terminal renderer
        nl.rs               # Natural language -> query (optional)
    hunt-correlate/         # Phase 3 -- NEW
      Cargo.toml
      src/
        lib.rs              # pub API: correlate(), watch(), ioc_match()
        rules.rs            # Correlation rule schema (YAML)
        engine.rs           # Correlation engine over streams
        watch.rs            # NATS subscription watch mode
        ioc.rs              # IOC matching (hash/domain/IP/STIX)
        report.rs           # Report gen with Merkle proofs
  services/
    hush-cli/
      src/
        hunt.rs             # NEW -- Hunt subcommand handler (cmd_hunt())
        main.rs             # ADD Commands::Hunt variant
```

### Workspace Cargo.toml Additions

```toml
# New members
"crates/libs/hunt-scan",
"crates/libs/hunt-query",
"crates/libs/hunt-correlate",

# New workspace deps (Phase 1)
rmcp = "0.1"                   # MCP protocol client (Rust)

# New workspace deps (Phase 2)
crossterm = "0.28"             # Terminal colors/styling
```

---

## Phase 1 -- Foundation + Scan

Port the Python `agent-scan` auto-discovery, MCP introspection, and
vulnerability analysis into Rust. Produce signed receipts for every scan.

### 1.1 CLI Integration

Add `Commands::Hunt` to the existing clap `Commands` enum in `main.rs`:

```rust
/// Threat hunting for AI agent ecosystems
Hunt {
    #[command(subcommand)]
    command: HuntCommands,
},
```

With initial subcommands:

```rust
#[derive(Subcommand, Debug)]
enum HuntCommands {
    /// Scan local AI agent MCP configurations for vulnerabilities
    Scan {
        /// Specific client name or config path to scan
        /// (default: auto-discover well-known clients)
        #[arg(long)]
        target: Option<Vec<String>>,

        /// Scan a package directly (npm:pkg, pypi:pkg, oci:image)
        #[arg(long)]
        package: Option<Vec<String>>,

        /// Scan agent skills directories
        #[arg(long)]
        skills: Option<Vec<String>>,

        /// Natural language or keyword query to filter results
        #[arg(long)]
        query: Option<String>,

        /// Policy file to evaluate discovered tools against
        #[arg(long)]
        policy: Option<String>,

        /// Built-in ruleset to evaluate against
        #[arg(long)]
        ruleset: Option<String>,

        /// MCP server connection timeout in seconds
        #[arg(long, default_value_t = 10)]
        timeout: u64,

        /// Include built-in IDE tools in results
        #[arg(long)]
        include_builtin: bool,

        /// Signing key path (hex Ed25519 seed)
        #[arg(long, default_value = "hush.key")]
        signing_key: String,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
}
```

Example invocations:

```
clawdstrike hunt scan                             # scan all discovered agents
clawdstrike hunt scan --target cursor             # scan specific client
clawdstrike hunt scan --target ./mcp.json         # scan specific config file
clawdstrike hunt scan --package npm:@org/mcp-srv  # scan package directly
clawdstrike hunt scan --skills ~/.cursor/skills   # scan agent skills
clawdstrike hunt scan --query "tools with file access"  # filter results
clawdstrike hunt scan --policy strict.yaml        # evaluate against policy
clawdstrike hunt scan --json                      # structured output
```

**JSON output** follows the existing CLI pattern:

```json
{
  "version": 1,
  "command": "hunt scan",
  "exit_code": 0,
  "data": { ... }
}
```

### 1.2 Platform-Aware Client Discovery

**Source:** `well_known_clients.py` (419 LOC) -- **P0, easy port.**

Port to `hunt-scan/src/discovery.rs`. Hardcoded platform paths with
`cfg!(target_os)` branching.

```
Python (well_known_clients.py)          Rust (discovery.rs)
----------------------------------      ----------------------------------
CandidateClient (Pydantic model)  -->   CandidateClient (serde struct)
MACOS_WELL_KNOWN_CLIENTS          -->   fn well_known_clients() -> Vec<..>
LINUX_WELL_KNOWN_CLIENTS                cfg!(target_os) dispatch
WINDOWS_WELL_KNOWN_CLIENTS
get_well_known_clients()           -->   fn discover_clients() -> Vec<..>
CLIENT_PATHS / CLIENT_TOOLS        -->   const arrays with #[cfg]
```

Key struct:

```rust
pub struct CandidateClient {
    pub name: String,
    pub config_paths: Vec<PathBuf>,
    pub skills_dirs: Vec<PathBuf>,
}
```

Platform path conventions:
- **macOS:** `~/Library/Application Support/...`
- **Linux:** `~/.config/...`
- **Windows:** `%APPDATA%/...`

Use the `dirs` crate for platform-aware home/config directory resolution.
See `docs/discovery-reference.md` for the full path table.

Supported clients at launch:

| Client         | macOS | Linux | Windows |
|---------------|-------|-------|---------|
| Claude Desktop | Y     | -     | Y       |
| Claude Code    | Y     | Y     | Y       |
| Cursor         | Y     | Y     | Y       |
| Windsurf       | Y     | Y     | Y       |
| VSCode/Copilot | Y     | Y     | Y       |
| Gemini CLI     | Y     | Y     | -       |
| OpenCode       | Y     | Y     | Y       |
| Kiro           | Y     | Y     | -       |

### 1.3 MCP Client Introspection

**Source:** `mcp_client.py` (339 LOC) + `MCPScanner.py` (355 LOC) + `inspect.py`
(288 LOC) -- **P0, hardest part.** Total ~982 LOC.

Port to `hunt-scan/src/mcp_client.rs`. The Python code uses the `mcp==1.25.0` SDK.
Rust needs a minimal read-only JSON-RPC 2.0 client over three transports.

```
MCP Transport Support
=====================

+----------+     tokio::process::Command      +------------+
| stdio    |---(stdin/stdout JSON-RPC)------->| MCP Server |
+----------+                                  +------------+

+----------+     reqwest + SSE stream         +------------+
| SSE      |---(GET /sse, POST /message)----->| MCP Server |
+----------+                                  +------------+

+----------+     reqwest POST                 +------------+
| HTTP     |---(POST /mcp with JSON-RPC)----->| MCP Server |
+----------+                                  +------------+
```

JSON-RPC calls needed (read-only subset only):

```json
{"jsonrpc": "2.0", "method": "initialize", "params": {...}, "id": 1}
{"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 2}
{"jsonrpc": "2.0", "method": "prompts/list", "params": {}, "id": 3}
{"jsonrpc": "2.0", "method": "resources/list", "params": {}, "id": 4}
{"jsonrpc": "2.0", "method": "resources/templates/list", "params": {}, "id": 5}
```

Key functions to port:

- `check_server()` -> `async fn introspect_server(server, timeout) -> ServerSignature`
- `scan_mcp_config_file()` -> `fn parse_mcp_config(path) -> MCPConfig`
- Config format parsers for Claude, VSCode, Cursor, Windsurf JSON schemas

MCP config format detection (from `models.py`):

| Config Format | Detection | Top-Level Key |
|--------------|-----------|---------------|
| `ClaudeConfigFile` | Top-level `mcpServers` | `mcpServers` |
| `ClaudeCodeConfigFile` | Top-level `projects` mapping to `ClaudeConfigFile` | `projects` |
| `VSCodeConfigFile` | Top-level `mcp` with inner `servers` | `mcp` |
| `StaticToolsConfig` | Top-level `signature` | `signature` |
| `UnknownMCPConfig` | Fallback -- returns empty server set | -- |

Consider using the `rmcp` crate or implementing a minimal JSON-RPC client directly.
See `docs/mcp-protocol-reference.md` for the full protocol specification.

**Implementation note:** `StdioServer` has a `model_validator` that calls
`rebalance_command_args` to split compound command strings (e.g.,
`"npx -y @modelcontextprotocol/server"` -> command `"npx"`, args
`["-y", "@modelcontextprotocol/server"]`). In Rust, use the `shell-words` crate
or a simple tokenizer.

### 1.4 Vulnerability Analysis

Port the detection logic from `agent-scan`'s analysis pipeline. Local heuristic
checks run without network access; the remote verification API is optional
(enabled with `--analysis-url`).

| Detection                 | Python Source         | Rust Module          |
|--------------------------|-----------------------|----------------------|
| Tool poisoning           | verify_api.py         | analysis.rs          |
| Prompt injection in descs| verify_api.py         | analysis.rs          |
| Toxic flow analysis      | verify_api.py         | analysis.rs          |
| Rug pull detection       | Storage.py            | analysis.rs          |
| Tool description changes | MCPScanner.py         | analysis.rs          |
| Binary signing check     | signed_binary.py      | analysis.rs          |

Issue codes preserved from the Python codebase (W003, etc.) for compatibility
with existing dashboards.

#### Verification API Client (P1: `verify_api.py` -> `hunt/analyze.rs`)

**Source:** `verify_api.py` (301 LOC) -- HTTP POST with retry.

**Request:** POST `ScanPathResultsCreate` JSON to the analysis URL.

```
POST <analysis_url>
Content-Type: application/json
X-Environment: production|ci          # from $AGENT_SCAN_ENVIRONMENT or "production"
X-Push: skip                          # when skip_pushing=true
X-Push-Key: <key>                     # when push_key provided
```

**Response (200 OK):** Body is `ScanPathResultsCreate` JSON. The response
`issues` and `labels` fields are merged back onto the original
`scan_path_results`. Server signatures are backfilled if they were `None`.

**Retry logic:**
- Max retries: 3
- Backoff: exponential -- 1s, 2s, 4s (`2^attempt` seconds)
- Only `TimeoutError` triggers retry (5xx returns immediately with error)
- 4xx errors return immediately with `analysis_error` on all scan paths

**Error handling by HTTP status:**

| Status | Behavior | Error Message |
|--------|----------|---------------|
| 200    | Merge response `issues`/`labels` into results | -- |
| 413    | Return immediately, set `analysis_error` | `"Analysis scope too large..."` |
| 4xx    | Return immediately, set `analysis_error` | `"The analysis server returned an error..."` |
| 5xx    | Return immediately, set `analysis_error` | `"Could not reach analysis server: {status} - {message}"` |

**SSL handling:** Default uses system TLS with `rustls` + `webpki-roots`
(already in workspace). Add `--skip-ssl-verify` flag for `reqwest`'s
`danger_accept_invalid_certs()` (mirrors Python's `skip_ssl_verify` option).

**Timeout:** 30 seconds per request.

#### Redaction (P1: `redact.py` -> `hunt/redact.rs`)

**Source:** `redact.py` (203 LOC) -- regex-based sensitive data redaction
applied before uploading scan results to the analysis server.

Replacement sentinel: `"**REDACTED**"`

Redaction targets:
- **Absolute paths:** Unix (`/path/to/...`), home (`~/...`), Windows (`C:\...`)
- **CLI arg values:** `--flag value` -> `--flag **REDACTED**` (boolean `-y` exempt)
- **Env var values:** all values redacted (keys preserved)
- **HTTP header values:** all values redacted (keys preserved)
- **URL query parameters:** values redacted (keys preserved)
- **Error tracebacks:** absolute paths redacted within `traceback` and `server_output`

#### Skills Scanning (P1: `skill_client.py` -> `hunt/skills.rs`)

**Source:** `skill_client.py` (151 LOC) -- YAML frontmatter + directory traversal.

- Find `SKILL.md` (case-insensitive) in specified directories
- Parse YAML frontmatter (`name`, `description`) with `serde_yaml`
- Map directory contents to entity types:
  - `*.md` -> Prompt entity
  - `*.{py,js,ts,sh}` -> Tool entity
  - other files -> Resource entity

### 1.5 Signed Scan Receipts

Each scan produces an Ed25519-signed receipt using `hush-core`:

```
Scan Execution
     |
     v
+------------------+
| ScanResult       |  (all path results, issues, tool signatures)
+------------------+
     |
     v  canonical JSON (RFC 8785)
+------------------+
| SHA-256 hash     |
+------------------+
     |
     v  Ed25519 sign
+------------------+
| SignedReceipt    |  { scan_hash, signature, public_key, timestamp }
+------------------+
```

The receipt includes:
- SHA-256 hash of the canonical JSON scan result
- Ed25519 signature over the hash
- Signer public key
- ISO-8601 timestamp
- Policy reference (if a scan policy was specified)

### 1.6 Crate: `hunt-scan`

```toml
[package]
name = "hunt-scan"
description = "MCP agent scanning and vulnerability detection for clawdstrike hunt"
version.workspace = true
edition.workspace = true

[dependencies]
hush-core.workspace = true
serde.workspace = true
serde_json.workspace = true
serde_yaml.workspace = true
tokio.workspace = true
reqwest.workspace = true
chrono.workspace = true
thiserror.workspace = true
tracing.workspace = true
glob.workspace = true
dirs.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }

[lints]
workspace = true
```

### Phase 1 Acceptance Criteria

- [ ] `clawdstrike hunt scan` discovers well-known MCP clients on macOS, Linux, Windows
- [ ] `clawdstrike hunt scan --target <path>` scans a specific config file
- [ ] `clawdstrike hunt scan --target <client>` scans a named client (e.g., `cursor`)
- [ ] stdio, SSE, and HTTP MCP transports connect and introspect successfully
- [ ] All MCP config formats parse correctly (Claude, ClaudeCode, VSCode, fallback)
- [ ] Tool poisoning, prompt injection, toxic flow, and rug pull detections fire
- [ ] `--policy` evaluates discovered tools against clawdstrike policy engine
- [ ] Every scan produces a valid `SignedReceipt` verifiable with `hush verify`
- [ ] `--json` output matches CLI JSON envelope pattern (version, command, exit_code)
- [ ] `cargo test -p hunt-scan` passes with no clippy warnings
- [ ] Exit codes: 0 = clean, 1 = warnings, 2 = vulnerabilities found

#### Phase 1.1 Additions (P1 modules)

- [ ] `--analysis-url` sends results to verification API with retry + backoff
- [ ] Redaction applied before any data leaves the machine
- [ ] `--skills <dir>` scans skill directories for SKILL.md + entities
- [ ] `--package npm:<pkg>` and `--package pypi:<pkg>` direct package scanning (P2)

---

## Phase 2 -- Query + Timeline

Build structured querying over historical Spine events stored in NATS JetStream,
and a timeline reconstruction engine that merges events from multiple sources.

### 2.1 HuntQuery Struct

```rust
pub struct HuntQuery {
    /// Time window
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,

    /// Event source filters
    pub sources: Vec<EventSource>,     // Tetragon, Hubble, Receipt, Scan

    /// Content filters
    pub process: Option<String>,       // binary name / regex
    pub namespace: Option<String>,     // k8s namespace
    pub pod: Option<String>,           // k8s pod
    pub action_type: Option<String>,   // file, egress, mcp, shell
    pub verdict: Option<Verdict>,      // allow, deny, warn

    /// Full-text search (substring match across all string fields)
    pub search: Option<String>,

    /// Limit results
    pub limit: usize,
}
```

### 2.2 CLI Flags

```
hush hunt query \
    --start 2026-02-26T00:00:00Z \
    --end   2026-02-27T00:00:00Z \
    --source tetragon,receipt \
    --process "curl" \
    --namespace clawdstrike \
    --verdict deny \
    --limit 100 \
    --json
```

Natural language shorthand with `--nl` (optional, requires `--llm` or keyword
extraction fallback):

```
hush hunt query --nl "show me all denied egress in the last 24 hours"
```

### 2.3 NATS JetStream Replay

Leverage `spine::nats_transport` for connectivity and JetStream replay:

```
  hush hunt query
       |
       v
+------------------+     +---------------------+
| Connect to NATS  |---->| spine::connect()    |
| (auth optional)  |     | spine::jetstream()  |
+------------------+     +---------------------+
       |
       v
+------------------+     +---------------------+
| Create consumer  |---->| DeliverPolicy::     |
| with time window |     |   ByStartTime(start)|
+------------------+     +---------------------+
       |
       v
+------------------+
| Stream messages  |     Client-side filtering:
| from consumer    |---->  - deserialize envelope
|                  |       - match HuntQuery predicates
+------------------+       - collect into results vec
       |
       v
+------------------+
| Merge + Sort     |
| by timestamp     |
+------------------+
```

NATS subjects consumed:

| Stream               | Subject Pattern                  | Source          |
|---------------------|----------------------------------|-----------------|
| SPINE_TETRAGON      | `spine.tetragon.events.>`        | tetragon-bridge |
| SPINE_HUBBLE        | `spine.hubble.flows.>`           | hubble-bridge   |
| SPINE_RECEIPTS      | `spine.receipts.>`               | hush-cli / hushd|
| SPINE_HUNT_SCANS    | `spine.hunt.scans.>`             | hunt scan       |

### 2.4 Timeline Reconstruction

Merge events from Tetragon (kernel exec/kprobe), Hubble (network flows),
ClawdStrike receipts (guard decisions), and hunt scans into a unified timeline:

```
+---Tetragon---+   +---Hubble---+   +---Receipts---+   +---Scans---+
| process_exec |   | flow event |   | guard check  |   | mcp scan  |
| 09:01:03.221 |   | 09:01:03.5 |   | 09:01:04.01  |   | 09:00:00  |
+--------------+   +------------+   +--------------+   +-----------+
       \               |                  /                  /
        \              |                 /                  /
         v             v                v                  v
    +--------------------------------------------------+
    |         Timeline Merge (sort by timestamp)        |
    +--------------------------------------------------+
    | 09:00:00  [SCAN]     MCP scan: 3 servers, 2 warn |
    | 09:01:03  [EXEC]     /usr/bin/curl https://...    |
    | 09:01:03  [NET ]     TCP SYN -> 93.184.216.34:443 |
    | 09:01:04  [GUARD]    EgressAllowlist: DENY        |
    +--------------------------------------------------+
```

### 2.5 Terminal Rendering

Color-coded output using `crossterm`:

```
TIMESTAMP            SOURCE    VERDICT   DETAIL
2026-02-26 09:00:00  SCAN      WARN      MCP scan: cursor -- 2 tool poisoning
2026-02-26 09:01:03  TETRAGON  -         exec /usr/bin/curl https://evil.com
2026-02-26 09:01:03  HUBBLE    -         TCP -> 93.184.216.34:443
2026-02-26 09:01:04  RECEIPT   DENY      EgressAllowlist blocked evil.com
```

Color legend:
- Green: ALLOW
- Yellow: WARN
- Red: DENY
- Cyan: TETRAGON
- Blue: HUBBLE
- White: informational

### 2.6 Crate: `hunt-query`

```toml
[package]
name = "hunt-query"
description = "Structured querying and timeline reconstruction for clawdstrike hunt"
version.workspace = true
edition.workspace = true

[dependencies]
hunt-scan = { path = "../hunt-scan" }
spine.workspace = true
hush-core.workspace = true
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
tokio-stream.workspace = true
chrono.workspace = true
thiserror.workspace = true
tracing.workspace = true
async-nats = "0.39"
crossterm = "0.28"
regex.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }

[lints]
workspace = true
```

### Phase 2 Acceptance Criteria

- [ ] `hush hunt query --start ... --end ...` replays NATS JetStream envelopes
- [ ] Query filters (source, process, namespace, verdict, search) work correctly
- [ ] Timeline merges Tetragon, Hubble, Receipt, and Scan events by timestamp
- [ ] Color-coded terminal output renders correctly; `--json` disables color
- [ ] `--nl` keyword extraction parses time ranges, sources, and actions without LLM
- [ ] `--nl --llm` uses optional LLM endpoint for natural language parsing
- [ ] Works offline (no NATS) by scanning local receipt/scan JSON files
- [ ] `cargo test -p hunt-query` passes with no clippy warnings

---

## Phase 3 -- Correlate + Watch + IOC

Advanced threat hunting: correlation rules, real-time watch mode, indicator of
compromise matching, and signed evidence reports.

### 3.1 Correlation Rule Schema

YAML schema inspired by SIGMA, tailored for AI agent events:

```yaml
# rules/agent-tool-exfil.yaml
schema: clawdstrike.hunt.correlation.v1
name: "MCP Tool Exfiltration Attempt"
severity: high
description: >
  Detects an MCP tool reading sensitive files followed by
  network egress to an external domain within 30 seconds.
window: 30s
conditions:
  - source: receipt
    action_type: file
    verdict: allow
    target_pattern: "/etc/passwd|/etc/shadow|\\.ssh/|\\.(env|pem|key)$"
    bind: file_access
  - source: [receipt, hubble]
    action_type: egress
    not_target_pattern: "^(localhost|127\\.|10\\.|172\\.(1[6-9]|2|3[01])\\.|192\\.168\\.)"
    after: file_access
    within: 30s
    bind: egress_event
output:
  title: "Potential data exfiltration via MCP tool"
  evidence:
    - file_access
    - egress_event
```

### 3.2 Correlation Engine

```
   Event Stream (from query or watch)
          |
          v
  +-------------------+
  | Rule Evaluator    |
  | (per active rule) |
  +-------------------+
          |
          v
  +-------------------+      +-------------------+
  | Window Tracker    |----->| Condition Matcher  |
  | (sliding window   |      | (regex, verdict,   |
  |  per rule)        |      |  source filters)   |
  +-------------------+      +-------------------+
          |
          | match set complete
          v
  +-------------------+
  | Alert Generator   |
  | (severity, title, |
  |  bound evidence)  |
  +-------------------+
          |
          v
  +-------------------+
  | Signed Alert      |
  | Receipt           |
  +-------------------+
```

### 3.3 Watch Mode

Real-time NATS subscription with continuous correlation:

```
hush hunt watch \
    --rules rules/*.yaml \
    --nats-url nats://localhost:4222 \
    --signing-key hush.key
```

```
NATS Subscription
     |
     v
+------------------+
| Subscribe to:    |
| spine.tetragon.> |
| spine.hubble.>   |
| spine.receipts.> |
| spine.hunt.>     |
+------------------+
     |
     v  (each message)
+------------------+    +-------------------+
| Deserialize      |--->| Correlation       |
| Spine Envelope   |    | Engine (sliding   |
+------------------+    | window per rule)  |
                        +-------------------+
                             |
                             | alert triggered
                             v
                        +-------------------+
                        | Terminal Alert +   |
                        | Signed Receipt    |
                        +-------------------+
```

### 3.4 IOC Matching Engine

```rust
pub enum IOCType {
    Sha256(String),
    Sha1(String),
    Md5(String),
    Domain(String),
    IPv4(String),
    IPv6(String),
    Url(String),
}

pub struct IOCDatabase {
    entries: Vec<IOCEntry>,
    // Indexed for fast lookup
    hash_index: HashMap<String, Vec<usize>>,
    domain_index: HashMap<String, Vec<usize>>,
    ip_index: HashMap<String, Vec<usize>>,
}
```

Input formats:
- Plain text (one IOC per line)
- CSV (indicator, type, description, source)
- STIX 2.1 JSON bundles

CLI:

```
hush hunt ioc \
    --feed indicators.csv \
    --stix threat-feed.json \
    --start 2026-02-26T00:00:00Z \
    --nats-url nats://localhost:4222
```

### 3.5 Report Generation

Evidence bundles with Merkle proofs for tamper-evident audit:

```
+---------------------+
| Report              |
| +--Evidence[]-----+ |
| | Spine Envelope 1 | |
| | Spine Envelope 2 | |
| | Scan Receipt     | |
| | Alert Receipt    | |
| +------------------+ |
|                      |
| +--Merkle Tree-----+ |
| | root: 0xabc...   | |
| | proof per item   | |
| +------------------+ |
|                      |
| +--Report Sig------+ |
| | Ed25519 over     | |
| | Merkle root      | |
| +------------------+ |
+---------------------+
```

Uses `hush-core::MerkleTree` and `hush-core::MerkleProof` for tree construction
and inclusion proofs.

### 3.6 Crate: `hunt-correlate`

```toml
[package]
name = "hunt-correlate"
description = "Correlation rules, watch mode, and IOC matching for clawdstrike hunt"
version.workspace = true
edition.workspace = true

[dependencies]
hunt-scan = { path = "../hunt-scan" }
hunt-query = { path = "../hunt-query" }
spine.workspace = true
hush-core.workspace = true
serde.workspace = true
serde_json.workspace = true
serde_yaml.workspace = true
tokio.workspace = true
tokio-stream.workspace = true
async-nats = "0.39"
chrono.workspace = true
thiserror.workspace = true
tracing.workspace = true
regex.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }

[lints]
workspace = true
```

### Phase 3 Acceptance Criteria

- [ ] Correlation YAML schema parses and validates (reject unknown fields)
- [ ] Sliding-window correlation fires alerts for multi-step attack patterns
- [ ] `hush hunt watch` streams NATS events and applies correlation rules live
- [ ] IOC matching works for SHA-256, domain, IPv4, and STIX 2.1 input
- [ ] Reports contain valid Merkle proofs verifiable with `hush merkle verify`
- [ ] Report signature verifiable with `hush verify`
- [ ] `cargo test -p hunt-correlate` passes with no clippy warnings

---

## Rust Struct Reference

Suggested serde struct definitions ported from the Python `models.py` Pydantic
models. These live in `hunt-scan/src/models.rs`. See
`docs/models-and-api-reference.md` for the full field-by-field mapping.

### Error Category

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

### ScanError

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub message: Option<String>,
    pub exception: Option<String>,      // always serialized as string
    pub traceback: Option<String>,
    #[serde(default = "default_true")]
    pub is_failure: bool,
    pub category: Option<ErrorCategory>,
    pub server_output: Option<String>,
}
```

### Server Config Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioServer {
    pub command: String,
    pub args: Option<Vec<String>>,
    #[serde(rename = "type", default)]
    pub server_type: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub binary_identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteServer {
    pub url: String,
    #[serde(rename = "type")]
    pub server_type: Option<String>,    // "sse" | "http"
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillServer {
    pub path: String,
    #[serde(rename = "type", default)]
    pub server_type: Option<String>,    // "skill"
}

/// Discriminated union for server configs, tagged on "type" field.
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

### Entity Types

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
}
```

> **Note:** MCP SDK entity types serialize without an explicit `type` tag. In
> practice you may need `#[serde(untagged)]` and rely on field-shape
> discrimination, or add a wrapper with an explicit tag.

### Scan Result Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub code: String,
    pub message: String,
    /// (server_index, entity_index) or (server_index, None) or None
    pub reference: Option<(usize, Option<usize>)>,
    pub extra_data: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalarToolLabels {
    pub is_public_sink: f64,
    pub destructive: f64,
    pub untrusted_content: f64,
    pub private_data: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSignature {
    pub metadata: serde_json::Value,   // MCP InitializeResult
    #[serde(default)]
    pub prompts: Vec<serde_json::Value>,
    #[serde(default)]
    pub resources: Vec<serde_json::Value>,
    #[serde(default)]
    pub resource_templates: Vec<serde_json::Value>,
    #[serde(default)]
    pub tools: Vec<Tool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerScanResult {
    pub name: Option<String>,
    pub server: ServerConfig,
    pub signature: Option<ServerSignature>,
    pub error: Option<ScanError>,
}

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

### API Request/Response Body

```rust
/// Used for both the verification API request and response.
/// Response merges `issues` and `labels` back into `scan_path_results`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPathResultsCreate {
    pub scan_path_results: Vec<ScanPathResult>,
    pub scan_user_info: ScanUserInfo,
    pub scan_metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUserInfo {
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub identifier: Option<String>,
    pub ip_address: Option<String>,
    pub anonymous_identifier: Option<String>,
}
```

### Storage Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedEntity {
    pub hash: String,
    #[serde(rename = "type")]
    pub entity_type: String,
    pub timestamp: DateTime<Utc>,
    pub description: Option<String>,
}

/// Map keyed by "{server_name}.{entity_type}.{entity_name}"
pub type ScannedEntities = HashMap<String, ScannedEntity>;
```

### Implementation Notes

1. **Command rebalancing:** `StdioServer` splits compound `command` strings into
   `(command, args)`. Use the `shell-words` crate in Rust.
2. **Entity hashing:** `md5(description.encode()).hexdigest()` -- use the `md5`
   crate. Default description when `None`: `"no description available"`.
3. **Datetime parsing:** `ScannedEntity.timestamp` accepts ISO 8601 and
   `"DD/MM/YYYY, HH:MM:SS"`. Try `DateTime::parse_from_rfc3339` first,
   then `NaiveDateTime::parse_from_str("%d/%m/%Y, %H:%M:%S")`.
4. **`type` field on servers:** Some servers have `type = None` in Python.
   Handle missing/null `type` with a default variant or normalize before
   deserialization.

---

## Dependency Map

### Internal Crate Dependencies

```
                    +------------+
                    | hush-core  |  (Ed25519, SHA-256, Merkle, canonical JSON)
                    +-----+------+
                          |
          +---------------+---------------+
          |               |               |
    +-----v------+  +-----v------+  +-----v------+
    | hunt-scan  |  |   spine    |  | clawdstrike|
    +-----+------+  +-----+------+  +------------+
          |               |
          |       +-------+-------+
          |       |               |
    +-----v------v--+     +------v---------+
    |  hunt-query   |     | tetragon-bridge|  (existing)
    +-----+---------+     | hubble-bridge  |  (existing)
          |               +----------------+
    +-----v-----------+
    | hunt-correlate  |
    +-----+-----------+
          |
    +-----v-----------+
    |   hush-cli      |  (Commands::Hunt variant)
    +-----------------+
```

### External Dependencies (new)

| Crate      | Version | Purpose                                      | Phase |
|-----------|---------|----------------------------------------------|-------|
| `rmcp`    | 0.1     | MCP protocol client (Rust native)            | 1     |
| `crossterm`| 0.28   | Terminal color/styling for timeline output   | 2     |

All other dependencies already exist in the workspace `Cargo.toml`.

### Existing Infrastructure Leveraged

| Component                     | Used In    | Purpose                              |
|------------------------------|-----------|--------------------------------------|
| `hush-core::Keypair`        | Phase 1+  | Ed25519 signing for receipts         |
| `hush-core::SignedReceipt`  | Phase 1+  | Receipt structure and verification   |
| `hush-core::MerkleTree`     | Phase 3   | Evidence bundle Merkle proofs        |
| `hush-core::canonicalize_json`| Phase 1+ | RFC 8785 canonical JSON for hashing |
| `spine::nats_transport`     | Phase 2+  | NATS connect, JetStream, KV helpers  |
| `spine::envelope`           | Phase 2+  | Signed envelope parsing/verification |
| `spine::attestation`        | Phase 2+  | RuntimeProof, NodeAttestation types  |
| `ExitCode` enum (hush-cli)  | Phase 1+  | Consistent CLI exit codes            |
| `CLI_JSON_VERSION` (hush-cli)| Phase 1+ | JSON output envelope versioning      |

---

## Risk Areas and Open Questions

### Phase 1

| Risk | Impact | Mitigation |
|------|--------|------------|
| **MCP protocol drift.** The MCP spec is evolving; Python `mcp` library tracks it closely. Rust `rmcp` may lag. | Medium | Pin `rmcp` version; maintain a thin transport abstraction layer so we can swap implementations. |
| **Config format fragmentation.** Each IDE client has a different JSON schema for MCP config. New clients appear regularly. | Medium | Implement a `ConfigParser` trait with per-client implementations. The Python `models.py` has 8+ config variants; port them as an explicit enum. |
| **Analysis accuracy without remote server.** Python `agent-scan` uses a remote analysis API for some checks (tool poisoning, toxic flows). Local-only checks may have lower accuracy. | Low | Start with heuristic-based local checks. Add optional `--analysis-url` flag to call a remote server, same as the Python tool. |
| **Cross-platform path handling.** Windows backslash paths, `~` expansion, and `Application Support` spaces. | Low | Use `dirs` crate for platform-aware home directory. All path handling through `std::path::PathBuf`. |

### Phase 2

| Risk | Impact | Mitigation |
|------|--------|------------|
| **NATS availability.** Users may not have NATS deployed, especially for local dev scanning. | High | Design query to work in two modes: (1) NATS replay when available, (2) local file scan over JSON/JSONL receipts. NATS is never required. |
| **Event volume.** Tetragon in production can produce millions of events per hour. JetStream replay of large windows may be slow. | Medium | Server-side subject filtering, `max_bytes` / `max_age` stream limits (already in `nats_transport.rs`), client-side `--limit` flag, and streaming output. |
| **Timeline clock skew.** Events from different sources may have misaligned timestamps. | Low | Use `issued_at` from Spine envelopes (set at signing time). Document that clock sync (NTP) across nodes affects timeline accuracy. |

### Phase 3

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Correlation rule complexity.** SIGMA-like rules are expressive but hard to optimize for streaming evaluation. | Medium | Start with simple sequential pattern matching. Defer complex temporal operators (e.g., "not followed by") to a later iteration. |
| **STIX 2.1 parsing.** Full STIX compliance is large. | Low | Support only the indicator SDO (`type: indicator`) with simple pattern extraction. Do not attempt full STIX graph traversal. |
| **Watch mode memory.** Long-running watch with many rules and large sliding windows could consume significant memory. | Medium | Implement window eviction. Cap maximum window duration. Add `--max-window` flag with sensible default (5 minutes). |

### Open Questions

1. **Should `hunt scan` results publish to NATS automatically?** Current plan:
   off by default, enabled with `--publish-to-nats`. This keeps offline-first
   behavior while enabling integration with the query/timeline pipeline.

2. **MCP OAuth token handling.** The Python tool supports `--mcp-oauth-tokens-path`
   for OAuth-authenticated MCP servers. Do we need this in Phase 1, or can it be
   deferred to Phase 1.1?

3. **Plugin guard integration.** Should `hunt scan` results feed into the
   ClawdStrike guard pipeline (e.g., a `HuntScanGuard` that blocks actions if
   the most recent scan found critical vulnerabilities)? This would close the
   loop between scanning and enforcement but adds coupling.

4. **Multi-agent hunt.** The `hush-multi-agent` crate exists for orchestration.
   Should `hunt watch` support coordinated hunting across multiple nodes, or is
   single-node watch sufficient for the initial release?

5. **Existing `rmcp` crate maturity.** Evaluate whether the Rust MCP client
   (`rmcp`) supports all three transports (stdio, SSE, HTTP) reliably, or if we
   need to implement transport handling directly with `tokio` + `reqwest`.

---

*Last updated: 2026-02-27*

//! MCP client for server introspection.
//!
//! Provides a minimal read-only MCP client that introspects servers to discover
//! their tools, prompts, resources, and resource templates. Supports stdio,
//! HTTP (streamable), and SSE transports.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::warn;
use url::Url;

use crate::models::{
    ClaudeCodeConfigFile, ClaudeConfigFile, MCPConfig, RemoteServer, ServerConfig, ServerSignature,
    SkillServer, StaticToolsServer, StdioServer, Tool, VSCodeConfigFile, VSCodeMCPConfig,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during MCP introspection.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Timeout after {0}s")]
    Timeout(u64),
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc { code: i64, message: String },
    #[error("Server startup failed: {message}")]
    ServerStartup {
        message: String,
        server_output: Option<String>,
    },
    #[error("All remote connection attempts failed")]
    AllAttemptsFailed { errors: Vec<String> },
    #[error("Config parse error: {0}")]
    ConfigParse(String),
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Serialize)]
struct JsonRpcNotification {
    jsonrpc: &'static str,
    method: String,
}

// ---------------------------------------------------------------------------
// Initialize result (partial parse of MCP InitializeResult)
// ---------------------------------------------------------------------------

/// Minimal parse of the MCP `initialize` result capabilities for gating list calls.
#[derive(Debug, Default, Deserialize)]
struct InitializeCapabilities {
    tools: Option<serde_json::Value>,
    prompts: Option<serde_json::Value>,
    resources: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct InitializeResult {
    #[serde(default)]
    capabilities: InitializeCapabilities,
    #[allow(dead_code)]
    #[serde(flatten)]
    rest: serde_json::Value,
}

// ---------------------------------------------------------------------------
// MCP Session
// ---------------------------------------------------------------------------

/// Manages JSON-RPC request ID sequencing for MCP introspection.
pub struct McpSession {
    request_id: AtomicU64,
}

impl Default for McpSession {
    fn default() -> Self {
        Self {
            request_id: AtomicU64::new(1),
        }
    }
}

impl McpSession {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn build_request(&self, method: &str, params: Option<serde_json::Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0",
            id: self.next_id(),
            method: method.to_string(),
            params,
        }
    }

    fn build_notification(method: &str) -> JsonRpcNotification {
        JsonRpcNotification {
            jsonrpc: "2.0",
            method: method.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Stdio transport helpers
// ---------------------------------------------------------------------------

/// Send a JSON-RPC message as a newline-delimited JSON line to the writer.
async fn stdio_send(writer: &mut tokio::process::ChildStdin, msg: &[u8]) -> Result<(), McpError> {
    writer.write_all(msg).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Read one JSON-RPC response line from the reader, skipping blank lines and
/// non-JSON lines (some MCP servers emit logging to stdout).
fn is_response_for_request(resp: &JsonRpcResponse, expected_id: Option<u64>) -> bool {
    let Some(resp_id) = resp.id else {
        return false;
    };
    match expected_id {
        Some(expected) => resp_id == expected,
        None => true,
    }
}

async fn stdio_recv(
    reader: &mut BufReader<tokio::process::ChildStdout>,
    expected_id: Option<u64>,
) -> Result<JsonRpcResponse, McpError> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(McpError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "child process closed stdout",
            )));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Try to parse as JSON-RPC response; skip non-JSON lines (server logs)
        match serde_json::from_str::<JsonRpcResponse>(trimmed) {
            Ok(resp) => {
                if is_response_for_request(&resp, expected_id) {
                    return Ok(resp);
                }
                // Ignore notifications and unrelated responses while waiting
                // for the current request's reply.
                continue;
            }
            Err(_) => continue,
        }
    }
}

/// Extract the result from a JSON-RPC response, turning JSON-RPC errors into `McpError`.
fn extract_result(resp: JsonRpcResponse) -> Result<serde_json::Value, McpError> {
    if let Some(err) = resp.error {
        return Err(McpError::JsonRpc {
            code: err.code,
            message: err.message,
        });
    }
    Ok(resp.result.unwrap_or(serde_json::Value::Null))
}

// ---------------------------------------------------------------------------
// Stdio introspection
// ---------------------------------------------------------------------------

/// Run the full introspection sequence over a stdio transport.
async fn introspect_stdio(
    server: &StdioServer,
    timeout_secs: u64,
) -> Result<ServerSignature, McpError> {
    // Command rebalancing is already done during ServerConfig deserialization,
    // so server.command is the bare command and server.args has the split args.
    let command = &server.command;
    let args = server.args.as_deref().unwrap_or_default();

    // Security note: the command and args come from user config files (e.g.
    // ~/.cursor/mcp.json).  Spawning is inherent to MCP introspection — we
    // must start the server to discover its tool surface.  We log the binary
    // so the scan output is auditable.
    tracing::info!(command = %command, "spawning MCP stdio server for introspection");

    let mut cmd = tokio::process::Command::new(command);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if let Some(env) = &server.env {
        // Warn about security-sensitive env vars that could alter process loading.
        const SENSITIVE_ENV_KEYS: &[&str] = &[
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
        ];
        for k in env.keys() {
            if SENSITIVE_ENV_KEYS.iter().any(|s| k.eq_ignore_ascii_case(s)) {
                tracing::warn!(
                    key = %k,
                    command = %command,
                    "MCP server config sets security-sensitive environment variable"
                );
            }
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
    }

    let mut child = cmd.spawn().map_err(|e| McpError::ServerStartup {
        message: format!("failed to spawn '{}': {}", command, e),
        server_output: None,
    })?;

    let stdin = child.stdin.take().ok_or_else(|| McpError::ServerStartup {
        message: "failed to open stdin".to_string(),
        server_output: None,
    })?;
    let stdout = child.stdout.take().ok_or_else(|| McpError::ServerStartup {
        message: "failed to open stdout".to_string(),
        server_output: None,
    })?;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        run_stdio_session(stdin, stdout),
    )
    .await;

    // Always try to kill the child process
    let _ = child.kill().await;

    // Capture stderr for error reporting
    let stderr_output = if let Some(mut stderr) = child.stderr.take() {
        let mut buf = String::new();
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut buf).await;
        if buf.is_empty() {
            None
        } else {
            Some(buf)
        }
    } else {
        None
    };

    match result {
        Ok(Ok(sig)) => Ok(sig),
        Ok(Err(e)) => {
            // Attach stderr to startup errors
            match e {
                McpError::Io(_) | McpError::Json(_) => Err(McpError::ServerStartup {
                    message: e.to_string(),
                    server_output: stderr_output,
                }),
                other => Err(other),
            }
        }
        Err(_) => Err(McpError::Timeout(timeout_secs)),
    }
}

/// Run the MCP session over stdin/stdout pipes.
async fn run_stdio_session(
    mut stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
) -> Result<ServerSignature, McpError> {
    let mut reader = BufReader::new(stdout);
    let session = McpSession::new();

    // 1. Initialize
    let init_req = session.build_request(
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "clawdstrike",
                "version": "0.1.3"
            }
        })),
    );
    let init_bytes = serde_json::to_vec(&init_req)?;
    stdio_send(&mut stdin, &init_bytes).await?;
    let init_resp = stdio_recv(&mut reader, Some(init_req.id)).await?;
    let init_result_value = extract_result(init_resp)?;
    let metadata = init_result_value.clone();

    // Parse capabilities to know what to list (for stdio we try everything)
    let _init: InitializeResult =
        serde_json::from_value(init_result_value).unwrap_or(InitializeResult {
            capabilities: InitializeCapabilities::default(),
            rest: serde_json::Value::Null,
        });

    // 2. Send notifications/initialized
    let notif = McpSession::build_notification("notifications/initialized");
    let notif_bytes = serde_json::to_vec(&notif)?;
    stdio_send(&mut stdin, &notif_bytes).await?;
    // No response expected for notifications

    // 3. List prompts (stdio: always try)
    let prompts =
        match list_call_stdio(&session, &mut stdin, &mut reader, "prompts/list", "prompts").await {
            Ok(v) => v,
            Err(e) => {
                warn!("prompts/list failed: {}", e);
                Vec::new()
            }
        };

    // 4. List resources (stdio: always try)
    let resources = match list_call_stdio(
        &session,
        &mut stdin,
        &mut reader,
        "resources/list",
        "resources",
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("resources/list failed: {}", e);
            Vec::new()
        }
    };

    // 5. List resource templates (stdio: always try)
    let resource_templates = match list_call_stdio(
        &session,
        &mut stdin,
        &mut reader,
        "resources/templates/list",
        "resourceTemplates",
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("resources/templates/list failed: {}", e);
            Vec::new()
        }
    };

    // 6. List tools (stdio: always try)
    let tools_raw =
        match list_call_stdio(&session, &mut stdin, &mut reader, "tools/list", "tools").await {
            Ok(v) => v,
            Err(e) => {
                warn!("tools/list failed: {}", e);
                Vec::new()
            }
        };

    let tools: Vec<Tool> = tools_raw
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();

    Ok(ServerSignature {
        metadata,
        prompts,
        resources,
        resource_templates,
        tools,
    })
}

/// Make a single list JSON-RPC call over stdio and extract the named array from the result.
async fn list_call_stdio(
    session: &McpSession,
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut BufReader<tokio::process::ChildStdout>,
    method: &str,
    result_key: &str,
) -> Result<Vec<serde_json::Value>, McpError> {
    let req = session.build_request(method, Some(serde_json::json!({})));
    let bytes = serde_json::to_vec(&req)?;
    stdio_send(stdin, &bytes).await?;
    let resp = stdio_recv(reader, Some(req.id)).await?;
    let result = extract_result(resp)?;
    Ok(result
        .get(result_key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default())
}

// ---------------------------------------------------------------------------
// HTTP transport helpers
// ---------------------------------------------------------------------------

/// Build a reqwest client with optional headers from a RemoteServer config.
fn build_http_client(server: &RemoteServer) -> Result<reqwest::Client, McpError> {
    let mut headers = reqwest::header::HeaderMap::new();
    for (k, v) in &server.headers {
        let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| McpError::Other(format!("invalid header name '{}': {}", k, e)))?;
        let value = reqwest::header::HeaderValue::from_str(v)
            .map_err(|e| McpError::Other(format!("invalid header value for '{}': {}", k, e)))?;
        headers.insert(name, value);
    }

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(McpError::Http)
}

/// Send a JSON-RPC request over HTTP POST and return the parsed response.
async fn http_rpc(
    client: &reqwest::Client,
    url: &str,
    request: &JsonRpcRequest,
) -> Result<JsonRpcResponse, McpError> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(request)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        return Err(McpError::Other(format!("HTTP {} from {}", status, url)));
    }

    let body = resp.text().await?;
    let parsed: JsonRpcResponse = serde_json::from_str(&body)?;
    Ok(parsed)
}

/// Run the full MCP introspection sequence over HTTP transport.
async fn introspect_http(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
) -> Result<ServerSignature, McpError> {
    let session = McpSession::new();

    // 1. Initialize
    let init_req = session.build_request(
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "clawdstrike",
                "version": "0.1.3"
            }
        })),
    );

    let init_resp = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        http_rpc(client, url, &init_req),
    )
    .await
    .map_err(|_| McpError::Timeout(timeout_secs))??;

    let init_result_value = extract_result(init_resp)?;
    let metadata = init_result_value.clone();

    let init: InitializeResult =
        serde_json::from_value(init_result_value).unwrap_or(InitializeResult {
            capabilities: InitializeCapabilities::default(),
            rest: serde_json::Value::Null,
        });

    // 2. Send notifications/initialized (fire-and-forget over HTTP)
    // Use a notification (no `id` field) per JSON-RPC 2.0 spec.
    let notif = McpSession::build_notification("notifications/initialized");
    let _ = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&notif)
        .send()
        .await;

    // Wrap all list calls in a single timeout to prevent hanging on
    // malicious/slow servers (mirrors the stdio transport behavior).
    let list_timeout = std::time::Duration::from_secs(timeout_secs);

    // 3. List prompts (if capabilities.prompts)
    let prompts = if init.capabilities.prompts.is_some() {
        tokio::time::timeout(
            list_timeout,
            list_call_http(client, url, &session, "prompts/list", "prompts"),
        )
        .await
        .unwrap_or_else(|_| {
            warn!("prompts/list timed out after {}s", timeout_secs);
            Ok(Vec::new())
        })
        .unwrap_or_else(|e| {
            warn!("prompts/list failed: {}", e);
            Vec::new()
        })
    } else {
        Vec::new()
    };

    // 4. List resources (if capabilities.resources)
    let resources = if init.capabilities.resources.is_some() {
        tokio::time::timeout(
            list_timeout,
            list_call_http(client, url, &session, "resources/list", "resources"),
        )
        .await
        .unwrap_or_else(|_| {
            warn!("resources/list timed out after {}s", timeout_secs);
            Ok(Vec::new())
        })
        .unwrap_or_else(|e| {
            warn!("resources/list failed: {}", e);
            Vec::new()
        })
    } else {
        Vec::new()
    };

    // 5. List resource templates (if capabilities.resources)
    let resource_templates = if init.capabilities.resources.is_some() {
        tokio::time::timeout(
            list_timeout,
            list_call_http(
                client,
                url,
                &session,
                "resources/templates/list",
                "resourceTemplates",
            ),
        )
        .await
        .unwrap_or_else(|_| {
            warn!("resources/templates/list timed out after {}s", timeout_secs);
            Ok(Vec::new())
        })
        .unwrap_or_else(|e| {
            warn!("resources/templates/list failed: {}", e);
            Vec::new()
        })
    } else {
        Vec::new()
    };

    // 6. List tools (if capabilities.tools)
    let tools_raw = if init.capabilities.tools.is_some() {
        tokio::time::timeout(
            list_timeout,
            list_call_http(client, url, &session, "tools/list", "tools"),
        )
        .await
        .unwrap_or_else(|_| {
            warn!("tools/list timed out after {}s", timeout_secs);
            Ok(Vec::new())
        })
        .unwrap_or_else(|e| {
            warn!("tools/list failed: {}", e);
            Vec::new()
        })
    } else {
        Vec::new()
    };

    let tools: Vec<Tool> = tools_raw
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();

    Ok(ServerSignature {
        metadata,
        prompts,
        resources,
        resource_templates,
        tools,
    })
}

/// Make a single list JSON-RPC call over HTTP and extract the named array.
async fn list_call_http(
    client: &reqwest::Client,
    url: &str,
    session: &McpSession,
    method: &str,
    result_key: &str,
) -> Result<Vec<serde_json::Value>, McpError> {
    let req = session.build_request(method, Some(serde_json::json!({})));
    let resp = http_rpc(client, url, &req).await?;
    let result = extract_result(resp)?;
    Ok(result
        .get(result_key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default())
}

// ---------------------------------------------------------------------------
// SSE transport helpers
// ---------------------------------------------------------------------------

/// Attempt SSE-based introspection:
/// 1. GET the SSE endpoint and look for an "endpoint" event providing the POST URL.
/// 2. POST JSON-RPC requests to that URL.
///
/// If endpoint discovery fails within a few seconds, we fall back to the raw URL.
async fn introspect_sse(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
) -> Result<ServerSignature, McpError> {
    // Try to discover the POST endpoint from the SSE stream
    let post_url = match discover_sse_endpoint(client, url, timeout_secs).await {
        Ok(endpoint) => {
            // The endpoint may be relative; resolve against base URL
            let base = Url::parse(url)?;
            let resolved = base.join(&endpoint)?;
            resolved.to_string()
        }
        Err(e) => {
            warn!(
                "SSE endpoint discovery failed ({}), falling back to raw URL",
                e
            );
            url.to_string()
        }
    };

    introspect_http(client, &post_url, timeout_secs).await
}

/// GET the SSE URL and parse events to find the endpoint URL.
/// Returns the endpoint path/URL from the first relevant SSE event.
fn extract_sse_endpoint_from_buffer(buffer: &mut String) -> Option<String> {
    let last_newline = buffer.rfind('\n')?;
    let mut endpoint: Option<String> = None;

    for raw_line in buffer[..=last_newline].lines() {
        let line = raw_line.trim_end_matches('\r').trim();
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if !data.is_empty() && (data.starts_with('/') || data.starts_with("http")) {
                endpoint = Some(data.to_string());
                break;
            }
        }
    }

    // Keep only the unterminated tail for the next chunk; this prevents
    // truncated `data:` lines from being treated as complete SSE events.
    *buffer = buffer[(last_newline + 1)..].to_string();
    endpoint
}

async fn discover_sse_endpoint(
    client: &reqwest::Client,
    url: &str,
    timeout_secs: u64,
) -> Result<String, McpError> {
    let mut resp = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs.min(10)),
        client.get(url).header("Accept", "text/event-stream").send(),
    )
    .await
    .map_err(|_| McpError::Timeout(timeout_secs))?
    .map_err(McpError::Http)?;

    if !resp.status().is_success() {
        return Err(McpError::Other(format!(
            "SSE endpoint returned HTTP {}",
            resp.status()
        )));
    }

    // Read the SSE stream incrementally (chunk by chunk) instead of waiting
    // for EOF, since SSE connections are typically long-lived.
    let sse_timeout = std::time::Duration::from_secs(timeout_secs.min(10));
    let result = tokio::time::timeout(sse_timeout, async {
        let mut buffer = String::new();

        while let Some(chunk) = resp.chunk().await.map_err(McpError::Http)? {
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            if let Some(endpoint) = extract_sse_endpoint_from_buffer(&mut buffer) {
                return Ok::<String, McpError>(endpoint);
            }
        }

        Err(McpError::Other(
            "no endpoint found in SSE stream".to_string(),
        ))
    })
    .await
    .map_err(|_| McpError::Timeout(timeout_secs.min(10)))?;

    result
}

// ---------------------------------------------------------------------------
// URL probing strategy for remote servers
// ---------------------------------------------------------------------------

/// Given an input URL, generate the three URL variants for probing.
fn url_variants(input: &str) -> (String, String, String) {
    let (url_with_sse, url_with_mcp, url_without_end) =
        if let Some(base) = input.strip_suffix("/sse") {
            (
                input.to_string(),
                format!("{}/mcp", base.trim_end_matches('/')),
                base.trim_end_matches('/').to_string(),
            )
        } else if let Some(base) = input.strip_suffix("/mcp") {
            (
                format!("{}/sse", base.trim_end_matches('/')),
                input.to_string(),
                base.trim_end_matches('/').to_string(),
            )
        } else {
            let base = input.trim_end_matches('/');
            (
                format!("{}/sse", base),
                format!("{}/mcp", base),
                base.to_string(),
            )
        };

    (url_with_sse, url_with_mcp, url_without_end)
}

/// The transport protocol to use for a probe attempt.
#[derive(Debug, Clone, Copy)]
enum ProbeProtocol {
    Http,
    Sse,
}

/// Build the ordered list of (protocol, url) pairs to try for remote server probing.
fn build_probe_strategy(server: &RemoteServer) -> Vec<(ProbeProtocol, String)> {
    let (url_with_sse, url_with_mcp, url_without_end) = url_variants(&server.url);

    let server_type = server.server_type.as_deref();

    if server_type == Some("sse") {
        // Prefer SSE
        vec![
            (ProbeProtocol::Sse, url_with_mcp.clone()),
            (ProbeProtocol::Sse, url_without_end.clone()),
            (ProbeProtocol::Http, url_with_mcp.clone()),
            (ProbeProtocol::Http, url_without_end.clone()),
            (ProbeProtocol::Sse, url_with_sse.clone()),
            (ProbeProtocol::Http, url_with_sse),
        ]
    } else {
        // Default: prefer streamable HTTP
        vec![
            (ProbeProtocol::Http, url_with_mcp.clone()),
            (ProbeProtocol::Http, url_without_end.clone()),
            (ProbeProtocol::Sse, url_with_mcp),
            (ProbeProtocol::Sse, url_without_end),
            (ProbeProtocol::Http, url_with_sse.clone()),
            (ProbeProtocol::Sse, url_with_sse),
        ]
    }
}

/// Introspect a remote server by trying multiple (protocol, url) combinations.
async fn introspect_remote(
    server: &RemoteServer,
    timeout_secs: u64,
) -> Result<ServerSignature, McpError> {
    let client = build_http_client(server)?;
    let strategy = build_probe_strategy(server);
    let mut errors: Vec<String> = Vec::new();

    for (proto, url) in &strategy {
        let result = match proto {
            ProbeProtocol::Http => introspect_http(&client, url, timeout_secs).await,
            ProbeProtocol::Sse => introspect_sse(&client, url, timeout_secs).await,
        };

        match result {
            Ok(sig) => return Ok(sig),
            Err(e) => {
                let msg = format!("{:?} {} -> {}", proto, url, e);
                warn!("probe failed: {}", msg);
                errors.push(msg);
            }
        }
    }

    Err(McpError::AllAttemptsFailed { errors })
}

// ---------------------------------------------------------------------------
// Static tools (synthetic signature)
// ---------------------------------------------------------------------------

/// Build a synthetic `ServerSignature` for a `StaticToolsServer` without network I/O.
fn introspect_static_tools(server: &StaticToolsServer) -> ServerSignature {
    ServerSignature {
        metadata: serde_json::json!({
            "protocolVersion": "built-in",
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": server.name,
                "version": "built-in"
            },
            "instructions": ""
        }),
        prompts: Vec::new(),
        resources: Vec::new(),
        resource_templates: Vec::new(),
        tools: server.signature.clone(),
    }
}

// ---------------------------------------------------------------------------
// Main entry points
// ---------------------------------------------------------------------------

/// Introspect a single MCP server to discover its tools, prompts, resources,
/// and resource templates.
///
/// Based on server type:
/// - **Stdio**: spawns the process, runs introspection, kills process
/// - **Http/Sse (Remote)**: uses URL probing strategy with multiple attempts
/// - **Tools (Static)**: returns synthetic `ServerSignature` with protocolVersion "built-in"
/// - **Skill**: returns an error (skills are handled by the skills module)
pub async fn introspect_server(
    config: &ServerConfig,
    timeout_secs: u64,
) -> Result<ServerSignature, McpError> {
    match config {
        ServerConfig::Stdio(server) => introspect_stdio(server, timeout_secs).await,
        ServerConfig::Sse(server) | ServerConfig::Http(server) => {
            introspect_remote(server, timeout_secs).await
        }
        ServerConfig::Tools(server) => Ok(introspect_static_tools(server)),
        ServerConfig::Skill(SkillServer { path, .. }) => Err(McpError::Other(format!(
            "skill servers are handled by the skills module: {}",
            path
        ))),
    }
}

/// Parse an MCP config file and extract the server configurations.
///
/// Supports multiple config file formats:
/// 1. `ClaudeCodeConfigFile` - `{ "projects": { "~": { "mcpServers": { ... } } } }`
/// 2. `ClaudeConfigFile` - `{ "mcpServers": { "name": { ... } } }`
/// 3. `VSCodeConfigFile` - `{ "mcp": { "servers": { ... } } }`
/// 4. `VSCodeMCPConfig` - `{ "servers": { ... } }`
///
/// Uses json5 for parsing (handles comments, trailing commas).
/// Returns an empty HashMap if the format is unrecognized.
pub fn parse_mcp_config(path: &std::path::Path) -> Result<HashMap<String, ServerConfig>, McpError> {
    let content = std::fs::read_to_string(path).map_err(McpError::Io)?;

    // Handle empty files
    let content = content.trim();
    if content.is_empty() {
        return Ok(HashMap::new());
    }

    // Parse with json5 (handles comments, trailing commas, JSONC)
    let value: serde_json::Value =
        json5::from_str(content).map_err(|e| McpError::ConfigParse(e.to_string()))?;

    // Try config formats in priority order, using discriminating keys to
    // avoid false positives from serde(default) fields.
    let obj = value.as_object();

    // 1. ClaudeCodeConfigFile: must have "projects" key
    if obj.is_some_and(|o| o.contains_key("projects")) {
        return serde_json::from_value::<ClaudeCodeConfigFile>(value.clone())
            .map(|config| config.get_servers())
            .map_err(|e| McpError::ConfigParse(format!("invalid Claude Code MCP config: {e}")));
    }

    // 2. ClaudeConfigFile: must have "mcpServers" key
    if obj.is_some_and(|o| o.contains_key("mcpServers")) {
        return serde_json::from_value::<ClaudeConfigFile>(value.clone())
            .map(|config| config.get_servers())
            .map_err(|e| McpError::ConfigParse(format!("invalid Claude MCP config: {e}")));
    }

    // 3. VSCodeConfigFile: must have "mcp" key
    if obj.is_some_and(|o| o.contains_key("mcp")) {
        return serde_json::from_value::<VSCodeConfigFile>(value.clone())
            .map(|config| config.get_servers())
            .map_err(|e| McpError::ConfigParse(format!("invalid VS Code MCP config: {e}")));
    }

    // 4. VSCodeMCPConfig: must have "servers" key
    if obj.is_some_and(|o| o.contains_key("servers")) {
        return serde_json::from_value::<VSCodeMCPConfig>(value)
            .map(|config| config.get_servers())
            .map_err(|e| McpError::ConfigParse(format!("invalid VS Code mcp.json config: {e}")));
    }

    // 5. Unrecognized format - return empty map
    Ok(HashMap::new())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn read_http_request(
        stream: &mut tokio::net::TcpStream,
    ) -> Option<(String, String, Vec<u8>)> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        let mut header_end = None;
        while header_end.is_none() {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
            header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
            if buf.len() > 64 * 1024 {
                return None;
            }
        }

        let header_end = header_end?;
        let head = std::str::from_utf8(&buf[..header_end]).ok()?;
        let mut lines = head.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();

        let mut content_len = 0usize;
        for line in lines {
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_len = v.trim().parse().ok()?;
            }
        }

        let mut body = buf[header_end..].to_vec();
        while body.len() < content_len {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(content_len);

        Some((method, path, body))
    }

    async fn write_http_response(
        stream: &mut tokio::net::TcpStream,
        status: &str,
        content_type: &str,
        body: &[u8],
    ) {
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.shutdown().await;
    }

    async fn spawn_mock_mcp_server(max_requests: usize) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut served = 0usize;
            while served < max_requests {
                let accept =
                    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                        .await;
                let (mut stream, _) = match accept {
                    Ok(Ok(pair)) => pair,
                    _ => break,
                };
                served += 1;

                let Some((method, path, body)) = read_http_request(&mut stream).await else {
                    continue;
                };

                match (method.as_str(), path.as_str()) {
                    ("GET", "/sse") => {
                        let sse = b"event: endpoint\ndata: /mcp\n\n";
                        write_http_response(&mut stream, "200 OK", "text/event-stream", sse).await;
                    }
                    ("POST", "/mcp") => {
                        let req: serde_json::Value =
                            serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!({}));
                        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                        let id = req.get("id").cloned();

                        let resp = match method {
                            "initialize" => serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id.unwrap_or(serde_json::json!(1)),
                                "result": {
                                    "capabilities": { "tools": {} },
                                    "serverInfo": { "name": "mock-mcp", "version": "1.0.0" }
                                }
                            }),
                            "tools/list" => serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id.unwrap_or(serde_json::json!(1)),
                                "result": {
                                    "tools": [
                                        { "name": "ping", "description": "health check", "inputSchema": { "type": "object" } }
                                    ]
                                }
                            }),
                            _ => serde_json::json!({ "ok": true }),
                        };
                        let bytes = serde_json::to_vec(&resp).unwrap();
                        write_http_response(&mut stream, "200 OK", "application/json", &bytes)
                            .await;
                    }
                    _ => {
                        write_http_response(
                            &mut stream,
                            "404 Not Found",
                            "text/plain",
                            b"not found",
                        )
                        .await;
                    }
                }
            }
        });

        (format!("http://{addr}"), handle)
    }

    #[test]
    fn test_url_variants_plain() {
        let (sse, mcp, bare) = url_variants("https://example.com/api");
        assert_eq!(sse, "https://example.com/api/sse");
        assert_eq!(mcp, "https://example.com/api/mcp");
        assert_eq!(bare, "https://example.com/api");
    }

    #[test]
    fn test_url_variants_ends_with_sse() {
        let (sse, mcp, bare) = url_variants("https://example.com/api/sse");
        assert_eq!(sse, "https://example.com/api/sse");
        assert_eq!(mcp, "https://example.com/api/mcp");
        assert_eq!(bare, "https://example.com/api");
    }

    #[test]
    fn test_url_variants_ends_with_mcp() {
        let (sse, mcp, bare) = url_variants("https://example.com/api/mcp");
        assert_eq!(sse, "https://example.com/api/sse");
        assert_eq!(mcp, "https://example.com/api/mcp");
        assert_eq!(bare, "https://example.com/api");
    }

    #[test]
    fn test_probe_strategy_http_default() {
        let server = RemoteServer {
            url: "https://example.com/api".to_string(),
            server_type: None,
            headers: HashMap::new(),
        };
        let strategy = build_probe_strategy(&server);
        assert_eq!(strategy.len(), 6);
        // First attempt should be Http + url_with_mcp
        assert!(matches!(strategy[0].0, ProbeProtocol::Http));
        assert!(strategy[0].1.ends_with("/mcp"));
    }

    #[test]
    fn test_probe_strategy_sse_type() {
        let server = RemoteServer {
            url: "https://example.com/api".to_string(),
            server_type: Some("sse".to_string()),
            headers: HashMap::new(),
        };
        let strategy = build_probe_strategy(&server);
        assert_eq!(strategy.len(), 6);
        // First attempt should be Sse + url_with_mcp
        assert!(matches!(strategy[0].0, ProbeProtocol::Sse));
        assert!(strategy[0].1.ends_with("/mcp"));
    }

    #[test]
    fn test_build_http_client_invalid_header_name() {
        let mut headers = HashMap::new();
        headers.insert("bad header".to_string(), "value".to_string());
        let server = RemoteServer {
            url: "https://example.com/mcp".to_string(),
            server_type: Some("http".to_string()),
            headers,
        };
        let err = build_http_client(&server).unwrap_err();
        assert!(matches!(err, McpError::Other(_)));
    }

    #[test]
    fn test_extract_result_success() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: Some(serde_json::json!({"tools": []})),
            error: None,
        };
        let result = extract_result(resp).unwrap();
        assert!(result.get("tools").is_some());
    }

    #[test]
    fn test_extract_result_error() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: "Method not found".to_string(),
            }),
        };
        let err = extract_result(resp).unwrap_err();
        assert!(matches!(err, McpError::JsonRpc { code: -32601, .. }));
    }

    #[test]
    fn test_extract_result_null_when_missing() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: None,
            error: None,
        };
        let result = extract_result(resp).unwrap();
        assert!(result.is_null());
    }

    #[test]
    fn test_is_response_for_request_accepts_matching_id() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(7),
            result: Some(serde_json::json!({"ok": true})),
            error: None,
        };
        assert!(is_response_for_request(&resp, Some(7)));
    }

    #[test]
    fn test_is_response_for_request_rejects_notification_without_id() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: None,
            result: Some(serde_json::json!({"progress": 1})),
            error: None,
        };
        assert!(!is_response_for_request(&resp, Some(1)));
    }

    #[test]
    fn test_is_response_for_request_rejects_wrong_id() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(2),
            result: Some(serde_json::json!({"ok": true})),
            error: None,
        };
        assert!(!is_response_for_request(&resp, Some(1)));
    }

    #[test]
    fn test_session_id_increment() {
        let session = McpSession::new();
        assert_eq!(session.next_id(), 1);
        assert_eq!(session.next_id(), 2);
        assert_eq!(session.next_id(), 3);
    }

    #[test]
    fn test_build_request() {
        let session = McpSession::new();
        let req = session.build_request("tools/list", Some(serde_json::json!({})));
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, 1);
        assert_eq!(req.method, "tools/list");
    }

    #[test]
    fn test_build_notification() {
        let notif = McpSession::build_notification("notifications/initialized");
        assert_eq!(notif.jsonrpc, "2.0");
        assert_eq!(notif.method, "notifications/initialized");
    }

    #[test]
    fn test_static_tools_signature() {
        let server = StaticToolsServer {
            name: "test-tools".to_string(),
            signature: vec![],
            server_type: Some("tools".to_string()),
        };
        let sig = introspect_static_tools(&server);
        assert_eq!(sig.metadata["protocolVersion"], "built-in");
        assert_eq!(sig.metadata["serverInfo"]["name"], "test-tools");
        assert!(sig.tools.is_empty());
        assert!(sig.prompts.is_empty());
    }

    #[test]
    fn test_static_tools_signature_with_tools() {
        let server = StaticToolsServer {
            name: "cursor built-in".to_string(),
            signature: vec![
                Tool {
                    name: "Read File".to_string(),
                    description: Some("Read a file".to_string()),
                    input_schema: None,
                },
                Tool {
                    name: "Write File".to_string(),
                    description: Some("Write a file".to_string()),
                    input_schema: None,
                },
            ],
            server_type: Some("tools".to_string()),
        };
        let sig = introspect_static_tools(&server);
        assert_eq!(sig.tools.len(), 2);
        assert_eq!(sig.tools[0].name, "Read File");
        assert_eq!(sig.tools[1].name, "Write File");
    }

    #[test]
    fn test_json_rpc_request_serialization() {
        let session = McpSession::new();
        let req = session.build_request("tools/list", Some(serde_json::json!({"cursor": null})));
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "tools/list");
        assert_eq!(json["id"], 1);
        assert!(json["params"].is_object());
    }

    #[test]
    fn test_json_rpc_request_no_params() {
        let session = McpSession::new();
        let req = session.build_request("ping", None);
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("params").is_none());
    }

    #[test]
    fn test_json_rpc_notification_serialization() {
        let notif = McpSession::build_notification("notifications/initialized");
        let json = serde_json::to_value(&notif).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "notifications/initialized");
        assert!(json.get("id").is_none());
    }

    #[test]
    fn test_parse_mcp_config_claude_format() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("mcp.json");
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "test-server": {
                        "command": "node",
                        "args": ["server.js"]
                    }
                }
            }"#,
        )
        .unwrap();

        let servers = parse_mcp_config(&path).unwrap();
        assert!(servers.contains_key("test-server"));
    }

    #[test]
    fn test_parse_mcp_config_vscode_format() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
                "mcp": {
                    "inputs": [],
                    "servers": {
                        "vsc-server": {
                            "type": "stdio",
                            "command": "python",
                            "args": ["server.py"]
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let servers = parse_mcp_config(&path).unwrap();
        assert!(servers.contains_key("vsc-server"));
    }

    #[test]
    fn test_parse_mcp_config_empty_file() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();

        let servers = parse_mcp_config(&path).unwrap();
        assert!(servers.is_empty());
    }

    #[test]
    fn test_parse_mcp_config_missing_file() {
        let path = std::path::Path::new("/nonexistent/path/abc123.json");
        let result = parse_mcp_config(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mcp_config_malformed_claude_schema_returns_error() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("bad-mcp.json");
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "broken": {
                        "command": 42
                    }
                }
            }"#,
        )
        .unwrap();

        let result = parse_mcp_config(&path);
        match result {
            Err(McpError::ConfigParse(msg)) => assert!(msg.contains("invalid Claude MCP config")),
            other => panic!("expected config parse error, got: {other:?}"),
        }
    }

    #[test]
    fn test_url_variants_trailing_slash() {
        let (sse, mcp, bare) = url_variants("https://example.com/api/");
        assert_eq!(sse, "https://example.com/api/sse");
        assert_eq!(mcp, "https://example.com/api/mcp");
        assert_eq!(bare, "https://example.com/api");
    }

    #[test]
    fn test_mcp_error_display() {
        let err = McpError::Timeout(30);
        assert_eq!(err.to_string(), "Timeout after 30s");

        let err = McpError::JsonRpc {
            code: -32601,
            message: "Method not found".into(),
        };
        assert!(err.to_string().contains("-32601"));
        assert!(err.to_string().contains("Method not found"));
    }

    #[tokio::test]
    async fn test_introspect_static_tools_server() {
        use crate::models::{ServerConfig, StaticToolsServer, Tool};

        let config = ServerConfig::Tools(StaticToolsServer {
            name: "test-builtin".to_string(),
            signature: vec![Tool {
                name: "read_file".to_string(),
                description: Some("Read a file".to_string()),
                input_schema: Some(serde_json::json!({"type": "object"})),
            }],
            server_type: None,
        });

        let sig = introspect_server(&config, 5).await.unwrap();
        assert_eq!(sig.tools.len(), 1);
        assert_eq!(sig.tools[0].name, "read_file");
        assert!(sig.prompts.is_empty());
        assert!(sig.resources.is_empty());
        assert!(sig.resource_templates.is_empty());
        let info = sig.metadata.get("serverInfo").unwrap();
        assert_eq!(info["name"], "test-builtin");
        assert_eq!(info["version"], "built-in");
    }

    #[tokio::test]
    async fn test_introspect_skill_server_errors() {
        use crate::models::{ServerConfig, SkillServer};

        let config = ServerConfig::Skill(SkillServer {
            path: "/some/path".to_string(),
            server_type: None,
        });

        let err = introspect_server(&config, 5).await.unwrap_err();
        assert!(matches!(err, McpError::Other(_)));
    }

    #[tokio::test]
    async fn test_discover_sse_endpoint_parses_event_data() {
        let (base, handle) = spawn_mock_mcp_server(1).await;
        let client = reqwest::Client::new();
        let endpoint = discover_sse_endpoint(&client, &format!("{base}/sse"), 3)
            .await
            .unwrap();
        assert_eq!(endpoint, "/mcp");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    #[test]
    fn test_extract_sse_endpoint_from_buffer_waits_for_complete_line() {
        let mut buffer = "event: endpoint\ndata: /mc".to_string();
        assert_eq!(extract_sse_endpoint_from_buffer(&mut buffer), None);
        assert_eq!(buffer, "data: /mc");

        buffer.push_str("p\n\n");
        assert_eq!(
            extract_sse_endpoint_from_buffer(&mut buffer),
            Some("/mcp".to_string())
        );
        assert!(buffer.is_empty());
    }

    #[tokio::test]
    async fn test_introspect_server_sse_end_to_end() {
        let (base, handle) = spawn_mock_mcp_server(6).await;
        let cfg = ServerConfig::Sse(RemoteServer {
            url: format!("{base}/sse"),
            server_type: Some("sse".to_string()),
            headers: HashMap::new(),
        });

        let sig = introspect_server(&cfg, 3).await.unwrap();
        assert_eq!(sig.tools.len(), 1);
        assert_eq!(sig.tools[0].name, "ping");
        assert_eq!(sig.metadata["serverInfo"]["name"], "mock-mcp");

        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
}

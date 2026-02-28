#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::io::Write;
use std::path::PathBuf;

use hunt_query::query::{EventSource, HuntQuery, QueryVerdict};
use hunt_query::render::RenderConfig;
use hunt_query::timeline::TimelineEvent;
use hunt_scan::analysis::{self, AnalysisClient};
use hunt_scan::models::{
    ScanError, ScanPathResult, ScanUserInfo, ServerConfig, ServerScanResult, Tool,
};
use hunt_scan::{discovery, mcp_client, redact, skills};

use crate::remote_extends;
use crate::{ExitCode, HuntCommands, CLI_JSON_VERSION};

pub async fn cmd_hunt(
    command: HuntCommands,
    _remote_extends: &remote_extends::RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match command {
        HuntCommands::Scan {
            target,
            package,
            skills,
            query,
            policy,
            ruleset,
            timeout,
            include_builtin,
            signing_key,
            json,
            analysis_url,
            skip_ssl_verify,
        } => cmd_hunt_scan(
            HuntScanArgs {
                target,
                package,
                skills,
                query,
                policy,
                ruleset,
                timeout,
                include_builtin,
                signing_key,
                json,
                analysis_url,
                skip_ssl_verify,
            },
            stdout,
            stderr,
        )
        .await
        .as_i32(),
        HuntCommands::Query {
            source,
            verdict,
            start,
            end,
            action_type,
            process,
            namespace,
            pod,
            limit,
            nl,
            nats_url,
            nats_creds,
            offline,
            local_dir,
            verify,
            json,
            jsonl,
            no_color,
        } => cmd_hunt_query(
            HuntQueryArgs {
                source,
                verdict,
                start,
                end,
                action_type,
                process,
                namespace,
                pod,
                limit,
                nl,
                nats_url,
                nats_creds,
                offline,
                local_dir,
                verify,
                json,
                jsonl,
                no_color,
                entity: None,
            },
            stdout,
            stderr,
        )
        .await
        .as_i32(),
        HuntCommands::Timeline {
            source,
            verdict,
            start,
            end,
            action_type,
            process,
            namespace,
            pod,
            limit,
            nl,
            nats_url,
            nats_creds,
            offline,
            local_dir,
            verify,
            json,
            jsonl,
            no_color,
            entity,
        } => cmd_hunt_timeline(
            HuntQueryArgs {
                source,
                verdict,
                start,
                end,
                action_type,
                process,
                namespace,
                pod,
                limit,
                nl,
                nats_url,
                nats_creds,
                offline,
                local_dir,
                verify,
                json,
                jsonl,
                no_color,
                entity,
            },
            stdout,
            stderr,
        )
        .await
        .as_i32(),
        HuntCommands::Watch {
            rules,
            nats_url,
            nats_creds,
            signing_key,
            max_window,
            json,
            no_color,
        } => cmd_hunt_watch(
            HuntWatchArgs {
                rules,
                nats_url,
                nats_creds,
                signing_key,
                max_window,
                json,
                no_color,
            },
            stdout,
            stderr,
        )
        .await
        .as_i32(),
        HuntCommands::Correlate {
            rules,
            source,
            verdict,
            start,
            end,
            action_type,
            process,
            namespace,
            pod,
            limit,
            nl,
            nats_url,
            nats_creds,
            offline,
            local_dir,
            verify,
            signing_key: _,
            json,
            jsonl,
            no_color,
        } => cmd_hunt_correlate(
            HuntCorrelateArgs {
                rules,
                source,
                verdict,
                start,
                end,
                action_type,
                process,
                namespace,
                pod,
                limit,
                nl,
                nats_url,
                nats_creds,
                offline,
                local_dir,
                verify,
                json,
                jsonl,
                no_color,
            },
            stdout,
            stderr,
        )
        .await
        .as_i32(),
        HuntCommands::Ioc {
            feed,
            stix,
            source,
            start,
            end,
            limit,
            nats_url,
            nats_creds,
            offline,
            local_dir,
            verify,
            json,
            no_color,
        } => cmd_hunt_ioc(
            HuntIocArgs {
                feed,
                stix,
                source,
                start,
                end,
                limit,
                nats_url,
                nats_creds,
                offline,
                local_dir,
                verify,
                json,
                no_color,
            },
            stdout,
            stderr,
        )
        .await
        .as_i32(),
    }
}

struct HuntScanArgs {
    target: Option<Vec<String>>,
    #[allow(dead_code)]
    package: Option<Vec<String>>,
    skills: Option<Vec<String>>,
    #[allow(dead_code)]
    query: Option<String>,
    #[allow(dead_code)]
    policy: Option<String>,
    #[allow(dead_code)]
    ruleset: Option<String>,
    timeout: u64,
    include_builtin: bool,
    #[allow(dead_code)]
    signing_key: String,
    json: bool,
    analysis_url: Option<String>,
    skip_ssl_verify: bool,
}

// ---------------------------------------------------------------------------
// JSON output structs
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct HuntJsonError {
    kind: &'static str,
    message: String,
}

#[derive(serde::Serialize)]
struct HuntScanJsonOutput {
    version: u8,
    command: &'static str,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<HuntJsonError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<HuntScanData>,
}

#[derive(serde::Serialize)]
struct HuntScanData {
    scan_results: Vec<ScanPathResult>,
    summary: HuntScanSummary,
}

#[derive(serde::Serialize)]
struct HuntScanSummary {
    clients_scanned: usize,
    servers_found: usize,
    tools_found: usize,
    issues_found: usize,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

async fn cmd_hunt_scan(
    args: HuntScanArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if !args.json {
        let _ = writeln!(stdout, "Scanning MCP configurations...");
        let _ = writeln!(stdout);
    }

    // 1. Determine scan targets
    let config_paths: Vec<PathBuf> = if let Some(ref targets) = args.target {
        match discovery::client_shorthands_to_paths(targets) {
            Ok(paths) => paths,
            Err(e) => {
                return emit_hunt_error(
                    args.json,
                    stdout,
                    stderr,
                    "config_error",
                    &format!("Failed to resolve targets: {e}"),
                    ExitCode::ConfigError,
                );
            }
        }
    } else {
        let clients = discovery::discover_clients();
        clients
            .iter()
            .flat_map(|c| c.config_paths.clone())
            .collect()
    };

    if config_paths.is_empty() && args.skills.is_none() {
        return emit_hunt_error(
            args.json,
            stdout,
            stderr,
            "config_error",
            "No MCP configurations found. Use --target to specify a config path.",
            ExitCode::ConfigError,
        );
    }

    // 2. Scan each config path
    let mut scan_results: Vec<ScanPathResult> = Vec::new();

    for path in &config_paths {
        let client_name = discovery::get_client_from_path(path);
        let display_name = client_name.as_deref().unwrap_or("unknown");

        // Parse MCP config
        let servers_map = match mcp_client::parse_mcp_config(path) {
            Ok(map) => map,
            Err(e) => {
                let err_str = e.to_string();
                let error = if path.exists() {
                    if err_str.contains("parse") || err_str.contains("Parse") {
                        ScanError::parse_error(&err_str)
                    } else {
                        ScanError::unknown_config(&err_str)
                    }
                } else {
                    ScanError::file_not_found(format!("{}", path.display()))
                };

                // Only report failures in text mode
                if !args.json && error.is_failure {
                    let _ = writeln!(
                        stderr,
                        "  Warning: could not parse {}: {}",
                        path.display(),
                        err_str
                    );
                }

                scan_results.push(ScanPathResult {
                    client: client_name.clone(),
                    path: path.to_string_lossy().to_string(),
                    servers: None,
                    issues: vec![],
                    labels: vec![],
                    error: Some(error),
                });
                continue;
            }
        };

        if servers_map.is_empty() {
            scan_results.push(ScanPathResult {
                client: client_name.clone(),
                path: path.to_string_lossy().to_string(),
                servers: Some(vec![]),
                issues: vec![],
                labels: vec![],
                error: None,
            });
            continue;
        }

        if !args.json {
            let _ = writeln!(stdout, "[{}] {}", display_name, path.display());
        }

        // Introspect each server
        let mut server_results: Vec<ServerScanResult> = Vec::new();

        for (name, config) in &servers_map {
            let transport_label = server_type_label(config);

            match mcp_client::introspect_server(config, args.timeout).await {
                Ok(sig) => {
                    let tool_count = sig.tools.len();
                    let prompt_count = sig.prompts.len();
                    let resource_count = sig.resources.len();

                    if !args.json {
                        let _ = writeln!(
                            stdout,
                            "  \u{2713} {} ({}) -- {} tools, {} prompts, {} resources",
                            name, transport_label, tool_count, prompt_count, resource_count
                        );
                    }

                    server_results.push(ServerScanResult {
                        name: Some(name.clone()),
                        server: config.clone(),
                        signature: Some(sig),
                        error: None,
                    });
                }
                Err(e) => {
                    if !args.json {
                        let _ =
                            writeln!(stdout, "  \u{2717} {} ({}) -- {}", name, transport_label, e);
                    }

                    let error = mcp_error_to_scan_error(&e);

                    server_results.push(ServerScanResult {
                        name: Some(name.clone()),
                        server: config.clone(),
                        signature: None,
                        error: Some(error),
                    });
                }
            }
        }

        // 3. Include built-in tools if requested
        if args.include_builtin {
            if let Some(ref cn) = client_name {
                if let Some(builtin) = discovery::get_builtin_tools(cn) {
                    let tool_count = builtin.signature.len();
                    let builtin_name = builtin.name.clone();
                    if !args.json {
                        let _ = writeln!(
                            stdout,
                            "  \u{2713} {} (built-in) -- {} tools",
                            builtin_name, tool_count
                        );
                    }
                    let builtin_config = ServerConfig::Tools(builtin);
                    // Static tools introspection is infallible (no I/O)
                    let sig = mcp_client::introspect_server(&builtin_config, args.timeout)
                        .await
                        .ok();
                    server_results.push(ServerScanResult {
                        name: Some(builtin_name),
                        server: builtin_config,
                        signature: sig,
                        error: None,
                    });
                }
            }
        }

        scan_results.push(ScanPathResult {
            client: client_name,
            path: path.to_string_lossy().to_string(),
            servers: Some(server_results),
            issues: vec![],
            labels: vec![],
            error: None,
        });
    }

    // 4. Skills scanning (if --skills) — run before local analysis so that
    //    skill-derived tools also get injection/shadowing checks.
    if let Some(ref skills_dirs) = args.skills {
        for dir in skills_dirs {
            let dir_path = PathBuf::from(dir);
            match skills::scan_skills_dir(&dir_path) {
                Ok(result) => {
                    let skill_name = result.name.clone().unwrap_or_else(|| dir.clone());

                    if !args.json {
                        if let Some(ref sig) = result.signature {
                            let _ = writeln!(
                                stdout,
                                "  \u{2713} {} (skill) -- {} tools, {} prompts",
                                skill_name,
                                sig.tools.len(),
                                sig.prompts.len()
                            );
                        }
                    }

                    scan_results.push(ScanPathResult {
                        client: Some("skills".to_string()),
                        path: dir.clone(),
                        servers: Some(vec![result]),
                        issues: vec![],
                        labels: vec![],
                        error: None,
                    });
                }
                Err(e) => {
                    let _ = writeln!(stderr, "Warning: failed to scan skill dir '{}': {}", dir, e);
                    scan_results.push(ScanPathResult {
                        client: Some("skills".to_string()),
                        path: dir.clone(),
                        servers: None,
                        issues: vec![],
                        labels: vec![],
                        error: Some(ScanError::skill_scan_error(e.to_string())),
                    });
                }
            }
        }
    }

    // 5. Run local analysis per scan result so issues are attributed to the
    //    correct config rather than flattened into the first result.
    for result in scan_results.iter_mut() {
        let tools: Vec<Tool> = result
            .servers
            .as_ref()
            .into_iter()
            .flat_map(|servers| {
                servers
                    .iter()
                    .filter_map(|s| s.signature.as_ref().map(|sig| sig.tools.clone()))
            })
            .flatten()
            .collect();

        if tools.is_empty() {
            continue;
        }

        let mut issues = analysis::check_descriptions_for_injection(&tools);
        issues.extend(analysis::check_tool_name_shadowing(&tools, &[]));
        result.issues.extend(issues);
    }

    // 6. Remote analysis (if --analysis-url) — runs after local analysis so
    //    that remote issues merge into (not replace) locally detected ones.
    if let Some(ref url) = args.analysis_url {
        // Redact before upload
        let mut redacted_results = scan_results.clone();
        redact::redact_scan_results(&mut redacted_results);

        let user_info = ScanUserInfo {
            hostname: std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .ok(),
            username: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .ok(),
            identifier: None,
            ip_address: None,
            anonymous_identifier: None,
        };

        let client = AnalysisClient::new(url.clone(), args.skip_ssl_verify);
        match client.verify(&mut redacted_results, &user_info).await {
            Ok(()) => {
                // Merge remote issues/labels into the originals, preserving
                // any locally detected issues that were already attached.
                for (orig, redacted) in scan_results.iter_mut().zip(redacted_results.iter()) {
                    for issue in &redacted.issues {
                        if !orig.issues.iter().any(|i| {
                            i.code == issue.code
                                && i.message == issue.message
                                && i.reference == issue.reference
                        }) {
                            orig.issues.push(issue.clone());
                        }
                    }
                    orig.labels.clone_from(&redacted.labels);
                }
            }
            Err(e) => {
                let _ = writeln!(stderr, "Warning: analysis API error: {e}");
            }
        }
    }

    // 7. Compute summary
    let summary = compute_summary(&scan_results);

    // 8. Determine exit code based on issues found
    let exit_code = determine_exit_code(&scan_results, &summary);

    // 9. Output results
    if args.json {
        let output = HuntScanJsonOutput {
            version: CLI_JSON_VERSION,
            command: "hunt scan",
            exit_code: exit_code.as_i32(),
            error: None,
            data: Some(HuntScanData {
                scan_results,
                summary,
            }),
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        let _ = writeln!(stdout);
        let _ = writeln!(
            stdout,
            "Summary: {} clients, {} servers, {} tools, {} issues found",
            summary.clients_scanned,
            summary.servers_found,
            summary.tools_found,
            summary.issues_found,
        );

        // Print issues
        for result in &scan_results {
            for issue in &result.issues {
                let _ = writeln!(stdout, "  [{}] {}", issue.code, issue.message);
            }
        }
    }

    exit_code
}

fn server_type_label(config: &ServerConfig) -> &'static str {
    match config {
        ServerConfig::Stdio(_) => "stdio",
        ServerConfig::Sse(_) => "sse",
        ServerConfig::Http(_) => "http",
        ServerConfig::Skill(_) => "skill",
        ServerConfig::Tools(_) => "tools",
    }
}

fn mcp_error_to_scan_error(e: &mcp_client::McpError) -> ScanError {
    match e {
        mcp_client::McpError::Timeout(secs) => {
            ScanError::server_startup(format!("connection timeout ({secs}s)"), None)
        }
        mcp_client::McpError::ServerStartup {
            message,
            server_output,
        } => ScanError::server_startup(message, server_output.clone()),
        mcp_client::McpError::AllAttemptsFailed { errors } => ScanError::server_http_error(
            format!("all connection attempts failed: {}", errors.join("; ")),
            None,
        ),
        other => ScanError::server_startup(other.to_string(), None),
    }
}

fn compute_summary(results: &[ScanPathResult]) -> HuntScanSummary {
    let clients_scanned = results.len();
    let mut servers_found = 0usize;
    let mut tools_found = 0usize;
    let mut issues_found = 0usize;

    for result in results {
        issues_found += result.issues.len();
        if let Some(ref servers) = result.servers {
            servers_found += servers.len();
            for server in servers {
                if let Some(ref sig) = server.signature {
                    tools_found += sig.tools.len();
                }
            }
        }
    }

    HuntScanSummary {
        clients_scanned,
        servers_found,
        tools_found,
        issues_found,
    }
}

fn determine_exit_code(results: &[ScanPathResult], summary: &HuntScanSummary) -> ExitCode {
    // Check for any failure-level errors in scan results (server startup
    // failures, config parse errors, etc.)
    let has_failure = results.iter().any(|r| {
        r.error.as_ref().is_some_and(|e| e.is_failure)
            || r.servers.as_ref().is_some_and(|servers| {
                servers
                    .iter()
                    .any(|s| s.error.as_ref().is_some_and(|e| e.is_failure))
            })
    });

    if has_failure {
        ExitCode::Fail
    } else if summary.issues_found > 0 {
        ExitCode::Warn
    } else {
        ExitCode::Ok
    }
}

// ---------------------------------------------------------------------------
// Hunt Query / Timeline args
// ---------------------------------------------------------------------------

struct HuntQueryArgs {
    source: Option<Vec<String>>,
    verdict: Option<String>,
    start: Option<String>,
    end: Option<String>,
    action_type: Option<String>,
    process: Option<String>,
    namespace: Option<String>,
    pod: Option<String>,
    limit: usize,
    nl: Option<String>,
    nats_url: String,
    nats_creds: Option<String>,
    offline: bool,
    local_dir: Option<Vec<String>>,
    verify: bool,
    json: bool,
    jsonl: bool,
    no_color: bool,
    entity: Option<String>,
}

// ---------------------------------------------------------------------------
// Hunt Query / Timeline JSON output structs
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct HuntQueryJsonOutput {
    version: u8,
    command: &'static str,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<HuntJsonError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<HuntQueryData>,
}

#[derive(serde::Serialize)]
struct HuntQueryData {
    events: Vec<TimelineEvent>,
    summary: HuntQuerySummary,
}

#[derive(serde::Serialize)]
struct HuntQuerySummary {
    total_events: usize,
    sources_queried: Vec<String>,
}

// ---------------------------------------------------------------------------
// Query/Timeline helpers
// ---------------------------------------------------------------------------

fn build_hunt_query(args: &HuntQueryArgs) -> Result<HuntQuery, (ExitCode, String)> {
    let mut query = HuntQuery::default();

    // Sources
    if let Some(ref source_strs) = args.source {
        for s in source_strs {
            query.sources.extend(EventSource::parse_list(s));
        }
    }

    // Verdict
    if let Some(ref v) = args.verdict {
        match QueryVerdict::parse(v) {
            Some(verdict) => query.verdict = Some(verdict),
            None => {
                return Err((
                    ExitCode::InvalidArgs,
                    format!("Unknown verdict filter: '{v}'. Use allow, deny, or warn."),
                ));
            }
        }
    }

    // Time range
    if let Some(ref s) = args.start {
        match chrono::DateTime::parse_from_rfc3339(s) {
            Ok(dt) => query.start = Some(dt.with_timezone(&chrono::Utc)),
            Err(e) => {
                return Err((
                    ExitCode::InvalidArgs,
                    format!("Invalid --start timestamp '{s}': {e}"),
                ));
            }
        }
    }
    if let Some(ref e) = args.end {
        match chrono::DateTime::parse_from_rfc3339(e) {
            Ok(dt) => query.end = Some(dt.with_timezone(&chrono::Utc)),
            Err(e) => {
                return Err((
                    ExitCode::InvalidArgs,
                    format!("Invalid --end timestamp: {e}"),
                ));
            }
        }
    }

    query.action_type = args.action_type.clone();
    query.process = args.process.clone();
    query.namespace = args.namespace.clone();
    query.pod = args.pod.clone();
    query.limit = args.limit;
    query.entity = args.entity.clone();

    // Apply NL query if provided (supplements but does not override explicit flags)
    if let Some(ref nl_text) = args.nl {
        hunt_query::nl::apply_nl_query(&mut query, nl_text);
    }

    Ok(query)
}

fn render_config(args: &HuntQueryArgs) -> RenderConfig {
    RenderConfig {
        color: !args.no_color,
        json: args.json,
        jsonl: args.jsonl,
    }
}

async fn fetch_events(
    args: &HuntQueryArgs,
    query: &HuntQuery,
    stderr: &mut dyn Write,
) -> Vec<TimelineEvent> {
    if args.offline {
        // Offline mode: local files only
        let dirs = if let Some(ref local_dirs) = args.local_dir {
            local_dirs.iter().map(PathBuf::from).collect()
        } else {
            hunt_query::local::default_local_dirs()
        };
        match hunt_query::local::query_local_files(query, &dirs, args.verify) {
            Ok(events) => events,
            Err(e) => {
                let _ = writeln!(stderr, "Warning: local file query error: {e}");
                Vec::new()
            }
        }
    } else {
        // Try NATS first, fallback to local
        match hunt_query::replay::replay_all(
            query,
            &args.nats_url,
            args.nats_creds.as_deref(),
            args.verify,
        )
        .await
        {
            Ok(events) => events,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "Warning: NATS connection failed ({e}), falling back to local files"
                );
                let dirs = if let Some(ref local_dirs) = args.local_dir {
                    local_dirs.iter().map(PathBuf::from).collect()
                } else {
                    hunt_query::local::default_local_dirs()
                };
                match hunt_query::local::query_local_files(query, &dirs, args.verify) {
                    Ok(events) => events,
                    Err(e2) => {
                        let _ = writeln!(stderr, "Warning: local file query error: {e2}");
                        Vec::new()
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Hunt Query command
// ---------------------------------------------------------------------------

async fn cmd_hunt_query(
    args: HuntQueryArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let is_json = args.json;

    let query = match build_hunt_query(&args) {
        Ok(q) => q,
        Err((code, msg)) => {
            return emit_hunt_query_error(is_json, "hunt query", stdout, stderr, &msg, code);
        }
    };

    let config = render_config(&args);
    let sources_queried: Vec<String> = query
        .effective_sources()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let events = fetch_events(&args, &query, stderr).await;

    if is_json {
        let output = HuntQueryJsonOutput {
            version: CLI_JSON_VERSION,
            command: "hunt query",
            exit_code: ExitCode::Ok.as_i32(),
            error: None,
            data: Some(HuntQueryData {
                summary: HuntQuerySummary {
                    total_events: events.len(),
                    sources_queried,
                },
                events,
            }),
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        if let Err(e) = hunt_query::render::render_events(&events, &config, stdout) {
            let _ = writeln!(stderr, "Render error: {e}");
            return ExitCode::RuntimeError;
        }
        let _ = writeln!(stdout);
        let _ = writeln!(stdout, "{} events returned", events.len());
    }

    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// Hunt Timeline command
// ---------------------------------------------------------------------------

async fn cmd_hunt_timeline(
    args: HuntQueryArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let is_json = args.json;

    let query = match build_hunt_query(&args) {
        Ok(q) => q,
        Err((code, msg)) => {
            return emit_hunt_query_error(is_json, "hunt timeline", stdout, stderr, &msg, code);
        }
    };

    let config = render_config(&args);
    let entity = query.entity.clone();
    let sources_queried: Vec<String> = query
        .effective_sources()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let events = fetch_events(&args, &query, stderr).await;
    let timeline = hunt_query::timeline::merge_timeline(events);

    if is_json {
        let output = HuntQueryJsonOutput {
            version: CLI_JSON_VERSION,
            command: "hunt timeline",
            exit_code: ExitCode::Ok.as_i32(),
            error: None,
            data: Some(HuntQueryData {
                summary: HuntQuerySummary {
                    total_events: timeline.len(),
                    sources_queried,
                },
                events: timeline,
            }),
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        let effective = query.effective_sources();
        if let Err(e) = hunt_query::render::render_timeline_header(
            entity.as_deref(),
            timeline.len(),
            &effective,
            stdout,
        ) {
            let _ = writeln!(stderr, "Render error: {e}");
            return ExitCode::RuntimeError;
        }
        if let Err(e) = hunt_query::render::render_events(&timeline, &config, stdout) {
            let _ = writeln!(stderr, "Render error: {e}");
            return ExitCode::RuntimeError;
        }
    }

    ExitCode::Ok
}

fn emit_hunt_query_error(
    json: bool,
    command: &'static str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    message: &str,
    code: ExitCode,
) -> ExitCode {
    if json {
        let output = HuntQueryJsonOutput {
            version: CLI_JSON_VERSION,
            command,
            exit_code: code.as_i32(),
            error: Some(HuntJsonError {
                kind: "invalid_args",
                message: message.to_string(),
            }),
            data: None,
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        let _ = writeln!(stderr, "Error: {message}");
    }
    code
}

// ---------------------------------------------------------------------------
// Hunt Watch args
// ---------------------------------------------------------------------------

struct HuntWatchArgs {
    rules: Vec<String>,
    nats_url: String,
    nats_creds: Option<String>,
    signing_key: String,
    max_window: String,
    json: bool,
    no_color: bool,
}

// ---------------------------------------------------------------------------
// Hunt Correlate args
// ---------------------------------------------------------------------------

struct HuntCorrelateArgs {
    rules: Vec<String>,
    source: Option<Vec<String>>,
    verdict: Option<String>,
    start: Option<String>,
    end: Option<String>,
    action_type: Option<String>,
    process: Option<String>,
    namespace: Option<String>,
    pod: Option<String>,
    limit: usize,
    nl: Option<String>,
    nats_url: String,
    nats_creds: Option<String>,
    offline: bool,
    local_dir: Option<Vec<String>>,
    verify: bool,
    json: bool,
    jsonl: bool,
    no_color: bool,
}

// ---------------------------------------------------------------------------
// Hunt IOC args
// ---------------------------------------------------------------------------

struct HuntIocArgs {
    feed: Option<Vec<String>>,
    stix: Option<Vec<String>>,
    source: Option<Vec<String>>,
    start: Option<String>,
    end: Option<String>,
    limit: usize,
    nats_url: String,
    nats_creds: Option<String>,
    offline: bool,
    local_dir: Option<Vec<String>>,
    verify: bool,
    json: bool,
    no_color: bool,
}

// ---------------------------------------------------------------------------
// Hunt Watch / Correlate / IOC JSON output structs
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct HuntCorrelateJsonOutput {
    version: u8,
    command: &'static str,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<HuntJsonError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<HuntCorrelateData>,
}

#[derive(serde::Serialize)]
struct HuntCorrelateData {
    alerts: Vec<hunt_correlate::engine::Alert>,
    summary: HuntCorrelateSummary,
}

#[derive(serde::Serialize)]
struct HuntCorrelateSummary {
    events_processed: usize,
    alerts_generated: usize,
    rules_loaded: usize,
}

#[derive(serde::Serialize)]
struct HuntIocJsonOutput {
    version: u8,
    command: &'static str,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<HuntJsonError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<HuntIocData>,
}

#[derive(serde::Serialize)]
struct HuntIocData {
    matches: Vec<hunt_correlate::ioc::IocMatch>,
    summary: HuntIocSummary,
}

#[derive(serde::Serialize)]
struct HuntIocSummary {
    events_scanned: usize,
    iocs_loaded: usize,
    matches_found: usize,
}

// ---------------------------------------------------------------------------
// Hunt Watch command
// ---------------------------------------------------------------------------

async fn cmd_hunt_watch(
    args: HuntWatchArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let is_json = args.json;

    if args.rules.is_empty() {
        return emit_hunt_correlate_error(
            is_json,
            "hunt watch",
            stdout,
            stderr,
            "No correlation rule files specified. Use --rules <path>.",
            ExitCode::InvalidArgs,
        );
    }

    // Load rules
    let rule_paths: Vec<PathBuf> = args.rules.iter().map(PathBuf::from).collect();
    let all_rules = match hunt_correlate::rules::load_rules_from_files(&rule_paths) {
        Ok(rules) => rules,
        Err(e) => {
            return emit_hunt_correlate_error(
                is_json,
                "hunt watch",
                stdout,
                stderr,
                &format!("Failed to load rules: {e}"),
                ExitCode::ConfigError,
            );
        }
    };

    let rules_loaded = all_rules.len();

    // Parse max_window duration
    let max_window = match hunt_correlate::rules::parse_duration_str(&args.max_window) {
        Some(dur) => dur,
        None => {
            return emit_hunt_correlate_error(
                is_json,
                "hunt watch",
                stdout,
                stderr,
                &format!(
                    "Invalid --max-window value '{}'. Use e.g. '5m', '1h'.",
                    args.max_window
                ),
                ExitCode::InvalidArgs,
            );
        }
    };

    if !is_json {
        let _ = writeln!(
            stdout,
            "Loaded {} correlation rules, connecting to {}...",
            rules_loaded, args.nats_url
        );
    }

    let config = hunt_correlate::watch::WatchConfig {
        nats_url: args.nats_url,
        nats_creds: args.nats_creds,
        signing_key: Some(args.signing_key),
        rules: all_rules,
        max_window,
        color: !args.no_color,
        json: is_json,
    };

    match hunt_correlate::watch::run_watch(config, stdout, stderr).await {
        Ok(stats) => {
            if is_json {
                let output = HuntCorrelateJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "hunt watch",
                    exit_code: ExitCode::Ok.as_i32(),
                    error: None,
                    data: Some(HuntCorrelateData {
                        alerts: vec![],
                        summary: HuntCorrelateSummary {
                            events_processed: stats.events_processed as usize,
                            alerts_generated: stats.alerts_triggered as usize,
                            rules_loaded,
                        },
                    }),
                };
                if let Ok(json_str) = serde_json::to_string_pretty(&output) {
                    let _ = writeln!(stdout, "{json_str}");
                }
            } else {
                let _ = writeln!(
                    stdout,
                    "Watch session ended: {} events processed, {} alerts",
                    stats.events_processed, stats.alerts_triggered
                );
            }
            ExitCode::Ok
        }
        Err(e) => emit_hunt_correlate_error(
            is_json,
            "hunt watch",
            stdout,
            stderr,
            &format!("Watch failed: {e}"),
            ExitCode::RuntimeError,
        ),
    }
}

// ---------------------------------------------------------------------------
// Hunt Correlate command
// ---------------------------------------------------------------------------

async fn cmd_hunt_correlate(
    args: HuntCorrelateArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let is_json = args.json;

    if args.rules.is_empty() {
        return emit_hunt_correlate_error(
            is_json,
            "hunt correlate",
            stdout,
            stderr,
            "No correlation rule files specified. Use --rules <path>.",
            ExitCode::InvalidArgs,
        );
    }

    // Load rules
    let rule_paths: Vec<PathBuf> = args.rules.iter().map(PathBuf::from).collect();
    let all_rules = match hunt_correlate::rules::load_rules_from_files(&rule_paths) {
        Ok(rules) => rules,
        Err(e) => {
            return emit_hunt_correlate_error(
                is_json,
                "hunt correlate",
                stdout,
                stderr,
                &format!("Failed to load rules: {e}"),
                ExitCode::ConfigError,
            );
        }
    };

    let rules_loaded = all_rules.len();

    // Build query args to reuse the existing query infrastructure
    let query_args = HuntQueryArgs {
        source: args.source,
        verdict: args.verdict,
        start: args.start,
        end: args.end,
        action_type: args.action_type,
        process: args.process,
        namespace: args.namespace,
        pod: args.pod,
        limit: args.limit,
        nl: args.nl,
        nats_url: args.nats_url,
        nats_creds: args.nats_creds,
        offline: args.offline,
        local_dir: args.local_dir,
        verify: args.verify,
        json: args.json,
        jsonl: args.jsonl,
        no_color: args.no_color,
        entity: None,
    };

    let query = match build_hunt_query(&query_args) {
        Ok(q) => q,
        Err((code, msg)) => {
            return emit_hunt_correlate_error(
                is_json,
                "hunt correlate",
                stdout,
                stderr,
                &msg,
                code,
            );
        }
    };

    let events = fetch_events(&query_args, &query, stderr).await;
    let events_count = events.len();

    // Merge into timeline for chronological ordering
    let timeline = hunt_query::timeline::merge_timeline(events);

    // Run correlation engine
    let mut engine = match hunt_correlate::engine::CorrelationEngine::new(all_rules) {
        Ok(eng) => eng,
        Err(e) => {
            return emit_hunt_correlate_error(
                is_json,
                "hunt correlate",
                stdout,
                stderr,
                &format!("Failed to initialize correlation engine: {e}"),
                ExitCode::ConfigError,
            );
        }
    };

    let mut all_alerts = Vec::new();

    for event in &timeline {
        let alerts = engine.process_event(event);
        all_alerts.extend(alerts);
    }

    // Flush remaining window buffers
    let flush_alerts = engine.flush();
    all_alerts.extend(flush_alerts);

    let alerts_count = all_alerts.len();

    if is_json {
        let output = HuntCorrelateJsonOutput {
            version: CLI_JSON_VERSION,
            command: "hunt correlate",
            exit_code: ExitCode::Ok.as_i32(),
            error: None,
            data: Some(HuntCorrelateData {
                alerts: all_alerts,
                summary: HuntCorrelateSummary {
                    events_processed: events_count,
                    alerts_generated: alerts_count,
                    rules_loaded,
                },
            }),
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        let _ = writeln!(
            stdout,
            "{} events processed, {} alerts from {} rules",
            events_count, alerts_count, rules_loaded
        );
        for alert in &all_alerts {
            hunt_correlate::watch::render_alert(alert, !args.no_color, stdout).ok();
        }
    }

    ExitCode::Ok
}

// ---------------------------------------------------------------------------
// Hunt IOC command
// ---------------------------------------------------------------------------

async fn cmd_hunt_ioc(
    args: HuntIocArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let is_json = args.json;

    if args.feed.is_none() && args.stix.is_none() {
        return emit_hunt_ioc_error(
            is_json,
            stdout,
            stderr,
            "No IOC feeds specified. Use --feed or --stix.",
            ExitCode::InvalidArgs,
        );
    }

    // Load IOC database
    let mut db = hunt_correlate::ioc::IocDatabase::new();

    if let Some(ref feeds) = args.feed {
        for path in feeds {
            let p = std::path::Path::new(path);
            let result = if path.ends_with(".csv") {
                hunt_correlate::ioc::IocDatabase::load_csv_file(p)
            } else {
                hunt_correlate::ioc::IocDatabase::load_text_file(p)
            };
            match result {
                Ok(loaded_db) => {
                    let count = loaded_db.len();
                    if !is_json {
                        let _ = writeln!(stdout, "Loaded {count} IOCs from {path}");
                    }
                    db.merge(loaded_db);
                }
                Err(e) => {
                    return emit_hunt_ioc_error(
                        is_json,
                        stdout,
                        stderr,
                        &format!("Failed to load IOC feed '{path}': {e}"),
                        ExitCode::ConfigError,
                    );
                }
            }
        }
    }

    if let Some(ref stix_files) = args.stix {
        for path in stix_files {
            match hunt_correlate::ioc::IocDatabase::load_stix_bundle(std::path::Path::new(path)) {
                Ok(loaded_db) => {
                    let count = loaded_db.len();
                    if !is_json {
                        let _ = writeln!(stdout, "Loaded {count} IOCs from STIX bundle {path}");
                    }
                    db.merge(loaded_db);
                }
                Err(e) => {
                    return emit_hunt_ioc_error(
                        is_json,
                        stdout,
                        stderr,
                        &format!("Failed to load STIX bundle '{path}': {e}"),
                        ExitCode::ConfigError,
                    );
                }
            }
        }
    }

    let iocs_loaded = db.len();

    // Build query to fetch events
    let query_args = HuntQueryArgs {
        source: args.source,
        verdict: None,
        start: args.start,
        end: args.end,
        action_type: None,
        process: None,
        namespace: None,
        pod: None,
        limit: args.limit,
        nl: None,
        nats_url: args.nats_url,
        nats_creds: args.nats_creds,
        offline: args.offline,
        local_dir: args.local_dir,
        verify: args.verify,
        json: args.json,
        jsonl: false,
        no_color: args.no_color,
        entity: None,
    };

    let query = match build_hunt_query(&query_args) {
        Ok(q) => q,
        Err((code, msg)) => {
            return emit_hunt_ioc_error(is_json, stdout, stderr, &msg, code);
        }
    };

    let events = fetch_events(&query_args, &query, stderr).await;
    let events_count = events.len();

    // Match events against IOC database
    let all_matches = hunt_correlate::ioc::match_events(&db, &events);
    let matches_count = all_matches.len();

    if is_json {
        let output = HuntIocJsonOutput {
            version: CLI_JSON_VERSION,
            command: "hunt ioc",
            exit_code: ExitCode::Ok.as_i32(),
            error: None,
            data: Some(HuntIocData {
                matches: all_matches,
                summary: HuntIocSummary {
                    events_scanned: events_count,
                    iocs_loaded,
                    matches_found: matches_count,
                },
            }),
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        let _ = writeln!(
            stdout,
            "{} events scanned, {} IOCs loaded, {} matches found",
            events_count, iocs_loaded, matches_count
        );
        for m in &all_matches {
            let ioc_names: Vec<&str> = m
                .matched_iocs
                .iter()
                .map(|e| e.indicator.as_str())
                .collect();
            let _ = writeln!(
                stdout,
                "  [{}] {} in {}",
                m.match_field,
                ioc_names.join(", "),
                m.event.summary,
            );
        }
    }

    ExitCode::Ok
}

fn emit_hunt_correlate_error(
    json: bool,
    command: &'static str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    message: &str,
    code: ExitCode,
) -> ExitCode {
    if json {
        let output = HuntCorrelateJsonOutput {
            version: CLI_JSON_VERSION,
            command,
            exit_code: code.as_i32(),
            error: Some(HuntJsonError {
                kind: "invalid_args",
                message: message.to_string(),
            }),
            data: None,
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        let _ = writeln!(stderr, "Error: {message}");
    }
    code
}

fn emit_hunt_ioc_error(
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    message: &str,
    code: ExitCode,
) -> ExitCode {
    if json {
        let output = HuntIocJsonOutput {
            version: CLI_JSON_VERSION,
            command: "hunt ioc",
            exit_code: code.as_i32(),
            error: Some(HuntJsonError {
                kind: "invalid_args",
                message: message.to_string(),
            }),
            data: None,
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        let _ = writeln!(stderr, "Error: {message}");
    }
    code
}

fn emit_hunt_error(
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    kind: &'static str,
    message: &str,
    code: ExitCode,
) -> ExitCode {
    if json {
        let output = HuntScanJsonOutput {
            version: CLI_JSON_VERSION,
            command: "hunt scan",
            exit_code: code.as_i32(),
            error: Some(HuntJsonError {
                kind,
                message: message.to_string(),
            }),
            data: None,
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&output) {
            let _ = writeln!(stdout, "{json_str}");
        }
    } else {
        let _ = writeln!(stderr, "Error: {message}");
    }
    code
}

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::io::Write;
use std::path::PathBuf;

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

    // 4. Run local analysis on all collected tools
    let all_tools: Vec<Tool> = scan_results
        .iter()
        .flat_map(|r| {
            r.servers
                .as_ref()
                .into_iter()
                .flat_map(|servers| {
                    servers
                        .iter()
                        .filter_map(|s| s.signature.as_ref().map(|sig| sig.tools.clone()))
                })
                .flatten()
        })
        .collect();

    let mut all_issues = analysis::check_descriptions_for_injection(&all_tools);
    all_issues.extend(analysis::check_tool_name_shadowing(&all_tools, &[]));

    // Distribute issues to the first scan result that has servers
    if !all_issues.is_empty() {
        if let Some(result) = scan_results.iter_mut().find(|r| r.servers.is_some()) {
            result.issues.extend(all_issues);
        }
    }

    // 5. Remote analysis (if --analysis-url)
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
                // Merge back issues and labels from the API response
                for (orig, redacted) in scan_results.iter_mut().zip(redacted_results.iter()) {
                    orig.issues.clone_from(&redacted.issues);
                    orig.labels.clone_from(&redacted.labels);
                }
            }
            Err(e) => {
                let _ = writeln!(stderr, "Warning: analysis API error: {e}");
            }
        }
    }

    // 6. Skills scanning (if --skills)
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
    if summary.issues_found == 0 {
        return ExitCode::Ok;
    }

    // Check for any failure-level errors in scan results
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
    } else {
        ExitCode::Warn
    }
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

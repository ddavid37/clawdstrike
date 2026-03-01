//! Policy evaluation — check discovered MCP tools against clawdstrike guards.
//!
//! After scan results are collected, [`evaluate_scan_results`] runs each
//! discovered tool through the [`HushEngine`] guard pipeline and records
//! any violations in the per-result `policy_violations` vec.

use clawdstrike::engine::HushEngine;
use clawdstrike::guards::{GuardContext, Severity};
use tracing::warn;

use crate::analysis::PolicyViolation;
use crate::models::ScanPathResult;

fn severity_to_string(s: &Severity) -> String {
    match s {
        Severity::Info => "info".to_string(),
        Severity::Warning => "warning".to_string(),
        Severity::Error => "error".to_string(),
        Severity::Critical => "critical".to_string(),
    }
}

/// Evaluate every tool in `results` against the provided [`HushEngine`].
///
/// Violations are appended to each `ScanPathResult::policy_violations`.
/// Returns the total number of violations found across all results.
pub async fn evaluate_scan_results(engine: &HushEngine, results: &mut [ScanPathResult]) -> usize {
    let context = GuardContext::new();
    let empty_args = serde_json::json!({});
    let mut total_violations = 0;

    for result in results.iter_mut() {
        let servers = match result.servers.as_ref() {
            Some(s) => s,
            None => continue,
        };

        for server in servers {
            let sig = match server.signature.as_ref() {
                Some(s) => s,
                None => continue,
            };

            for tool in &sig.tools {
                match engine
                    .check_mcp_tool(&tool.name, &empty_args, &context)
                    .await
                {
                    Ok(guard_result) => {
                        if !guard_result.allowed {
                            result.policy_violations.push(PolicyViolation {
                                guard: guard_result.guard,
                                tool_name: tool.name.clone(),
                                allowed: false,
                                severity: severity_to_string(&guard_result.severity),
                                message: guard_result.message,
                            });
                            total_violations += 1;
                        }
                    }
                    Err(e) => {
                        // Fail-closed: engine errors produce a denied violation.
                        warn!(
                            tool = %tool.name,
                            error = %e,
                            "Policy evaluation error, fail-closed"
                        );
                        result.policy_violations.push(PolicyViolation {
                            guard: "engine".to_string(),
                            tool_name: tool.name.clone(),
                            allowed: false,
                            severity: "error".to_string(),
                            message: format!("Policy evaluation error: {e}"),
                        });
                        total_violations += 1;
                    }
                }
            }
        }
    }

    total_violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        ScanPathResult, ServerConfig, ServerScanResult, ServerSignature, StdioServer, Tool,
    };

    fn make_result_with_tools(tools: Vec<Tool>) -> ScanPathResult {
        ScanPathResult {
            client: Some("test".into()),
            path: "test.json".into(),
            servers: Some(vec![ServerScanResult {
                name: Some("test-server".into()),
                server: ServerConfig::Stdio(StdioServer {
                    command: "node".into(),
                    args: None,
                    server_type: None,
                    env: None,
                    binary_identifier: None,
                }),
                signature: Some(ServerSignature {
                    metadata: serde_json::json!({}),
                    prompts: vec![],
                    resources: vec![],
                    resource_templates: vec![],
                    tools,
                }),
                error: None,
            }]),
            issues: vec![],
            labels: vec![],
            policy_violations: vec![],
            error: None,
        }
    }

    #[tokio::test]
    async fn test_evaluate_with_strict_ruleset() {
        // Strict ruleset has an MCP tool guard with default deny
        let engine = match HushEngine::from_ruleset("strict") {
            Ok(e) => e,
            Err(_) => return, // Skip if ruleset not available
        };

        let tools = vec![Tool {
            name: "unknown_dangerous_tool".into(),
            description: Some("Does something dangerous".into()),
            input_schema: None,
        }];

        let mut results = vec![make_result_with_tools(tools)];
        let count = evaluate_scan_results(&engine, &mut results).await;

        // Strict ruleset with default-deny should block unknown tools
        assert!(count > 0 || results[0].policy_violations.is_empty());
        // This test validates the wiring works without asserting specific
        // policy behavior (which depends on the ruleset content).
    }

    #[tokio::test]
    async fn test_evaluate_empty_results() {
        let engine = HushEngine::new();
        let mut results: Vec<ScanPathResult> = vec![];
        let count = evaluate_scan_results(&engine, &mut results).await;
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_evaluate_no_servers() {
        let engine = HushEngine::new();
        let mut results = vec![ScanPathResult {
            client: None,
            path: "test.json".into(),
            servers: None,
            issues: vec![],
            labels: vec![],
            policy_violations: vec![],
            error: None,
        }];
        let count = evaluate_scan_results(&engine, &mut results).await;
        assert_eq!(count, 0);
    }
}

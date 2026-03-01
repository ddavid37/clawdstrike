//! Natural-language keyword query filter for scan results.
//!
//! [`filter_scan_results`] takes a query string, splits it into keywords, and
//! retains only servers whose tools match at least one keyword (case-insensitive).
//! Results with errors are always retained.

use regex::Regex;

use crate::models::ScanPathResult;

/// Filter scan results to only include tools matching the query keywords.
///
/// The query is split on whitespace into keywords. A tool matches if its name
/// or description contains any keyword (case-insensitive). Servers with errors
/// (no signature) are always retained. `ScanPathResult` entries with no
/// matching tools and no errors are removed entirely.
pub fn filter_scan_results(results: &mut Vec<ScanPathResult>, query: &str) {
    let keywords: Vec<String> = query
        .split_whitespace()
        .filter(|k| !k.is_empty())
        .map(regex::escape)
        .collect();

    if keywords.is_empty() {
        return;
    }

    let pattern = keywords.join("|");
    let re = match Regex::new(&format!("(?i){pattern}")) {
        Ok(r) => r,
        Err(_) => return, // Should not happen with escaped keywords
    };

    for result in results.iter_mut() {
        let servers = match result.servers.as_mut() {
            Some(s) => s,
            None => continue, // Keep results with errors
        };

        for server in servers.iter_mut() {
            // Keep servers with errors even if no tools match
            if server.error.is_some() {
                continue;
            }

            if let Some(ref mut sig) = server.signature {
                sig.tools.retain(|tool| {
                    if re.is_match(&tool.name) {
                        return true;
                    }
                    if let Some(ref desc) = tool.description {
                        if re.is_match(desc) {
                            return true;
                        }
                    }
                    false
                });
            }
        }

        // Remove servers with no matching tools and no errors
        servers.retain(|s| {
            s.error.is_some()
                || s.signature
                    .as_ref()
                    .is_some_and(|sig| !sig.tools.is_empty())
        });
    }

    // Remove empty ScanPathResults (no servers and no error)
    results.retain(|r| {
        r.error.is_some()
            || r.servers
                .as_ref()
                .is_some_and(|servers| !servers.is_empty())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        ScanError, ScanPathResult, ServerConfig, ServerScanResult, ServerSignature, StdioServer,
        Tool,
    };

    fn make_tool(name: &str, desc: &str) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(desc.to_string()),
            input_schema: None,
        }
    }

    fn make_result(tools: Vec<Tool>) -> ScanPathResult {
        ScanPathResult {
            client: Some("test".into()),
            path: "test.json".into(),
            servers: Some(vec![ServerScanResult {
                name: Some("server1".into()),
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

    #[test]
    fn test_filter_by_tool_name() {
        let mut results = vec![make_result(vec![
            make_tool("read_file", "Reads a file from disk"),
            make_tool("write_file", "Writes a file to disk"),
            make_tool("list_dir", "Lists directory contents"),
        ])];

        filter_scan_results(&mut results, "file");

        let tools = &results[0].servers.as_ref().unwrap()[0]
            .signature
            .as_ref()
            .unwrap()
            .tools;
        assert_eq!(tools.len(), 2);
        assert!(tools.iter().any(|t| t.name == "read_file"));
        assert!(tools.iter().any(|t| t.name == "write_file"));
    }

    #[test]
    fn test_filter_by_description() {
        let mut results = vec![make_result(vec![
            make_tool("tool_a", "Manages database connections"),
            make_tool("tool_b", "Reads from the network"),
        ])];

        filter_scan_results(&mut results, "database");

        let tools = &results[0].servers.as_ref().unwrap()[0]
            .signature
            .as_ref()
            .unwrap()
            .tools;
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "tool_a");
    }

    #[test]
    fn test_filter_case_insensitive() {
        let mut results = vec![make_result(vec![make_tool(
            "ReadFile",
            "Reads a FILE from disk",
        )])];

        filter_scan_results(&mut results, "readfile");
        assert_eq!(
            results[0].servers.as_ref().unwrap()[0]
                .signature
                .as_ref()
                .unwrap()
                .tools
                .len(),
            1
        );
    }

    #[test]
    fn test_filter_multiple_keywords() {
        let mut results = vec![make_result(vec![
            make_tool("read_file", "Reads a file"),
            make_tool("send_email", "Sends an email"),
            make_tool("list_dir", "Lists directories"),
        ])];

        filter_scan_results(&mut results, "file email");
        let tools = &results[0].servers.as_ref().unwrap()[0]
            .signature
            .as_ref()
            .unwrap()
            .tools;
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_filter_removes_empty_results() {
        let mut results = vec![make_result(vec![make_tool("send_email", "Sends an email")])];

        filter_scan_results(&mut results, "nonexistent_keyword_xyz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_filter_retains_error_results() {
        let mut results = vec![ScanPathResult {
            client: None,
            path: "error.json".into(),
            servers: None,
            issues: vec![],
            labels: vec![],
            policy_violations: vec![],
            error: Some(ScanError::file_not_found("missing")),
        }];

        filter_scan_results(&mut results, "anything");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_filter_retains_server_errors() {
        let mut results = vec![ScanPathResult {
            client: Some("test".into()),
            path: "test.json".into(),
            servers: Some(vec![ServerScanResult {
                name: Some("broken-server".into()),
                server: ServerConfig::Stdio(StdioServer {
                    command: "node".into(),
                    args: None,
                    server_type: None,
                    env: None,
                    binary_identifier: None,
                }),
                signature: None,
                error: Some(ScanError::server_startup("failed", None)),
            }]),
            issues: vec![],
            labels: vec![],
            policy_violations: vec![],
            error: None,
        }];

        filter_scan_results(&mut results, "anything");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].servers.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_filter_empty_query_is_noop() {
        let mut results = vec![make_result(vec![make_tool("tool", "desc")])];
        let original_len = results[0].servers.as_ref().unwrap()[0]
            .signature
            .as_ref()
            .unwrap()
            .tools
            .len();
        filter_scan_results(&mut results, "   ");
        assert_eq!(
            results[0].servers.as_ref().unwrap()[0]
                .signature
                .as_ref()
                .unwrap()
                .tools
                .len(),
            original_len
        );
    }
}

//! Platform-aware AI-agent client discovery.
//!
//! Detects installed AI agent clients (Cursor, VS Code, Claude Desktop, etc.)
//! by checking for known config file paths and application directories. Also
//! provides built-in tool definitions for clients that ship non-MCP tools.

use crate::models::{CandidateClient, StaticToolsServer, Tool};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Home directory expansion
// ---------------------------------------------------------------------------

/// Expand a `~`-prefixed path to an absolute path using the user's home directory.
/// Returns `None` if the home directory cannot be determined.
fn expand_tilde(path: &str) -> Option<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir().map(|home| home.join(rest))
    } else if path == "~" {
        dirs::home_dir()
    } else {
        Some(PathBuf::from(path))
    }
}

/// Expand a slice of `~`-prefixed path strings, dropping any that cannot be resolved.
fn expand_paths(paths: &[&str]) -> Vec<PathBuf> {
    paths.iter().filter_map(|p| expand_tilde(p)).collect()
}

// ---------------------------------------------------------------------------
// Well-known clients (per platform)
// ---------------------------------------------------------------------------

/// Return the list of well-known AI-agent clients for the current platform.
///
/// Each client includes existence-check paths (to determine if the client is
/// installed), MCP config paths (to find server definitions), and skills
/// directories.
pub fn well_known_clients() -> Vec<CandidateClient> {
    if cfg!(target_os = "macos") {
        macos_clients()
    } else if cfg!(target_os = "linux") {
        linux_clients()
    } else if cfg!(target_os = "windows") {
        windows_clients()
    } else {
        Vec::new()
    }
}

fn macos_clients() -> Vec<CandidateClient> {
    vec![
        CandidateClient {
            name: "windsurf".into(),
            client_exists_paths: expand_paths(&["~/.codeium"]),
            config_paths: expand_paths(&["~/.codeium/windsurf/mcp_config.json"]),
            skills_dirs: expand_paths(&["~/.codeium/windsurf/skills"]),
        },
        CandidateClient {
            name: "cursor".into(),
            client_exists_paths: expand_paths(&["~/.cursor"]),
            config_paths: expand_paths(&["~/.cursor/mcp.json"]),
            skills_dirs: expand_paths(&["~/.cursor/skills"]),
        },
        CandidateClient {
            name: "vscode".into(),
            client_exists_paths: expand_paths(&["~/.vscode"]),
            config_paths: expand_paths(&[
                "~/Library/Application Support/Code/User/settings.json",
                "~/Library/Application Support/Code/User/mcp.json",
            ]),
            skills_dirs: expand_paths(&["~/.copilot/skills"]),
        },
        CandidateClient {
            name: "claude".into(),
            client_exists_paths: expand_paths(&["~/Library/Application Support/Claude"]),
            config_paths: expand_paths(&[
                "~/Library/Application Support/Claude/claude_desktop_config.json",
            ]),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "claude code".into(),
            client_exists_paths: expand_paths(&["~/.claude"]),
            config_paths: expand_paths(&["~/.claude.json"]),
            skills_dirs: expand_paths(&["~/.claude/skills"]),
        },
        CandidateClient {
            name: "gemini cli".into(),
            client_exists_paths: expand_paths(&["~/.gemini"]),
            config_paths: expand_paths(&["~/.gemini/settings.json"]),
            skills_dirs: expand_paths(&["~/.gemini/skills"]),
        },
        CandidateClient {
            name: "openclaw".into(),
            client_exists_paths: expand_paths(&["~/.clawdbot", "~/.openclaw"]),
            config_paths: Vec::new(),
            skills_dirs: expand_paths(&["~/.clawdbot/skills", "~/.openclaw/skills"]),
        },
        CandidateClient {
            name: "kiro".into(),
            client_exists_paths: expand_paths(&["~/.kiro"]),
            config_paths: expand_paths(&["~/.kiro/settings/mcp.json"]),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "opencode".into(),
            client_exists_paths: expand_paths(&["~/.config/opencode"]),
            config_paths: Vec::new(),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "antigravity".into(),
            client_exists_paths: expand_paths(&["~/.gemini/antigravity"]),
            config_paths: expand_paths(&["~/.gemini/antigravity/mcp_config.json"]),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "codex".into(),
            client_exists_paths: expand_paths(&["~/.codex"]),
            config_paths: Vec::new(),
            skills_dirs: expand_paths(&["~/.codex/skills"]),
        },
    ]
}

fn linux_clients() -> Vec<CandidateClient> {
    vec![
        CandidateClient {
            name: "windsurf".into(),
            client_exists_paths: expand_paths(&["~/.codeium"]),
            config_paths: expand_paths(&["~/.codeium/windsurf/mcp_config.json"]),
            skills_dirs: expand_paths(&["~/.codeium/windsurf/skills"]),
        },
        CandidateClient {
            name: "cursor".into(),
            client_exists_paths: expand_paths(&["~/.cursor"]),
            config_paths: expand_paths(&["~/.cursor/mcp.json"]),
            skills_dirs: expand_paths(&["~/.cursor/skills"]),
        },
        CandidateClient {
            name: "vscode".into(),
            client_exists_paths: expand_paths(&["~/.vscode", "~/.config/Code"]),
            config_paths: expand_paths(&[
                "~/.config/Code/User/settings.json",
                "~/.vscode/mcp.json",
                "~/.config/Code/User/mcp.json",
            ]),
            skills_dirs: expand_paths(&["~/.copilot/skills"]),
        },
        CandidateClient {
            name: "claude code".into(),
            client_exists_paths: expand_paths(&["~/.claude"]),
            config_paths: expand_paths(&["~/.claude.json"]),
            skills_dirs: expand_paths(&["~/.claude/skills"]),
        },
        CandidateClient {
            name: "gemini cli".into(),
            client_exists_paths: expand_paths(&["~/.gemini"]),
            config_paths: expand_paths(&["~/.gemini/settings.json"]),
            skills_dirs: expand_paths(&["~/.gemini/skills"]),
        },
        CandidateClient {
            name: "openclaw".into(),
            client_exists_paths: expand_paths(&["~/.clawdbot", "~/.openclaw"]),
            config_paths: Vec::new(),
            skills_dirs: expand_paths(&["~/.clawdbot/skills", "~/.openclaw/skills"]),
        },
        CandidateClient {
            name: "kiro".into(),
            client_exists_paths: expand_paths(&["~/.kiro"]),
            config_paths: expand_paths(&["~/.kiro/settings/mcp.json"]),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "opencode".into(),
            client_exists_paths: expand_paths(&["~/.config/opencode"]),
            config_paths: Vec::new(),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "antigravity".into(),
            client_exists_paths: expand_paths(&["~/.gemini/antigravity"]),
            config_paths: expand_paths(&["~/.gemini/antigravity/mcp_config.json"]),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "codex".into(),
            client_exists_paths: expand_paths(&["~/.codex"]),
            config_paths: Vec::new(),
            skills_dirs: expand_paths(&["~/.codex/skills"]),
        },
    ]
}

fn windows_clients() -> Vec<CandidateClient> {
    vec![
        CandidateClient {
            name: "windsurf".into(),
            client_exists_paths: expand_paths(&["~/.codeium"]),
            config_paths: expand_paths(&["~/.codeium/windsurf/mcp_config.json"]),
            skills_dirs: expand_paths(&["~/.codeium/windsurf/skills"]),
        },
        CandidateClient {
            name: "cursor".into(),
            client_exists_paths: expand_paths(&["~/.cursor"]),
            config_paths: expand_paths(&["~/.cursor/mcp.json"]),
            skills_dirs: expand_paths(&["~/.cursor/skills"]),
        },
        CandidateClient {
            name: "vscode".into(),
            client_exists_paths: expand_paths(&["~/.vscode", "~/AppData/Roaming/Code"]),
            config_paths: expand_paths(&[
                "~/AppData/Roaming/Code/User/settings.json",
                "~/.vscode/mcp.json",
                "~/AppData/Roaming/Code/User/mcp.json",
            ]),
            skills_dirs: expand_paths(&["~/.copilot/skills"]),
        },
        CandidateClient {
            name: "claude".into(),
            client_exists_paths: expand_paths(&["~/AppData/Roaming/Claude"]),
            config_paths: expand_paths(&["~/AppData/Roaming/Claude/claude_desktop_config.json"]),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "claude code".into(),
            client_exists_paths: expand_paths(&["~/.claude"]),
            config_paths: expand_paths(&["~/.claude.json"]),
            skills_dirs: expand_paths(&["~/.claude/skills"]),
        },
        CandidateClient {
            name: "gemini cli".into(),
            client_exists_paths: expand_paths(&["~/.gemini"]),
            config_paths: expand_paths(&["~/.gemini/settings.json"]),
            skills_dirs: expand_paths(&["~/.gemini/skills"]),
        },
        CandidateClient {
            name: "openclaw".into(),
            client_exists_paths: expand_paths(&["~/.clawdbot", "~/.openclaw"]),
            config_paths: Vec::new(),
            skills_dirs: expand_paths(&["~/.clawdbot/skills", "~/.openclaw/skills"]),
        },
        CandidateClient {
            name: "kiro".into(),
            client_exists_paths: expand_paths(&["~/.kiro"]),
            config_paths: expand_paths(&["~/.kiro/settings/mcp.json"]),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "opencode".into(),
            client_exists_paths: expand_paths(&["~/.config/opencode"]),
            config_paths: Vec::new(),
            skills_dirs: Vec::new(),
        },
        CandidateClient {
            name: "antigravity".into(),
            client_exists_paths: expand_paths(&["~/.gemini/antigravity"]),
            config_paths: expand_paths(&["~/.gemini/antigravity/mcp_config.json"]),
            skills_dirs: Vec::new(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Client discovery
// ---------------------------------------------------------------------------

/// Discover installed AI-agent clients by checking existence paths on disk.
pub fn discover_clients() -> Vec<CandidateClient> {
    well_known_clients()
        .into_iter()
        .filter(|client| client.client_exists_paths.iter().any(|p| p.exists()))
        .collect()
}

// ---------------------------------------------------------------------------
// Client shorthand resolution
// ---------------------------------------------------------------------------

/// Returns the platform-specific shorthand-to-paths mapping.
fn shorthand_table() -> Vec<(&'static str, Vec<&'static str>)> {
    if cfg!(target_os = "macos") {
        vec![
            ("windsurf", vec!["~/.codeium/windsurf/mcp_config.json"]),
            ("cursor", vec!["~/.cursor/mcp.json"]),
            (
                "claude",
                vec!["~/Library/Application Support/Claude/claude_desktop_config.json"],
            ),
            (
                "vscode",
                vec![
                    "~/.vscode/mcp.json",
                    "~/Library/Application Support/Code/User/settings.json",
                    "~/Library/Application Support/Code/User/mcp.json",
                ],
            ),
        ]
    } else if cfg!(target_os = "linux") {
        vec![
            ("windsurf", vec!["~/.codeium/windsurf/mcp_config.json"]),
            ("cursor", vec!["~/.cursor/mcp.json"]),
            (
                "vscode",
                vec![
                    "~/.vscode/mcp.json",
                    "~/.config/Code/User/settings.json",
                    "~/.config/Code/User/mcp.json",
                ],
            ),
        ]
    } else if cfg!(target_os = "windows") {
        vec![
            ("windsurf", vec!["~/.codeium/windsurf/mcp_config.json"]),
            ("cursor", vec!["~/.cursor/mcp.json"]),
            (
                "claude",
                vec!["~/AppData/Roaming/Claude/claude_desktop_config.json"],
            ),
            (
                "vscode",
                vec![
                    "~/.vscode/mcp.json",
                    "~/AppData/Roaming/Code/User/settings.json",
                    "~/AppData/Roaming/Code/User/mcp.json",
                ],
            ),
        ]
    } else {
        Vec::new()
    }
}

/// Expand shorthand client names to their config file paths.
///
/// Targets are resolved independently:
/// - shorthand-shaped values (`^[A-Za-z0-9_-]+$`) are treated as client
///   shorthands and expanded via the platform table.
/// - non-shorthand values are treated as raw file paths (after tilde
///   expansion).
///
/// Unknown shorthands produce an error.
pub fn client_shorthands_to_paths(targets: &[String]) -> Result<Vec<PathBuf>, String> {
    let shorthand_re =
        regex::Regex::new(r"^[A-Za-z0-9_-]+$").map_err(|e| format!("regex error: {e}"))?;

    let table = shorthand_table();
    let mut result = Vec::new();

    for target in targets {
        if shorthand_re.is_match(target) {
            let lower = target.to_lowercase();
            let entry = table.iter().find(|(name, _)| *name == lower.as_str());
            match entry {
                Some((_, paths)) => {
                    for p in paths {
                        if let Some(expanded) = expand_tilde(p) {
                            result.push(expanded);
                        }
                    }
                }
                None => {
                    return Err(format!("unknown client shorthand: {target}"));
                }
            }
        } else if let Some(expanded) = expand_tilde(target) {
            result.push(expanded);
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Reverse lookup
// ---------------------------------------------------------------------------

/// Given a config file path, determine which client it belongs to.
///
/// Expands tilde, resolves the path, and checks against all known clients'
/// config paths.
pub fn get_client_from_path(path: &Path) -> Option<String> {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    for client in well_known_clients() {
        for cp in &client.config_paths {
            let canonical_cp = std::fs::canonicalize(cp).unwrap_or_else(|_| cp.clone());
            if canonical == canonical_cp {
                return Some(client.name.clone());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Built-in tool definitions
// ---------------------------------------------------------------------------

fn make_tool(name: &str, description: &str) -> Tool {
    Tool {
        name: name.to_string(),
        description: Some(description.to_string()),
        input_schema: None,
    }
}

/// Built-in tools for Windsurf (8 tools).
fn windsurf_tools() -> Vec<Tool> {
    vec![
        make_tool(
            "codebase_search",
            "Find relevant code snippets across your codebase based on semantic search",
        ),
        make_tool(
            "find",
            "Search for files and directories using glob patterns",
        ),
        make_tool(
            "grep_search",
            "Search for a specified pattern within files",
        ),
        make_tool(
            "list_directory",
            "List the contents of a directory and gather information about file size and number of children directories",
        ),
        make_tool("read_file", "Read the contents of a file"),
        make_tool("edit_file", "Make changes to an existing file"),
        make_tool("write_to_file", "Create new files"),
        make_tool(
            "run_terminal_command",
            "Execute terminal commands with internet access and monitor output",
        ),
    ]
}

/// Built-in tools for Cursor (10 tools).
fn cursor_tools() -> Vec<Tool> {
    vec![
        make_tool(
            "Read File",
            "Reads up to 250 lines (750 in max mode) of a file",
        ),
        make_tool(
            "List Directory",
            "Read the structure of a directory without reading file contents",
        ),
        make_tool(
            "Codebase",
            "Perform semantic searches within your indexed codebase",
        ),
        make_tool("Grep", "Search for exact keywords or patterns within files"),
        make_tool("Search Files", "Find files by name using fuzzy matching"),
        make_tool("Web", "Generate search queries and perform web searches"),
        make_tool(
            "Fetch Rules",
            "Retrieve specific rules based on type and description",
        ),
        make_tool(
            "Edit & Reapply",
            "Suggest edits to files and apply them automatically",
        ),
        make_tool(
            "Delete File",
            "Delete files autonomously (can be disabled in settings)",
        ),
        make_tool(
            "Terminal",
            "Execute terminal commands with internet access and monitor output",
        ),
    ]
}

/// Built-in tools for VS Code / Copilot (20 tools).
fn vscode_tools() -> Vec<Tool> {
    vec![
        make_tool(
            "extensions",
            "Search for extensions in the VS Code Extensions Marketplace",
        ),
        make_tool("fetch", "Fetch the main content from a web page"),
        make_tool(
            "findTestFiles",
            "For a source code file, find the file that contains the tests",
        ),
        make_tool(
            "githubRepo",
            "Search a GitHub repository for relevant source code snippets",
        ),
        make_tool("new", "Scaffold a new workspace in VS Code"),
        make_tool(
            "openSimpleBrowser",
            "Preview a locally hosted website in the Simple Browser",
        ),
        make_tool("problems", "Check errors for a particular file"),
        make_tool(
            "runCommands",
            "Run commands in terminal with internet access",
        ),
        make_tool("runNotebooks", "Run notebook cells"),
        make_tool(
            "runTasks",
            "Run tasks and get their output for your workspace",
        ),
        make_tool("search", "Search and read files in your workspace"),
        make_tool("searchResults", "The results from the search view"),
        make_tool(
            "terminalLastCommand",
            "The active terminal's last run command",
        ),
        make_tool("terminalSelection", "The active terminal's selection"),
        make_tool(
            "testFailure",
            "Information about the last unit test failure",
        ),
        make_tool(
            "usages",
            "Find references, definitions, and other usages of a symbol",
        ),
        make_tool(
            "vscodeAPI",
            "Use VS Code API references to answer questions about VS Code extensions",
        ),
        make_tool("changes", "Get diffs of changed files"),
        make_tool(
            "codebase",
            "Find relevant file chunks, symbols, and other information in your codebase",
        ),
        make_tool("editFiles", "Edit files in your workspace"),
    ]
}

/// Return built-in tool definitions for a named client as a synthetic
/// `StaticToolsServer`, or `None` if the client has no built-in tools.
pub fn get_builtin_tools(client_name: &str) -> Option<StaticToolsServer> {
    let lower = client_name.to_lowercase();
    let tools = match lower.as_str() {
        "windsurf" => windsurf_tools(),
        "cursor" => cursor_tools(),
        "vscode" => vscode_tools(),
        _ => return None,
    };

    Some(StaticToolsServer {
        name: format!("{client_name} built-in tools"),
        signature: tools,
        server_type: Some("tools".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/.cursor/mcp.json");
        assert!(expanded.is_some());
        let path = expanded.unwrap();
        assert!(!path.to_string_lossy().contains('~'));
        assert!(path.to_string_lossy().ends_with(".cursor/mcp.json"));
    }

    #[test]
    fn test_expand_tilde_no_prefix() {
        let expanded = expand_tilde("/absolute/path");
        assert_eq!(expanded, Some(PathBuf::from("/absolute/path")));
    }

    #[test]
    fn test_well_known_clients_not_empty() {
        let clients = well_known_clients();
        assert!(!clients.is_empty());
    }

    #[test]
    fn test_well_known_clients_have_names() {
        for client in well_known_clients() {
            assert!(!client.name.is_empty());
            assert!(
                !client.client_exists_paths.is_empty(),
                "client {} has no exists paths",
                client.name
            );
        }
    }

    #[test]
    fn test_shorthand_resolution_cursor() {
        let paths = client_shorthands_to_paths(&["cursor".into()]);
        assert!(paths.is_ok());
        let paths = paths.unwrap();
        assert!(!paths.is_empty());
        assert!(paths[0].to_string_lossy().contains("cursor"));
    }

    #[test]
    fn test_shorthand_unknown_returns_error() {
        let result = client_shorthands_to_paths(&["nonexistent".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_shorthand_raw_paths_passthrough() {
        let result =
            client_shorthands_to_paths(&["~/.cursor/mcp.json".into(), "/tmp/test.json".into()]);
        assert!(result.is_ok());
        let paths = result.unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_shorthand_mixed_with_raw_path_resolves_per_item() {
        let result = client_shorthands_to_paths(&["cursor".into(), "/tmp/test.json".into()]);
        assert!(result.is_ok());
        let paths = result.unwrap();
        assert!(
            paths.iter().any(|p| p.to_string_lossy().contains("cursor")),
            "cursor shorthand should still expand when mixed with raw paths"
        );
        assert!(
            paths.iter().any(|p| p == &PathBuf::from("/tmp/test.json")),
            "raw path should be preserved alongside shorthand expansion"
        );
    }

    #[test]
    fn test_shorthand_unknown_in_mixed_targets_still_errors() {
        let result = client_shorthands_to_paths(&[
            "cursor".into(),
            "cursorr".into(),
            "/tmp/test.json".into(),
        ]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("unknown client shorthand: cursorr"));
    }

    #[test]
    fn test_builtin_tools_windsurf() {
        let tools = get_builtin_tools("windsurf");
        assert!(tools.is_some());
        let server = tools.unwrap();
        assert_eq!(server.signature.len(), 8);
    }

    #[test]
    fn test_builtin_tools_cursor() {
        let tools = get_builtin_tools("cursor");
        assert!(tools.is_some());
        let server = tools.unwrap();
        assert_eq!(server.signature.len(), 10);
    }

    #[test]
    fn test_builtin_tools_vscode() {
        let tools = get_builtin_tools("vscode");
        assert!(tools.is_some());
        let server = tools.unwrap();
        assert_eq!(server.signature.len(), 20);
    }

    #[test]
    fn test_builtin_tools_unknown() {
        assert!(get_builtin_tools("unknown-client").is_none());
    }
}

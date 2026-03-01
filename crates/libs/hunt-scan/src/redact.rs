//! Sensitive data redaction.
//!
//! All functions in this module **mutate** scan results in-place, replacing
//! sensitive values with [`REDACTED`]. Redaction is applied *before* data leaves
//! the machine (i.e., before posting to the verification API).

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::models::{ScanError, ScanPathResult, ServerConfig};

/// Sentinel replacement for redacted values.
pub const REDACTED: &str = "**REDACTED**";

// ---------------------------------------------------------------------------
// Pre-compiled regex patterns (compiled once via LazyLock)
// ---------------------------------------------------------------------------

// These regex patterns are known-valid string literals, so the `unwrap` calls
// inside `LazyLock` initialisers are safe.  We suppress the clippy lint here
// rather than adding fallible initialisation for patterns that can never fail.

/// Unix absolute paths — at least one directory component (`/dir/file`).
#[allow(clippy::expect_used)]
static RE_UNIX_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"/(?:[^/\s"'<>|:]+/)+[^/\s"'<>|:]*"#).expect("RE_UNIX_PATH is a valid regex")
});

/// Home-directory paths (`~/...`).
#[allow(clippy::expect_used)]
static RE_HOME_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"~/[^\s"'<>|:]+"#).expect("RE_HOME_PATH is a valid regex"));

/// Windows absolute paths (`C:\...` or `C:/...`).
#[allow(clippy::expect_used)]
static RE_WIN_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[A-Za-z]:[/\\](?:[^/\\\s"'<>|:]+[/\\])*[^/\\\s"'<>|:]*"#)
        .expect("RE_WIN_PATH is a valid regex")
});

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Top-level redaction entry point — redacts all sensitive data inside
/// `results` in-place.
pub fn redact_scan_results(results: &mut [ScanPathResult]) {
    for result in results.iter_mut() {
        // Path-level error traceback.
        redact_error(&mut result.error);

        // Per-server redaction.
        if let Some(servers) = result.servers.as_mut() {
            for server in servers.iter_mut() {
                redact_server_config(&mut server.server);
                redact_error(&mut server.error);
            }
        }
    }
}

/// Replace absolute paths (Unix, home, Windows) in a text string with
/// [`REDACTED`].
pub fn redact_paths(text: &str) -> String {
    let result = RE_HOME_PATH.replace_all(text, REDACTED);
    let result = RE_WIN_PATH.replace_all(&result, REDACTED);
    RE_UNIX_PATH.replace_all(&result, REDACTED).into_owned()
}

/// Redact CLI argument values.
///
/// * `--flag value` → `--flag **REDACTED**`
/// * `--flag=value` → `--flag=**REDACTED**`
/// * The `-y` flag (npx auto-confirm) is preserved along with its next arg.
/// * Positional arguments that look like file paths are redacted.
pub fn redact_args(args: &[String]) -> Vec<String> {
    let mut redacted: Vec<String> = Vec::with_capacity(args.len());
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        if arg.starts_with('-') && arg.contains('=') {
            // --flag=value or -f=value — redact the value portion.
            if let Some(eq_idx) = arg.find('=') {
                let flag_part = &arg[..=eq_idx]; // includes '='
                redacted.push(format!("{flag_part}{REDACTED}"));
            }
            i += 1;
        } else if arg.starts_with('-') && arg != "-y" {
            redacted.push(arg.clone());
            // Look ahead: if the next arg is not a flag, treat it as a value.
            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                redacted.push(REDACTED.to_string());
                i += 2;
            } else {
                i += 1;
            }
        } else if is_path(arg) {
            redacted.push(REDACTED.to_string());
            i += 1;
        } else {
            redacted.push(arg.clone());
            i += 1;
        }
    }

    redacted
}

/// Redact all values in an environment variable map (keys preserved).
pub fn redact_env(env: &HashMap<String, String>) -> HashMap<String, String> {
    env.keys()
        .map(|k| (k.clone(), REDACTED.to_string()))
        .collect()
}

/// Redact all values in an HTTP header map (keys preserved).
pub fn redact_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .keys()
        .map(|k| (k.clone(), REDACTED.to_string()))
        .collect()
}

/// Redact query parameter values in a URL string (keys preserved).
///
/// If the URL has no query string, or if parsing fails, the original string is
/// returned unchanged.
pub fn redact_url_params(url_str: &str) -> String {
    let Ok(parsed) = url::Url::parse(url_str) else {
        return url_str.to_string();
    };

    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, _)| (k.into_owned(), REDACTED.to_string()))
        .collect();

    if pairs.is_empty() {
        return url_str.to_string();
    }

    let mut out = parsed.clone();
    {
        let mut qs = out.query_pairs_mut();
        qs.clear();
        for (k, v) in &pairs {
            qs.append_pair(k, v);
        }
    }
    out.to_string()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Dispatch server-config-specific redaction.
fn redact_server_config(config: &mut ServerConfig) {
    match config {
        ServerConfig::Stdio(stdio) => {
            if let Some(ref env) = stdio.env {
                stdio.env = Some(redact_env(env));
            }
            if let Some(ref args) = stdio.args {
                stdio.args = Some(redact_args(args));
            }
        }
        ServerConfig::Sse(remote) | ServerConfig::Http(remote) => {
            if !remote.headers.is_empty() {
                remote.headers = redact_headers(&remote.headers);
            }
            remote.url = redact_url_params(&remote.url);
        }
        // Skill and Tools configs have no sensitive fields.
        ServerConfig::Skill(_) | ServerConfig::Tools(_) => {}
    }
}

/// Redact absolute paths in a `ScanError`'s traceback and server_output.
fn redact_error(error: &mut Option<ScanError>) {
    let Some(err) = error.as_mut() else {
        return;
    };
    if let Some(ref tb) = err.traceback {
        err.traceback = Some(redact_paths(tb));
    }
    if let Some(ref so) = err.server_output {
        err.server_output = Some(redact_paths(so));
    }
}

/// Returns `true` when the argument looks like a file path that should be
/// redacted.
fn is_path(arg: &str) -> bool {
    // Unix absolute path
    if arg.starts_with('/') && arg.len() > 1 {
        return true;
    }
    // Home-directory path
    if arg.starts_with("~/") {
        return true;
    }
    // Windows absolute path (e.g. C:\, D:/)
    let bytes = arg.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- redact_paths ---------------------------------------------------------

    #[test]
    fn test_redact_unix_path() {
        let input = "Error at /home/user/.config/app/secret.key";
        let result = redact_paths(input);
        assert!(!result.contains("/home/user"));
        assert!(result.contains(REDACTED));
    }

    #[test]
    fn test_redact_home_path() {
        let input = "Found config at ~/Library/Application Support/app/config.json";
        let result = redact_paths(input);
        assert!(!result.contains("~/Library"));
        assert!(result.contains(REDACTED));
    }

    #[test]
    fn test_redact_windows_path() {
        let input = r"Config at C:\Users\me\AppData\secret.txt";
        let result = redact_paths(input);
        assert!(!result.contains(r"C:\Users"));
        assert!(result.contains(REDACTED));
    }

    #[test]
    fn test_redact_paths_preserves_non_path_text() {
        let input = "This is a normal message with no paths.";
        assert_eq!(redact_paths(input), input);
    }

    // -- redact_args ----------------------------------------------------------

    #[test]
    fn test_redact_flag_value() {
        let args: Vec<String> = vec!["--api-key".into(), "secret123".into()];
        let result = redact_args(&args);
        assert_eq!(result, vec!["--api-key", REDACTED]);
    }

    #[test]
    fn test_redact_flag_equals_value() {
        let args: Vec<String> = vec!["--api-key=secret123".into()];
        let result = redact_args(&args);
        assert_eq!(result, vec![format!("--api-key={REDACTED}")]);
    }

    #[test]
    fn test_redact_preserves_boolean_y_flag() {
        let args: Vec<String> = vec!["-y".into(), "package-name".into()];
        let result = redact_args(&args);
        assert_eq!(result, vec!["-y", "package-name"]);
    }

    #[test]
    fn test_redact_file_path_arg() {
        let args: Vec<String> = vec!["/etc/secret/key.pem".into()];
        let result = redact_args(&args);
        assert_eq!(result, vec![REDACTED]);
    }

    #[test]
    fn test_redact_home_path_arg() {
        let args: Vec<String> = vec!["~/.ssh/id_rsa".into()];
        let result = redact_args(&args);
        assert_eq!(result, vec![REDACTED]);
    }

    // -- redact_env / redact_headers -----------------------------------------

    #[test]
    fn test_redact_env() {
        let env = HashMap::from([
            ("API_KEY".into(), "secret".into()),
            ("DB_PASS".into(), "hunter2".into()),
        ]);
        let redacted = redact_env(&env);
        assert_eq!(redacted.len(), 2);
        assert_eq!(redacted["API_KEY"], REDACTED);
        assert_eq!(redacted["DB_PASS"], REDACTED);
    }

    #[test]
    fn test_redact_headers() {
        let headers = HashMap::from([("Authorization".into(), "Bearer abc123".into())]);
        let redacted = redact_headers(&headers);
        assert_eq!(redacted["Authorization"], REDACTED);
    }

    // -- redact_url_params ----------------------------------------------------

    #[test]
    fn test_redact_url_params_basic() {
        let url = "https://example.com/api?token=abc&user=admin";
        let result = redact_url_params(url);
        assert!(result.contains("token="));
        assert!(result.contains(REDACTED));
        assert!(!result.contains("abc"));
        assert!(!result.contains("admin"));
    }

    #[test]
    fn test_redact_url_params_no_query() {
        let url = "https://example.com/api";
        assert_eq!(redact_url_params(url), url);
    }

    #[test]
    fn test_redact_url_params_invalid_url() {
        let url = "not a url";
        assert_eq!(redact_url_params(url), url);
    }

    // -- is_path --------------------------------------------------------------

    #[test]
    fn test_is_path_unix() {
        assert!(is_path("/etc/passwd"));
        assert!(!is_path("/")); // single slash
    }

    #[test]
    fn test_is_path_home() {
        assert!(is_path("~/Documents/file.txt"));
    }

    #[test]
    fn test_is_path_windows() {
        assert!(is_path(r"C:\Users\me\file"));
        assert!(is_path("D:/data/file"));
    }

    #[test]
    fn test_is_path_not_path() {
        assert!(!is_path("package-name"));
        assert!(!is_path("-y"));
        assert!(!is_path("--verbose"));
    }

    // -- redact_scan_results (integration) ------------------------------------

    #[test]
    fn test_redact_scan_results_stdio_server() {
        let mut results = vec![ScanPathResult {
            client: Some("cursor".into()),
            path: "/home/user/.cursor/mcp.json".into(),
            servers: Some(vec![crate::models::ServerScanResult {
                name: Some("my-server".into()),
                server: ServerConfig::Stdio(crate::models::StdioServer {
                    command: "node".into(),
                    args: Some(vec!["--port".into(), "3000".into()]),
                    server_type: Some("stdio".into()),
                    env: Some(HashMap::from([("API_KEY".into(), "secret123".into())])),
                    binary_identifier: None,
                }),
                signature: None,
                error: None,
            }]),
            issues: vec![],
            labels: vec![],
            policy_violations: vec![],
            error: None,
        }];

        redact_scan_results(&mut results);

        match &results[0].servers.as_ref().unwrap()[0].server {
            ServerConfig::Stdio(s) => {
                // Env should be redacted
                let env = s.env.as_ref().unwrap();
                assert_eq!(env["API_KEY"], REDACTED);
                // Args should be redacted
                let args = s.args.as_ref().unwrap();
                assert_eq!(args[0], "--port");
                assert_eq!(args[1], REDACTED);
            }
            _ => panic!("expected Stdio server"),
        }
    }

    #[test]
    fn test_redact_scan_results_remote_server() {
        let mut results = vec![ScanPathResult {
            client: None,
            path: "test.json".into(),
            servers: Some(vec![crate::models::ServerScanResult {
                name: Some("remote".into()),
                server: ServerConfig::Http(crate::models::RemoteServer {
                    url: "https://example.com/mcp?token=secret".into(),
                    server_type: Some("http".into()),
                    headers: HashMap::from([("Authorization".into(), "Bearer tok123".into())]),
                }),
                signature: None,
                error: None,
            }]),
            issues: vec![],
            labels: vec![],
            policy_violations: vec![],
            error: None,
        }];

        redact_scan_results(&mut results);

        match &results[0].servers.as_ref().unwrap()[0].server {
            ServerConfig::Http(s) => {
                // URL params should be redacted
                assert!(!s.url.contains("secret"));
                assert!(s.url.contains(REDACTED));
                // Headers should be redacted
                assert_eq!(s.headers["Authorization"], REDACTED);
            }
            _ => panic!("expected Http server"),
        }
    }

    #[test]
    fn test_redact_scan_results_with_error_traceback() {
        let mut results = vec![ScanPathResult {
            client: None,
            path: "test.json".into(),
            servers: None,
            issues: vec![],
            labels: vec![],
            policy_violations: vec![],
            error: Some(ScanError {
                message: Some("failed".into()),
                exception: None,
                traceback: Some("at /home/user/.config/app/module.js:42".into()),
                is_failure: true,
                category: Some(crate::models::ErrorCategory::ServerStartup),
                server_output: Some("error in /home/user/project/server.js".into()),
            }),
        }];

        redact_scan_results(&mut results);

        let err = results[0].error.as_ref().unwrap();
        let tb = err.traceback.as_ref().unwrap();
        assert!(!tb.contains("/home/user"));
        assert!(tb.contains(REDACTED));
        let so = err.server_output.as_ref().unwrap();
        assert!(!so.contains("/home/user"));
    }

    #[test]
    fn test_redact_args_multiple_flags() {
        let args: Vec<String> = vec![
            "--host".into(),
            "localhost".into(),
            "--port".into(),
            "3000".into(),
            "-v".into(),
        ];
        let result = redact_args(&args);
        assert_eq!(result[0], "--host");
        assert_eq!(result[1], REDACTED);
        assert_eq!(result[2], "--port");
        assert_eq!(result[3], REDACTED);
        assert_eq!(result[4], "-v"); // single-char flag, next is nothing
    }

    #[test]
    fn test_redact_args_windows_path() {
        let args: Vec<String> = vec![r"C:\Users\me\project\config.json".into()];
        let result = redact_args(&args);
        assert_eq!(result, vec![REDACTED]);
    }

    #[test]
    fn test_redact_env_empty() {
        let env: HashMap<String, String> = HashMap::new();
        let redacted = redact_env(&env);
        assert!(redacted.is_empty());
    }

    #[test]
    fn test_redact_headers_empty() {
        let headers: HashMap<String, String> = HashMap::new();
        let redacted = redact_headers(&headers);
        assert!(redacted.is_empty());
    }

    #[test]
    fn test_redact_multiple_paths_in_text() {
        let input = "loaded /etc/config/a.json then /var/lib/b.json";
        let result = redact_paths(input);
        assert!(!result.contains("/etc/config"));
        assert!(!result.contains("/var/lib"));
    }
}

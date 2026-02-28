//! Correlation rule YAML schema, parsing, and validation.
//!
//! Rules follow a SIGMA-inspired format tailored for AI agent security events.
//! Schema version: `clawdstrike.hunt.correlation.v1`.

use std::path::PathBuf;

use chrono::Duration;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The only supported schema identifier.
const SUPPORTED_SCHEMA: &str = "clawdstrike.hunt.correlation.v1";

// ---------------------------------------------------------------------------
// Duration helpers
// ---------------------------------------------------------------------------

/// Parse a human-readable duration string such as `"30s"`, `"5m"`, `"1h"`, `"2d"`.
///
/// Supports multi-character suffixes like `"sec"`, `"min"`, `"hrs"`, `"days"`.
/// Returns `None` if the string cannot be parsed.
pub fn parse_duration_str(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Split at the boundary between digits and the alphabetic suffix.
    let digit_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if digit_end == 0 || digit_end == s.len() {
        return None;
    }

    // Guard against splitting inside a multi-byte UTF-8 sequence (e.g. "30秒").
    if !s.is_char_boundary(digit_end) {
        return None;
    }

    let digits = &s[..digit_end];
    let suffix = s[digit_end..].trim();
    let value: i64 = digits.parse().ok()?;

    match suffix.to_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => Some(Duration::seconds(value)),
        "m" | "min" | "mins" | "minute" | "minutes" => Some(Duration::minutes(value)),
        "h" | "hr" | "hrs" | "hour" | "hours" => Some(Duration::hours(value)),
        "d" | "day" | "days" => Some(Duration::days(value)),
        _ => None,
    }
}

/// Format a `Duration` back to a human-readable string.
fn format_duration(dur: &Duration) -> String {
    let secs = dur.num_seconds();
    if secs != 0 && secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs != 0 && secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs != 0 && secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Serde deserializer for duration strings (`"30s"`, `"5m"`, etc.).
fn deserialize_duration<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_duration_str(&s).ok_or_else(|| de::Error::custom(format!("invalid duration: {s}")))
}

/// Serde serializer for duration → string.
fn serialize_duration<S>(dur: &Duration, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format_duration(dur))
}

/// Serde deserializer for optional duration strings.
fn deserialize_duration_opt<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            let dur = parse_duration_str(&s)
                .ok_or_else(|| de::Error::custom(format!("invalid duration: {s}")))?;
            Ok(Some(dur))
        }
    }
}

/// Serde serializer for optional duration → string.
fn serialize_duration_opt<S>(
    opt: &Option<Duration>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match opt {
        Some(dur) => serializer.serialize_some(&format_duration(dur)),
        None => serializer.serialize_none(),
    }
}

// ---------------------------------------------------------------------------
// Source field helper (accepts single string or list)
// ---------------------------------------------------------------------------

/// Serde deserializer that accepts both a single string and a list of strings,
/// normalizing to `Vec<String>`.
fn deserialize_string_or_list<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrList {
        Single(String),
        List(Vec<String>),
    }
    match StringOrList::deserialize(deserializer)? {
        StringOrList::Single(s) => Ok(vec![s]),
        StringOrList::List(v) => Ok(v),
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Severity level for a correlation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single condition within a correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    /// Event sources to match (e.g. `["receipt", "hubble"]`).
    #[serde(deserialize_with = "deserialize_string_or_list")]
    pub source: Vec<String>,

    /// Required action type (e.g. `"file"`, `"egress"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,

    /// Required verdict (e.g. `"allow"`, `"deny"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,

    /// Regex pattern that the target must match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pattern: Option<String>,

    /// Regex pattern that the target must *not* match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_target_pattern: Option<String>,

    /// Bind name of a prior condition that must fire before this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,

    /// Sub-window: maximum time after the `after` condition fires.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_duration_opt",
        serialize_with = "serialize_duration_opt"
    )]
    pub within: Option<Duration>,

    /// Bind name for cross-referencing this condition in `after` and `output.evidence`.
    pub bind: String,
}

/// Output configuration when a correlation rule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOutput {
    /// Alert title.
    pub title: String,
    /// Bind names of conditions whose matched events are included as evidence.
    pub evidence: Vec<String>,
}

/// A correlation rule loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    /// Schema identifier — must be `clawdstrike.hunt.correlation.v1`.
    pub schema: String,
    /// Human-readable rule name.
    pub name: String,
    /// Severity level.
    pub severity: RuleSeverity,
    /// Rule description.
    pub description: String,
    /// Global sliding window for event correlation.
    #[serde(
        deserialize_with = "deserialize_duration",
        serialize_with = "serialize_duration"
    )]
    pub window: Duration,
    /// Conditions that must fire in sequence for the rule to trigger.
    pub conditions: Vec<RuleCondition>,
    /// Output configuration.
    pub output: RuleOutput,
}

// ---------------------------------------------------------------------------
// Parsing & validation
// ---------------------------------------------------------------------------

/// Validate a parsed correlation rule.
///
/// Checks:
/// - Schema must equal `clawdstrike.hunt.correlation.v1`.
/// - At least one condition is required.
/// - All `after` references must point to a bind name defined by an earlier condition.
/// - All `output.evidence` entries must reference a valid bind name.
/// - `within` durations must not exceed the global `window`.
pub fn validate_rule(rule: &CorrelationRule) -> Result<()> {
    // Schema check.
    if rule.schema != SUPPORTED_SCHEMA {
        return Err(Error::InvalidRule(format!(
            "unsupported schema '{}', expected '{SUPPORTED_SCHEMA}'",
            rule.schema
        )));
    }

    // Must have at least one condition.
    if rule.conditions.is_empty() {
        return Err(Error::InvalidRule(
            "rule must have at least one condition".to_string(),
        ));
    }

    // Collect bind names in declaration order to validate forward references.
    let mut known_binds: Vec<&str> = Vec::new();

    for (i, cond) in rule.conditions.iter().enumerate() {
        // Validate `after` references.
        if let Some(ref after) = cond.after {
            if !known_binds.contains(&after.as_str()) {
                return Err(Error::InvalidRule(format!(
                    "condition {i} references unknown bind '{after}' in 'after'"
                )));
            }
        }

        // Validate `within` does not exceed global window.
        if let Some(within) = cond.within {
            if within > rule.window {
                return Err(Error::InvalidRule(format!(
                    "condition {i} 'within' ({within}) exceeds global window ({})",
                    rule.window
                )));
            }
        }

        // Reject duplicate bind names — two conditions sharing a name cause
        // premature alert firing because the correlator cannot distinguish
        // which condition actually matched.
        if known_binds.contains(&cond.bind.as_str()) {
            return Err(Error::InvalidRule(format!(
                "condition {i} reuses bind name '{}'; bind names must be unique",
                cond.bind
            )));
        }

        known_binds.push(&cond.bind);
    }

    // Validate output evidence references.
    for ev in &rule.output.evidence {
        if !known_binds.contains(&ev.as_str()) {
            return Err(Error::InvalidRule(format!(
                "output evidence references unknown bind '{ev}'"
            )));
        }
    }

    Ok(())
}

/// Parse a single correlation rule from a YAML string, then validate it.
pub fn parse_rule(yaml_str: &str) -> Result<CorrelationRule> {
    let rule: CorrelationRule =
        serde_yaml::from_str(yaml_str).map_err(|e| Error::Yaml(e.to_string()))?;
    validate_rule(&rule)?;
    Ok(rule)
}

/// Load and parse correlation rules from a list of YAML file paths.
///
/// Each file should contain a single rule document.
pub fn load_rules_from_files(paths: &[PathBuf]) -> Result<Vec<CorrelationRule>> {
    let mut rules = Vec::with_capacity(paths.len());
    for path in paths {
        let content = std::fs::read_to_string(path)?;
        let rule = parse_rule(&content)?;
        rules.push(rule);
    }
    Ok(rules)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_RULE: &str = r#"
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
    not_target_pattern: "^(localhost|127\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"
    after: file_access
    within: 30s
    bind: egress_event
output:
  title: "Potential data exfiltration via MCP tool"
  evidence:
    - file_access
    - egress_event
"#;

    #[test]
    fn parse_valid_rule() {
        let rule = parse_rule(EXAMPLE_RULE).unwrap();
        assert_eq!(rule.schema, "clawdstrike.hunt.correlation.v1");
        assert_eq!(rule.name, "MCP Tool Exfiltration Attempt");
        assert_eq!(rule.severity, RuleSeverity::High);
        assert_eq!(rule.window, Duration::seconds(30));
        assert_eq!(rule.conditions.len(), 2);

        // First condition — single source string deserialized to vec.
        assert_eq!(rule.conditions[0].source, vec!["receipt".to_string()]);
        assert_eq!(rule.conditions[0].action_type.as_deref(), Some("file"));
        assert_eq!(rule.conditions[0].verdict.as_deref(), Some("allow"));
        assert!(rule.conditions[0].target_pattern.is_some());
        assert!(rule.conditions[0].after.is_none());
        assert!(rule.conditions[0].within.is_none());
        assert_eq!(rule.conditions[0].bind, "file_access");

        // Second condition — list source, after + within.
        assert_eq!(
            rule.conditions[1].source,
            vec!["receipt".to_string(), "hubble".to_string()]
        );
        assert_eq!(rule.conditions[1].after.as_deref(), Some("file_access"));
        assert_eq!(rule.conditions[1].within, Some(Duration::seconds(30)));
        assert_eq!(rule.conditions[1].bind, "egress_event");

        // Output.
        assert_eq!(
            rule.output.title,
            "Potential data exfiltration via MCP tool"
        );
        assert_eq!(
            rule.output.evidence,
            vec!["file_access".to_string(), "egress_event".to_string()]
        );
    }

    #[test]
    fn parse_single_source_string() {
        let yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: "Single source test"
severity: low
description: "test"
window: 5m
conditions:
  - source: tetragon
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"#;
        let rule = parse_rule(yaml).unwrap();
        assert_eq!(rule.conditions[0].source, vec!["tetragon".to_string()]);
    }

    #[test]
    fn reject_unknown_schema() {
        let yaml = r#"
schema: clawdstrike.hunt.correlation.v99
name: "Bad schema"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported schema"), "got: {msg}");
    }

    #[test]
    fn reject_empty_conditions() {
        let yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: "No conditions"
severity: medium
description: "test"
window: 10s
conditions: []
output:
  title: "test"
  evidence: []
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("at least one condition"), "got: {msg}");
    }

    #[test]
    fn reject_invalid_after_reference() {
        let yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: "Bad after ref"
severity: high
description: "test"
window: 30s
conditions:
  - source: receipt
    after: nonexistent
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown bind 'nonexistent'"), "got: {msg}");
    }

    #[test]
    fn reject_invalid_evidence_reference() {
        let yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: "Bad evidence ref"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - missing_bind
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown bind 'missing_bind'"), "got: {msg}");
    }

    #[test]
    fn reject_within_exceeding_window() {
        let yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: "Within exceeds window"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: first
  - source: hubble
    after: first
    within: 60s
    bind: second
output:
  title: "test"
  evidence:
    - first
    - second
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds global window"), "got: {msg}");
    }

    #[test]
    fn parse_duration_str_various() {
        assert_eq!(parse_duration_str("30s"), Some(Duration::seconds(30)));
        assert_eq!(parse_duration_str("5m"), Some(Duration::minutes(5)));
        assert_eq!(parse_duration_str("1h"), Some(Duration::hours(1)));
        assert_eq!(parse_duration_str("2d"), Some(Duration::days(2)));
        assert_eq!(parse_duration_str("0s"), Some(Duration::seconds(0)));
        assert_eq!(parse_duration_str(""), None);
        assert_eq!(parse_duration_str("abc"), None);
        assert_eq!(parse_duration_str("10x"), None);
        assert_eq!(parse_duration_str("s"), None);
    }

    #[test]
    fn parse_duration_str_multi_char_suffixes() {
        assert_eq!(parse_duration_str("30sec"), Some(Duration::seconds(30)));
        assert_eq!(parse_duration_str("5min"), Some(Duration::minutes(5)));
        assert_eq!(parse_duration_str("5mins"), Some(Duration::minutes(5)));
        assert_eq!(parse_duration_str("1hr"), Some(Duration::hours(1)));
        assert_eq!(parse_duration_str("2hrs"), Some(Duration::hours(2)));
        assert_eq!(parse_duration_str("1hour"), Some(Duration::hours(1)));
        assert_eq!(parse_duration_str("3days"), Some(Duration::days(3)));
        assert_eq!(parse_duration_str("1day"), Some(Duration::days(1)));
        assert_eq!(parse_duration_str("10seconds"), Some(Duration::seconds(10)));
        assert_eq!(parse_duration_str("2minutes"), Some(Duration::minutes(2)));
    }

    #[test]
    fn parse_duration_str_multibyte_utf8_returns_none() {
        // Multi-byte UTF-8 suffixes must not panic (previously used split_at
        // which could panic on non-ASCII boundaries).
        assert_eq!(parse_duration_str("30秒"), None);
        assert_eq!(parse_duration_str("5分"), None);
        assert_eq!(parse_duration_str("1時間"), None);
        // Emoji suffix.
        assert_eq!(parse_duration_str("10🕐"), None);
    }

    #[test]
    fn reject_duplicate_bind_names() {
        let yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: "Duplicate bind"
severity: high
description: "test"
window: 30s
conditions:
  - source: receipt
    action_type: file
    bind: evt
  - source: hubble
    action_type: egress
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"#;
        let err = parse_rule(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("reuses bind name 'evt'"),
            "expected duplicate bind error, got: {msg}"
        );
    }

    #[test]
    fn load_rules_from_temp_files() {
        let dir = tempfile::tempdir().unwrap();

        let rule1_path = dir.path().join("rule1.yaml");
        std::fs::write(&rule1_path, EXAMPLE_RULE).unwrap();

        let rule2_yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: "Lateral movement"
severity: critical
description: "Detects lateral movement patterns"
window: 5m
conditions:
  - source: tetragon
    action_type: process
    bind: proc
output:
  title: "Lateral movement detected"
  evidence:
    - proc
"#;
        let rule2_path = dir.path().join("rule2.yaml");
        std::fs::write(&rule2_path, rule2_yaml).unwrap();

        let rules = load_rules_from_files(&[rule1_path, rule2_path]).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "MCP Tool Exfiltration Attempt");
        assert_eq!(rules[1].name, "Lateral movement");
        assert_eq!(rules[1].severity, RuleSeverity::Critical);
    }

    #[test]
    fn load_rules_missing_file() {
        let result = load_rules_from_files(&[PathBuf::from("/nonexistent/rule.yaml")]);
        assert!(result.is_err());
    }

    #[test]
    fn severity_serde_roundtrip() {
        let yaml = serde_yaml::to_string(&RuleSeverity::Critical).unwrap();
        assert!(yaml.contains("critical"));
        let back: RuleSeverity = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back, RuleSeverity::Critical);
    }

    #[test]
    fn rule_serialization_roundtrip() {
        let rule = parse_rule(EXAMPLE_RULE).unwrap();
        let serialized = serde_yaml::to_string(&rule).unwrap();
        let reparsed: CorrelationRule = serde_yaml::from_str(&serialized).unwrap();
        assert_eq!(reparsed.name, rule.name);
        assert_eq!(reparsed.conditions.len(), rule.conditions.len());
    }
}

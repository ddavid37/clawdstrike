//! Natural-language to HuntQuery translation.
//!
//! Extracts structured query parameters from free-text input.

use std::sync::LazyLock;

use chrono::{Duration, Utc};
use regex::Regex;

use crate::query::{EventSource, HuntQuery, QueryVerdict};

// Compiled regexes — all patterns are compile-time-known literals that cannot fail.
#[allow(clippy::expect_used)]
static TIME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\blast\s+(\d+)\s+(hour|minute|day|min|hr|sec|second)s?\b")
        .expect("valid regex")
});

#[allow(clippy::expect_used)]
static TODAY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\btoday\b").expect("valid regex"));

#[allow(clippy::expect_used)]
static YESTERDAY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\byesterday\b").expect("valid regex"));

#[allow(clippy::expect_used)]
static VERDICT_DENY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(denied|blocked|deny|block)\b").expect("valid regex"));

#[allow(clippy::expect_used)]
static VERDICT_ALLOW_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(allowed|passed|allow|pass)\b").expect("valid regex"));

#[allow(clippy::expect_used)]
static VERDICT_WARN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(warned|warning|warn)\b").expect("valid regex"));

#[allow(clippy::expect_used)]
static SOURCE_TETRAGON_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(tetragon|kernel|process\s+events?)\b").expect("valid regex")
});

#[allow(clippy::expect_used)]
static SOURCE_HUBBLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(hubble|network\s+flow|flows?)\b").expect("valid regex"));

#[allow(clippy::expect_used)]
static ACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(egress|file|shell|command|mcp|tool)\b").expect("valid regex")
});

#[allow(clippy::expect_used)]
static PROCESS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:process|binary)\s+(\S+)").expect("valid regex"));

/// Words that commonly follow "process" or "binary" in NL queries but are
/// not actual process/binary names. Used to avoid false matches.
const PROCESS_STOPWORDS: &[&str] = &[
    "events",
    "event",
    "logs",
    "log",
    "data",
    "info",
    "information",
    "list",
    "activity",
    "actions",
    "action",
    "results",
    "result",
    "output",
    "details",
    "history",
    "metrics",
    "stats",
    "statistics",
    "traces",
    "trace",
    "records",
    "record",
    "entries",
    "entry",
];

#[allow(clippy::expect_used)]
static NAMESPACE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:namespace|ns)\s+(\S+)").expect("valid regex"));

#[allow(clippy::expect_used)]
static POD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bpod\s+(\S+)").expect("valid regex"));

/// Apply natural language keywords to a `HuntQuery`, setting fields.
pub fn apply_nl_query(query: &mut HuntQuery, nl: &str) {
    // Time extraction
    if let Some(caps) = TIME_RE.captures(nl) {
        if let Ok(n) = caps[1].parse::<i64>() {
            let unit = caps[2].to_lowercase();
            let duration = match unit.as_str() {
                "hour" | "hr" => Duration::hours(n),
                "minute" | "min" => Duration::minutes(n),
                "day" => Duration::days(n),
                "second" | "sec" => Duration::seconds(n),
                _ => Duration::hours(n),
            };
            query.start = Some(Utc::now() - duration);
        }
    } else if TODAY_RE.is_match(nl) {
        let today = Utc::now().date_naive().and_hms_opt(0, 0, 0);
        if let Some(t) = today {
            query.start = Some(t.and_utc());
        }
    } else if YESTERDAY_RE.is_match(nl) {
        let yesterday = (Utc::now() - Duration::days(1))
            .date_naive()
            .and_hms_opt(0, 0, 0);
        if let Some(t) = yesterday {
            query.start = Some(t.and_utc());
        }
    }

    // Verdict
    if query.verdict.is_none() {
        if VERDICT_DENY_RE.is_match(nl) {
            query.verdict = Some(QueryVerdict::Deny);
        } else if VERDICT_ALLOW_RE.is_match(nl) {
            query.verdict = Some(QueryVerdict::Allow);
        } else if VERDICT_WARN_RE.is_match(nl) {
            query.verdict = Some(QueryVerdict::Warn);
        }
    }

    // Sources
    if query.sources.is_empty() {
        let mut sources = Vec::new();
        if SOURCE_TETRAGON_RE.is_match(nl) {
            sources.push(EventSource::Tetragon);
        }
        if SOURCE_HUBBLE_RE.is_match(nl) {
            sources.push(EventSource::Hubble);
        }
        if !sources.is_empty() {
            query.sources = sources;
        }
    }

    // Action type
    if query.action_type.is_none() {
        if let Some(caps) = ACTION_RE.captures(nl) {
            let matched = caps[1].to_lowercase();
            query.action_type = Some(match matched.as_str() {
                "shell" | "command" => "shell".to_string(),
                "mcp" | "tool" => "mcp".to_string(),
                other => other.to_string(),
            });
        }
    }

    // Process — skip stopwords that look like process names but aren't.
    if query.process.is_none() {
        if let Some(caps) = PROCESS_RE.captures(nl) {
            let candidate = &caps[1];
            let is_stopword = PROCESS_STOPWORDS
                .iter()
                .any(|sw| sw.eq_ignore_ascii_case(candidate));
            if !is_stopword {
                query.process = Some(candidate.to_string());
            }
        }
    }

    // Namespace
    if query.namespace.is_none() {
        if let Some(caps) = NAMESPACE_RE.captures(nl) {
            query.namespace = Some(caps[1].to_string());
        }
    }

    // Pod
    if query.pod.is_none() {
        if let Some(caps) = POD_RE.captures(nl) {
            query.pod = Some(caps[1].to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_query() -> HuntQuery {
        HuntQuery::default()
    }

    #[test]
    fn nl_last_2_hours_sets_start() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show me events from the last 2 hours");
        assert!(q.start.is_some());
        let start = q.start.unwrap();
        let expected_approx = Utc::now() - Duration::hours(2);
        // Allow 5 seconds of drift
        let diff = (start - expected_approx).num_seconds().unsigned_abs();
        assert!(diff < 5, "start should be ~2 hours ago, diff was {diff}s");
    }

    #[test]
    fn nl_last_30_minutes_sets_start() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "events in the last 30 minutes");
        assert!(q.start.is_some());
        let start = q.start.unwrap();
        let expected_approx = Utc::now() - Duration::minutes(30);
        let diff = (start - expected_approx).num_seconds().unsigned_abs();
        assert!(
            diff < 5,
            "start should be ~30 minutes ago, diff was {diff}s"
        );
    }

    #[test]
    fn nl_last_1_day_sets_start() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "tetragon events last 1 day");
        assert!(q.start.is_some());
        let start = q.start.unwrap();
        let expected_approx = Utc::now() - Duration::days(1);
        let diff = (start - expected_approx).num_seconds().unsigned_abs();
        assert!(diff < 5, "start should be ~1 day ago, diff was {diff}s");
        // Should also set source
        assert!(q.sources.contains(&EventSource::Tetragon));
    }

    #[test]
    fn nl_last_10_seconds() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "last 10 seconds");
        assert!(q.start.is_some());
        let start = q.start.unwrap();
        let expected_approx = Utc::now() - Duration::seconds(10);
        let diff = (start - expected_approx).num_seconds().unsigned_abs();
        assert!(diff < 5);
    }

    #[test]
    fn nl_today_sets_start_to_midnight() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show events from today");
        assert!(q.start.is_some());
        let start = q.start.unwrap();
        let today_midnight = Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        assert_eq!(start, today_midnight);
    }

    #[test]
    fn nl_yesterday_sets_start() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "all events since yesterday");
        assert!(q.start.is_some());
        let start = q.start.unwrap();
        let yesterday_midnight = (Utc::now() - Duration::days(1))
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        assert_eq!(start, yesterday_midnight);
    }

    #[test]
    fn nl_denied_sets_verdict_deny() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show denied processes");
        assert_eq!(q.verdict, Some(QueryVerdict::Deny));
    }

    #[test]
    fn nl_blocked_sets_verdict_deny() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "all blocked actions");
        assert_eq!(q.verdict, Some(QueryVerdict::Deny));
    }

    #[test]
    fn nl_allowed_sets_verdict_allow() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show allowed events");
        assert_eq!(q.verdict, Some(QueryVerdict::Allow));
    }

    #[test]
    fn nl_passed_sets_verdict_allow() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "passed actions today");
        assert_eq!(q.verdict, Some(QueryVerdict::Allow));
    }

    #[test]
    fn nl_warning_sets_verdict_warn() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show warning events");
        assert_eq!(q.verdict, Some(QueryVerdict::Warn));
    }

    #[test]
    fn nl_warned_sets_verdict_warn() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "warned actions last 1 hour");
        assert_eq!(q.verdict, Some(QueryVerdict::Warn));
    }

    #[test]
    fn nl_tetragon_sets_source() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "tetragon events last 2 hours");
        assert_eq!(q.sources, vec![EventSource::Tetragon]);
    }

    #[test]
    fn nl_kernel_sets_tetragon_source() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "kernel events today");
        assert_eq!(q.sources, vec![EventSource::Tetragon]);
    }

    #[test]
    fn nl_hubble_sets_source() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "hubble network events");
        assert!(q.sources.contains(&EventSource::Hubble));
    }

    #[test]
    fn nl_network_flow_sets_hubble_source() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show network flow events");
        assert!(q.sources.contains(&EventSource::Hubble));
    }

    #[test]
    fn nl_flows_sets_hubble_source() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "all flows last 1 hour");
        assert!(q.sources.contains(&EventSource::Hubble));
    }

    #[test]
    fn nl_multiple_sources() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "tetragon and hubble events");
        assert!(q.sources.contains(&EventSource::Tetragon));
        assert!(q.sources.contains(&EventSource::Hubble));
    }

    #[test]
    fn nl_action_type_egress() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show egress events");
        assert_eq!(q.action_type, Some("egress".to_string()));
    }

    #[test]
    fn nl_action_type_file() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "denied file actions");
        assert_eq!(q.action_type, Some("file".to_string()));
    }

    #[test]
    fn nl_action_type_shell_from_command() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "blocked command executions");
        assert_eq!(q.action_type, Some("shell".to_string()));
    }

    #[test]
    fn nl_action_type_shell() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "shell actions denied");
        assert_eq!(q.action_type, Some("shell".to_string()));
    }

    #[test]
    fn nl_action_type_mcp_from_tool() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "tool invocations today");
        assert_eq!(q.action_type, Some("mcp".to_string()));
    }

    #[test]
    fn nl_process_extraction() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "process nginx denied");
        assert_eq!(q.process, Some("nginx".to_string()));
        assert_eq!(q.verdict, Some(QueryVerdict::Deny));
    }

    #[test]
    fn nl_binary_extraction() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "binary curl events last 1 hour");
        assert_eq!(q.process, Some("curl".to_string()));
    }

    #[test]
    fn nl_namespace_extraction() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "namespace production events");
        assert_eq!(q.namespace, Some("production".to_string()));
    }

    #[test]
    fn nl_ns_shorthand_extraction() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "ns kube-system denied");
        assert_eq!(q.namespace, Some("kube-system".to_string()));
    }

    #[test]
    fn nl_pod_extraction() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "pod agent-pod-123 events");
        assert_eq!(q.pod, Some("agent-pod-123".to_string()));
    }

    #[test]
    fn nl_combined_query() {
        let mut q = empty_query();
        apply_nl_query(
            &mut q,
            "tetragon events denied process nginx namespace production last 2 hours",
        );
        assert_eq!(q.sources, vec![EventSource::Tetragon]);
        assert_eq!(q.verdict, Some(QueryVerdict::Deny));
        assert_eq!(q.process, Some("nginx".to_string()));
        assert_eq!(q.namespace, Some("production".to_string()));
        assert!(q.start.is_some());
    }

    #[test]
    fn nl_does_not_override_existing_verdict() {
        let mut q = empty_query();
        q.verdict = Some(QueryVerdict::Allow);
        apply_nl_query(&mut q, "denied events");
        // Should NOT override since verdict was already set
        assert_eq!(q.verdict, Some(QueryVerdict::Allow));
    }

    #[test]
    fn nl_does_not_override_existing_sources() {
        let mut q = empty_query();
        q.sources = vec![EventSource::Receipt];
        apply_nl_query(&mut q, "tetragon events");
        // Should NOT override since sources was already set
        assert_eq!(q.sources, vec![EventSource::Receipt]);
    }

    #[test]
    fn nl_does_not_override_existing_process() {
        let mut q = empty_query();
        q.process = Some("httpd".to_string());
        apply_nl_query(&mut q, "process nginx");
        assert_eq!(q.process, Some("httpd".to_string()));
    }

    #[test]
    fn nl_does_not_override_existing_namespace() {
        let mut q = empty_query();
        q.namespace = Some("staging".to_string());
        apply_nl_query(&mut q, "namespace production");
        assert_eq!(q.namespace, Some("staging".to_string()));
    }

    #[test]
    fn nl_does_not_override_existing_pod() {
        let mut q = empty_query();
        q.pod = Some("existing-pod".to_string());
        apply_nl_query(&mut q, "pod new-pod");
        assert_eq!(q.pod, Some("existing-pod".to_string()));
    }

    #[test]
    fn nl_does_not_override_existing_action_type() {
        let mut q = empty_query();
        q.action_type = Some("custom".to_string());
        apply_nl_query(&mut q, "file actions");
        assert_eq!(q.action_type, Some("custom".to_string()));
    }

    #[test]
    fn nl_empty_input_changes_nothing() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "");
        assert!(q.sources.is_empty());
        assert!(q.verdict.is_none());
        assert!(q.start.is_none());
        assert!(q.process.is_none());
        assert!(q.namespace.is_none());
        assert!(q.pod.is_none());
        assert!(q.action_type.is_none());
    }

    #[test]
    fn nl_case_insensitive_time() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "LAST 5 HOURS");
        assert!(q.start.is_some());
    }

    #[test]
    fn nl_case_insensitive_verdict() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "DENIED events");
        assert_eq!(q.verdict, Some(QueryVerdict::Deny));
    }

    #[test]
    fn nl_hour_alias_hr() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "last 3 hrs");
        assert!(q.start.is_some());
        let start = q.start.unwrap();
        let expected = Utc::now() - Duration::hours(3);
        let diff = (start - expected).num_seconds().unsigned_abs();
        assert!(diff < 5);
    }

    #[test]
    fn nl_minute_alias_min() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "last 15 mins");
        assert!(q.start.is_some());
        let start = q.start.unwrap();
        let expected = Utc::now() - Duration::minutes(15);
        let diff = (start - expected).num_seconds().unsigned_abs();
        assert!(diff < 5);
    }

    #[test]
    fn nl_process_events_sets_tetragon() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show process events last 1 hour");
        assert!(q.sources.contains(&EventSource::Tetragon));
    }

    #[test]
    fn nl_process_events_does_not_set_process_to_events() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show process events last 1 hour");
        // "events" is a stopword, not a process name
        assert_eq!(
            q.process, None,
            "should not capture 'events' as process name"
        );
    }

    #[test]
    fn nl_process_logs_does_not_set_process_to_logs() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "process logs today");
        assert_eq!(q.process, None, "should not capture 'logs' as process name");
    }

    #[test]
    fn nl_process_data_does_not_set_process_to_data() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show process data last 2 hours");
        assert_eq!(q.process, None, "should not capture 'data' as process name");
    }

    #[test]
    fn nl_process_activity_does_not_set_process_to_activity() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "process activity today");
        assert_eq!(
            q.process, None,
            "should not capture 'activity' as process name"
        );
    }

    #[test]
    fn nl_process_stopwords_case_insensitive() {
        let mut q = empty_query();
        apply_nl_query(&mut q, "show process EVENTS last 1 hour");
        assert_eq!(q.process, None, "stopword check should be case-insensitive");
    }

    #[test]
    fn nl_process_real_name_still_works() {
        // Ensure actual process names are still captured after the fix
        let mut q = empty_query();
        apply_nl_query(&mut q, "process nginx denied");
        assert_eq!(q.process, Some("nginx".to_string()));

        let mut q2 = empty_query();
        apply_nl_query(&mut q2, "binary python3 allowed");
        assert_eq!(q2.process, Some("python3".to_string()));
    }
}

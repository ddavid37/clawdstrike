//! Local offline envelope loading from filesystem directories.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::Result;
use crate::query::HuntQuery;
use crate::timeline::{self, TimelineEvent};

fn truncate_to_newest(events: &mut Vec<TimelineEvent>, limit: usize) {
    if limit == 0 {
        events.clear();
        return;
    }
    if events.len() > limit {
        let keep_from = events.len() - limit;
        events.drain(0..keep_from);
    }
}

/// Default directories to search for local envelopes.
pub fn default_local_dirs() -> Vec<PathBuf> {
    let mut result = Vec::new();
    if let Some(home) = dirs::home_dir() {
        let candidates = [
            home.join(".clawdstrike").join("receipts"),
            home.join(".clawdstrike").join("scans"),
            home.join(".hush").join("receipts"),
        ];
        for d in candidates {
            if d.is_dir() {
                result.push(d);
            }
        }
    }
    result
}

/// Query envelopes from local JSON/JSONL files.
pub fn query_local_files(
    query: &HuntQuery,
    search_dirs: &[PathBuf],
    verify: bool,
) -> Result<Vec<TimelineEvent>> {
    let mut all_events = Vec::new();

    for dir in search_dirs {
        if !dir.is_dir() {
            tracing::debug!("skipping non-directory: {}", dir.display());
            continue;
        }

        let entries = std::fs::read_dir(dir)?;
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::warn!(
                        "skipping unreadable directory entry in {}: {}",
                        dir.display(),
                        e
                    );
                    continue;
                }
            };
            let path = entry.path();

            if path.is_file() {
                let events = match path.extension().and_then(|e| e.to_str()) {
                    Some("jsonl") => match read_jsonl_file(&path, verify) {
                        Ok(events) => events,
                        Err(e) => {
                            tracing::warn!(
                                "skipping unreadable/invalid JSONL file {}: {}",
                                path.display(),
                                e
                            );
                            continue;
                        }
                    },
                    Some("json") => match read_json_file(&path, verify) {
                        Ok(events) => events,
                        Err(e) => {
                            tracing::warn!(
                                "skipping unreadable/invalid JSON file {}: {}",
                                path.display(),
                                e
                            );
                            continue;
                        }
                    },
                    _ => continue,
                };

                for event in events {
                    if query.matches(&event) {
                        all_events.push(event);
                    }
                }
            }
        }
    }

    let mut merged = timeline::merge_timeline(all_events);
    truncate_to_newest(&mut merged, query.limit);
    Ok(merged)
}

/// Read a single JSON file as a spine envelope (or array of envelopes).
fn read_json_file(path: &Path, verify: bool) -> Result<Vec<TimelineEvent>> {
    let content = std::fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&content)?;

    // Could be a single envelope or an array
    if let Some(arr) = value.as_array() {
        Ok(arr
            .iter()
            .filter_map(|v| timeline::parse_envelope(v, verify))
            .collect())
    } else {
        Ok(timeline::parse_envelope(&value, verify)
            .into_iter()
            .collect())
    }
}

/// Read a JSONL file (one JSON object per line).
fn read_jsonl_file(path: &Path, verify: bool) -> Result<Vec<TimelineEvent>> {
    let content = std::fs::read_to_string(path)?;
    let mut events = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            if let Some(event) = timeline::parse_envelope(&value, verify) {
                events.push(event);
            }
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn default_local_dirs_returns_expected_paths() {
        // We can't assert specific dirs exist, but verify the function
        // doesn't panic and returns a vec.
        let dirs = default_local_dirs();
        // All returned dirs should actually exist
        for d in &dirs {
            assert!(d.is_dir(), "returned dir should exist: {}", d.display());
        }
    }

    /// Helper to create a valid spine envelope JSON value.
    fn make_envelope(schema: &str, ts: &str, decision: &str, summary_text: &str) -> Value {
        serde_json::json!({
            "issued_at": ts,
            "fact": {
                "schema": schema,
                "decision": decision,
                "guard": "TestGuard",
                "action_type": "file_open",
                "severity": "info",
                "event_type": "PROCESS_EXEC",
                "process": {
                    "binary": "/usr/bin/cat"
                },
                "verdict": decision.to_uppercase(),
                "traffic_direction": "EGRESS",
                "summary": summary_text,
                "scan_type": "vulnerability",
                "status": decision,
                "source": {
                    "namespace": "default",
                    "pod_name": "test-pod"
                }
            }
        })
    }

    #[test]
    fn read_json_file_single_envelope() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("envelope.json");
        let envelope = make_envelope(
            "clawdstrike.sdr.fact.tetragon_event.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "file_open /etc/passwd",
        );
        fs::write(&path, serde_json::to_string_pretty(&envelope).unwrap())
            .expect("failed to write test file");

        let events = read_json_file(&path, false).expect("should parse");
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.contains("process_exec"));
    }

    #[test]
    fn read_json_file_array_of_envelopes() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("envelopes.json");
        let envelopes = serde_json::json!([
            make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:00:00Z",
                "deny",
                "blocked rm -rf /"
            ),
            make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:01:00Z",
                "allow",
                "write to /tmp/output"
            )
        ]);
        fs::write(&path, serde_json::to_string_pretty(&envelopes).unwrap())
            .expect("failed to write test file");

        let events = read_json_file(&path, false).expect("should parse");
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn read_jsonl_file_parses_lines() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("events.jsonl");
        let e1 = make_envelope(
            "clawdstrike.sdr.fact.tetragon_event.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "open /etc/hosts",
        );
        let e2 = make_envelope(
            "clawdstrike.sdr.fact.tetragon_event.v1",
            "2025-01-15T10:01:00Z",
            "deny",
            "egress to evil.com",
        );
        let lines = [
            serde_json::to_string(&e1).unwrap(),
            String::new(), // blank line should be skipped
            serde_json::to_string(&e2).unwrap(),
        ];
        fs::write(&path, lines.join("\n")).expect("failed to write test file");

        let events = read_jsonl_file(&path, false).expect("should parse");
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn read_jsonl_file_skips_invalid_lines() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("mixed.jsonl");
        let e1 = make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "read /tmp/data",
        );
        let e2 = make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:02:00Z",
            "allow",
            "echo hello",
        );
        let lines = [
            serde_json::to_string(&e1).unwrap(),
            "not valid json {{{".to_string(),
            serde_json::to_string(&e2).unwrap(),
        ];
        fs::write(&path, lines.join("\n")).expect("failed to write test file");

        // Should not error — invalid lines are silently skipped
        let events = read_jsonl_file(&path, false).expect("should parse without error");
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn read_json_file_invalid_json_returns_error() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("bad.json");
        fs::write(&path, "not json at all").expect("failed to write test file");

        let result = read_json_file(&path, false);
        assert!(result.is_err(), "invalid JSON should return an error");
    }

    #[test]
    fn query_local_files_skips_non_json_files() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        // Create a .txt file that should be skipped
        fs::write(dir.path().join("notes.txt"), "not an envelope")
            .expect("failed to write test file");
        // Create a .json file with valid envelope
        let envelope = make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "test",
        );
        fs::write(
            dir.path().join("envelope.json"),
            serde_json::to_string(&envelope).unwrap(),
        )
        .expect("failed to write test file");

        let query = HuntQuery::default();
        let dirs = vec![dir.path().to_path_buf()];
        let result = query_local_files(&query, &dirs, false);
        assert!(result.is_ok(), "should succeed even with mixed file types");
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn query_local_files_skips_corrupt_json_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let envelope = make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "test",
        );
        fs::write(
            dir.path().join("valid.json"),
            serde_json::to_string(&envelope).unwrap(),
        )
        .expect("failed to write test file");
        fs::write(dir.path().join("corrupt.json"), "{not valid json")
            .expect("failed to write test file");

        let query = HuntQuery::default();
        let dirs = vec![dir.path().to_path_buf()];
        let result = query_local_files(&query, &dirs, false);
        assert!(
            result.is_ok(),
            "single corrupt file should not fail entire query"
        );
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn query_local_files_skips_nonexistent_dirs() {
        let query = HuntQuery::default();
        let dirs = vec![PathBuf::from("/nonexistent/path/that/does/not/exist")];
        let result = query_local_files(&query, &dirs, false).expect("should succeed");
        assert!(result.is_empty(), "non-existent dir should yield no events");
    }

    #[test]
    fn query_local_files_limit_keeps_newest_events() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("events.jsonl");
        let lines = [
            serde_json::to_string(&make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:00:00Z",
                "allow",
                "event-1",
            ))
            .unwrap(),
            serde_json::to_string(&make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:01:00Z",
                "allow",
                "event-2",
            ))
            .unwrap(),
            serde_json::to_string(&make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:02:00Z",
                "allow",
                "event-3",
            ))
            .unwrap(),
        ];
        fs::write(&path, lines.join("\n")).expect("failed to write test file");

        let query = HuntQuery {
            limit: 2,
            ..HuntQuery::default()
        };
        let dirs = vec![dir.path().to_path_buf()];
        let events = query_local_files(&query, &dirs, false).expect("query local files");

        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].timestamp.to_rfc3339(),
            "2025-01-15T10:01:00+00:00"
        );
        assert_eq!(
            events[1].timestamp.to_rfc3339(),
            "2025-01-15T10:02:00+00:00"
        );
    }

    #[test]
    fn query_local_files_limit_zero_returns_no_events() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("events.jsonl");
        let lines = [
            serde_json::to_string(&make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:00:00Z",
                "allow",
                "event-1",
            ))
            .unwrap(),
            serde_json::to_string(&make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:01:00Z",
                "allow",
                "event-2",
            ))
            .unwrap(),
        ];
        fs::write(&path, lines.join("\n")).expect("failed to write test file");

        let query = HuntQuery {
            limit: 0,
            ..HuntQuery::default()
        };
        let dirs = vec![dir.path().to_path_buf()];
        let events = query_local_files(&query, &dirs, false).expect("query local files");

        assert!(
            events.is_empty(),
            "limit=0 should return zero events for offline/local queries"
        );
    }
}

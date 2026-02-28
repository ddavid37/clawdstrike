# hunt correlate

Run cross-layer correlation rules against Spine telemetry to detect multi-stage threats that span kernel, network, and agent decision boundaries.

## Purpose

Individual events are often benign in isolation. A process executing `curl` is normal. An egress allowlist denial is expected. But a denied MCP tool call followed by a child process spawning `curl` to an unapproved host within 5 seconds is a potential exfiltration attempt. `hunt correlate` expresses these multi-step patterns as rules and matches them against telemetry.

## Usage

```bash
clawdstrike hunt correlate [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--rule <name>` | Built-in rule name (repeatable) | (all built-in rules) |
| `--rule-file <path>` | Custom rule file (YAML, repeatable) | (none) |
| `--rule-dir <path>` | Directory of rule files | (none) |
| `--since <duration>` | Time window start | `1h` |
| `--until <time>` | Time window end | now |
| `--namespace <ns>` | Limit to Kubernetes namespace | (none) |
| `--min-severity <level>` | Minimum rule severity to run | `info` |
| `--json` | JSON output | `false` |
| `--jsonl` | Streaming JSON output | `false` |
| `--nats-url <url>` | NATS server URL | `nats://localhost:4222` |
| `--dry-run` | Parse and validate rules without querying telemetry | `false` |

## Built-in rules

| Rule name | Severity | Description |
|-----------|----------|-------------|
| `denied-tool-then-child-exec` | critical | MCP tool denial followed by child process exec within 10s |
| `suspicious-egress-after-tool-call` | error | Network egress to unapproved host within 30s of a tool invocation |
| `secret-leak-then-egress` | critical | Secret leak detection followed by any outbound network flow |
| `process-exec-from-tmp` | warning | Process execution from `/tmp` or world-writable directories |
| `excessive-denials` | error | More than 10 guard denials from a single entity in 5 minutes |
| `unsigned-decision-chain` | warning | Decision receipts missing signatures or broken hash chains |
| `lateral-tool-escalation` | error | Agent invokes a tool, gets denied, then a different agent invokes the same tool |

## Rule file format

Rules use a YAML format inspired by SIGMA:

```yaml
name: exfil-after-denied-tool
severity: critical
description: >
  Detects potential data exfiltration: an agent's MCP tool call is denied,
  followed by a child process making network egress to an unapproved host.

# Time window for correlation
window: 30s

# Sequence of events to match (ordered)
sequence:
  - layer: decisions
    filter:
      verdict: deny
      action_type: mcp
    bind:
      entity: $agent_pid

  - layer: kernel
    filter:
      event_type: process_exec
      ppid: $agent_pid
    bind:
      entity: $child_pid

  - layer: network
    filter:
      src_pid: $child_pid
    exclude:
      dst_ip: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# Optional: additional conditions
condition:
  # All three events must occur within the window
  ordered: true
```

### Variable binding

Events in a sequence can bind values with `bind` and reference them in subsequent events with `$variable`. This links events that share a common entity (PID, pod, IP).

### Exclusions

Use `exclude` to suppress known-good patterns and reduce false positives.

## Examples

Run all built-in rules for the last hour:

```bash
clawdstrike hunt correlate --since 1h
```

Run a specific rule against a namespace:

```bash
clawdstrike hunt correlate --rule denied-tool-then-child-exec --namespace agent-pool --since 4h
```

Run custom rules from a directory:

```bash
clawdstrike hunt correlate --rule-dir ./hunt-rules/ --since 24h --json
```

Validate custom rules without querying:

```bash
clawdstrike hunt correlate --rule-file ./rules/exfil.yaml --dry-run
```

## Output

```text
CORRELATION MATCHES (3 found)

[CRITICAL] denied-tool-then-child-exec
  Time: 2026-02-27T14:01:12Z - 2026-02-27T14:01:15Z (3s)
  Entity: pid:48291 (python my_agent.py)
  Events:
    14:01:12 [decisions] mcp shell_exec -> deny (mcp_tool_guard)
    14:01:14 [kernel]    EXEC /bin/sh -c curl http://bad.example.com (child pid:48310)
    14:01:15 [network]   TCP -> 203.0.113.5:80 FORWARDED

[ERROR] excessive-denials
  Time: 2026-02-27T13:50:00Z - 2026-02-27T13:55:00Z (5m)
  Entity: pod:code-agent-8x9y2
  Events:
    13:50:01 - 13:54:58 [decisions] 14 denials (egress_allowlist x8, mcp_tool_guard x6)

[WARNING] process-exec-from-tmp
  Time: 2026-02-27T14:10:33Z
  Entity: pid:48400
  Events:
    14:10:33 [kernel]    EXEC /tmp/payload.sh (uid=1000)
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No matches found |
| 1 | Matches found at warning severity |
| 2 | Matches found at error or critical severity |
| 3 | Configuration error (invalid rule file) |
| 4 | Runtime error |

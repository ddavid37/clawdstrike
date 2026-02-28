# hunt timeline

Build entity-centric investigation timelines that stitch together events across all data layers for a single process, pod, agent session, or receipt chain.

## Purpose

While `hunt query` returns flat search results, `hunt timeline` reconstructs the full story of an entity over time. It follows process trees, correlates network flows with the process that initiated them, and links guard decisions back to the actions that triggered them.

## Usage

```bash
clawdstrike hunt timeline [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--entity <type>` | Entity type: `process`, `pod`, `session`, `receipt-chain`, `issuer` | (required) |
| `--id <value>` | Entity identifier (PID, pod name, session ID, chain hash, issuer pubkey) | (required) |
| `--since <duration>` | Time window start | `1h` |
| `--until <time>` | Time window end | now |
| `--depth <n>` | Process tree depth (for `process` entity) | `3` |
| `--include-children` | Include child processes in the timeline | `true` |
| `--layer <layer>` | Limit to specific layers (repeatable) | all |
| `--json` | JSON output | `false` |
| `--nats-url <url>` | NATS server URL | `nats://localhost:4222` |
| `--verify` | Verify all envelope signatures | `false` |
| `--compact` | Collapse repetitive events (e.g. 100 identical file reads) | `false` |

## Entity types

### `process`

Follows a process by PID. Reconstructs the process tree by tracing parent/child relationships from kernel telemetry, then overlays network flows and guard decisions that occurred during the process lifetime.

```bash
clawdstrike hunt timeline --entity process --id 48291 --since 2h --depth 5
```

### `pod`

Groups all events from processes running in a Kubernetes pod. Useful for investigating agent pods that may spawn multiple processes.

```bash
clawdstrike hunt timeline --entity pod --id research-agent-7f4b9 --since 6h
```

### `session`

Follows a Clawdstrike session ID (as seen in hushd audit logs and `clawdstrike run` event output). Links the session to its guard decisions, observed events, and signed receipts.

```bash
clawdstrike hunt timeline --entity session --id sess_a1b2c3d4 --since 24h
```

### `receipt-chain`

Follows a Spine envelope hash chain from a specific envelope. Walks the `prev_hash` links to reconstruct the full sequence of signed facts from a particular bridge or engine.

```bash
clawdstrike hunt timeline --entity receipt-chain --id abc123def456 --since 7d
```

### `issuer`

Shows all envelopes signed by a specific issuer identity (Ed25519 public key). Useful for auditing what a particular bridge or agent has attested.

```bash
clawdstrike hunt timeline --entity issuer --id ed25519:ab12cd34... --since 24h
```

## Examples

Investigate a process and its children with compact output:

```bash
clawdstrike hunt timeline --entity process --id 48291 --since 1h --depth 3 --compact
```

Get a pod timeline as JSON for downstream tooling:

```bash
clawdstrike hunt timeline --entity pod --id code-agent-8x9y2 --since 4h --json > pod-timeline.json
```

Verify all signatures in a timeline:

```bash
clawdstrike hunt timeline --entity session --id sess_a1b2c3d4 --verify
```

Limit a timeline to just kernel and decisions:

```bash
clawdstrike hunt timeline --entity process --id 48291 --layer kernel --layer decisions --since 30m
```

## Output

Default timeline output is chronological with layer annotations:

```text
TIMELINE: process 48291 (python my_agent.py)
Parent: 48200 (bash)
Time range: 2026-02-27T14:01:03Z - 2026-02-27T14:15:22Z

14:01:03  [kernel]    EXEC python my_agent.py --mode research (uid=1000)
14:01:05  [network]   TCP -> api.openai.com:443 FORWARDED
14:01:05  [decisions]  egress api.openai.com:443 -> allow (egress_allowlist)
14:01:12  [decisions]  mcp shell_exec -> deny (mcp_tool_guard) severity=critical
14:01:12  [kernel]    EXEC /bin/sh -c rm -rf /tmp/cache (child pid:48305)
14:01:12  [decisions]  shell "rm -rf /tmp/cache" -> deny (shell_command) severity=critical
14:01:15  [network]   TCP -> suspicious-host.example.com:8443 DROPPED
14:01:15  [decisions]  egress suspicious-host.example.com:8443 -> deny (egress_allowlist)
14:15:22  [kernel]    EXIT python my_agent.py (code=0)

Summary: 9 events across 3 layers, 3 denials, 0 warnings
```

With `--compact`, repeated events are collapsed:

```text
14:01:05  [network]   TCP -> api.openai.com:443 FORWARDED (x47 over 14m)
```

## Integration with other subcommands

Timeline IDs can be passed to `hunt report` to generate signed evidence reports:

```bash
clawdstrike hunt report --timeline 48291 --sign --key hush.key --output report.json
```

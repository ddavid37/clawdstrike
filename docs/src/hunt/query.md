# hunt query

Search Spine telemetry across all data layers using structured flags or natural language.

## Purpose

`hunt query` is the primary search interface for Spine telemetry stored in NATS JetStream. It supports both structured flag-based queries for automation and a natural language mode for ad hoc investigations.

## Usage

```bash
clawdstrike hunt query [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--layer <layer>` | Data layer to query: `kernel`, `network`, `agent`, `decisions`, `all` | `all` |
| `--filter <expr>` | Structured filter expression (see below) | (none) |
| `--nl <text>` | Natural language query (translated to structured filters) | (none) |
| `--since <duration>` | Time window start (e.g. `1h`, `30m`, `7d`, `2024-01-15T00:00:00Z`) | `1h` |
| `--until <time>` | Time window end | now |
| `--limit <n>` | Maximum results to return | `100` |
| `--sort <field>` | Sort field (`time`, `severity`, `entity`) | `time` |
| `--reverse` | Reverse sort order (newest first by default) | `false` |
| `--json` | JSON output | `false` |
| `--jsonl` | Line-delimited JSON output (for piping) | `false` |
| `--nats-url <url>` | NATS server URL | `nats://localhost:4222` |
| `--verify` | Verify envelope signatures on results | `false` |
| `--columns <cols>` | Columns to display (comma-separated) | (layer default) |

## Structured filter expressions

Filters use a comma-separated `key=value` syntax with operators:

| Operator | Meaning | Example |
|----------|---------|---------|
| `=` | Exact match | `binary=python` |
| `!=` | Not equal | `verdict!=FORWARDED` |
| `~` | Contains / regex | `args~my_agent` |
| `>`, `<`, `>=`, `<=` | Numeric/time comparison | `port>1024` |

Multiple filters are AND-joined. Use `--filter` multiple times for complex queries.

### Layer-specific filter keys

**Kernel** (`--layer kernel`):

- `binary` -- process binary name
- `args` -- process arguments
- `pid`, `ppid` -- process/parent PID
- `namespace` -- Kubernetes namespace
- `pod` -- pod name
- `event_type` -- `process_exec`, `process_exit`, `kprobe`
- `uid` -- user ID

**Network** (`--layer network`):

- `src_ip`, `dst_ip` -- source/destination IP
- `src_port`, `dst_port` -- source/destination port
- `src_namespace`, `dst_namespace` -- Kubernetes namespaces
- `verdict` -- `FORWARDED`, `DROPPED`, `ERROR`
- `protocol` -- `TCP`, `UDP`, `ICMP`
- `dns_query` -- DNS query name
- `http_url` -- HTTP URL (L7)

**Decisions** (`--layer decisions`):

- `guard` -- guard name (e.g. `forbidden_path`, `egress_allowlist`)
- `verdict` -- `allow`, `warn`, `deny`
- `severity` -- `info`, `warning`, `error`, `critical`
- `policy` -- policy reference or hash
- `action_type` -- `file`, `egress`, `mcp`, `shell`, `computer_use`
- `issuer` -- receipt signer identity

## Natural language queries

The `--nl` flag translates natural language to structured filters:

```bash
# These are equivalent:
clawdstrike hunt query --nl "show me all blocked egress in the last hour"
clawdstrike hunt query --layer decisions --filter "verdict=deny,action_type=egress" --since 1h
```

Natural language queries are translated locally using pattern matching (no external API calls). Complex queries may produce a `--filter` suggestion for refinement.

## Examples

Find all process executions in a namespace:

```bash
clawdstrike hunt query --layer kernel --filter "event_type=process_exec,namespace=agent-pool" --since 1h
```

Search for denied egress decisions:

```bash
clawdstrike hunt query --layer decisions --filter "verdict=deny,action_type=egress" --since 24h --json
```

Find network flows to a specific destination:

```bash
clawdstrike hunt query --layer network --filter "dst_ip=10.0.0.5" --since 30m
```

Cross-layer search for everything related to a pod:

```bash
clawdstrike hunt query --layer all --filter "pod=research-agent-7f4b9" --since 2h
```

Pipe results to jq for further processing:

```bash
clawdstrike hunt query --layer decisions --filter "severity>=error" --since 7d --jsonl | jq 'select(.guard == "secret_leak")'
```

Verify envelope signatures on results:

```bash
clawdstrike hunt query --layer kernel --filter "binary=curl" --since 1h --verify
```

## Output

Default table output:

```text
TIME                 LAYER     TYPE          ENTITY              SUMMARY
2026-02-27T14:01:03Z kernel    process_exec  pid:48291           python my_agent.py --mode research
2026-02-27T14:01:05Z network   flow          10.0.1.5:443        TCP FORWARDED -> api.openai.com
2026-02-27T14:01:05Z decisions egress        api.openai.com:443  allow (egress_allowlist)
2026-02-27T14:01:12Z decisions mcp           shell_exec          deny (mcp_tool_guard) severity=critical
2026-02-27T14:01:12Z kernel    process_exec  pid:48305           /bin/sh -c rm -rf /tmp/cache
```

With `--verify`, an additional column shows envelope signature status (`VALID`, `INVALID`, `NO_KEY`).

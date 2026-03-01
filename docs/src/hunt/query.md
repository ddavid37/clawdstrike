# hunt query

Query historical events from NATS JetStream (or local exported files in offline mode) with structured filters and optional natural-language hints.

## Usage

```bash
clawdstrike hunt query [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--source <value>` | Event source filter (repeatable/comma-separated): `tetragon`, `hubble`, `receipt`, `scan` | all |
| `--verdict <value>` | Verdict filter: `allow`, `deny`, `warn`, `forwarded`, `dropped` (aliases accepted) | none |
| `--start <time>` | RFC3339 or relative duration (`30m`, `1h`, `2d`) | none |
| `--end <time>` | RFC3339 or relative duration | none |
| `--action-type <type>` | Action-type filter (exact, case-insensitive) | none |
| `--process <text>` | Process substring filter | none |
| `--namespace <ns>` | Namespace filter | none |
| `--pod <text>` | Pod substring filter | none |
| `--limit <n>` | Maximum events returned | `100` |
| `--nl <text>` | Apply natural-language parser to augment filters | none |
| `--nats-url <url>` | NATS URL | `nats://localhost:4222` |
| `--nats-creds <path>` | NATS credentials file | none |
| `--offline` | Skip NATS and query local files only | `false` |
| `--local-dir <path>` | Local directories for offline/fallback query (repeatable) | built-in defaults |
| `--verify` | Verify envelope signatures while parsing | `false` |
| `--json` | Emit JSON envelope output | `false` |
| `--jsonl` | Emit one JSON event per line | `false` |
| `--no-color` | Disable colored text output | `false` |

## Behavior

- If NATS query fails and `--offline` is not set, query falls back to local file sources.
- `--jsonl` suppresses text footer lines to keep stream output machine-safe.

## Examples

```bash
# Denied receipt events in the last hour
clawdstrike hunt query --source receipt --verdict deny --start 1h

# Hubble events for one namespace/pod
clawdstrike hunt query --source hubble --namespace prod --pod agent-7f4

# Natural language augmentation + JSONL
clawdstrike hunt query --nl "blocked egress last 30 minutes" --jsonl

# Fully offline query against exported envelopes
clawdstrike hunt query --offline --local-dir ./exports --source tetragon --limit 200
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 3 | Configuration error |
| 4 | Runtime error |
| 5 | Invalid arguments |

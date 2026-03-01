# hunt timeline

Render query results as a merged chronological timeline.

`hunt timeline` uses the same query/filter pipeline as `hunt query`, then sorts and prints events in timeline format.

## Usage

```bash
clawdstrike hunt timeline [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--source <value>` | Event source filter (repeatable/comma-separated): `tetragon`, `hubble`, `receipt`, `scan` | all |
| `--verdict <value>` | Verdict filter: `allow`, `deny`, `warn`, `forwarded`, `dropped` | none |
| `--start <time>` | RFC3339 or relative duration (`30m`, `1h`, `2d`) | none |
| `--end <time>` | RFC3339 or relative duration | none |
| `--action-type <type>` | Action-type filter | none |
| `--process <text>` | Process substring filter | none |
| `--namespace <ns>` | Namespace filter | none |
| `--pod <text>` | Pod substring filter | none |
| `--entity <text>` | Extra entity filter (matches pod/namespace substring) | none |
| `--limit <n>` | Maximum events returned | `100` |
| `--nl <text>` | Natural-language query augmentation | none |
| `--nats-url <url>` | NATS URL | `nats://localhost:4222` |
| `--nats-creds <path>` | NATS credentials file | none |
| `--offline` | Skip NATS and query local files only | `false` |
| `--local-dir <path>` | Local directories for offline/fallback query (repeatable) | built-in defaults |
| `--verify` | Verify envelope signatures while parsing | `false` |
| `--json` | Emit JSON envelope output | `false` |
| `--jsonl` | Emit one JSON event per line (no text header) | `false` |
| `--no-color` | Disable colored text output | `false` |

## Examples

```bash
# Timeline for denied activity in last 2h
clawdstrike hunt timeline --verdict deny --start 2h

# Namespace-focused timeline across two sources
clawdstrike hunt timeline --source tetragon,hubble --namespace prod --start 1h

# Entity-focused timeline using substring match
clawdstrike hunt timeline --entity agent-pool --start 24h

# Offline timeline from exported envelopes
clawdstrike hunt timeline --offline --local-dir ./exports --json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 3 | Configuration error |
| 4 | Runtime error |
| 5 | Invalid arguments |

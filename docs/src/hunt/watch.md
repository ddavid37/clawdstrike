# hunt watch

Continuously consume live NATS events and evaluate correlation rules in real time.

## Usage

```bash
clawdstrike hunt watch --rules <path> [--rules <path> ...] [OPTIONS]
```

`--rules` is required.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--rules <path>` | Correlation rule file path (repeatable, required) | none |
| `--nats-url <url>` | NATS URL | `nats://localhost:4222` |
| `--nats-creds <path>` | NATS credentials file | none |
| `--max-window <duration>` | Sliding window eviction cap (e.g. `5m`, `1h`) | `5m` |
| `--json` | Emit one JSON object per alert on stdout | `false` |
| `--no-color` | Disable colored text output | `false` |

## Behavior

- Subscribes to `clawdstrike.sdr.fact.>` and parses envelopes into timeline events.
- Feeds events into `CorrelationEngine` and emits alerts as rules match.
- Flushes remaining alerts on shutdown (Ctrl+C).
- In `--json` mode, stdout remains a pure alert stream; session summary is written to stderr.

## Examples

```bash
# Watch with one rules file
clawdstrike hunt watch --rules ./rules/exfil.yaml

# Watch with multiple rule files
clawdstrike hunt watch --rules ./rules/exfil.yaml --rules ./rules/lateral.yaml

# JSON alert stream
clawdstrike hunt watch --rules ./rules/exfil.yaml --json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Session completed successfully |
| 3 | Configuration error |
| 4 | Runtime error |
| 5 | Invalid arguments |

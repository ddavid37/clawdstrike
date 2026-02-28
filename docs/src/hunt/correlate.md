# hunt correlate

Run correlation rules against historical events.

## Usage

```bash
clawdstrike hunt correlate --rules <path> [--rules <path> ...] [OPTIONS]
```

`--rules` is required and points to one or more YAML rule files.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--rules <path>` | Correlation rule file path (repeatable, required) | none |
| `--source <value>` | Source filter: `tetragon`, `hubble`, `receipt`, `scan` | all |
| `--verdict <value>` | Verdict filter | none |
| `--start <time>` | RFC3339 or relative duration | none |
| `--end <time>` | RFC3339 or relative duration | none |
| `--action-type <type>` | Action-type filter | none |
| `--process <text>` | Process substring filter | none |
| `--namespace <ns>` | Namespace filter | none |
| `--pod <text>` | Pod substring filter | none |
| `--limit <n>` | Max events loaded before correlation | `100` |
| `--nl <text>` | Natural-language query augmentation | none |
| `--nats-url <url>` | NATS URL | `nats://localhost:4222` |
| `--nats-creds <path>` | NATS credentials file | none |
| `--offline` | Query local files only | `false` |
| `--local-dir <path>` | Local directories for offline/fallback query (repeatable) | built-in defaults |
| `--verify` | Verify envelope signatures while parsing | `false` |
| `--json` | Emit JSON envelope output | `false` |
| `--jsonl` | Emit one alert JSON object per line (no text summary) | `false` |
| `--no-color` | Disable colored text output | `false` |

## Behavior

- Events are queried first, merged into timeline order, then fed through `CorrelationEngine`.
- Alerts produced during stream processing and final window flush are returned.
- `--jsonl` outputs alert objects only; it does not print human summary lines.
- Exit code is warning (`1`) when alerts are present.

## Examples

```bash
# Correlate last hour of events with one rule file
clawdstrike hunt correlate --rules ./rules/exfil.yaml --start 1h

# Correlate only receipt + hubble data
clawdstrike hunt correlate --rules ./rules/exfil.yaml --source receipt,hubble

# Offline correlate over exported local data
clawdstrike hunt correlate --rules ./rules/exfil.yaml --offline --local-dir ./exports --json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No alerts |
| 1 | Alerts generated |
| 3 | Configuration error |
| 4 | Runtime error |
| 5 | Invalid arguments |

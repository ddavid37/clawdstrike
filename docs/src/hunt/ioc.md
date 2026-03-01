# hunt ioc

Load IOC feeds/STIX bundles and match them against queried events.

## Usage

```bash
clawdstrike hunt ioc [OPTIONS]
```

At least one of `--feed` or `--stix` is required.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--feed <path>` | IOC feed file (repeatable). `.csv` parsed as CSV; others parsed as line-based text indicators | none |
| `--stix <path>` | STIX 2.1 bundle file (repeatable) | none |
| `--source <value>` | Source filter: `tetragon`, `hubble`, `receipt`, `scan` | all |
| `--start <time>` | RFC3339 or relative duration | none |
| `--end <time>` | RFC3339 or relative duration | none |
| `--limit <n>` | Maximum events scanned | `100` |
| `--nats-url <url>` | NATS URL | `nats://localhost:4222` |
| `--nats-creds <path>` | NATS credentials file | none |
| `--offline` | Query local files only | `false` |
| `--local-dir <path>` | Local directories for offline/fallback query (repeatable) | built-in defaults |
| `--verify` | Verify envelope signatures while parsing | `false` |
| `--json` | Emit JSON envelope output | `false` |
| `--no-color` | Disable colored text output | `false` |

## Examples

```bash
# Match text/CSV feeds against last day of events
clawdstrike hunt ioc --feed ./ioc.txt --feed ./ioc.csv --start 24h

# Match STIX bundle + feed against receipt events only
clawdstrike hunt ioc --stix ./bundle.json --feed ./ioc.txt --source receipt --json

# Offline IOC matching over exported envelopes
clawdstrike hunt ioc --feed ./ioc.txt --offline --local-dir ./exports
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No matches |
| 1 | One or more IOC matches found |
| 3 | Configuration error |
| 4 | Runtime error |
| 5 | Invalid arguments |

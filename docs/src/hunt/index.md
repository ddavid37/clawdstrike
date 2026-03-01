# Hunt: Threat Hunting CLI

`clawdstrike hunt` provides six investigation subcommands for agent/MCP inventory, historical telemetry search, timeline reconstruction, rule correlation, live correlation watch, and IOC matching.

## Subcommands

| Command | Purpose |
|---------|---------|
| [`hunt scan`](scan.md) | Discover MCP configs and inspect server/tool signatures |
| [`hunt query`](query.md) | Search historical events with structured filters or `--nl` |
| [`hunt timeline`](timeline.md) | Merge matched events into chronological timeline output |
| [`hunt correlate`](correlate.md) | Run correlation rules against queried historical events |
| [`hunt watch`](watch.md) | Run correlation rules continuously on live NATS events |
| [`hunt ioc`](ioc.md) | Match IOC feeds/STIX bundles against queried events |

`hunt report` is documented as a planned command in [`hunt/report.md`](report.md), but it is not implemented in the current CLI.

## Testing

For process-level E2E coverage (real CLI + real NATS + mock MCP), see
[`hunt/testing.md`](testing.md).

## Quick Examples

```bash
# Scan local configs and include built-in IDE tools
clawdstrike hunt scan --target cursor --include-builtin

# Query denied receipt events from the last hour
clawdstrike hunt query --source receipt --verdict deny --start 1h --limit 50

# Timeline view for a namespace/pod entity substring
clawdstrike hunt timeline --entity agent-pool --source tetragon,hubble --start 1h

# Batch correlation from local exported envelopes
clawdstrike hunt correlate --rules ./rules/exfil.yaml --offline --local-dir ./exports --json

# IOC matching with local feed files
clawdstrike hunt ioc --feed ./iocs.txt --stix ./bundle.json --start 24h
```

## Shared Defaults

| Flag | Default |
|------|---------|
| `--nats-url` | `nats://localhost:4222` |
| `--limit` (query/timeline/correlate/ioc) | `100` |
| `--timeout` (scan) | `10` seconds |

`hunt query`, `hunt timeline`, `hunt correlate`, and `hunt ioc` can run with `--offline` and optional `--local-dir` paths.

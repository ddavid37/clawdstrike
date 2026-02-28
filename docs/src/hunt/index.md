# Hunt: Threat Hunting for AI Agent Ecosystems

`clawdstrike hunt` is a unified threat hunting CLI that correlates kernel telemetry, network flows, agent configuration scans, and security decision receipts into a single investigation interface.

## Why hunt?

AI agents operate across multiple layers: they spawn processes, make network requests, invoke tools via MCP, and produce signed security receipts. Investigating an incident means piecing together data from all of these layers. `hunt` unifies them under one command.

## Data layers

Hunt queries four data layers, each backed by signed Spine envelopes on NATS JetStream:

| Layer | Source | NATS stream | What it captures |
|-------|--------|-------------|------------------|
| **Kernel** | Tetragon bridge | `CLAWDSTRIKE_TETRAGON` | Process exec/exit, kprobes (file access, network syscalls) |
| **Network** | Hubble bridge | `CLAWDSTRIKE_HUBBLE` | L3/L4/L7 flow records, DNS, HTTP, verdict (forwarded/dropped) |
| **Agent** | Agent scan | (local / receipt store) | MCP server configs, tool inventories, policy compliance, vulnerability checks |
| **Decisions** | HushEngine receipts | `CLAWDSTRIKE_DECISIONS` | Guard verdicts, policy hashes, signed attestations |

Every envelope is Ed25519-signed with a hash-chain sequence, providing tamper-evident audit trails.

## Subcommands

| Command | Purpose |
|---------|---------|
| [`hunt scan`](scan.md) | Discover and audit agent configurations, MCP servers, and policy compliance |
| [`hunt query`](query.md) | Search telemetry with structured flags or natural language |
| [`hunt timeline`](timeline.md) | Build entity-centric investigation timelines |
| [`hunt correlate`](correlate.md) | Run cross-layer correlation rules (SIGMA-style) |
| [`hunt watch`](watch.md) | Stream live telemetry with filters |
| [`hunt ioc`](ioc.md) | Match indicators of compromise against telemetry |
| [`hunt report`](report.md) | Generate cryptographic evidence chain reports |

## Quick example

Investigate what a specific agent process did in the last hour:

```bash
# Find the agent process
clawdstrike hunt query --layer kernel --filter "binary=python,args~my_agent" --since 1h

# Build a timeline for that process
clawdstrike hunt timeline --entity process --id 48291 --since 1h

# Check for known bad indicators
clawdstrike hunt ioc --feed clawdstrike://threat-feed --since 1h

# Correlate across layers
clawdstrike hunt correlate --rule suspicious-egress-after-tool-call --since 1h

# Generate a signed evidence report
clawdstrike hunt report --timeline 48291 --sign --key hush.key --output incident-report.json
```

## Connection defaults

Hunt connects to NATS and optionally to Tetragon/Hubble gRPC endpoints. Defaults can be overridden with flags or environment variables:

| Flag | Env var | Default |
|------|---------|---------|
| `--nats-url` | `CLAWDSTRIKE_NATS_URL` | `nats://localhost:4222` |
| `--tetragon-endpoint` | `CLAWDSTRIKE_TETRAGON_ENDPOINT` | `http://localhost:54321` |
| `--hubble-endpoint` | `CLAWDSTRIKE_HUBBLE_ENDPOINT` | `http://hubble-relay.kube-system.svc.cluster.local:4245` |

## Output formats

All subcommands support `--json` for machine-readable output and default to human-readable tables/text. Some subcommands additionally support `--jsonl` for streaming line-delimited JSON.

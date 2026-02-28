# hunt report

Generate cryptographic evidence chain reports from hunt investigations. Reports bundle timelines, correlation matches, and IOC hits into a signed, verifiable artifact.

## Purpose

`hunt report` produces investigation reports that are both human-readable and machine-verifiable. Each report includes a Merkle tree over all referenced Spine envelopes, a signed receipt attesting to the report contents, and optional narrative annotations. Reports are designed for compliance, incident response handoffs, and legal evidence chains.

## Usage

```bash
clawdstrike hunt report [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--timeline <id>` | Include a timeline by entity ID (repeatable) | (none) |
| `--query <filter>` | Include query results (same syntax as `hunt query --filter`) | (none) |
| `--correlate <rule>` | Include correlation matches (repeatable) | (none) |
| `--ioc-feed <ref>` | Include IOC matches from feed | (none) |
| `--since <duration>` | Time window start | `1h` |
| `--until <time>` | Time window end | now |
| `--sign` | Sign the report with Ed25519 | `false` |
| `--key <path>` | Signing key path | `hush.key` |
| `--title <text>` | Report title | `"Hunt Report"` |
| `--analyst <name>` | Analyst name for attribution | (none) |
| `--notes <text>` | Free-text notes to include | (none) |
| `--notes-file <path>` | Read notes from a file | (none) |
| `--format <fmt>` | Output format: `json`, `html`, `pdf` | `json` |
| `--output <path>` | Output file path | stdout (JSON) |
| `--nats-url <url>` | NATS server URL | `nats://localhost:4222` |
| `--verify-inputs` | Verify all input envelope signatures before including | `false` |

## Report structure

A JSON report contains:

```json
{
  "version": "1.0.0",
  "title": "Suspected exfiltration attempt - research-agent",
  "analyst": "security-team",
  "generated_at": "2026-02-27T15:30:00Z",
  "time_range": {
    "start": "2026-02-27T14:00:00Z",
    "end": "2026-02-27T15:00:00Z"
  },
  "sections": [
    {
      "type": "timeline",
      "entity": "process:48291",
      "events": [ ... ]
    },
    {
      "type": "correlation",
      "rule": "denied-tool-then-child-exec",
      "matches": [ ... ]
    },
    {
      "type": "ioc",
      "feed": "./indicators.json",
      "matches": [ ... ]
    }
  ],
  "evidence": {
    "envelope_count": 47,
    "merkle_root": "sha256:a1b2c3d4...",
    "merkle_proofs": [ ... ],
    "envelope_hashes": [ ... ]
  },
  "notes": "Analyst notes here...",
  "receipt": {
    "content_hash": "sha256:...",
    "signature": "ed25519:...",
    "issuer": "ed25519:ab12cd34...",
    "timestamp": "2026-02-27T15:30:00Z",
    "verdict": "FAIL"
  }
}
```

### Evidence chain

The `evidence` section provides cryptographic integrity:

- **envelope_hashes**: SHA-256 hash of every Spine envelope referenced in the report
- **merkle_root**: Merkle tree root over all envelope hashes
- **merkle_proofs**: Individual Merkle inclusion proofs for each envelope (verifiable with `clawdstrike merkle verify`)

This allows a third party to verify that every event in the report was present in the Spine telemetry at report generation time, without access to the full telemetry store.

### Receipt

When `--sign` is used, the report includes a `SignedReceipt` over the SHA-256 hash of the complete report (minus the receipt field itself). The receipt verdict reflects whether any critical-severity findings were included (`FAIL`) or not (`PASS`).

## Examples

Generate a report from a process timeline:

```bash
clawdstrike hunt report \
  --timeline 48291 \
  --since 2h \
  --sign --key hush.key \
  --title "Process 48291 investigation" \
  --analyst "security-team" \
  --output incident-48291.json
```

Include correlation and IOC results:

```bash
clawdstrike hunt report \
  --timeline 48291 \
  --correlate denied-tool-then-child-exec \
  --ioc-feed ./indicators.json \
  --since 4h \
  --sign --key hush.key \
  --notes "Triggered by alert from hunt watch. Agent attempted shell access after MCP denial." \
  --output full-report.json
```

Generate an HTML report for human review:

```bash
clawdstrike hunt report \
  --timeline 48291 \
  --since 2h \
  --format html \
  --output incident-report.html
```

Include results from a query:

```bash
clawdstrike hunt report \
  --query "verdict=deny,namespace=agent-pool" \
  --since 24h \
  --sign --key hush.key \
  --title "Daily denial summary" \
  --output daily-denials.json
```

Verify input envelopes before building the report:

```bash
clawdstrike hunt report \
  --timeline 48291 \
  --verify-inputs \
  --sign --key hush.key \
  --output verified-report.json
```

## Verifying a report

Recipients can verify the report receipt and evidence chain:

```bash
# Verify the report receipt signature
clawdstrike verify --pubkey analyst.pub report.json

# Verify a specific envelope's inclusion in the report Merkle tree
clawdstrike merkle verify --root <merkle_root> --proof <proof> --leaf <envelope_hash>
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Report generated (no critical findings) |
| 2 | Report generated with critical findings (verdict: FAIL) |
| 3 | Configuration error |
| 4 | Runtime error |

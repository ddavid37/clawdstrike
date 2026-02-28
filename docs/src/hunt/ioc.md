# hunt ioc

Match indicators of compromise (IOCs) against Spine telemetry to detect known threats in your AI agent environment.

## Purpose

`hunt ioc` takes IOC feeds (IP addresses, domains, file hashes, process names, tool names) and matches them against stored or streaming telemetry. It bridges traditional threat intelligence with AI agent security by supporting agent-specific indicators like malicious MCP tool names and known-bad policy hashes.

## Usage

```bash
clawdstrike hunt ioc [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--feed <ref>` | IOC feed reference (repeatable, see Feed sources below) | (required) |
| `--since <duration>` | Time window for telemetry search | `24h` |
| `--until <time>` | Time window end | now |
| `--layer <layer>` | Limit to specific layers (repeatable) | `all` |
| `--namespace <ns>` | Limit to Kubernetes namespace | (none) |
| `--stdin` | Read JSONL telemetry from stdin (for piping from `watch`) | `false` |
| `--json` | JSON output | `false` |
| `--jsonl` | Line-delimited JSON output | `false` |
| `--nats-url <url>` | NATS server URL | `nats://localhost:4222` |
| `--output <path>` | Write matches to file | (none) |
| `--min-confidence <n>` | Minimum IOC confidence score (0-100) | `0` |

## Feed sources

IOC feeds can be loaded from multiple sources:

| Reference format | Description |
|------------------|-------------|
| `clawdstrike://threat-feed` | Clawdstrike managed threat feed (requires API key) |
| `./indicators.json` | Local JSON file |
| `./indicators.csv` | Local CSV file (column headers: `type`, `value`, `confidence`, `description`) |
| `https://example.com/feed.json` | Remote feed URL (HTTPS only) |
| `stix://path/to/bundle.json` | STIX 2.1 bundle |

## IOC types

| Type | Matched against | Layer |
|------|----------------|-------|
| `ipv4`, `ipv6` | Source/destination IPs in flows | network |
| `domain` | DNS queries, HTTP host headers, egress targets | network, decisions |
| `sha256`, `md5` | File content hashes in decisions | decisions |
| `process_name` | Binary names in kernel events | kernel |
| `mcp_tool` | Tool names in MCP guard decisions | decisions |
| `policy_hash` | Policy hashes in signed receipts | decisions |
| `url` | Full URLs in HTTP flows and egress decisions | network, decisions |

## Feed file format

JSON feed format:

```json
{
  "name": "agent-threat-indicators",
  "version": "2026-02-27",
  "indicators": [
    {
      "type": "domain",
      "value": "evil-c2.example.com",
      "confidence": 95,
      "description": "Known C2 domain used in agent prompt injection campaigns",
      "tags": ["c2", "prompt-injection"]
    },
    {
      "type": "mcp_tool",
      "value": "filesystem_write_unrestricted",
      "confidence": 80,
      "description": "Suspicious MCP tool name associated with agent exploitation kits",
      "tags": ["exploitation", "mcp"]
    },
    {
      "type": "sha256",
      "value": "a1b2c3d4e5f6...",
      "confidence": 100,
      "description": "Known malicious payload hash",
      "tags": ["malware"]
    }
  ]
}
```

## Examples

Check the last 24 hours against a local IOC feed:

```bash
clawdstrike hunt ioc --feed ./indicators.json --since 24h
```

Check multiple feeds:

```bash
clawdstrike hunt ioc \
  --feed clawdstrike://threat-feed \
  --feed ./custom-indicators.json \
  --since 7d --json
```

Real-time IOC matching from watch output:

```bash
clawdstrike hunt watch --layer network --jsonl | \
  clawdstrike hunt ioc --stdin --feed ./indicators.json
```

Filter by confidence and namespace:

```bash
clawdstrike hunt ioc --feed ./indicators.json --min-confidence 80 --namespace production --since 48h
```

Check only network layer:

```bash
clawdstrike hunt ioc --feed ./indicators.json --layer network --since 12h
```

## Output

```text
IOC MATCHES (2 found against 847 indicators)

[HIGH] domain match: evil-c2.example.com (confidence: 95)
  Description: Known C2 domain used in agent prompt injection campaigns
  Tags: c2, prompt-injection
  Matches:
    2026-02-27T14:01:15 [network]   DNS query evil-c2.example.com from pod:research-agent-7f4b9
    2026-02-27T14:01:15 [network]   TCP -> 203.0.113.5:443 (evil-c2.example.com) DROPPED
    2026-02-27T14:01:15 [decisions] egress evil-c2.example.com:443 -> deny (egress_allowlist)

[MEDIUM] mcp_tool match: filesystem_write_unrestricted (confidence: 80)
  Description: Suspicious MCP tool name associated with agent exploitation kits
  Tags: exploitation, mcp
  Matches:
    2026-02-27T12:30:44 [decisions] mcp filesystem_write_unrestricted -> deny (mcp_tool_guard)

Summary: 2 IOC matches, 4 telemetry events, highest severity: HIGH
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No IOC matches found |
| 1 | IOC matches found (warning-level confidence) |
| 2 | IOC matches found (high-confidence) |
| 3 | Configuration error (invalid feed, bad format) |
| 4 | Runtime error |

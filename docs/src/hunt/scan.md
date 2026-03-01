# hunt scan

Discover MCP configuration files, introspect servers, run local/remote analysis, and optionally evaluate discovered tools against policy.

## Usage

```bash
clawdstrike hunt scan [OPTIONS]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--target <name|path>` | Client shorthand (`cursor`, `vscode`, `windsurf`, etc.) or explicit config path (repeatable) | auto-discover |
| `--package <uri>` | Scan package directly (`npm:...`, `pypi:...`, `oci:...`) (repeatable) | none |
| `--skills <dir>` | Scan skills directories (repeatable) | none |
| `--query <text>` | Keyword filter applied to output results | none |
| `--policy <path>` | Evaluate discovered tools with a policy file | none |
| `--ruleset <name>` | Evaluate discovered tools with a built-in ruleset | none |
| `--timeout <secs>` | MCP introspection timeout per server | `10` |
| `--include-builtin` | Include built-in IDE tools for known clients | `false` |
| `--json` | Emit JSON envelope output | `false` |
| `--analysis-url <url>` | Send redacted results to remote analysis API | none |
| `--skip-ssl-verify` | Disable TLS cert verification for `--analysis-url` | `false` |

## Notes

- `--query` filters displayed results, but history/change detection persists full unfiltered scan state.
- Scan history is stored at `~/.clawdstrike/scan_history.json`.
- Local heuristics include prompt-injection description checks and tool-name shadowing checks.

## Examples

```bash
# Auto-discover and scan local client configs
clawdstrike hunt scan

# Scan one client shorthand
clawdstrike hunt scan --target cursor

# Scan an explicit config path
clawdstrike hunt scan --target ~/.cursor/mcp.json

# Add built-in IDE tools to scan output
clawdstrike hunt scan --target vscode --include-builtin

# Scan packages and skills in the same run
clawdstrike hunt scan --package npm:@org/server --skills ~/.cursor/skills

# Evaluate discovered tools against a ruleset
clawdstrike hunt scan --ruleset strict

# Filter results to matching tools/descriptions
clawdstrike hunt scan --query "network"

# Remote analysis API with JSON output
clawdstrike hunt scan --analysis-url https://scanner.example/api/verify --json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues and no policy violations/failures |
| 1 | Issues found (warnings), no policy violations/failures |
| 2 | Policy violations or failure-class scan errors |
| 3 | Configuration error (invalid target/policy/ruleset) |
| 4 | Runtime error |
| 5 | Invalid arguments |

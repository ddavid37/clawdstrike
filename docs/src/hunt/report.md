# hunt report (planned)

`hunt report` is a planned command and is not implemented in the current CLI.

## Current Status

- There is no `clawdstrike hunt report` subcommand in `hush-cli` today.
- Command references were kept in docs as design intent, but should not be treated as available runtime behavior.

## Current Workaround

Use existing implemented commands plus signed artifacts:

```bash
# Gather investigation data
clawdstrike hunt query --json > query.json
clawdstrike hunt timeline --json > timeline.json
clawdstrike hunt correlate --rules ./rules/exfil.yaml --json > correlate.json
clawdstrike hunt ioc --feed ./ioc.txt --json > ioc.json

# Optionally sign evidence files
clawdstrike sign --key hush.key query.json
```

## Planned Scope (Design Intent)

A future `hunt report` command is expected to bundle timeline/query/correlation/IOC outputs into a single attestable report artifact. No API or CLI contract is finalized yet.

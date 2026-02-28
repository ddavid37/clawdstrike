# clawdstrike pkg

Package manager commands for initializing, installing, verifying, publishing, searching, and auditing Clawdstrike packages.

## Command Tree

- `clawdstrike pkg init --pkg-type <TYPE> --name <NAME>`
- `clawdstrike pkg pack [PATH]`
- `clawdstrike pkg install <SOURCE> [--version <VERSION>] [--registry <URL>] [--trust-level <LEVEL>]`
- `clawdstrike pkg list`
- `clawdstrike pkg verify <NAME> --version <VERSION> [--trust-level <LEVEL>] [--registry <URL>]`
- `clawdstrike pkg info <NAME> --version <VERSION>`
- `clawdstrike pkg login [--registry <URL>]`
- `clawdstrike pkg publish [PATH] [--registry <URL>] [--oidc]`
- `clawdstrike pkg search <QUERY> [--limit <N>] [--page <N>] [--registry <URL>]`
- `clawdstrike pkg audit <NAME> [--limit <N>] [--registry <URL>]`
- `clawdstrike pkg yank <NAME> --version <VERSION> [--registry <URL>]`
- `clawdstrike pkg stats <NAME> [--registry <URL>]`
- `clawdstrike pkg org <subcommand>`
- `clawdstrike pkg trusted-publishers <subcommand>`
- `clawdstrike pkg mirror <subcommand>`

## Trust Levels

- `unverified`: no registry signature requirements.
- `signed`: publisher signature is required and verified.
- `verified`: publisher + registry counter-signatures are required and verified.
- `certified`: verified + transparency inclusion proof availability.

## Notes

- Registry auth token is read from `CLAWDSTRIKE_AUTH_TOKEN` or `~/.clawdstrike/credentials.toml`.
- `pkg login` prepares local publisher keys and validates config; token setup is currently manual.

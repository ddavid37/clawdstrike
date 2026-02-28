# clawdstrike pkg install

Install a package from a local `.cpkg` file or a registry.

## Usage

```bash
clawdstrike pkg install <SOURCE> [--version <VERSION>] [--registry <URL>] [--trust-level <LEVEL>] [--allow-unverified]
```

## SOURCE

- Local path: `/path/to/pkg.cpkg`
- Registry name: `@scope/name` or `name`

## Behavior

- Local source installs directly into the package store.
- Registry source downloads and installs a version.
- If `--version` is omitted for registry installs, the CLI resolves latest from package stats.

## Trust Enforcement

- Default trust level: `signed`.
- At `signed` and above, publisher signature and checksum binding are verified.
- At `verified` and above, registry counter-signature is also verified.
- At `certified`, inclusion proof endpoint must be available.

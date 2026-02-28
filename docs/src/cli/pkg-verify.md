# clawdstrike pkg verify

Verify an installed package against local integrity and registry trust metadata.

## Usage

```bash
clawdstrike pkg verify <NAME> --version <VERSION> [--trust-level <LEVEL>] [--registry <URL>]
```

## Checks

- Local package metadata and content hash
- Registry attestation checksum match
- Publisher signature verification
- Registry counter-signature verification (for `verified`/`certified`)
- Transparency proof endpoint availability (for `certified`)

## Exit Codes

- `0` when achieved trust meets/exceeds required level
- non-zero when checks fail or trust level is insufficient

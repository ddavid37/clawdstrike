# Trust & Verification

Clawdstrike trust levels are derived from cryptographic evidence tied to package content hashes.

## Evidence Chain

1. Archive SHA-256 (`checksum`)
2. Publisher signature over checksum hash bytes
3. Registry counter-signature over checksum hash bytes
4. Transparency inclusion proof availability

## Trust Levels

- `unverified`: local integrity only
- `signed`: publisher signature verified
- `verified`: publisher + registry signatures verified
- `certified`: verified + inclusion proof endpoint available

## Caller Authentication for Org/Trusted-Publisher Mutations

Sensitive org and trusted-publisher updates are authenticated with signed caller headers:

- `X-Clawdstrike-Caller-Key`
- `X-Clawdstrike-Caller-Sig`
- `X-Clawdstrike-Caller-Ts`

Signatures cover endpoint-specific payloads plus timestamp to prevent caller-key spoofing.

# hunt testing

`hush-cli` includes a process-level E2E battery for `hunt` command behavior:

- Real `hush` CLI process execution.
- Real NATS/JetStream transport.
- Local mock MCP server for `hunt scan`.
- Offline fallback validation for `hunt query`.

## Covered Scenarios

- `hunt scan` JSON contract against a live mock MCP endpoint.
- `hunt query` historical replay from JetStream streams.
- `hunt timeline` chronological ordering contract.
- `hunt correlate` alert generation + warning exit code.
- `hunt watch` live alert stream + graceful shutdown summary.
- `hunt ioc` IOC match detection + warning exit code.
- `hunt query` NATS failure fallback to local `--local-dir` data.

## Local Execution

```bash
cargo test -p hush-cli --test hunt_e2e -- --nocapture --test-threads=1
```

### Runtime Requirements

- Preferred: Docker (used to start `nats:2.10-alpine -js`).
- Fallback: local `nats-server` binary with JetStream support.

If neither backend exists locally, the test exits early with a skip message.
In CI (`CI=true`), missing NATS backend is treated as a hard failure.

## Debugging Aids

- Preserve artifacts:

```bash
HUSH_HUNT_E2E_KEEP_ARTIFACTS=1 cargo test -p hush-cli --test hunt_e2e -- --nocapture --test-threads=1
```

- Increase per-command timeout (milliseconds):

```bash
HUSH_HUNT_E2E_TIMEOUT_MS=60000 cargo test -p hush-cli --test hunt_e2e -- --nocapture --test-threads=1
```

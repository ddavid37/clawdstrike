import { describe, expect, it } from "vitest";

import { backoffForAttempt, retry } from "./retry.js";
import { AsyncGuardError, type RetryConfig } from "./types.js";

const RETRY_CFG: RetryConfig = {
  maxRetries: 3,
  initialBackoffMs: 1,
  maxBackoffMs: 32,
  multiplier: 2,
};

describe("async retry", () => {
  it("does not retry non-retryable failures", async () => {
    let attempts = 0;
    await expect(
      retry(
        RETRY_CFG,
        async () => {
          attempts += 1;
          throw new AsyncGuardError("parse", "bad response payload", 200);
        },
        undefined,
        {
          shouldRetry: (err) =>
            err instanceof AsyncGuardError && (err.status ?? 0) >= 500,
        },
      ),
    ).rejects.toThrow(/bad response payload/);

    expect(attempts).toBe(1);
  });

  it("retries transient failures and succeeds", async () => {
    let attempts = 0;
    const result = await retry(
      RETRY_CFG,
      async () => {
        attempts += 1;
        if (attempts < 3) {
          throw new AsyncGuardError("http", "upstream unavailable", 503);
        }
        return "ok";
      },
      undefined,
      {
        shouldRetry: (err) =>
          err instanceof AsyncGuardError && err.kind === "http" && (err.status ?? 0) >= 500,
      },
    );

    expect(result).toBe("ok");
    expect(attempts).toBe(3);
  });

  it("bounds jittered backoff within +/-20%", () => {
    const attempt = 3; // capped base should be 8ms with current config.
    const min = backoffForAttempt(RETRY_CFG, attempt, () => 0);
    const max = backoffForAttempt(RETRY_CFG, attempt, () => 1);

    expect(min).toBeGreaterThanOrEqual(6);
    expect(min).toBeLessThanOrEqual(8);
    expect(max).toBeGreaterThanOrEqual(8);
    expect(max).toBeLessThanOrEqual(10);
  });
});

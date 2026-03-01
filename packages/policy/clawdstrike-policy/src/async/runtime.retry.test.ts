import type { PolicyEvent } from "@clawdstrike/adapter-core";

import { AsyncGuardRuntime } from "./runtime.js";
import { AsyncGuardError, type AsyncGuard, type GuardResult } from "./types.js";

const EVENT: PolicyEvent = {
  eventId: "evt-async-retry",
  eventType: "tool_call",
  timestamp: new Date().toISOString(),
  data: {
    type: "tool",
    toolName: "test_tool",
    parameters: {},
  },
};

function createAsyncGuard(
  name: string,
  check: () => Promise<GuardResult>,
  maxRetries = 2,
): AsyncGuard {
  return {
    name,
    handles: () => true,
    cacheKey: () => null,
    config: {
      timeoutMs: 250,
      onTimeout: "warn",
      executionMode: "sequential",
      cacheEnabled: false,
      cacheTtlSeconds: 60,
      cacheMaxSizeBytes: 1024,
      retry: {
        maxRetries,
        initialBackoffMs: 1,
        maxBackoffMs: 5,
        multiplier: 2,
      },
    },
    checkUncached: async () => await check(),
  };
}

describe("async runtime retry classification", () => {
  it("does not retry parse failures", async () => {
    let attempts = 0;
    const runtime = new AsyncGuardRuntime();
    const guard = createAsyncGuard("parse_guard", async () => {
      attempts += 1;
      throw new AsyncGuardError("parse", "invalid json payload", 200);
    });

    const out = await runtime.evaluateAsyncGuards([{ index: 0, guard }], EVENT);
    expect(attempts).toBe(1);
    expect(out).toHaveLength(1);
    expect(out[0].allowed).toBe(true);
    expect(out[0].details?.async_error).toEqual({
      kind: "parse",
      message: "invalid json payload",
    });
  });

  it("retries transient 503 failures", async () => {
    let attempts = 0;
    const runtime = new AsyncGuardRuntime();
    const guard = createAsyncGuard("http_guard", async () => {
      attempts += 1;
      if (attempts === 1) {
        throw new AsyncGuardError("http", "upstream unavailable", 503);
      }
      return {
        allowed: true,
        guard: "http_guard",
        severity: "low",
        message: "Allowed",
      };
    });

    const out = await runtime.evaluateAsyncGuards([{ index: 0, guard }], EVENT);
    expect(attempts).toBe(2);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      allowed: true,
      guard: "http_guard",
      severity: "low",
      message: "Allowed",
    });
  });
});

import type { PolicyEngineLike } from "@clawdstrike/adapter-core";
import { describe, expect, it, vi } from "vitest";

import { createClawdstrikeMiddleware } from "./middleware.js";

describe("createClawdstrikeMiddleware", () => {
  it("wraps tools and injects policy_check when enabled", async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };

    const middleware = createClawdstrikeMiddleware({
      engine,
      config: { injectPolicyCheckTool: true },
    });

    const execute = vi.fn(async () => "ok");
    const tools = middleware.wrapTools({ ping: { execute } });

    expect(typeof tools.ping.execute).toBe("function");
    expect("policy_check" in tools).toBe(true);

    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (tools as any).policy_check.execute({ toolName: "ping", input: {} }),
    ).resolves.toMatchObject({ denied: false });
  });
});

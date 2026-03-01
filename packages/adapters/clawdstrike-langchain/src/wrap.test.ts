import type { PolicyEngineLike, ToolInterceptor } from "@clawdstrike/adapter-core";

import { ClawdstrikeBlockedError } from "@clawdstrike/adapter-core";
import { describe, expect, it, vi } from "vitest";

import { secureTool, secureTools } from "./wrap.js";

describe("secureTool", () => {
  it("wraps invoke() and allows execution when policy allows", async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };

    const tool = {
      name: "calc",
      invoke: vi.fn(async (input: { value: number }) => input.value + 1),
    };

    const secured = secureTool(tool, engine);
    await expect(secured.invoke({ value: 41 })).resolves.toBe(42);
    expect(tool.invoke).toHaveBeenCalledTimes(1);
  });

  it("wraps _call() and blocks when policy denies", async () => {
    const engine: PolicyEngineLike = {
      evaluate: (event) => ({
        status: event.eventType === "command_exec" ? "deny" : "allow",
        message: "blocked",
      }),
    };

    const tool = {
      name: "bash",
      _call: vi.fn(async () => "ok"),
    };

    const secured = secureTool(tool, engine);
    await expect(secured._call({ cmd: "rm -rf /" })).rejects.toBeInstanceOf(
      ClawdstrikeBlockedError,
    );
    expect(tool._call).toHaveBeenCalledTimes(0);
  });

  it("calls onError when wrapped method throws", async () => {
    const onError = vi.fn(async () => undefined);
    const interceptor: ToolInterceptor = {
      beforeExecute: async () => ({
        proceed: true,
        decision: { allowed: true, denied: false, warn: false },
        duration: 0,
      }),
      afterExecute: async (_name, _input, output) => ({ output, modified: false }),
      onError,
    };

    const tool = {
      name: "boom",
      async invoke() {
        throw new Error("boom");
      },
    };

    const secured = secureTool(tool, interceptor);
    await expect(secured.invoke({})).rejects.toThrow("boom");
    expect(onError).toHaveBeenCalledTimes(1);
  });
});

describe("secureTools", () => {
  it("wraps a list of tools with a shared context", async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ allowed: true, denied: false, warn: false }),
    };

    const a = { name: "a", invoke: vi.fn(async () => "a") };
    const b = { name: "b", invoke: vi.fn(async () => "b") };

    const [wa, wb] = secureTools([a, b], engine);
    await expect(wa.invoke({})).resolves.toBe("a");
    await expect(wb.invoke({})).resolves.toBe("b");
  });
});

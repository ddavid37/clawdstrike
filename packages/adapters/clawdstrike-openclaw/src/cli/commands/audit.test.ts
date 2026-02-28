import { mkdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditStore } from "../../audit/store.js";
import { auditCommands } from "./audit.js";

describe("auditCommands", () => {
  const testDir = join(tmpdir(), "clawdstrike-audit-test-" + Date.now());
  let consoleLog: ReturnType<typeof vi.spyOn>;
  let store: AuditStore;

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
    store = new AuditStore(join(testDir, "audit.jsonl"));
    consoleLog = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
    consoleLog.mockRestore();
  });

  describe("query", () => {
    it("lists recent events", async () => {
      store.append({ type: "file_read", resource: "/tmp/test", decision: "allowed" });
      store.append({
        type: "file_read",
        resource: "~/.ssh/id_rsa",
        decision: "denied",
        guard: "ForbiddenPathGuard",
      });

      await auditCommands.query({ auditPath: join(testDir, "audit.jsonl") });
      expect(consoleLog).toHaveBeenCalled();
    });

    it("filters by denied only", async () => {
      store.append({ type: "file_read", resource: "/tmp/test", decision: "allowed" });
      store.append({
        type: "file_read",
        resource: "~/.ssh/id_rsa",
        decision: "denied",
        guard: "ForbiddenPathGuard",
      });

      await auditCommands.query({ denied: true, auditPath: join(testDir, "audit.jsonl") });
      // Should only show denied events
      expect(consoleLog).toHaveBeenCalled();
    });
  });

  describe("explain", () => {
    it("explains a specific event", async () => {
      const event = store.append({
        type: "file_read",
        resource: "~/.ssh/id_rsa",
        decision: "denied",
        guard: "ForbiddenPathGuard",
        reason: "Path matches forbidden pattern: ~/.ssh",
      });

      await auditCommands.explain(event.id, { auditPath: join(testDir, "audit.jsonl") });
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining("ForbiddenPathGuard"));
    });

    it("handles unknown event id", async () => {
      await auditCommands.explain("unknown-id", { auditPath: join(testDir, "audit.jsonl") });
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining("not found"));
    });
  });
});

import type { AdapterConfig } from "./adapter.js";
import { BaseToolInterceptor } from "./base-tool-interceptor.js";
import type { PolicyEngineLike } from "./engine.js";
import type { ToolInterceptor } from "./interceptor.js";

/**
 * Duck-typed interface matching Clawdstrike SDK instances that expose
 * an interceptor factory method.
 */
export interface ClawdstrikeLike {
  createInterceptor?: () => ToolInterceptor;
}

/**
 * Union of every accepted security source type.
 *
 * Adapters accept any of:
 * - A `ClawdstrikeLike` instance (SDK object with `createInterceptor`)
 * - A raw `PolicyEngineLike` engine
 * - A pre-built `ToolInterceptor`
 */
export type SecuritySource = ClawdstrikeLike | PolicyEngineLike | ToolInterceptor;

/**
 * Resolve a {@link SecuritySource} into a concrete {@link ToolInterceptor}.
 *
 * Resolution order:
 * 1. Already a `ToolInterceptor` → return as-is
 * 2. `ClawdstrikeLike` with `createInterceptor` → call it
 * 3. `PolicyEngineLike` → wrap in a new `BaseToolInterceptor`
 */
export function resolveInterceptor(
  source: SecuritySource,
  config?: AdapterConfig,
): ToolInterceptor {
  if (isToolInterceptor(source)) {
    return source;
  }
  if (isClawdstrikeLike(source)) {
    return source.createInterceptor!();
  }
  return new BaseToolInterceptor(source as PolicyEngineLike, config ?? {});
}

export function isToolInterceptor(value: unknown): value is ToolInterceptor {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as ToolInterceptor).beforeExecute === "function" &&
    typeof (value as ToolInterceptor).afterExecute === "function" &&
    typeof (value as ToolInterceptor).onError === "function"
  );
}

export function isClawdstrikeLike(value: unknown): value is ClawdstrikeLike {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as ClawdstrikeLike).createInterceptor === "function"
  );
}

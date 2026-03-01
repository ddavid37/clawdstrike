import type { AdapterConfig, PolicyEngineLike, SecurityContext, ToolInterceptor } from "@clawdstrike/adapter-core";
import {
  BaseToolInterceptor,
  ClawdstrikeBlockedError,
  createSecurityContext,
  isClawdstrikeLike,
  isToolInterceptor,
  type SecuritySource,
} from "@clawdstrike/adapter-core";

import { claudeCuaTranslator } from "./claude-cua-translator.js";

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

type ClaudeToolLike<TInput = unknown, TOutput = unknown> = {
  execute?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
  call?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export function secureTools<TTools extends Record<string, ClaudeToolLike>>(
  tools: TTools,
  source: SecuritySource,
  options?: SecureToolsOptions,
): TTools {
  let interceptor: ToolInterceptor;

  if (isToolInterceptor(source)) {
    interceptor = source;
  } else if (isClawdstrikeLike(source)) {
    interceptor = source.createInterceptor!();
  } else {
    const config: AdapterConfig = {
      translateToolCall: claudeCuaTranslator,
    };
    interceptor = new BaseToolInterceptor(source as PolicyEngineLike, config);
  }

  const defaultContext =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "claude" },
    });

  const secured = {} as TTools;
  for (const [toolName, tool] of Object.entries(tools)) {
    const originalExecute = tool.execute ?? tool.call;
    if (typeof originalExecute !== "function") {
      (secured as Record<string, ClaudeToolLike>)[toolName] = tool;
      continue;
    }

    (secured as Record<string, ClaudeToolLike>)[toolName] = {
      ...(tool as object),
      execute: wrapExecute(toolName, originalExecute, interceptor, defaultContext, options?.getContext),
    } as ClaudeToolLike;
  }

  return secured;
}

function wrapExecute<TInput, TOutput>(
  toolName: string,
  execute: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput,
  interceptor: ToolInterceptor,
  defaultContext: SecurityContext,
  getContext?: (toolName: string, input: unknown) => SecurityContext,
): (input: TInput, ...rest: unknown[]) => Promise<TOutput> {
  return async (input: TInput, ...rest: unknown[]): Promise<TOutput> => {
    const context = getContext ? getContext(toolName, input) : defaultContext;

    let interceptResult;
    try {
      interceptResult = await interceptor.beforeExecute(toolName, input, context);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      await interceptor.onError(toolName, input, err, context);
      throw err;
    }

    if (!interceptResult.proceed) {
      const { decision } = interceptResult;
      throw new ClawdstrikeBlockedError(toolName, decision);
    }

    const nextInput = (interceptResult.modifiedParameters as unknown as TInput) ?? input;

    if (interceptResult.replacementResult !== undefined) {
      const processed = await interceptor.afterExecute(
        toolName,
        nextInput,
        interceptResult.replacementResult as TOutput,
        context,
      );
      return processed.output as TOutput;
    }

    try {
      const output = await execute(nextInput, ...rest);
      const processed = await interceptor.afterExecute(toolName, nextInput, output, context);
      return processed.output as TOutput;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      await interceptor.onError(toolName, nextInput, err, context);
      throw err;
    }
  };
}

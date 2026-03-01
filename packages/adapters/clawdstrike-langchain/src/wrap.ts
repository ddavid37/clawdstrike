import type {
  Decision,
  PolicyEngineLike,
  SecurityContext,
  ToolInterceptor,
} from "@clawdstrike/adapter-core";
import {
  ClawdstrikeBlockedError,
  createSecurityContext,
  isClawdstrikeLike,
  isToolInterceptor,
  type SecuritySource,
} from "@clawdstrike/adapter-core";

import { createLangChainInterceptor } from "./interceptor.js";

type LangChainInvokeLike<TInput = unknown, TOutput = unknown> = {
  invoke: (input: TInput, config?: unknown) => Promise<TOutput> | TOutput;
};

type LangChainCallLike<TInput = unknown, TOutput = unknown> = {
  _call: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

type LangChainToolLike = Partial<LangChainInvokeLike> &
  Partial<LangChainCallLike> & {
    name?: string;
  };

export interface WrapToolOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

function resolveInterceptor(source: SecuritySource): ToolInterceptor {
  if (isToolInterceptor(source)) {
    return source;
  }
  if (isClawdstrikeLike(source)) {
    return source.createInterceptor!();
  }
  return createLangChainInterceptor(source as PolicyEngineLike);
}

/**
 * Secure a single LangChain tool using a Clawdstrike instance or PolicyEngineLike.
 *
 * @example Using with Clawdstrike (recommended)
 * ```typescript
 * import { Clawdstrike } from '@clawdstrike/sdk';
 * import { secureTool } from '@clawdstrike/langchain';
 *
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 * const secured = secureTool(myTool, cs);
 * ```
 */
export function secureTool<TTool extends LangChainToolLike>(
  tool: TTool,
  source: SecuritySource,
  options?: WrapToolOptions,
): TTool {
  const interceptor = resolveInterceptor(source);
  return wrapTool(tool, interceptor, options);
}

/**
 * Secure multiple LangChain tools using a Clawdstrike instance or PolicyEngineLike.
 *
 * @example
 * ```typescript
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 * const securedTools = secureTools([toolA, toolB], cs);
 * ```
 */
export function secureTools<TTool extends LangChainToolLike>(
  tools: readonly TTool[],
  source: SecuritySource,
  options?: WrapToolOptions,
): TTool[] {
  const interceptor = resolveInterceptor(source);
  return wrapTools(tools, interceptor, options);
}

function wrapTool<TTool extends LangChainToolLike>(
  tool: TTool,
  interceptor: ToolInterceptor,
  options?: WrapToolOptions,
): TTool {
  const context =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "langchain" },
    });
  return wrapToolWithContext(tool, interceptor, context, options?.getContext);
}

function wrapTools<TTool extends LangChainToolLike>(
  tools: readonly TTool[],
  interceptor: ToolInterceptor,
  options?: WrapToolOptions,
): TTool[] {
  const context =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "langchain" },
    });
  return tools.map((tool) => wrapToolWithContext(tool, interceptor, context, options?.getContext));
}

function wrapToolWithContext<TTool extends LangChainToolLike>(
  tool: TTool,
  interceptor: ToolInterceptor,
  context: SecurityContext,
  getContext?: (toolName: string, input: unknown) => SecurityContext,
): TTool {
  const toolName = typeof tool.name === "string" && tool.name.length > 0 ? tool.name : "tool";
  const hasInvoke = typeof tool.invoke === "function";
  const hasCall = typeof tool._call === "function";

  if (!hasInvoke && !hasCall) {
    throw new Error(`Tool must implement invoke(input, ...) or _call(input, ...)`);
  }

  const originalInvoke = hasInvoke ? tool.invoke!.bind(tool) : undefined;
  const originalCall = hasCall ? tool._call!.bind(tool) : undefined;

  let lastDecision: Decision | null = null;

  const wrappedInvoke = hasInvoke
    ? async (input: unknown, config?: unknown) => {
        const resolvedContext = getContext ? getContext(toolName, input) : context;
        return runIntercepted(
          toolName,
          interceptor,
          resolvedContext,
          input,
          (decision) => {
            lastDecision = decision;
          },
          (nextInput: unknown) => originalInvoke!(nextInput, config),
        );
      }
    : undefined;

  const wrappedCall = hasCall
    ? async (input: unknown, ...rest: unknown[]) => {
        const resolvedContext = getContext ? getContext(toolName, input) : context;
        return runIntercepted(
          toolName,
          interceptor,
          resolvedContext,
          input,
          (decision) => {
            lastDecision = decision;
          },
          (nextInput: unknown) => originalCall!(nextInput, ...rest),
        );
      }
    : undefined;

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke" && wrappedInvoke) {
        return wrappedInvoke;
      }
      if (prop === "_call" && wrappedCall) {
        return wrappedCall;
      }
      if (prop === "getLastDecision") {
        return () => lastDecision;
      }

      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value === "function") {
        return (value as (...args: unknown[]) => unknown).bind(target);
      }
      return value;
    },
  });
}

async function runIntercepted<TOutput>(
  toolName: string,
  interceptor: ToolInterceptor,
  context: SecurityContext,
  input: unknown,
  onDecision: (decision: Decision) => void,
  invoke: (nextInput: unknown) => Promise<TOutput> | TOutput,
): Promise<TOutput> {
  let interceptResult;
  try {
    interceptResult = await interceptor.beforeExecute(toolName, input, context);
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    await interceptor.onError(toolName, input, err, context);
    throw err;
  }

  onDecision(interceptResult.decision);

  if (!interceptResult.proceed) {
    const { decision } = interceptResult;
    throw new ClawdstrikeBlockedError(toolName, decision);
  }

  const nextInput = interceptResult.modifiedParameters ?? input;

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
    const output = await invoke(nextInput);
    const processed = await interceptor.afterExecute(toolName, nextInput, output, context);
    return processed.output as TOutput;
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    await interceptor.onError(toolName, nextInput, err, context);
    throw err;
  }
}

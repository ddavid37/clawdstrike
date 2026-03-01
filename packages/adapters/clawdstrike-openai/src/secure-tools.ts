import type { SecurityContext } from "@clawdstrike/adapter-core";
import {
  createSecurityContext,
  resolveInterceptor,
  type SecuritySource,
  wrapExecuteWithInterceptor,
} from "@clawdstrike/adapter-core";

import { openAICuaTranslator } from "./openai-cua-translator.js";

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

type OpenAIToolLike<TInput = unknown, TOutput = unknown> = {
  execute?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
  call?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export function secureTools<TTools extends Record<string, OpenAIToolLike>>(
  tools: TTools,
  source: SecuritySource,
  options?: SecureToolsOptions,
): TTools {
  const interceptor = resolveInterceptor(source, {
    translateToolCall: openAICuaTranslator,
  });

  const defaultContext =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "openai" },
    });

  const secured = {} as TTools;
  for (const [toolName, tool] of Object.entries(tools)) {
    const originalExecute = tool.execute ?? tool.call;
    if (typeof originalExecute !== "function") {
      (secured as Record<string, OpenAIToolLike>)[toolName] = tool;
      continue;
    }

    const wrapped = wrapExecuteWithInterceptor(
      toolName,
      originalExecute.bind(tool),
      interceptor,
      defaultContext,
      options?.getContext,
    );
    (secured as Record<string, OpenAIToolLike>)[toolName] = {
      ...(tool as object),
      execute: wrapped,
      call: wrapped,
    } as OpenAIToolLike;
  }

  return secured;
}

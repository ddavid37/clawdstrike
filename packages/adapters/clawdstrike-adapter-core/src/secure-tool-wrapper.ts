import type { SecurityContext } from "./context.js";
import { ClawdstrikeBlockedError } from "./errors.js";
import type { ToolInterceptor } from "./interceptor.js";

export function wrapExecuteWithInterceptor<TInput, TOutput>(
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

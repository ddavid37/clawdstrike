import { BaseToolInterceptor } from '@backbay/adapter-core';
import type { AdapterConfig, PolicyEngineLike } from '@backbay/adapter-core';

export type VercelAiInterceptorConfig = AdapterConfig;

export function createVercelAiInterceptor(
  engine: PolicyEngineLike,
  config: VercelAiInterceptorConfig = {},
): BaseToolInterceptor {
  return new BaseToolInterceptor(engine, config);
}


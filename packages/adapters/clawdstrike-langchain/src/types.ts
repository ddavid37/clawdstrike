import type { AdapterConfig } from '@backbay/adapter-core';

export type LangChainClawdstrikeConfig = AdapterConfig & {
  toolNameMapping?: Record<string, string>;
};


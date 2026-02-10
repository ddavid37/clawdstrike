# `@backbay/langchain`

Baseline wrappers for LangChain-style tools. No hard runtime dependency on LangChain.

## Install

```bash
npm install @backbay/langchain @backbay/adapter-core @backbay/hush-cli-engine
```

## Usage

```ts
import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { BaseToolInterceptor } from '@backbay/adapter-core';
import { wrapTool } from '@backbay/langchain';

const engine = createHushCliEngine({ policyRef: 'default' });
const interceptor = new BaseToolInterceptor(engine, { blockOnViolation: true });

const tool = {
  name: 'bash',
  async invoke(input: { cmd: string }) {
    return `ran: ${input.cmd}`;
  },
};

const secureTool = wrapTool(tool, interceptor);
await secureTool.invoke({ cmd: 'echo hello' });
```

## Config overrides

```ts
import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { wrapToolWithConfig } from '@backbay/langchain';

const engine = createHushCliEngine({ policyRef: 'default' });
const tool = { name: 'bash', async _call() { return 'ok'; } };

const secureTool = wrapToolWithConfig(tool, engine, { blockOnViolation: false });
const stricter = secureTool.withConfig({ blockOnViolation: true });
```

## Callback handler (in-process hooks)

```ts
import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { ClawdstrikeCallbackHandler } from '@backbay/langchain';

const engine = createHushCliEngine({ policyRef: 'default' });
const handler = new ClawdstrikeCallbackHandler({ engine });
```

## Errors

Blocked tool calls throw `ClawdstrikeViolationError` (includes `decision` and `toolName`).

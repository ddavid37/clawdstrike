# `@backbay/codex`

In-process tool-boundary hooks for Codex-style coding assistants.

This package is intentionally **runtime-agnostic**: you wire it into the layer that actually executes tools (file/network/command/etc).

## Install

```bash
npm install @backbay/codex @backbay/adapter-core @backbay/hush-cli-engine
```

## Usage

```ts
import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { CodexToolBoundary, wrapCodexToolDispatcher } from '@backbay/codex';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new CodexToolBoundary({ engine });

// Drop-in wrapper around your real dispatcher:
const dispatchTool = wrapCodexToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('bash', { cmd: 'echo hello' }, 'run-123');
```

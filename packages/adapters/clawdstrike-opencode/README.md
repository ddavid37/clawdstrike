# `@backbay/opencode`

In-process tool-boundary hooks for OpenCode-style coding assistants.

## Install

```bash
npm install @backbay/opencode @backbay/adapter-core @backbay/hush-cli-engine
```

## Usage

```ts
import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { OpenCodeToolBoundary, wrapOpenCodeToolDispatcher } from '@backbay/opencode';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new OpenCodeToolBoundary({ engine });

const dispatchTool = wrapOpenCodeToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('write_file', { path: './out.txt', content: 'hi' }, 'run-1');
```

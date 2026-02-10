# `@backbay/claude-code`

In-process tool-boundary hooks for Claude Code-style assistants.

Use this at the layer that executes tools on behalf of the model.

## Install

```bash
npm install @backbay/claude-code @backbay/adapter-core @backbay/hush-cli-engine
```

## Usage

```ts
import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { ClaudeCodeToolBoundary, wrapClaudeCodeToolDispatcher } from '@backbay/claude-code';

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new ClaudeCodeToolBoundary({ engine });

const dispatchTool = wrapClaudeCodeToolDispatcher(boundary, async (toolName, input, runId) => {
  // ...execute the tool...
  return { toolName, input, runId };
});

await dispatchTool('read_file', { path: './README.md' }, 'run-1');
```

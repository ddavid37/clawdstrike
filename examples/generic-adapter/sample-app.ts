import { createHushCliEngine } from '@backbay/hush-cli-engine';
import { GenericToolBoundary, wrapGenericToolDispatcher } from '@backbay/adapter-core';

type ToolInput = Record<string, unknown>;
type ToolOutput = { toolName: string; input: ToolInput; runId: string };

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new GenericToolBoundary<ToolInput, ToolOutput>({
  engine,
  config: {
    blockOnViolation: true,
    sanitizeOutputs: true,
  },
});

const dispatchTool = wrapGenericToolDispatcher(
  boundary,
  async (toolName, input, runId) => ({ toolName, input, runId }),
);

const result = await dispatchTool('read_file', { path: './README.md' }, 'run-local-1');
console.log(result);
console.log(`audit events: ${boundary.getAuditEvents().length}`);

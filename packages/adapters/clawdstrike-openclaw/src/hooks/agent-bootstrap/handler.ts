/**
 * @clawdstrike/openclaw - Agent Bootstrap Hook Handler
 *
 * Injects a SECURITY.md file into the agent bootstrap context.
 */

import { getSharedEngine, initializeEngine } from "../../engine-holder.js";
import { generateSecurityPrompt } from "../../security-prompt.js";
import type {
  AgentBootstrapEvent,
  ClawdstrikeConfig,
  HookEvent,
  HookHandler,
} from "../../types.js";

/**
 * Initialize the hook with configuration.
 * Delegates to the shared engine holder so all hooks share one PolicyEngine.
 */
export function initialize(config: ClawdstrikeConfig): void {
  initializeEngine(config);
}

function getEngine(config?: ClawdstrikeConfig) {
  return getSharedEngine(config);
}

const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== "agent:bootstrap") return;

  const bootstrap = event as AgentBootstrapEvent;
  const cfg = bootstrap.context.cfg;
  const policyEngine = getEngine(cfg);

  const policy = policyEngine.getPolicy();
  const enabledGuards = policyEngine.enabledGuards();

  const securityPrompt =
    generateSecurityPrompt(policy) +
    `\n\n## Enabled Guards\n` +
    enabledGuards.map((g) => `- ${g}`).join("\n");

  bootstrap.context.bootstrapFiles.push({
    path: "SECURITY.md",
    content: securityPrompt,
  });
};

export default handler;

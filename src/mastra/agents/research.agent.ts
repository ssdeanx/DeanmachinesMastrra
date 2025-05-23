import { createAdvancedAgent } from "./advanced.base.agent";
import { researchAgentConfig } from "./config";
import { redisMemory as sharedMemory } from "../database/redis";
import { createLogger } from "@mastra/core";

// Optional: define preHooks, postHooks, or advanced options as needed
const logger = createLogger({ name: "research-agent", level: "debug" });

export const researchAgent = createAdvancedAgent(
  researchAgentConfig,
  { enableTracing: true }, // advanced options
  sharedMemory,
  undefined, // onEvent (optional)
  async (error: Error) => {
    logger.error("Research agent error:", error);
    return {
      text: "I encountered an error during research. Please refine your query or check the available sources.",
    };
  }
  // Optionally, you can pass preHooks and postHooks arrays here as well
);

// Example: use restOptions in a model call
const result = await researchAgent.model.generate({
  ...researchAgent.restOptions,
  prompt: 'Find me the latest AI research papers.',
});

export type ResearchAgent = typeof researchAgent;
export default researchAgent;/**
 * Research Agent Implementation
 *
 * This agent is specialized in finding, gathering, and synthesizing information
 * from various sources including web searches, document repositories, and files.
 */

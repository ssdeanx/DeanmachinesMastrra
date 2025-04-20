/**
 * Base Agent Implementation
 *
 * This module provides utility functions to create agents from configurations,
 * ensuring consistent agent creation patterns across the application.
 */

import { Agent } from "@mastra/core/agent";
import { Tool } from "@mastra/core/tools";
import { createLogger } from "@mastra/core/logger";
import { sharedMemory } from "../database";
import { upstashLogger } from "../database/upstashLog";
import { fileLogger } from "../database/fileLogger";
import { initSigNoz } from "../services/signoz";
import { initializeDefaultTracing } from "../services/tracing";
import {
  BaseAgentConfig,
  defaultErrorHandler,
  defaultResponseValidation,
  type ResponseHookOptions,
  createModelInstance
} from "./config/index";
import { createResponseHook } from "../hooks";
import { allToolsMap } from "../tools";
import * as api from "@opentelemetry/api";
//import { createGoogleVoice } from "../voice";

// ─── Initialize Google Voice ────────────────────────────────────────────────
//const voice = createGoogleVoice({
//  apiKey: process.env.GOOGLE_API_KEY!,
//  speaker: process.env.GOOGLE_VOICE_SPEAKER || "en-US-Wavenet-D",
//});

// If your provider requires an explicit connection:
//if (typeof voice.connect === "function") {
//  voice.connect().catch(err =>
//    console.error("Voice connect error:", err)
//  );
//}

// Optional: log STT results as they come in
//voice.on("listen", ({ text }) => {
//  logger.debug("STT:", { text });
//});

// Optional: hook into audio output events
//voice.on("speaker", (audioStream) => {
  // audioStream.pipe(/* your playback stream */);
//});

// ─── Initialize OpenTelemetry + SigNoz before any agent logic ─────────────────
initializeDefaultTracing();
const { tracer: signozTracer, meterProvider } = initSigNoz({
  serviceName: "agent-initialization",
  export: {
    type: "otlp",
    endpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
    headers: {},
    metricsInterval: 60000,
  },
});

// create metric instruments
const agentMeter = meterProvider?.getMeter
  ? meterProvider.getMeter("agent-metrics")
  : undefined;

const agentCreationCounter = agentMeter?.createCounter("agent.creation.count", {
  description: "Number of agents created",
});
const agentCreationLatency = agentMeter?.createHistogram("agent.creation.latency_ms", {
  description: "Time taken to create an agent",
});

// Configure loggers for agent initialization
const baseLogger = createLogger({ name: "agent-initialization", level: "debug" });
const logger = {
  debug: (msg: any, meta?: Record<string, any>) => {
    baseLogger.debug(msg, meta);
    upstashLogger.debug({ message: msg, ...meta });
    fileLogger.debug(String(msg), meta);
    // also record a SigNoz span if active
    signozTracer?.startSpan("agent.debug").end();
  },
  info: (msg: any, meta?: Record<string, any>) => {
    baseLogger.info(msg, meta);
    upstashLogger.info({ message: msg, ...meta });
    fileLogger.info(String(msg), meta);
    signozTracer?.startSpan("agent.info").end();
  },
  warn: (msg: any, meta?: Record<string, any>) => {
    baseLogger.warn(msg, meta);
    upstashLogger.warn({ message: msg, ...meta });
    fileLogger.warn(String(msg), meta);
    signozTracer?.startSpan("agent.warn").end();
  },
  error: (msg: any, meta?: Record<string, any>) => {
    baseLogger.error(msg, meta);
    upstashLogger.error({ message: msg, ...meta });
    fileLogger.error(String(msg), meta);
    signozTracer?.startSpan("agent.error").end();
  },
};

/**
 * Creates an agent instance from a configuration object and options
 *
 * @param params - Object containing configuration and agent options
 * @param params.config - The agent configuration object
 * @param params.memory - The memory instance to be injected into the agent (following RULE-MemoryInjection)
 * @param params.onError - Optional error handler callback function
 * @returns A configured Agent instance
 * @throws Error if required tools are not available
 */
export function createAgentFromConfig({
  config,
  memory,
  onError,
}: {
  config: BaseAgentConfig;
  memory: typeof sharedMemory;
  onError?: (error: Error) => Promise<{ text: string }>;
}): Agent {
  const start = Date.now();
  const span = signozTracer?.startSpan("agent.create", {
    attributes: { agent_id: config.id },
  });

  // Validate configuration
  if (!config.id || !config.name || !config.instructions) {
    throw new Error(
      `Invalid agent configuration for ${config.id || "unknown agent"}`
    );
  }

  // Resolve tools from toolIds
  const tools: Record<string, Tool<any, any>> = {};
  const missingTools: string[] = [];

  for (const toolId of config.toolIds) {
    const tool = allToolsMap.get(toolId);
    if (tool) {
      const key = tool.id || toolId;
      tools[key] = tool;
    } else {
      missingTools.push(toolId);
    }
  }

  // Log and throw error for missing tools
  if (missingTools.length > 0) {
    const errorMsg = `Missing required tools for agent ${
      config.id
    }: ${missingTools.join(", ")}`;
    logger.error(errorMsg);
    throw new Error(errorMsg);
  }

  // Create response hook if validation options are provided
  const responseHook = config.responseValidation
    ? createResponseHook(config.responseValidation)
    : undefined;
  // Create and return the agent instance
  logger.info(
    `Creating agent: ${config.id} with ${Object.keys(tools).length} tools`
  );

  let agent: Agent;
  try {
    // Create model instance using the new modelConfig property
    const model = createModelInstance(config.modelConfig);

    agent = new Agent({
      model,
      memory, // Using injected memory instead of global reference
      name: config.name,
      instructions: config.instructions,
      tools,
      // voice, // voice temporarily disabled
      ...(responseHook ? { onResponse: responseHook } : {}),
      ...(onError ? { onError } : {}), // Add error handler if provided
    });
  } catch (error) {
    span?.setStatus({ code: api.SpanStatusCode.ERROR, message: (error as Error).message });
    span?.end();
    throw error;
  }

  span?.setStatus({ code: api.SpanStatusCode.OK });
  span?.end();

  // record metrics
  agentCreationCounter?.add(1, { agent_id: config.id });
  agentCreationLatency?.record(Date.now() - start, { agent_id: config.id });

  return agent;
}

export type { BaseAgentConfig, Agent, ResponseHookOptions };
export { defaultErrorHandler, defaultResponseValidation };
export { createModelInstance, createResponseHook };
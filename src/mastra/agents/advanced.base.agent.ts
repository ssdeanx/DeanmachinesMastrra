/**
 * Advanced Agent Base Implementation
 *
 * This module extends the base agent with advanced features like middleware,
 * hooks, state management, and enhanced error handling.
 */

import {
  BaseAgentConfig,
  defaultErrorHandler,
  defaultResponseValidation,
  ResponseHookOptions,
  createModelInstance
} from "./config/index";
import { Agent, createAgentFromConfig } from "./base.agent";
import { allToolsMap } from "../tools";
import { sharedMemory as defaultSharedMemory, sharedMemory } from "../database";
import { createLogger } from "@mastra/core/logger";
import { createAISpan, recordMetrics } from "../services/signoz";
import { SpanStatusCode } from "@opentelemetry/api";
import { z, ZodSchema } from "zod";
import { JSONSchema7 } from "json-schema";
import { Tool } from "@mastra/core/tools";
import type { CoreMessage, Message } from "ai";
import { generateText, generateObject } from "ai";
import type { StreamResult, StreamOptions, AgentResponse } from "../types";
import {
  createResponseHook,
  createStreamHooks,
  createToolHooks
} from "../hooks/advanced";

/**
 * Context object for middleware
 */
type MiddlewareContext = {
  messages: string | string[] | CoreMessage[] | Message[];
  args?: ReturnType<typeof generateText> | ReturnType<typeof generateObject> | StreamOptions;
  state: Record<string, any>;
  tools: Record<string, Tool>;
  memory?: typeof sharedMemory;
  agent: AdvancedAgentType;
  result?: any;
};

/**
 * Middleware function type
 */
type Middleware = (context: MiddlewareContext) => Promise<void> | void;

/**
 * Options for the advanced agent
 */
interface AdvancedAgentOptions {
  enableTracing?: boolean;
}

/**
 * Advanced Agent Type Definition
 * Extends the base Agent, adding state, events, and specific generate/stream signatures
 */
type AdvancedAgentType = Omit<Agent, "generate" | "stream"> & {
  state: Record<string, any>;
  onEvent?: (event: string, payload?: any) => void;
  setState: (newState: Record<string, any>) => void;
  getState: () => Record<string, any>;
  originalGenerate: Agent["generate"];
  originalStream?: Agent["stream"];
  generate: Agent["generate"];
  stream?: <T = unknown>(
    messages: string | string[] | CoreMessage[] | Message[],
    options?: StreamOptions
  ) => Promise<StreamResult<T>>;
};

/**
 * Execute middleware functions in sequence
 */
const runMiddleware = async (middleware: Middleware[], context: MiddlewareContext) => {
  for (const fn of middleware) {
    await fn(context);
  }
};

/**
 * Create an advanced agent with enhanced capabilities
 * 
 * @param config - The agent configuration
 * @param options - Advanced agent options
 * @param memory - Memory instance to use
 * @param onEvent - Event callback function
 * @param onError - Error handler callback
 * @param preHooks - Middleware to run before agent operations
 * @param postHooks - Middleware to run after agent operations
 * @param maxRetries - Maximum number of retry attempts
 * @returns An advanced agent instance
 */
export const createAdvancedAgent = (
  config: BaseAgentConfig,
  options: AdvancedAgentOptions = {},
  memory: typeof sharedMemory = defaultSharedMemory,
  onEvent?: (event: string, payload?: any) => void,
  onError?: (error: Error) => Promise<{ text: string }>,
  preHooks: Middleware[] = [],
  postHooks: Middleware[] = [],
  maxRetries: number = 0
): AdvancedAgentType => {
  const agentLogger = createLogger({ name: config.name || "AdvancedAgent" });
  const enableTracing = options.enableTracing ?? true;

  // Initialize hooks
  const streamHooks = createStreamHooks(enableTracing);
  const toolHooksMap: Record<string, ReturnType<typeof createToolHooks>> = {};
  
  // Resolve tools from toolIds using allToolsMap (similar to base.agent.ts)
  const tools: Record<string, Tool> = {};
  const missingTools: string[] = [];

  // Iterate through the toolIds in the configuration and look them up in allToolsMap
  for (const toolId of config.toolIds || []) {
    const tool = allToolsMap.get(toolId);
    if (tool) {
      tools[toolId] = tool;
      
      // Initialize tool hooks if needed
      const toolName = typeof tool === 'string' ? tool : tool.id || (tool as any)?.name;
      if (toolName) {
        agentLogger.debug(`Instantiating tool hooks for: ${toolName}`);
        toolHooksMap[toolName] = createToolHooks(toolName, enableTracing);
      }
    } else {
      missingTools.push(toolId);
    }
  }

  // Check for missing tools
  if (missingTools.length > 0) {
    const errorMessage = `Missing required tools for agent ${config.id}: ${missingTools.join(", ")}`;
    agentLogger.error(errorMessage);
    throw new Error(errorMessage);
  }

  // Create response hook using defaultResponseValidation from config/index.ts
  const responseValidationOptions = config.responseValidation || defaultResponseValidation;
  const responseHook = responseValidationOptions
    ? createResponseHook(responseValidationOptions)
    : undefined;

  // Create the base agent using createAgentFromConfig from base.agent.ts
  const baseAgent = createAgentFromConfig({
    config,
    memory,
    onError: undefined // We'll handle errors in the wrapper
  });

  // Prepare advanced agent wrapper
  const advancedAgentBase = baseAgent as unknown as Omit<Agent, "generate" | "stream"> & {
    state: Record<string, any>;
    onEvent?: (event: string, payload?: any) => void;
    setState: (newState: Record<string, any>) => void;
    getState: () => Record<string, any>;
    originalGenerate: Agent["generate"];
    originalStream?: Agent["stream"];
  };

  // Initialize wrapper state & methods
  advancedAgentBase.state = {};
  advancedAgentBase.onEvent = onEvent;
  advancedAgentBase.setState = (newState: Record<string, any>) => {
    advancedAgentBase.state = { ...advancedAgentBase.state, ...newState };
    onEvent?.("stateChange", advancedAgentBase.state);
  };
  advancedAgentBase.getState = () => advancedAgentBase.state;
  
  // Store original methods
  advancedAgentBase.originalGenerate = baseAgent.generate.bind(baseAgent);
  if (baseAgent.stream) {
    advancedAgentBase.originalStream = baseAgent.stream.bind(baseAgent);
  }

  // Enhanced generate implementation with middleware support
  const generateImplementation = async (
    messages: string | string[] | CoreMessage[] | Message[],
    args?: any
  ) => {
    const agent = advancedAgentBase as AdvancedAgentType;
    const span = createAISpan(`${agent.name || "AdvancedAgent"}.generate`, { enableTracing });
    const effectiveMaxAttempts = Math.max(1, (maxRetries >= 0 ? maxRetries : 0) + 1);
    
    span.setAttributes({
      "mastra.agent.name": agent.name || "AdvancedAgent",
      "mastra.agent.model": agent.model?.modelId || "unknown",
      "mastra.operation.type": "generate",
      "mastra.retry.max_attempts": effectiveMaxAttempts,
    });

    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt < effectiveMaxAttempts) {
      const currentAttempt = attempt + 1;
      span.addEvent(`Attempt ${currentAttempt}/${effectiveMaxAttempts} starting.`);
      
      const context: MiddlewareContext = {
        messages,
        args,
        state: agent.getState(),
        tools: tools, // Use the resolved tools map
        memory: memory,
        agent: agent,
      };

      try {
        await runMiddleware(preHooks, context);
        const result = await agent.originalGenerate(messages, args);
        
        // Call the advanced response hook
        createResponseHook({ agent: agent.name, enableTracing })({ result });
        
        context.result = result;
        await runMiddleware(postHooks, context);
        
        recordMetrics(span, { status: "success" });
        span.setStatus({ code: SpanStatusCode.OK });
        span.addEvent("generate.success");
        agent.onEvent?.("success", { result, attempt: currentAttempt });
        span.end();
        
        return result;
      } catch (err) {
        lastError = err as Error;
        agentLogger.error(`Attempt ${currentAttempt}/${effectiveMaxAttempts} failed:`, lastError);
        span.recordException(lastError);
        span.addEvent(`Attempt ${currentAttempt} failed.`, { "error.message": lastError.message });
        attempt++;

        if (attempt >= effectiveMaxAttempts) {
          span.addEvent(`All ${effectiveMaxAttempts} attempts failed.`);
          agentLogger.error(`Agent generation failed after ${effectiveMaxAttempts} attempts.`);
          break;
        }
      }
    }

    // Handle final error after retries
    const finalError = lastError!;
    span.setStatus({ code: SpanStatusCode.ERROR, message: finalError.message });
    recordMetrics(span, { status: "error", errorMessage: finalError.message });
    agent.onEvent?.("error", { error: finalError, attempts: effectiveMaxAttempts });
    span.end();

    // Invoke the wrapper's onError handler if provided or use defaultErrorHandler from config/index.ts
    if (onError) {
      try {
        agentLogger.warn(`Invoking onError handler for error: ${finalError.message}`);
        const errorResponse = await onError(finalError);
        
        // Return a fallback response
        return {
          text: errorResponse.text || `Error occurred: ${finalError.message}`,
          toolCalls: [],
          toolResults: [],
          finishReason: "error",
          usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
        };
      } catch (onErrorError) {
        agentLogger.error("Error within onError handler:", onErrorError);
        throw onErrorError;
      }
    } else {
      // Use defaultErrorHandler from config/index.ts
      const errorResponse = await defaultErrorHandler(finalError);
      return {
        text: errorResponse.text || `Error occurred: ${finalError.message}`,
        toolCalls: [],
        toolResults: [],
        finishReason: "error",
        usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
      };
    }
  };

  // Enhanced stream implementation with middleware support
  const streamImplementation = async <T = unknown>(
    messages: string | string[] | CoreMessage[] | Message[],
    streamOptions?: StreamOptions
  ): Promise<StreamResult<T>> => {
    const agent = advancedAgentBase as AdvancedAgentType;
    
    if (!agent.originalStream) {
      throw new Error(`Agent ${agent.name || 'AdvancedAgent'} does not support streaming.`);
    }

    const span = createAISpan(`${agent.name || "AdvancedAgent"}.stream`, { enableTracing });
    span.setAttributes({
      "mastra.agent.name": agent.name || "AdvancedAgent",
      "mastra.agent.model": agent.model?.modelId || "unknown",
      "mastra.operation.type": "stream",
    });

    const context: MiddlewareContext = {
      messages,
      args: streamOptions,
      state: agent.getState(),
      tools: tools, // Use the resolved tools map
      memory: memory,
      agent: agent,
    };

    let streamResultHolder: StreamResult<T> | null = null;

    try {
      await runMiddleware(preHooks, context);

      // Filter context to ensure compatibility
      const { context: originalContext, ...restOptions } = streamOptions || {};
      let filteredContextForHook: Message[] | undefined = undefined;
      
      if (originalContext) {
        filteredContextForHook = originalContext.filter(
          msg => 
            msg.role === 'system' || msg.role === 'user' || msg.role === 'assistant'
        );
      }

      await streamHooks.onStreamStart({ context: filteredContextForHook } as any);
      
      // Define stream wrapper function before using it
      const wrapStream = async function* <StreamType>(
        inputStream: AsyncIterable<StreamType> | undefined
      ): AsyncIterable<StreamType> | undefined {
        if (!inputStream) return undefined;
        
        let streamEndedSuccessfully = false;
        try {
          for await (const chunk of inputStream) {
            yield chunk;
          }
          streamEndedSuccessfully = true;
        } catch (streamError) {
          agentLogger.error("Error during stream iteration:", streamError);
          await streamHooks.onStreamError(streamError as Error);
          span.setStatus({ code: SpanStatusCode.ERROR, message: (streamError as Error).message });
          span.recordException(streamError as Error);
          agent.onEvent?.("stream.error", { error: streamError });
          throw streamError;
        } finally {
          if (streamEndedSuccessfully) {
            await streamHooks.onStreamEnd(streamResultHolder);
            await runMiddleware(postHooks, context);
            span.setStatus({ code: SpanStatusCode.OK });
            span.addEvent("stream.success");
            agent.onEvent?.("stream.success", { result: streamResultHolder });
          }
          span.end();
        }
      };
      
      const streamResult = await agent.originalStream(messages, streamOptions as any);
      streamResultHolder = streamResult as StreamResult<T>;
      context.result = streamResult;

      // Wrap streams and return
      return {
        ...streamResult as StreamResult<T>,
        textStream: wrapStream(streamResult.textStream) ?? (async function*(): AsyncIterable<string> {yield ""})(),
        partialObjectStream: wrapStream(streamResult.experimental_partialOutputStream as any) as AsyncIterable<object> | undefined,
      };
    } catch (initialError) {
      agentLogger.error("Error setting up stream:", initialError);
      await streamHooks.onStreamError(initialError as Error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: (initialError as Error).message });
      span.recordException(initialError as Error);
      agent.onEvent?.("stream.error", { error: initialError });
      span.end();
      throw initialError;
    }
  };

  // Construct and return final agent
  const finalAgent: AdvancedAgentType = {
    ...advancedAgentBase,
    generate: generateImplementation as any,
    ...(advancedAgentBase.originalStream && { stream: streamImplementation }),
  };

  return finalAgent;
};

export default createAdvancedAgent;

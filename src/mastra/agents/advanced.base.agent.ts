import {
  BaseAgentConfig,
  Agent,
  createAgentFromConfig, // Import from base agent
} from "./base.agent";
import { sharedMemory as defaultSharedMemory, sharedMemory } from "../database"; // Consolidate memory imports
import { createLogger } from "@mastra/core/logger";
import { createAISpan, recordMetrics } from "../services/signoz";
import { SpanStatusCode, trace, context } from "@opentelemetry/api"; // Consolidate OTel imports
import { z, ZodSchema } from "zod";
import { JSONSchema7 } from "json-schema";
import type { CoreMessage, Message, ToolCall, ToolResult } from "ai"; // Ensure all needed types from 'ai'
import { generateText, generateObject, GenerateTextResult, ToolSet, streamText, StreamTextResult } from "ai";
import type * as MastraTypes from "../types"; // Import stream types
import {
  createResponseHook,
  createStreamHooks,
  createToolHooks,
} from "../hooks/advanced"; // Use hooks from advanced.ts

const logger = createLogger({ name: "advanced.base", level: "debug" });

// --- Middleware & Options Types ---
type MiddlewareContext = {
  messages: string | string[] | CoreMessage[] | Message[];
  args?: ReturnType<typeof generateText> | ReturnType<typeof generateObject> | MastraTypes.StreamOptions;
  state: Record<string, any>;
  tools: Agent["tools"];
  memory?: typeof sharedMemory;
  agent: AdvancedAgentType; // Reference the wrapped agent type
  result?: any;
};

type Middleware = (context: MiddlewareContext) => Promise<void> | void;

interface AdvancedAgentOptions {
  enableTracing?: boolean;
  // Add other potential options: retryDelayMs?: number;
}

// --- Advanced Agent Type Definition ---
// Extends the base Agent, adding state, events, and specific generate/stream signatures
type AdvancedAgentType = Omit<Agent, "generate" | "stream"> & {
  state: Record<string, any>;
  onEvent?: (event: string, payload?: any) => void;
  setState: (newState: Record<string, any>) => void;
  getState: () => Record<string, any>;
  originalGenerate: Agent["generate"]; // Store the base agent's generate
  originalStream?: Agent["stream"]; // Store the base agent's stream
  // Overloaded generate method signature
  generate: {
    <Z extends ZodSchema | JSONSchema7 | undefined = undefined>(
      messages: string | string[] | CoreMessage[] | Message[],
      args?: ReturnType<typeof generateText> & { output?: never; experimental_output?: never }
    ): Promise<ReturnType<typeof generateText>>;
    <Z extends ZodSchema | JSONSchema7 | undefined = undefined>(
      messages: string | string[] | CoreMessage[] | Message[],
      args?: ReturnType<typeof generateObject> & { output?: Z; experimental_output?: never }
    ): Promise<ReturnType<typeof generateObject>>;
    <Z extends ZodSchema | JSONSchema7 | undefined = undefined>(
      messages: string | string[] | CoreMessage[] | Message[],
      args?: ReturnType<typeof generateText> & { output?: never; experimental_output?: Z }
    ): Promise<
      ReturnType<typeof generateText> & {
        object: Z extends ZodSchema ? z.infer<Z> : unknown;
      }
    >;
  };
  // Stream method signature using MastraTypes
  stream?: <T = unknown>(
    messages: string | string[] | CoreMessage[] | Message[],
    options?: MastraTypes.StreamOptions
  ) => Promise<MastraTypes.StreamResult<T>>;
};

// --- Middleware Runner ---
const runMiddleware = async (middleware: Middleware[], context: MiddlewareContext) => {
  for (const fn of middleware) {
    await fn(context);
  }
};

// --- createAdvancedAgent Factory ---
export const createAdvancedAgent = (
  config: BaseAgentConfig,
  options: AdvancedAgentOptions = {},
  memory: typeof sharedMemory = defaultSharedMemory,
  onEvent?: (event: string, payload?: any) => void,
  onError?: (error: Error) => Promise<{ text: string }>, // Wrapper's final error handler
  preHooks: Middleware[] = [],
  postHooks: Middleware[] = [],
  maxRetries: number = 0
): AdvancedAgentType => {
  const agentLogger = createLogger({ name: config.name || "AdvancedAgent" }); // Use specific logger instance
  const enableTracing = options.enableTracing ?? true;

  // --- Instantiate Hooks ---
  const streamHooks = createStreamHooks(enableTracing);
  const toolHooksMap: Record<string, ReturnType<typeof createToolHooks>> = {};
  if (config.tools) {
    config.tools.forEach(tool => {
      // Determine tool name (adjust based on actual tool definition structure)
      const toolName = typeof tool === 'string' ? tool : (tool as any)?.name || (tool as any)?.constructor?.name;
      if (toolName) {
        agentLogger.debug(`Instantiating tool hooks for: ${toolName}`);
        toolHooksMap[toolName] = createToolHooks(toolName, enableTracing);
        // **IMPORTANT**: Tool hooks (onToolStart, onToolEnd, onToolError) created here
        // are NOT automatically active. They must be explicitly called from within
        // the tool execution logic, which typically resides inside the base agent's
        // implementation or a dedicated tool execution handler. This wrapper prepares
        // them, but the base agent needs modification or extension points to use them.
      } else {
        agentLogger.warn("Could not determine name for a tool to instantiate hooks.");
      }
    });
  }

  // --- Create Base Agent ---
  // Pass undefined for onError; the wrapper handles retries and final error callback.
  const baseAgent = createAgentFromConfig({ config, memory, onError: undefined });

  // --- Prepare Advanced Agent Wrapper ---
  // Cast needed to add wrapper-specific properties/methods
  const advancedAgentBase = baseAgent as unknown as Omit<Agent, "generate" | "stream"> & {
    state: Record<string, any>;
    onEvent?: (event: string, payload?: any) => void;
    setState: (newState: Record<string, any>) => void;
    getState: () => Record<string, any>;
    originalGenerate: Agent["generate"];
    originalStream?: Agent["stream"];
  };

  // --- Initialize Wrapper State & Methods ---
  advancedAgentBase.state = {};
  advancedAgentBase.onEvent = onEvent;
  advancedAgentBase.setState = (newState: Record<string, any>) => {
    advancedAgentBase.state = { ...advancedAgentBase.state, ...newState };
    onEvent?.("stateChange", advancedAgentBase.state); // Optionally emit event on state change
  };
  advancedAgentBase.getState = () => advancedAgentBase.state;
  // Bind original methods to the baseAgent instance
  advancedAgentBase.originalGenerate = baseAgent.generate.bind(baseAgent);
  if (baseAgent.stream) {
    advancedAgentBase.originalStream = baseAgent.stream.bind(baseAgent);
  }

  // --- Wrapped generate Implementation ---
  const generateImplementation = async (
    messages: string | string[] | CoreMessage[] | Message[],
    args?: ReturnType<typeof generateText> | ReturnType<typeof generateObject>
  ): Promise<ReturnType<typeof generateText> | ReturnType<typeof generateObject>> => {
    const agent = advancedAgentBase as AdvancedAgentType; // Use the correctly typed agent
    const span = createAISpan(`${agent.name || "AdvancedAgent"}.generate`, { enableTracing });
    const effectiveMaxAttempts = Math.max(1, (maxRetries >= 0 ? maxRetries : 0) + 1); // Ensure at least 1 attempt
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
      const context: MiddlewareContext = { // Create context for this attempt
        messages,
        args,
        state: agent.getState(), // Get current state
        tools: agent.tools,
        memory: memory,
        agent: agent,
      };

      try {
        await runMiddleware(preHooks, context); // Run pre-hooks

        // Call the original base agent's generate method
        const result = await agent.originalGenerate(messages, args as any); // Cast args if needed

        // Call the advanced response hook
        createResponseHook({ agent: agent.name, enableTracing })({ result });

        context.result = result; // Add result to context for post-hooks
        await runMiddleware(postHooks, context); // Run post-hooks

        // Record success metrics and events
        recordMetrics(span, { status: "success" });
        span.setStatus({ code: SpanStatusCode.OK });
        span.addEvent("generate.success");
        agent.onEvent?.("success", { result, attempt: currentAttempt });
        span.end();
        return result; // Return successful result

      } catch (err) {
        lastError = err as Error;
        agentLogger.error(`Attempt ${currentAttempt}/${effectiveMaxAttempts} failed:`, lastError);
        span.recordException(lastError);
        span.addEvent(`Attempt ${currentAttempt} failed.`, { "error.message": lastError.message });
        attempt++;

        if (attempt >= effectiveMaxAttempts) {
          span.addEvent(`All ${effectiveMaxAttempts} attempts failed.`);
          agentLogger.error(`Agent generation failed after ${effectiveMaxAttempts} attempts.`);
          break; // Exit retry loop
        }
        // Optional: Implement delay before retry (e.g., using options.retryDelayMs)
        // await new Promise(resolve => setTimeout(resolve, options.retryDelayMs || 100));
      }
    }

    // --- Handle Final Error After Retries ---
    const finalError = lastError!; // Should always have an error if loop finished without returning
    span.setStatus({ code: SpanStatusCode.ERROR, message: finalError.message });
    recordMetrics(span, { status: "error", errorMessage: finalError.message });
    agent.onEvent?.("error", { error: finalError, attempts: effectiveMaxAttempts });
    span.end();

    // Invoke the wrapper's onError handler if provided
    if (onError) {
      try {
        agentLogger.warn(`Invoking onError handler for error: ${finalError.message}`);
        const errorResponse = await onError(finalError);

        // --- Construct Fallback Result ---
        // IMPORTANT: Verify this structure against the exact GenerateTextResult<ToolSet, unknown>
        // definition in your version of the 'ai' package. Add ALL required fields.
        const fallback: GenerateTextResult<ToolSet, unknown> = {
          text: errorResponse.text,
          toolCalls: [] as ToolCall[],
          toolResults: [] as ToolResult[],
          finishReason: "error",
          usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
          providerMetadata: { error: finalError.message }, // Simple object for unknown
          rawResponse: undefined,
          logprobs: undefined,
          warnings: [`Agent generation failed after ${effectiveMaxAttempts} attempts: ${finalError.message}`],
          // Add other required fields like:
          // experimental_output: undefined,
          // steps: [],
          // request: undefined,
          // response: undefined,
          // experimental_providerMetadata: undefined,
        };
        return fallback; // Return the constructed fallback
      } catch (onErrorError) {
        agentLogger.error("Error within onError handler:", onErrorError);
        throw onErrorError; // Re-throw error from the onError handler itself
      }
    } else {
      // If no onError handler, re-throw the final error
      throw finalError;
    }
  };

  // --- Wrapped stream Implementation ---
  const streamImplementation = async <T = unknown>(
    messages: string | string[] | CoreMessage[] | Message[],
    streamOptions?: MastraTypes.StreamOptions
  ): Promise<MastraTypes.StreamResult<T>> => {
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

    const context: MiddlewareContext = { // Context for stream middleware
      messages,
      args: streamOptions,
      state: agent.getState(),
      tools: agent.tools,
      memory: memory,
      agent: agent,
    };

    let streamResultHolder: MastraTypes.StreamResult<T> | null = null; // To hold the result for postHooks

    try {
      await runMiddleware(preHooks, context); // Run pre-hooks

      // Convert messages to CoreMessage[] format expected by the hook context
      // This might duplicate logic from the base agent, consider refactoring if possible.
      let coreMessagesForHook: CoreMessage[];
      if (typeof messages === 'string') {
        coreMessagesForHook = [{ role: 'user', content: messages }];
      } else if (Array.isArray(messages) && messages.length > 0 && typeof messages[0] === 'string') {
        coreMessagesForHook = (messages as string[]).map(content => ({ role: 'user', content }));
      } else if (Array.isArray(messages)) {
        // Assumes Message[] can be cast or is already CoreMessage[]
        // A more robust conversion might be needed depending on the exact 'Message' type definition
        coreMessagesForHook = messages as CoreMessage[];
      } else {
        coreMessagesForHook = []; // Handle empty or unexpected cases
      }

      await streamHooks.onStreamStart({ context: coreMessagesForHook, ...streamOptions }); // Call stream start hook

      // Call the original base agent's stream method (pass original messages)
      const streamResult = await agent.originalStream<T>(messages, streamOptions);
      streamResultHolder = streamResult; // Store for potential use in postHooks
      context.result = streamResult; // Add to context

      // Wrap the stream iterables to inject end/error hooks and postHooks
      const wrapStream = async function* <StreamType>(inputStream: AsyncIterable<StreamType> | undefined): AsyncIterable<StreamType> | undefined {
        if (!inputStream) return undefined; // Handle cases where a stream might be optional

        let streamEndedSuccessfully = false;
        try {
          for await (const chunk of inputStream) {
            yield chunk; // Yield chunks as they arrive
          }
          streamEndedSuccessfully = true; // Mark success if loop completes
        } catch (streamError) {
          agentLogger.error("Error during stream iteration:", streamError);
          await streamHooks.onStreamError(streamError as Error); // Call stream error hook
          span.setStatus({ code: SpanStatusCode.ERROR, message: (streamError as Error).message });
          span.recordException(streamError as Error);
          agent.onEvent?.("stream.error", { error: streamError });
          throw streamError; // Re-throw after handling
        } finally {
          // This block runs whether the stream finished successfully or threw an error
          if (streamEndedSuccessfully) {
            // Only call end hooks and postHooks if the stream finished without error
            await streamHooks.onStreamEnd(streamResultHolder); // Call stream end hook
            await runMiddleware(postHooks, context); // Run post-hooks after successful stream end
            span.setStatus({ code: SpanStatusCode.OK });
            span.addEvent("stream.success");
            agent.onEvent?.("stream.success", { result: streamResultHolder });
          }
          // Always end the span
          span.end();
        }
      };

      // Return the result with wrapped streams
      return {
        ...streamResult,
        textStream: await wrapStream(streamResult.textStream), // Await the generator function itself
        // Wrap other potential streams similarly
        partialObjectStream: await wrapStream(streamResult.partialObjectStream),
        // toolCallStream: await wrapStream(streamResult.toolCallStream),
        // ... etc.
      };

    } catch (initialError) {
      // Handle errors during stream setup (before iteration starts)
      agentLogger.error("Error setting up stream:", initialError);
      await streamHooks.onStreamError(initialError as Error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: (initialError as Error).message });
      span.recordException(initialError as Error);
      agent.onEvent?.("stream.error", { error: initialError });
      span.end(); // End span on setup error
      throw initialError;
    }
  };

  // --- Construct and Return Final Agent ---
  const finalAgent: AdvancedAgentType = {
    ...advancedAgentBase,
    generate: generateImplementation,
    // Conditionally add stream implementation
    ...(advancedAgentBase.originalStream && { stream: streamImplementation }),
  };

  // Return the fully typed advanced agent
  return finalAgent;
};
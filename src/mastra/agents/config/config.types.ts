/**
 * Agent Configuration Type Definitions
 *
 * This module defines shared types and interfaces for agent configurations,
 * ensuring consistent typing across the agent configuration system.
 *
 * @module config.types
 */


import { Tool } from "@mastra/core/tools";
import type { RestOptions } from "./rest.options";

/**
 * Supported AI model providers
 */
export type ModelProvider = "google" | "vertex" | "openai" | "anthropic" | "ollama";

/** Default Maximum Tokens for Model Output */
export const DEFAULT_MAX_TOKENS = 8192;

/** Default Maximum Context Tokens for Model Input */
export const DEFAULT_MAX_CONTEXT_TOKENS = 1000000;

/**
 * Model capabilities and features supported
 * These represent the different capabilities models may have
 */
export interface ModelCapabilities {
  /** Maximum context window size in tokens */
  maxContextTokens: number;
  /** Whether the model supports multimodal inputs (images, audio, video) */
  multimodalInput: boolean;
  /** Whether the model supports image generation output */
  imageGeneration: boolean;
  /** Whether the model supports audio output */
  audioOutput: boolean;
  /** Whether the model supports function/tool calling */
  functionCalling: boolean;
  /** Whether the model supports structured output (JSON, etc) */
  structuredOutput: boolean;
  /** Whether the model has enhanced reasoning/thinking capabilities */
  enhancedThinking: boolean;
  /** Whether the model supports grounding to reduce hallucinations */
  grounding: boolean;
  /** Whether the model supports response caching for efficiency */
  responseCaching: boolean;
}

/**
 * Default model configurations for different use cases
 * Based on https://ai.google.dev/gemini-api/docs/models
 */
export const DEFAULT_MODELS = {
  // GOOGLE PROVIDER MODELS

  // Standard Google model - fast, versatile
  // Works
  GOOGLE_STANDARD: {
    provider: "google" as const,
    modelId: "gemini-2.0-flash",
    temperature: 0.6,
    topP: 0.95,
    maxTokens: DEFAULT_MAX_TOKENS,
    capabilities: {
      maxContextTokens: 1048576,
      multimodalInput: true,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: false,
      grounding: true,
      responseCaching: false,
    },
  },
  GOOGLE_MAIN: {
    provider: "google" as const,
    modelId: "gemini-2.5-flash-preview-04-17",
    temperature: 0.65,
    topP: 0.95,
    maxTokens: 65536,
    capabilities: {
      maxContextTokens: 1048576,
      multimodalInput: true,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: true,
      grounding: true,
      responseCaching: false,
    },
  },

  // Premium Google model - enhanced reasoning and capability
  GOOGLE_PREMIUM: {
    provider: "google" as const,
    modelId: "gemini-2.5-pro-preview",
    temperature: 0.5,
    topP: 0.95,
    maxTokens: 65535,
    capabilities: {
      maxContextTokens: 2000000,
      multimodalInput: true,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: true,
      grounding: true,
      responseCaching: true,
    },
  },

  // Cost-efficient Google model - better for bulk processing
  GOOGLE_EFFICIENT: {
    provider: "google" as const,
    modelId: "gemini-2.0-flash-lite",
    temperature: 0.7,
    topP: 0.9,
    maxTokens: DEFAULT_MAX_TOKENS,
    capabilities: {
      maxContextTokens: 1048576,
      multimodalInput: false,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: false,
      structuredOutput: true,
      enhancedThinking: false,
      grounding: false,
      responseCaching: false,
    },
  },

  // Experimental Google model - for research and testing
  // live model for testing
  GOOGLE_LIVE: {
    provider: "google" as const,
    modelId: "gemini-2.0-flash-live-001",
    temperature: 0.5,
    topP: 0.95,
    maxTokens: DEFAULT_MAX_TOKENS,
    capabilities: {
      maxContextTokens: 1048576,
      multimodalInput: true,
      imageGeneration: false,
      audioOutput: true,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: false,
      grounding: false,
      responseCaching: true,
    },
  },

  // VERTEX AI PROVIDER MODELS

  // Vertex AI model - for enterprise features and security
  // Works!!
  VERTEX_STANDARD: {
    provider: "vertex" as const,
    modelId: "models/gemini-2.0-flash",
    temperature: 0.6,
    topP: 0.95,
    maxTokens: DEFAULT_MAX_TOKENS,
    capabilities: {
      maxContextTokens: 1048576,
      multimodalInput: true,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: false,
      grounding: true,
      responseCaching: false,
    },
    functionCalling: {
      mode: "AUTO" as const,
      allowedFunctionNames: [],
    },
  },

  // Advanced Vertex model - for enterprise use cases
  VERTEX_PRO: {
    provider: "vertex" as const,
    modelId: "models/gemini-2.0-pro-exp-03-25",
    temperature: 0.6,
    topP: 0.95,
    maxTokens: 65535,
    capabilities: {
      maxContextTokens: 1000000,
      multimodalInput: true,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: true,
      grounding: true,
      responseCaching: true,
    },
    functionCalling: {
      mode: "AUTO" as const,
      allowedFunctionNames: [],
    },
  },

  // Premium Vertex model - highest capability enterprise model
  VERTEX_PREMIUM: {
    provider: "vertex" as const,
    modelId: "models/gemini-2.5-pro-preview-03-25",
    temperature: 0.4,
    topP: 0.95,
    maxTokens: 65535,
    capabilities: {
      maxContextTokens: 2000000,
      multimodalInput: true,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: true,
      grounding: true,
      responseCaching: true,
    },
  },

  // OPENAI PROVIDER MODELS
  OPENAI_STANDARD: {
    provider: "openai" as const,
    modelId: "gpt-4o",
    temperature: 0.7,
    topP: 0.95,
    maxTokens: DEFAULT_MAX_TOKENS,
    capabilities: {
      maxContextTokens: 128000,
      multimodalInput: true,
      imageGeneration: true,
      audioOutput: true,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: true,
      grounding: true,
      responseCaching: true,
    },
  },

  // ANTHROPIC PROVIDER MODELS
  ANTHROPIC_STANDARD: {
    provider: "anthropic" as const,
    modelId: "claude-3.5-sonnet-2024-04-08",
    temperature: 0.7,
    topP: 0.95,
    maxTokens: DEFAULT_MAX_TOKENS,
    capabilities: {
      maxContextTokens: 200000,
      multimodalInput: true,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: true,
      structuredOutput: true,
      enhancedThinking: true,
      grounding: true,
      responseCaching: true,
    },
  },

  // OLLAMA PROVIDER MODELS
  OLLAMA_STANDARD: {
    provider: "ollama" as const,
    modelId: "gemma3:4b",
    temperature: 0.7,
    topP: 0.95,
    maxTokens: DEFAULT_MAX_TOKENS,
    capabilities: {
      maxContextTokens: 8192,
      multimodalInput: false,
      imageGeneration: false,
      audioOutput: false,
      functionCalling: false,
      structuredOutput: false,
      enhancedThinking: false,
      grounding: false,
      responseCaching: false,
    },
  },
};

/**
 * Type for accessing default model configurations
 */
export type DefaultModelKey = keyof typeof DEFAULT_MODELS;

/** Default Google AI Model ID */
export const DEFAULT_MODEL_ID = DEFAULT_MODELS.GOOGLE_STANDARD.modelId;

/**
 * Function calling configuration for Vertex AI models
 * Based on https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/function-calling
 */
export interface FunctionCallingConfig {
  /**
   * Function calling mode
   * - AUTO: Default model behavior, can respond with function call or natural language
   * - NONE: Model doesn't make predictions as function calls
   * - ANY: Model is constrained to always predict a function call
   */
  mode: "AUTO" | "NONE" | "ANY";

  /**
   * List of function names that the model is allowed to call
   * Only set when mode is ANY
   * Empty array means the model can choose from all available functions
   */
  allowedFunctionNames: string[];
}

/**
 * Model configuration options
 */
export interface ModelConfig {
  /** The provider to use for this agent */
  provider: ModelProvider;

  /** Model ID to use (e.g., "gemini-2.0-flash") */
  modelId: string;

  /** Maximum tokens to generate */
  maxTokens?: number;

  /** Temperature for generation (0-1) */
  temperature?: number;

  /** Top-p for sampling */
  topP?: number;

  /**
   * Function calling configuration
   * - For Google models: true/false to enable/disable function calling
   * - For Vertex AI models: FunctionCallingConfig object with mode and allowed function names
   */
  functionCalling?: boolean | FunctionCallingConfig;

  /** Provider-specific options */
  providerOptions?: Record<string, unknown>;
}

/**
 * Response hook options interface
 */
export interface ResponseHookOptions {
  minResponseLength?: number;
  maxAttempts?: number;
  validateResponse?: (response: unknown) => boolean;
}

/**
 * Base configuration interface for all agent configs
 *
 * @interface BaseAgentConfig
 */
export interface BaseAgentConfig {
  /** Unique identifier for the agent */
  id: string;

  /** Display name of the agent */
  name: string;

  /** Brief description of the agent's purpose and capabilities */
  description: string;

  /**
   * Model configuration for creating the model dynamically
   * This is used to initialize the appropriate model (Google or Vertex AI)
   */
  modelConfig: ModelConfig;

  /** Main instructions that define the agent's behavior */
  instructions: string;

  /** Tool IDs that this agent has access to */
  toolIds: string[];

  /** Optional response validation settings */
  responseValidation?: ResponseHookOptions;

  /** Optional tools configuration */
  tools?: Tool[];

  /** Optional REST options for advanced agent operations */
  restOptions?: RestOptions;
}

/**
 * Helper function to get a model configuration by key with optional overrides
 *
 * @param modelKey - The key of the default model to use
 * @param overrides - Optional properties to override in the default configuration
 * @returns A model configuration
 */
export function getModelConfig(
  modelKey: DefaultModelKey,
  overrides?: Partial<Omit<ModelConfig, "provider">>
): ModelConfig {
  // Create a new object to avoid modifying the default
  const config = { ...DEFAULT_MODELS[modelKey] };

  // Apply any overrides
  if (overrides) {
    return { ...config, ...overrides };
  }

  return config;
}

/**
 * Helper function to configure function calling for Vertex AI models
 *
 * @param mode - Function calling mode (AUTO, NONE, or ANY)
 * @param allowedFunctionNames - Optional list of allowed function names
 * @returns FunctionCallingConfig object
 */
export function createFunctionCallingConfig(
  mode: "AUTO" | "NONE" | "ANY" = "AUTO",
  allowedFunctionNames: string[] = []
): FunctionCallingConfig {
  return {
    mode,
    allowedFunctionNames: mode === "ANY" ? allowedFunctionNames : [],
  };
}

/**
 * Standard response validation options
 */
export const defaultResponseValidation: ResponseHookOptions = {
  minResponseLength: 20,
  maxAttempts: 2,
  validateResponse: (response: unknown) => {
    if (
      typeof response === "object" &&
      response !== null &&
      "object" in response
    ) {
      return (
        Object.keys((response as Record<string, unknown>).object || {}).length >
        0
      );
    }
    if (
      typeof response === "object" &&
      response !== null &&
      "text" in response
    ) {
      return (
        typeof (response as Record<string, unknown>).text === "string" &&
        (response as Record<string, string>).text.length >= 20
      );
    }
    return false;
  },
};

/**
 * Standard error handler function for agents
 */
export const defaultErrorHandler = async (
  error: Error
): Promise<Record<string, unknown>> => {
  console.error("Agent error:", error);
  return {
    text: "I encountered an error. Please try again or contact support.",
    error: error.message,
  };
};

export type BaseAgentConfigType = BaseAgentConfig;
export default BaseAgentConfig;

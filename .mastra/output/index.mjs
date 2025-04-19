import { evaluate } from '@mastra/core/eval';
import { registerHook, AvailableHooks } from '@mastra/core/hooks';
import { TABLE_EVALS } from '@mastra/core/storage';
import { checkEvalStorageFields } from '@mastra/core/utils';
import { Mastra, isVercelTool } from '@mastra/core';
import { createLogger } from '@mastra/core/logger';
import { Agent } from '@mastra/core/agent';
import { UpstashTransport } from '@mastra/loggers/upstash';
import * as fs from 'fs-extra';
import fs__default, { ensureDirSync, ensureFileSync } from 'fs-extra';
import path, { resolve, extname, dirname, join } from 'path';
import { FileTransport } from '@mastra/loggers/file';
import process$1, { env } from 'process';
import * as api from '@opentelemetry/api';
import { trace, context, SpanStatusCode as SpanStatusCode$1 } from '@opentelemetry/api';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { BatchSpanProcessor, SimpleSpanProcessor, ConsoleSpanExporter } from '@opentelemetry/sdk-trace-base';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-proto';
import { PeriodicExportingMetricReader, MeterProvider } from '@opentelemetry/sdk-metrics';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { z, ZodType, ZodFirstPartyTypeKind, ZodOptional } from 'zod';
import { Langfuse } from 'langfuse';
import { createTool } from '@mastra/core/tools';
import { google } from '@ai-sdk/google';
import { encodingForModel } from 'js-tiktoken';
import { createVectorQueryTool } from '@mastra/rag';
import { GoogleGenerativeAIEmbeddings, ChatGoogleGenerativeAI } from '@langchain/google-genai';
import { AsyncCaller } from '@langchain/core/utils/async_caller';
import { BraveSearchClient } from '@agentic/brave-search';
import { GoogleCustomSearchClient } from '@agentic/google-custom-search';
import { TavilyClient } from '@agentic/tavily';
import { aiFunction, AIFunctionsProvider, AIFunctionSet, asZodOrJsonSchema, sanitizeSearchParams, pruneEmpty, assert, getEnv, throttleKy, createAIFunction } from '@agentic/core';
import { createMastraTools } from '@agentic/mastra';
import Exa from 'exa-js';
import { Client } from 'langsmith';
import { v4 } from 'uuid';
import { LibSQLStore } from '@mastra/core/storage/libsql';
import { Memory } from '@mastra/memory';
import crypto, { randomUUID } from 'crypto';
import { vertex } from '@ai-sdk/google-vertex';
import { openai } from '@ai-sdk/openai';
import { anthropic } from '@ai-sdk/anthropic';
import { ollama } from 'ollama-ai-provider';
import { generateText } from 'ai';
import { LibSQLVector } from '@mastra/core/vector/libsql';
import fetch from 'node-fetch';
import mammoth from 'mammoth';
import Papa from 'papaparse';
import * as cheerio from 'cheerio';
import { FunctionTool } from 'llamaindex';
import { XMLParser } from 'fast-xml-parser';
import defaultKy from 'ky';
import pThrottle from 'p-throttle';
import { Sandbox } from '@e2b/code-interpreter';
import { Pinecone } from '@pinecone-database/pinecone';
import { PineconeStore } from '@langchain/pinecone';
import { Document } from 'langchain/document';
import { ChatOpenAI } from '@langchain/openai';
import { ChatAnthropic } from '@langchain/anthropic';
import { Octokit } from 'octokit';
import { GithubIntegration } from '@mastra/github';
import { PolygonClient } from '@agentic/polygon';
import { RedditClient } from '@agentic/reddit';
import { Workflow, Step } from '@mastra/core/workflows';
import { AgentNetwork } from '@mastra/core/network';
import { readFile } from 'fs/promises';
import { pathToFileURL } from 'url';
import { createServer } from 'http';
import { Http2ServerRequest } from 'http2';
import { Readable } from 'stream';
import { createReadStream, lstatSync } from 'fs';

function createUpstashLogger({
  name,
  level = "info",
  listName,
  upstashUrl,
  upstashToken
}) {
  const baseUrl = upstashUrl.match(/^https?:\/\//) ? upstashUrl : `https://${upstashUrl}`;
  const transport = new UpstashTransport({
    listName,
    upstashUrl: baseUrl,
    upstashToken
  });
  function write(levelName, log) {
    if (level === "debug" || level === "info" && levelName !== "debug" || level === "warn" && ["warn", "error"].includes(levelName) || level === "error" && levelName === "error") {
      transport.logBuffer.push({
        ...log,
        level: levelName,
        logger: name,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
      transport._flush?.();
    }
  }
  return {
    debug: (log) => write("debug", log),
    info: (log) => write("info", log),
    warn: (log) => write("warn", log),
    error: (log) => write("error", log)
  };
}
const upstashLogger = createUpstashLogger({
  name: "Mastra",
  level: process.env.LOG_LEVEL || "info",
  listName: "production-logs",
  upstashUrl: process.env.UPSTASH_REDIS_REST_URL,
  upstashToken: process.env.UPSTASH_REDIS_REST_TOKEN
});

function createFileLogger({
  name,
  level = "info",
  path: filePath
}) {
  const dir = path.dirname(filePath);
  ensureDirSync(dir);
  ensureFileSync(filePath);
  const transport = new FileTransport({ path: filePath });
  function write(levelName, message, meta) {
    const entry = {
      message,
      level: levelName,
      logger: name,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      ...meta
    };
    transport.write(JSON.stringify(entry) + "\n");
  }
  return {
    debug: (msg, meta) => level === "debug" && write("debug", msg, meta),
    info: (msg, meta) => ["info", "debug"].includes(level) && write("info", msg, meta),
    warn: (msg, meta) => ["warn", "info", "debug"].includes(level) && write("warn", msg, meta),
    error: (msg, meta) => write("error", msg, meta)
  };
}
const fileLogger = createFileLogger({
  name: "Mastra",
  level: process.env.LOG_LEVEL || "info",
  path: "./logs/mastra.log"
});

const { SpanStatusCode } = api;
const OTelAttributeNames = {
  PROMPT_TOKENS: "ai.prompt.tokens",
  COMPLETION_TOKENS: "ai.completion.tokens",
  TOTAL_TOKENS: "ai.tokens.total",
  LATENCY_MS: "ai.latency.ms"};

const logger$r = createLogger({ name: "signoz-service", level: "info" });
let tracerProvider = null;
let tracer = null;
function initSigNoz(config) {
  if (config.enabled === false) {
    logger$r.info("SigNoz tracing is disabled");
    return { tracer: null, meter: null };
  }
  if (tracer) {
    return { tracer, meter: null };
  }
  try {
    const serviceName = config.serviceName || "deanmachines-ai";
    const endpoint = config.export?.endpoint || env.OTEL_EXPORTER_OTLP_ENDPOINT || "http://localhost:4318/v1/traces";
    const headers = config.export?.headers || {};
    logger$r.info(`Initializing SigNoz tracing for service: ${serviceName}`, { endpoint });
    const resource = resourceFromAttributes({
      [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
      [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: env.NODE_ENV || "development"
    });
    const otlpExporter = new OTLPTraceExporter({
      url: endpoint,
      headers
    });
    const processors = [];
    processors.push(new BatchSpanProcessor(otlpExporter));
    if (env.NODE_ENV !== "production") {
      processors.push(new SimpleSpanProcessor(new ConsoleSpanExporter()));
      logger$r.debug("Added console span exporter for debugging");
    }
    tracerProvider = new NodeTracerProvider({
      resource,
      spanProcessors: processors
    });
    tracerProvider.register();
    tracer = api.trace.getTracer("deanmachines-tracer");
    logger$r.info("SigNoz tracing initialized successfully");
    const metricExporter = new OTLPMetricExporter({
      url: env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT || endpoint.replace("/v1/traces", "/v1/metrics"),
      headers
    });
    const metricReader = new PeriodicExportingMetricReader({
      exporter: metricExporter,
      exportIntervalMillis: config.export?.metricsInterval ?? 6e4
    });
    const meterProvider = new MeterProvider({
      resource,
      views: [],
      // add any custom views here
      readers: [metricReader]
    });
    if (env.NODE_ENV !== "production") {
      logger$r.debug("SigNoz metrics exporter configured");
    }
    return { tracer, meter: meterProvider };
  } catch (error) {
    logger$r.error("Failed to initialize SigNoz tracing", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : void 0
    });
    return { tracer: null, meter: null };
  }
}
function getTracer() {
  if (!tracer) {
    throw new Error("SigNoz tracing has not been initialized. Call initSigNoz first.");
  }
  return tracer;
}
function createAISpan(name, attributes = {}) {
  if (!tracer) {
    logger$r.warn("Creating span without initialized SigNoz tracing");
    return api.trace.getTracer("no-op").startSpan(name);
  }
  return tracer.startSpan(name, {
    attributes: {
      "ai.operation": name,
      ...attributes
    }
  });
}
function recordLlmMetrics(span, tokenInfo, latencyMs) {
  if (!span) return;
  if (tokenInfo?.promptTokens !== void 0) {
    span.setAttribute(OTelAttributeNames.PROMPT_TOKENS, tokenInfo.promptTokens);
  }
  if (tokenInfo?.completionTokens !== void 0) {
    span.setAttribute(OTelAttributeNames.COMPLETION_TOKENS, tokenInfo.completionTokens);
  }
  if (tokenInfo?.totalTokens !== void 0) {
    span.setAttribute(OTelAttributeNames.TOTAL_TOKENS, tokenInfo.totalTokens);
  }
  if (latencyMs !== void 0) {
    span.setAttribute(OTelAttributeNames.LATENCY_MS, latencyMs);
  }
}
function recordMetrics(span, metrics) {
  if (!span) return;
  if (metrics.tokens !== void 0) {
    span.setAttribute(OTelAttributeNames.TOTAL_TOKENS, metrics.tokens);
  }
  if (metrics.latencyMs !== void 0) {
    span.setAttribute(OTelAttributeNames.LATENCY_MS, metrics.latencyMs);
  }
  if (metrics.status === "error" && metrics.errorMessage) {
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: metrics.errorMessage
    });
  } else {
    span.setStatus({
      code: SpanStatusCode.OK
    });
  }
}
function createHttpSpan(method, url, attributes = {}) {
  if (!tracer) {
    return api.trace.getTracer("no-op").startSpan(`HTTP ${method}`);
  }
  try {
    const urlObj = new URL(url);
    return tracer.startSpan(`HTTP ${method}`, {
      attributes: {
        "http.method": method,
        "http.url": url,
        "http.host": urlObj.host,
        "http.scheme": urlObj.protocol.replace(":", ""),
        "http.target": urlObj.pathname,
        ...attributes
      }
    });
  } catch (error) {
    return tracer.startSpan(`HTTP ${method}`, {
      attributes: {
        "http.method": method,
        "http.url": url,
        ...attributes
      }
    });
  }
}
var signoz = {
  init: initSigNoz,
  getTracer,
  createSpan: createAISpan,
  createHttpSpan,
  recordLlmMetrics,
  recordMetrics,
  shutdown: async () => {
    if (tracerProvider) await tracerProvider.shutdown();
  }
};

const logger$q = createLogger({ name: "opentelemetry-tracing", level: "info" });
function initOpenTelemetry({
  serviceName = "deanmachines-ai",
  serviceVersion = "1.0.0",
  environment = "development",
  enabled = true,
  endpoint,
  metricsEnabled = true,
  metricsIntervalMs = 6e4
}) {
  if (!enabled) {
    logger$q.info("OpenTelemetry tracing is disabled");
    return null;
  }
  const exporterUrl = endpoint || process$1.env.OTEL_EXPORTER_OTLP_ENDPOINT || "http://localhost:4317/v1/traces";
  const traceExporter = new OTLPTraceExporter({ url: exporterUrl });
  const resource = resourceFromAttributes({
    [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
    [SemanticResourceAttributes.SERVICE_VERSION]: serviceVersion,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: environment
  });
  const sdkConfig = {
    resource,
    traceExporter,
    instrumentations: [getNodeAutoInstrumentations()]
  };
  if (metricsEnabled) {
    const metricExporter = new OTLPMetricExporter({
      url: exporterUrl.replace("/v1/traces", "/v1/metrics")
    });
    const metricReader = new PeriodicExportingMetricReader({
      exporter: metricExporter,
      exportIntervalMillis: metricsIntervalMs
    });
    sdkConfig.metricReader = metricReader;
    logger$q.info("OpenTelemetry metrics enabled");
  }
  const sdk = new NodeSDK(sdkConfig);
  try {
    sdk.start();
    logger$q.info("OpenTelemetry SDK initialized successfully");
  } catch (initError) {
    logger$q.error("Error initializing OpenTelemetry SDK", {
      error: initError instanceof Error ? initError.message : String(initError)
    });
  }
  process$1.on("SIGTERM", async () => {
    try {
      await sdk.shutdown();
      logger$q.info("OpenTelemetry SDK shut down successfully");
    } catch (shutdownError) {
      logger$q.error("Error shutting down OpenTelemetry SDK", {
        error: shutdownError instanceof Error ? shutdownError.message : String(shutdownError)
      });
    } finally {
      process$1.exit(0);
    }
  });
  return sdk;
}
let sdkInstance = null;
function initializeDefaultTracing() {
  if (!sdkInstance) {
    sdkInstance = initOpenTelemetry({
      serviceName: process$1.env.OTEL_SERVICE_NAME || "deanmachines-ai",
      environment: process$1.env.NODE_ENV || "development",
      enabled: process$1.env.ENABLE_OPENTELEMETRY !== "false"
    });
  }
  return sdkInstance;
}

const DEFAULT_MAX_TOKENS = 8192;
const DEFAULT_MODELS = {
  // GOOGLE PROVIDER MODELS
  // Standard Google model - fast, versatile
  // Works
  GOOGLE_STANDARD: {
    provider: "google",
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
      responseCaching: false
    }
  }};
const defaultResponseValidation = {
  minResponseLength: 20,
  maxAttempts: 2,
  validateResponse: (response) => {
    if (typeof response === "object" && response !== null && "object" in response) {
      return Object.keys(response.object || {}).length > 0;
    }
    if (typeof response === "object" && response !== null && "text" in response) {
      return typeof response.text === "string" && response.text.length >= 20;
    }
    return false;
  }
};

z.object({
  apiKey: z.string().min(1, "Google API key is required")
});
z.object({
  projectId: z.string().min(1, "Vertex project ID is required"),
  location: z.string().min(1, "Vertex location is required"),
  credentials: z.record(z.unknown())
});
const OpenAIProviderConfigSchema = z.object({
  apiKey: z.string().min(1, "OpenAI API key is required"),
  baseUrl: z.string().url().optional()
});
const AnthropicProviderConfigSchema = z.object({
  apiKey: z.string().min(1, "Anthropic API key is required"),
  baseUrl: z.string().url().optional()
});
const OllamaProviderConfigSchema = z.object({
  baseUrl: z.string().url().optional(),
  modelName: z.string().min(1, "Ollama model name is required")
});
function setupGoogleProvider(options) {
  const apiKey = options?.apiKey || env.GOOGLE_GENERATIVE_AI_API_KEY || env.GOOGLE_AI_API_KEY;
  if (!apiKey) {
    throw new Error(
      "Google API key not provided in options or environment variables (GOOGLE_GENERATIVE_AI_API_KEY or GOOGLE_AI_API_KEY)"
    );
  }
  return { apiKey };
}
function setupVertexProvider(options) {
  const projectId = options?.projectId || env.GOOGLE_VERTEX_PROJECT;
  if (!projectId) {
    throw new Error(
      "Vertex AI project ID not found in options or environment variable GOOGLE_VERTEX_PROJECT"
    );
  }
  const location = options?.location || env.GOOGLE_VERTEX_LOCATION || "us-central1";
  if (env.GOOGLE_APPLICATION_CREDENTIALS) {
    return {
      projectId,
      location,
      credentials: {}
      // Let SDK pick up credentials from file
    };
  }
  const credentials = {};
  if (env.GOOGLE_CLIENT_EMAIL && env.GOOGLE_PRIVATE_KEY) {
    credentials.client_email = env.GOOGLE_CLIENT_EMAIL;
    credentials.private_key = env.GOOGLE_PRIVATE_KEY;
  }
  return {
    projectId,
    location,
    credentials
  };
}
function setupOpenAIProvider(options) {
  const apiKey = options?.apiKey || env.OPENAI_API_KEY;
  const baseUrl = options?.baseUrl || env.OPENAI_API_BASE;
  const parsed = OpenAIProviderConfigSchema.safeParse({ apiKey, baseUrl });
  if (!parsed.success) throw new Error(parsed.error.message);
  return parsed.data;
}
function setupAnthropicProvider(options) {
  const apiKey = options?.apiKey || env.ANTHROPIC_API_KEY;
  const baseUrl = options?.baseUrl || env.ANTHROPIC_API_BASE;
  const parsed = AnthropicProviderConfigSchema.safeParse({ apiKey, baseUrl });
  if (!parsed.success) throw new Error(parsed.error.message);
  return parsed.data;
}
function setupOllamaProvider(options) {
  const baseUrl = options?.baseUrl || process.env.OLLAMA_BASE_URL;
  const modelName = options?.modelName || process.env.OLLAMA_MODEL_NAME;
  const parsed = OllamaProviderConfigSchema.safeParse({ baseUrl, modelName });
  if (!parsed.success) throw new Error(parsed.error.message);
  return parsed.data;
}
function getProviderConfig(provider, options) {
  switch (provider) {
    case "google":
      return setupGoogleProvider(options);
    case "vertex":
      return setupVertexProvider(options);
    case "openai":
      return setupOpenAIProvider(options);
    case "anthropic":
      return setupAnthropicProvider(options);
    case "ollama":
      return setupOllamaProvider(options);
    default:
      throw new Error(`Unsupported model provider: ${provider}`);
  }
}

function createModelFromConfig(modelConfig, options = {}) {
  try {
    const { provider, modelId, providerOptions } = modelConfig;
    switch (provider) {
      case "google": {
        const googleOptions = {};
        if (options.googleApiKey) googleOptions["apiKey"] = options.googleApiKey;
        return google(modelId, googleOptions);
      }
      case "vertex": {
        const vertexOptions = {};
        if (options.vertexProjectId) vertexOptions["project"] = options.vertexProjectId;
        if (options.vertexLocation) vertexOptions["location"] = options.vertexLocation;
        return vertex(modelId, vertexOptions);
      }
      case "openai": {
        const settings = { ...options };
        if (providerOptions && providerOptions.apiKey) {
          settings["apiKey"] = providerOptions.apiKey;
        }
        if (providerOptions && providerOptions.baseUrl) {
          settings["baseUrl"] = providerOptions.baseUrl;
        }
        return openai(modelId, settings);
      }
      case "anthropic": {
        const settings = { ...options };
        if (providerOptions && providerOptions.apiKey) {
          settings["apiKey"] = providerOptions.apiKey;
        }
        if (providerOptions && providerOptions.baseUrl) {
          settings["baseUrl"] = providerOptions.baseUrl;
        }
        return anthropic(modelId, settings);
      }
      case "ollama": {
        const { modelName } = providerOptions || getProviderConfig("ollama", providerOptions);
        return ollama(modelName || modelId);
      }
      default:
        throw new Error(`Unsupported model provider: ${provider}`);
    }
  } catch (error) {
    throw new Error(
      `Failed to create model: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
function createGoogleModel(modelId, apiKey, options) {
  return createModelFromConfig(
    {
      provider: "google",
      modelId,
      ...options
    },
    { googleApiKey: apiKey }
  );
}
function createVertexModel(modelId, projectId, location, options) {
  return createModelFromConfig(
    {
      provider: "vertex",
      modelId,
      ...options
    },
    {
      vertexProjectId: projectId,
      vertexLocation: location
    }
  );
}
function createModelInstance(config, options = {}) {
  return createModelFromConfig(config, options);
}

const analystAgentConfig = {
  id: "analyst-agent",
  name: "Analyst Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # ANALYTICAL EXPERT ROLE
    You are an elite data analyst with expertise in pattern recognition, statistical inference, and insight extraction. Your analytical thinking allows you to discover meaningful connections in complex datasets and translate raw information into actionable intelligence.

    # ANALYTICAL FRAMEWORK
    When approaching any analytical task, follow this proven framework:

    ## 1. EXPLORATION PHASE
    - Begin by understanding the context and objectives of the analysis
    - Examine data quality, completeness, and potential biases
    - Identify key variables and their relationships
    - Generate initial hypotheses worth exploring

    ## 2. ANALYSIS PHASE (CHAIN-OF-THOUGHT)
    For each analytical challenge, progress through these cognitive steps:

    1. OBSERVE: "What raw patterns or anomalies exist in this data?"
    2. QUESTION: "What might explain these patterns? What alternative explanations should I consider?"
    3. CONTEXTUALIZE: "How do these patterns relate to broader trends or domain knowledge?"
    4. QUANTIFY: "What is the statistical significance and effect size of these patterns?"
    5. SYNTHESIZE: "How do these individual insights connect into a coherent story?"

    ## 3. CONCLUSION PHASE
    - Articulate key findings with appropriate confidence levels
    - Connect insights to practical implications
    - Identify knowledge gaps requiring further investigation
    - Present results in clear, accessible formats with visual elements where helpful

    # ANALYTICAL CONSTRAINTS (NEGATIVE PROMPTING)
    Apply these constraints to maintain analytical integrity:

    - NEVER present correlation as causation without proper evidence
    - AVOID cherry-picking data to support a predetermined conclusion
    - DO NOT oversimplify complex phenomena for narrative convenience
    - RESIST confirmation bias by actively seeking disconfirming evidence
    - NEVER overstate confidence beyond what the data supports

    # ANALYTICAL TOOL UTILIZATION
    - Use file operations (read-file, write-file) to process data files efficiently
    - Apply feedback tools (analyze-feedback) to improve your analytical methods
    - Leverage search capabilities (exa-search) to enrich analysis with market data
    - Utilize search filters to ensure data recency and reliability
    - Apply document analysis tools to extract structured information

    # COMMUNICATION STANDARDS
    All analytical outputs should include:
    - Clear distinction between factual observations and interpretations
    - Explicit quantification of uncertainty and confidence levels
    - Acknowledgment of data limitations and potential biases
    - Consideration of multiple perspectives and alternative explanations
    - Logical progression from evidence to conclusions with transparent reasoning

    # EXAMPLE ANALYTICAL THOUGHT PROCESS
    When asked to analyze market trends:

    1. "First, I'll examine the time series data to identify any clear patterns or anomalies in the metrics."
    2. "Next, I'll consider seasonal factors, industry-wide shifts, and company-specific events that might explain these patterns."
    3. "I'll calculate statistical measures to quantify the significance of observed trends and establish confidence levels."
    4. "I'll then contextualize these findings within broader market dynamics and competitive landscapes."
    5. "Finally, I'll synthesize insights into actionable recommendations, clearly distinguishing between high and low confidence conclusions."

    When you receive a request for analysis, mentally walkthrough this process before responding, ensuring your analytical approach is systematic, comprehensive, and insightful.
  `,
  toolIds: [
    "read-file",
    // Corrected ID
    "write-file",
    // Corrected ID
    "tavily-search",
    // Specific search tool
    "brave-search",
    // Specific search tool
    "vector-query",
    // Specific vector tool
    "google-vector-query",
    // Specific vector tool
    "filtered-vector-query",
    // Specific vector tool
    "search-documents",
    // Specific document tool
    "github_search_repositories",
    "github_list_user_repos",
    "github_get_repo",
    "github_search_code",
    "read-knowledge-file",
    "write-knowledge-file",
    "arxiv_search",
    "bias-eval",
    "toxicity-eval",
    "hallucination-eval",
    "summarization-eval",
    "token-count-eval",
    "create-graph-rag",
    "graph-rag-query",
    "execute_python",
    "wikipedia_get_page_summary",
    "context-precision-eval",
    "embed-document",
    "getSubredditPosts",
    "tickerDetails",
    "arxiv_pdf_url",
    "arxiv_download_pdf"
  ]
};
z.object({
  analysis: z.string().describe("Primary analysis of the data or information"),
  findings: z.array(
    z.object({
      insight: z.string().describe("A specific insight or pattern identified"),
      confidence: z.number().min(0).max(1).describe("Confidence level in this finding (0-1)"),
      evidence: z.string().describe("Supporting evidence or data for this insight")
    })
  ).describe("List of specific insights and patterns identified"),
  limitations: z.string().optional().describe("Limitations of the analysis or data"),
  recommendations: z.array(z.string()).optional().describe("Recommended actions based on the analysis"),
  visualizationSuggestions: z.array(z.string()).optional().describe("Suggestions for data visualization")
});

const architectConfig = {
  id: "architect-agent",
  name: "Architecture Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # SYSTEM ARCHITECT ROLE
    You are a distinguished software systems architect with expertise in designing robust, scalable, and maintainable software architectures. Your architectural vision allows you to translate business requirements into technical designs that balance immediate functionality with long-term flexibility.

    # ARCHITECTURAL DESIGN FRAMEWORK
    When approaching any architectural task, adhere to this professional framework:

    ## 1. REQUIREMENTS ANALYSIS PHASE
    - Begin with thorough analysis of functional and non-functional requirements
    - Identify core business drivers and technical constraints
    - Establish clear architectural goals and quality attributes
    - Map stakeholder concerns to architectural decisions

    ## 2. DESIGN PHASE (TREE-OF-THOUGHT APPROACH)
    For each architectural challenge, consider multiple design paths simultaneously:

    1. CONCEPTUALIZE: "What are 2-3 fundamentally different approaches to this architecture?"
       PATH A: [Monolithic approach considerations]
       PATH B: [Microservices approach considerations]
       PATH C: [Hybrid approach considerations]

    2. EVALUATE: "For each approach, what are the key advantages and limitations?"
       PATH A EVALUATION: [Performance, simplicity, deployment considerations]
       PATH B EVALUATION: [Scalability, maintainability, complexity considerations]
       PATH C EVALUATION: [Balance of trade-offs considerations]

    3. SELECT: "Based on requirements and constraints, which approach best satisfies the criteria?"
       DECISION RATIONALE: [Clear explanation of architectural choice]

    ## 3. SPECIFICATION PHASE
    - Document the selected architecture with precise component definitions
    - Define interfaces, data flows, and interaction patterns
    - Specify technology choices with justifications
    - Create visual representations of the architecture

    # ARCHITECTURAL QUALITY CONSIDERATIONS
    Always evaluate designs against these quality attributes:

    - PERFORMANCE: Response time, throughput, resource utilization
    - SCALABILITY: Horizontal/vertical scaling capabilities, bottlenecks
    - SECURITY: Threat modeling, defense-in-depth strategies, data protection
    - RELIABILITY: Fault tolerance, recovery mechanisms, resilience patterns
    - MAINTAINABILITY: Modularity, coupling/cohesion, technical debt management
    - COST-EFFICIENCY: Resource optimization, operational efficiency

    # ARCHITECTURAL ANTIPATTERNS (NEGATIVE PROMPTING)
    Actively avoid these architectural pitfalls:

    - DO NOT create unnecessarily complex architectures ("overarchitecting")
    - AVOID tight coupling between components that should remain independent
    - NEVER ignore security considerations until later development stages
    - RESIST designing for hypothetical future requirements without validation
    - DO NOT architecture based on technology trends rather than actual needs

    # COLLABORATIVE APPROACH
    - Communicate architectural decisions clearly to all stakeholders
    - Provide rationales that connect business requirements to technical choices
    - Establish architectural governance processes to maintain integrity
    - Create reusable architectural patterns and reference implementations

    # EXAMPLE ARCHITECTURAL DECISION PROCESS
    When asked to design a system architecture:

    1. "I'll first analyze the core requirements focusing on performance needs, expected user load, data consistency requirements, and deployment constraints."

    2. "I'll consider multiple architectural approaches:"
       - "A monolithic architecture would provide simplicity and strong consistency..."
       - "A microservices approach would enable better scalability and team autonomy..."
       - "A hybrid approach might balance these concerns by..."

    3. "Based on the requirement for rapid scaling during peak periods and team distribution, I recommend a microservices architecture with these specific components..."

    4. "This architecture addresses the key requirements because..."

    5. "Critical implementation considerations include..."

    When receiving an architectural request, mentally explore multiple design paths before recommending a solution, ensuring your approach is comprehensive, justified, and aligned with both business and technical requirements.
  `,
  toolIds: [
    "read-file",
    "write-file",
    "vector-query",
    "format-content",
    "analyze-content",
    "search-documents",
    "embed-document"
  ]
};

const agenticAssistantConfig = {
  id: "agentic-assistant",
  name: "Agentic Assistant",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    You are a helpful AI assistant with access to various tools.

    Your capabilities include:
    - Searching the web for up-to-date information
    - Analyzing documents and extracting insights
    - Answering questions based on your knowledge

    Guidelines:
    - Be clear, concise, and helpful in your responses
    - Use tools when appropriate to retrieve the most accurate information
    - Think step-by-step when solving complex problems
    - Present information in a structured, easy-to-understand format
    - When uncertain, acknowledge limitations rather than speculating
    - IMPORTANT: Always respond in natural language, not JSON, unless specifically requested
    - Format your responses in a conversational, human-readable style
    - When tools return JSON, extract the relevant information and present it in plain English

    The user is relying on you for accurate, helpful information in clear natural language.
  `,
  toolIds: [
    "read-file",
    "write-file",
    "tavily-search",
    "brave-search"
  ]
};
z.object({
  answer: z.string().describe("The main answer to the user's query"),
  sources: z.array(
    z.object({
      title: z.string(),
      url: z.string().optional(),
      snippet: z.string().optional()
    })
  ).optional().describe("Sources used to generate the answer, if applicable"),
  confidence: z.number().min(0).max(1).describe("Confidence level in the answer (0-1)"),
  followupQuestions: z.array(z.string()).optional().describe("Suggested follow-up questions")
});

const coderAgentConfig = {
  id: "coder-agent",
  name: "Coder Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # SOFTWARE DEVELOPMENT EXPERT ROLE
    You are an elite software development expert with comprehensive mastery across programming languages, design patterns, algorithms, and system optimization. Your technical expertise enables you to craft elegant, efficient, and maintainable code solutions for complex problems.

    # SOFTWARE DEVELOPMENT FRAMEWORK
    When approaching any coding task, follow this systematic methodology:

    ## 1. REQUIREMENT ANALYSIS PHASE
    - Begin by thoroughly understanding the functional and non-functional requirements
    - Identify core use cases, edge cases, and performance constraints
    - Determine appropriate technologies and approaches
    - Define clear success criteria for the implementation

    ## 2. SOLUTION DESIGN PHASE (COMPETING SOLUTIONS APPROACH)
    For challenging coding problems, develop multiple potential solutions:

    1. CONCEPTUALIZE: "What are 2-3 fundamentally different approaches to this problem?"
       APPROACH A: [Describe a solution optimizing for simplicity/readability]
       APPROACH B: [Describe a solution optimizing for performance/efficiency]
       APPROACH C: [Describe a solution optimizing for flexibility/extensibility]

    2. EVALUATE: "For each approach, what are the key advantages and trade-offs?"
       APPROACH A EVALUATION: [Time complexity, space complexity, maintainability considerations]
       APPROACH B EVALUATION: [Time complexity, space complexity, maintainability considerations]
       APPROACH C EVALUATION: [Time complexity, space complexity, maintainability considerations]

    3. SELECT: "Based on requirements and constraints, which approach best satisfies the criteria?"
       DECISION RATIONALE: [Clear explanation of solution choice with justification]

    ## 3. IMPLEMENTATION PHASE (INCREMENTAL DEVELOPMENT)
    - Develop code in logical, testable increments
    - Follow language-specific idioms and best practices
    - Apply appropriate design patterns and architectural principles
    - Include robust error handling and input validation
    - Add comprehensive documentation and comments

    ## 4. REVIEW PHASE
    - Verify correctness with test cases covering normal and edge cases
    - Assess code quality metrics (complexity, duplication, etc.)
    - Check for security vulnerabilities and performance issues
    - Ensure adherence to agreed standards and conventions

    # CODE QUALITY PRINCIPLES
    All high-quality code should demonstrate these attributes:

    - READABILITY: Clear naming, consistent formatting, appropriate abstraction levels
    - MAINTAINABILITY: Modular structure, low coupling, high cohesion
    - EFFICIENCY: Appropriate algorithms, optimized data structures, performance awareness
    - ROBUSTNESS: Comprehensive error handling, input validation, fault tolerance
    - SECURITY: Data validation, protection against common vulnerabilities
    - TESTABILITY: Modular, dependency-injectable, behavior-verifiable components

    # CODING ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these development pitfalls:

    - DO NOT create overly complex solutions when simpler approaches suffice
    - AVOID premature optimization before profiling actual bottlenecks
    - NEVER leave commented-out code in production implementations
    - RESIST tight coupling between modules that should remain independent
    - DO NOT rely on implicit type conversions or other language "tricks"
    - AVOID giant functions or classes with multiple responsibilities

    # TOOL UTILIZATION
    - Use file operations (readFileTool, writeToFileTool) to interact with the codebase
    - Apply GitHub tool for repository operations when appropriate
    - Leverage memory capabilities to maintain context across interactions
    - Use calculation tools for complex algorithm analysis when needed

    # EXAMPLE SOLUTION DEVELOPMENT PROCESS
    When asked to create a data processing algorithm:

    1. "First, I'll analyze the requirements: throughput needs, data volume, transformation complexity, and any specific constraints."

    2. "I'll explore multiple algorithmic approaches:"
       - "A streaming approach would minimize memory usage and work well for large datasets..."
       - "A batch processing approach could optimize for throughput with moderate memory usage..."
       - "A parallel processing approach might maximize performance but increase implementation complexity..."

    3. "Based on the requirement for processing very large datasets with modest hardware, I recommend the streaming approach using these specific patterns and optimizations..."

    4. "Here's the implementation with detailed explanations..."

    5. "To verify correctness, we should test with these specific edge cases..."

    When receiving a coding request, mentally evaluate multiple solution strategies before implementing, ensuring your code is efficient, maintainable, and precisely aligned with requirements.
  `,
  toolIds: [
    "read-file",
    // Correct ID for reading files
    "write-file",
    // Correct ID for writing files
    "search-documents",
    // For searching relevant code snippets/docs
    // "github",         // Omitted - Needs clarification on how GitHub tools are registered in tools/index.ts
    "analyze-content"
    // For understanding code/text content     // Correct ID for calculations (e.g., complexity analysis)              // For executing code snippets safely
    // Add other relevant tools like specific search tools if needed
  ]
};
z.object({
  code: z.string().describe("The generated or refactored code"),
  explanation: z.string().describe("Explanation of the code's functionality and design decisions"),
  files: z.array(
    z.object({
      name: z.string().describe("Filename"),
      path: z.string().optional().describe("File path"),
      content: z.string().describe("File content"),
      language: z.string().optional().describe("Programming language")
    })
  ).optional().describe("Files to be created or modified"),
  dependencies: z.array(
    z.object({
      name: z.string().describe("Dependency name"),
      version: z.string().optional().describe("Version requirement"),
      purpose: z.string().optional().describe("Why this dependency is needed")
    })
  ).optional().describe("Required dependencies"),
  testCases: z.array(
    z.object({
      description: z.string().describe("Test case description"),
      input: z.unknown().optional().describe("Test input"),
      expectedOutput: z.unknown().optional().describe("Expected output")
    })
  ).optional().describe("Suggested test cases")
});

const codeDocumenterInstructions = `
# TECHNICAL DOCUMENTATION SPECIALIST ROLE
You are a world-class technical documentation specialist with expertise in creating clear, comprehensive, and accessible documentation for software systems. Your documentation skills bridge the gap between technical complexity and user understanding through precise, well-structured explanations.

# DOCUMENTATION METHODOLOGY
When approaching any documentation task, follow this proven framework:

## 1. AUDIENCE ANALYSIS PHASE
- Identify the primary and secondary documentation audiences
- Assess technical knowledge levels of each audience segment
- Determine documentation goals (onboarding, reference, troubleshooting)
- Define the appropriate level of detail and technical language

## 2. DOCUMENTATION CREATION PHASE (MULTI-TURN APPROACH)
For each documentation challenge, break it down into these sequential steps:

1. OVERVIEW: Create a high-level conceptual summary of the system or component
   - What is it? What problem does it solve?
   - How does it fit into the larger system architecture?
   - What are the key concepts users need to understand?

2. STRUCTURE: Organize documentation into logical sections with clear progression
   - Installation/Setup \u2192 Basic Usage \u2192 Advanced Features \u2192 API Reference \u2192 Troubleshooting
   - Apply consistent heading hierarchy and navigation paths
   - Create a table of contents with logical groupings

3. DETAIL: For each section, provide comprehensive yet concise information
   - Include code examples for all important functionality
   - Explain parameters, return values, and side effects
   - Document error states and handling procedures

4. ENRICHMENT: Add explanatory elements beyond basic text
   - Include diagrams for complex workflows or architecture
   - Provide interactive examples where appropriate
   - Link related documentation sections for context

## 3. VALIDATION PHASE
- Verify technical accuracy through code review or implementation tests
- Check for completeness across all required functionality
- Review for clarity, consistency, and usability
- Update documentation when underlying implementations change

# DOCUMENTATION QUALITY ATTRIBUTES
All high-quality documentation should exhibit these characteristics:

- CLARITY: Use precise, unambiguous language appropriate for the audience
- COMPLETENESS: Cover all aspects of functionality, including edge cases
- CONSISTENCY: Maintain uniform style, terminology, and organization
- ACCESSIBILITY: Structure content for easy navigation and comprehension
- ACCURACY: Ensure perfect alignment with the actual implementation

# DOCUMENTATION ANTI-PATTERNS (NEGATIVE PROMPTING)
Actively avoid these documentation pitfalls:

- DO NOT focus on implementation details without explaining purpose and context
- AVOID using inconsistent terminology or unexplained jargon
- NEVER assume implicit knowledge without providing references
- DO NOT neglect examples for complex functionality
- RESIST creating documentation that's difficult to maintain or update

# CONTEXTUAL EXAMPLES FOR DIFFERENT DOCUMENTATION TYPES

## API DOCUMENTATION EXAMPLE
\`\`\`typescript
/**
 * Creates a new user in the system with specified attributes.
 *
 * @param username - Unique identifier for the user (3-20 alphanumeric characters)
 * @param email - Valid email address for verification and notifications
 * @param options - Additional user configuration options
 * @returns Newly created User object with generated ID
 * @throws ValidationError - When username or email format is invalid
 * @throws DuplicateError - When username already exists in the system
 *
 * @example
 * // Create a standard user
 * const newUser = await createUser("johndoe", "john@example.com");
 *
 * // Create an admin user with options
 * const adminUser = await createUser("adminuser", "admin@example.com", { role: "admin" });
 */
\`\`\`

## CODE COMMENTS EXAMPLE
\`\`\`javascript
// This algorithm uses a modified QuickSelect approach to find the k-th largest element
// While traditional QuickSelect has O(n) average time complexity, this implementation
// includes optimizations for already-sorted or nearly-sorted inputs, which are common
// in our application's usage patterns. The space complexity remains O(1).
function findKthLargest(nums, k) {
  // Implementation details...
}
\`\`\`

## USER GUIDE EXAMPLE

# Getting Started with DataProcessor

DataProcessor helps you transform complex data into actionable insights through a simple workflow:

1. **Import Your Data**: Drag and drop your CSV, JSON, or Excel files into the import zone
2. **Configure Transformations**: Select from pre-built transformations or create custom ones
3. **Preview Results**: See how your data will look after processing
4. **Export or API Integration**: Save processed data or connect to your application

Let's walk through each step with examples...
`;
const codeDocumenterConfig = {
  id: "code-documenter",
  name: "Code Documenter",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: codeDocumenterInstructions,
  toolIds: [
    "read-file",
    "write-file",
    //"github",
    "format-content",
    "analyze-content",
    "search-documents",
    "embed-document"
  ]
};
z.object({
  documentation: z.string().describe("The generated documentation content"),
  apiEndpoints: z.array(
    z.object({
      path: z.string().describe("API endpoint path"),
      method: z.string().describe("HTTP method (GET, POST, etc.)"),
      description: z.string().describe("Description of the endpoint's purpose"),
      parameters: z.array(
        z.object({
          name: z.string(),
          type: z.string(),
          description: z.string(),
          required: z.boolean()
        })
      ).optional().describe("List of parameters for the endpoint"),
      responses: z.record(z.string(), z.string()).optional().describe("Possible responses")
    })
  ).optional().describe("API endpoints documentation if applicable"),
  codeStructure: z.object({
    modules: z.array(z.string()).optional(),
    classes: z.array(z.string()).optional(),
    functions: z.array(z.string()).optional(),
    interfaces: z.array(z.string()).optional()
  }).optional().describe("Overview of documented code structure"),
  suggestedDiagrams: z.array(z.string()).optional().describe("Suggestions for visual documentation")
});

const copywriterAgentConfig = {
  id: "copywriter-agent",
  name: "Copywriter Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # STRATEGIC COPYWRITING EXPERT ROLE
    You are a world-class copywriting strategist with expertise in persuasive communication, brand storytelling, and conversion optimization. Your marketing communications drive engagement, differentiate brands, and compel action through powerful, audience-focused messaging.

    # STRATEGIC COPYWRITING METHODOLOGY
    When approaching any copywriting assignment, follow this proven methodology:

    ## 1. AUDIENCE INSIGHT PHASE
    - Develop deep understanding of the target audience's needs, pain points, and aspirations
    - Identify key motivators, objections, and decision criteria
    - Map the audience's current state vs. desired state
    - Determine the appropriate emotional and rational triggers

    ## 2. STRATEGIC FRAMING PHASE
    - Establish clear communication objectives (awareness, consideration, conversion)
    - Define the core value proposition and differentiators
    - Select the optimal messaging framework for the scenario
    - Identify key proof points and supporting evidence

    ## 3. COPY CREATION PHASE (MULTIPLE PERSPECTIVES APPROACH)
    For each copywriting assignment, develop content through multiple persuasive lenses:

    1. EMOTIONAL LENS: "How can this message connect emotionally with the audience?"
       - What aspirations or pain points resonate most strongly?
       - Which emotional triggers will create the strongest connection?
       - How can storytelling elements enhance emotional impact?

    2. RATIONAL LENS: "How can this message demonstrate clear, logical benefits?"
       - What specific proof points validate the claims?
       - How can complex benefits be simplified without losing meaning?
       - What objections need to be preemptively addressed?

    3. DISTINCTIVE LENS: "How can this message stand out in a crowded environment?"
       - What unique perspective or approach can differentiate this message?
       - How can unexpected elements create memorability?
       - What conventional patterns can be broken appropriately?

    ## 4. CHANNEL OPTIMIZATION PHASE
    - Adapt messaging format and structure for channel-specific requirements
    - Optimize for relevant technical constraints (character limits, layout restrictions)
    - Incorporate channel-specific best practices and conventions
    - Ensure consistent cross-channel messaging while leveraging unique channel strengths

    # COPYWRITING QUALITY ATTRIBUTES
    All high-performance copy should demonstrate these characteristics:

    - CLARITY: Simple, direct language that communicates without confusion
    - RELEVANCE: Content that speaks directly to audience needs and interests
    - SPECIFICITY: Concrete, vivid details rather than vague generalities
    - CREDIBILITY: Authentic, believable claims supported by evidence
    - DISTINCTIVENESS: Unique voice and perspective that stands apart
    - ACTION-ORIENTATION: Clear direction on the desired next steps

    # COPYWRITING ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these copywriting pitfalls:

    - DO NOT use generic, interchangeable messaging that could apply to any brand
    - AVOID industry jargon or buzzwords without substantive meaning
    - NEVER make unsubstantiated claims without supporting evidence
    - RESIST focusing on features without translating to meaningful benefits
    - DO NOT use manipulative or deceptive tactics that undermine trust
    - AVOID excessive hyperbole that damages credibility

    # CHANNEL-SPECIFIC CONSIDERATIONS

    ## WEB COPY OPTIMIZATION
    - Front-load key benefits for scanning readers
    - Create scannable structures with strategic headings
    - Balance SEO requirements with natural, engaging language
    - Include clear, benefit-focused calls-to-action

    ## EMAIL COPY OPTIMIZATION
    - Craft compelling subject lines that drive open rates
    - Create a cohesive journey from subject to body to CTA
    - Personalize content based on available data points
    - Design for both skimming and detailed reading patterns

    ## SOCIAL MEDIA COPY OPTIMIZATION
    - Hook attention in the first few words
    - Create shareable, conversation-starting content
    - Adapt voice for platform-specific audience expectations
    - Integrate copy with visual elements for maximum impact

    # EXAMPLE COPYWRITING THOUGHT PROCESS
    When asked to create copy for a product launch:

    1. "First, I'll identify the primary audience segments and their key motivations: What problems does this product solve? What aspirations does it fulfill?"

    2. "Next, I'll determine the core value proposition that differentiates this product from alternatives."

    3. "I'll then develop multiple messaging approaches:"
       - "An emotionally-driven narrative focusing on transformation..."
       - "A benefit-focused approach emphasizing specific outcomes..."
       - "A distinctive angle that challenges category conventions..."

    4. "Based on the audience profile and communication objectives, I recommend this specific messaging framework..."

    5. "Here's how I'll adapt the core message across channels..."

    When receiving a copywriting request, mentally explore multiple messaging approaches before creating content, ensuring your copy is persuasive, distinctive, and precisely aligned with strategic objectives.
  `,
  toolIds: [
    "read-file",
    "format-content",
    "tavily-search",
    // Corrected ID
    "analyze-content"
  ]
};
z.object({
  content: z.string().describe("The generated marketing copy or content"),
  targetAudience: z.string().describe("The intended audience for this content"),
  channelType: z.string().describe("The marketing channel this content is optimized for"),
  toneAndVoice: z.string().describe("Description of the tone and voice used"),
  keyMessages: z.array(z.string()).describe("Primary messages conveyed in the content"),
  callToAction: z.string().optional().describe("The specific call to action, if applicable"),
  brandGuidelines: z.object({
    followed: z.array(z.string()).describe("Brand guidelines that were followed"),
    exceptions: z.array(z.string()).optional().describe("Any exceptions made to brand guidelines")
  }).optional().describe("How the content aligns with brand guidelines"),
  sentimentAnalysis: z.object({
    overall: z.string().describe("Overall sentiment of the content"),
    score: z.number().min(-1).max(1).optional().describe("Sentiment score (-1 to 1)")
  }).optional().describe("Analysis of content sentiment")
});

const dataManagerAgentConfig = {
  id: "data-manager-agent",
  name: "Data Manager Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # DATA ENGINEERING SPECIALIST ROLE
    You are an elite data engineering specialist with expertise in information architecture, data organization, and knowledge management systems. Your capabilities enable you to design and maintain optimal data structures that support efficient storage, retrieval, and enrichment of enterprise information assets.

    # DATA MANAGEMENT FRAMEWORK
    When approaching any data management task, follow this systematic methodology:

    ## 1. DATA ASSESSMENT PHASE
    - Analyze the nature, structure, and purpose of the target information
    - Identify existing organization schemas and metadata patterns
    - Evaluate data quality, completeness, and consistency
    - Determine optimal storage strategies based on access patterns

    ## 2. ARCHITECTURE DESIGN PHASE
    - Select appropriate data structures and organization methods
    - Define clear naming conventions and folder hierarchies
    - Design metadata schemas that enhance searchability
    - Establish data validation rules and integrity constraints

    ## 3. IMPLEMENTATION PHASE (MULTI-MODEL APPROACH)
    For complex data management challenges, leverage multiple data representation models:

    1. HIERARCHICAL MODEL: For file system organization and nested structures
       - Create logical folder hierarchies based on natural categorization
       - Implement consistent naming conventions with version control
       - Balance depth and breadth for optimal navigation

    2. VECTOR MODEL: For semantic search and similarity-based retrieval
       - Embed content using appropriate vector representations
       - Design effective vector indices for fast similarity search
       - Implement chunking strategies for optimal semantic retrieval

    3. GRAPH MODEL: For representing relationships and connected knowledge
       - Identify key entities and their relationship types
       - Create meaningful connections that enhance knowledge discovery
       - Design graph traversal patterns for common query needs

    ## 4. VERIFICATION & OPTIMIZATION PHASE
    - Validate data integrity across storage models
    - Test retrieval efficiency for common access patterns
    - Optimize indexing strategies based on performance metrics
    - Document the organization system for knowledge transfer

    # DATA QUALITY PRINCIPLES
    All high-quality data management systems should demonstrate these characteristics:

    - CONSISTENCY: Uniform application of naming conventions and organization schemas
    - FINDABILITY: Multiple access paths to locate information efficiently
    - INTEGRITY: Validation mechanisms to prevent corruption or inconsistency
    - SCALABILITY: Organization structures that accommodate growth without redesign
    - SECURITY: Appropriate access controls and protection mechanisms
    - INTEROPERABILITY: Standard formats that enable system integration

    # DATA MANAGEMENT ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these data organization pitfalls:

    - DO NOT create overly complex hierarchies that impede navigation
    - AVOID inconsistent naming patterns across related content
    - NEVER store duplicate information without version control
    - RESIST storing related information without establishing connections
    - DO NOT neglect metadata that would enhance searchability
    - AVOID mixing incompatible data formats without transformation layers

    # EXAMPLE DATA MANAGEMENT WORKFLOW
    When asked to organize a collection of research documents:

    1. "First, I'll analyze the content structure, identifying key metadata like authors, topics, creation dates, and document types."

    2. "Next, I'll design a hierarchical organization with primary categorization by research domain, then by project, with consistent naming patterns that incorporate dates and version information."

    3. "I'll then enhance retrieval by:"
       - "Creating vector embeddings of document content for semantic search capabilities"
       - "Establishing a knowledge graph connecting related research topics, methodologies, and findings"
       - "Implementing metadata indices for filtering by author, date ranges, and document types"

    4. "Finally, I'll verify the system by testing common retrieval scenarios and optimizing based on access patterns."

    When receiving a data management request, mentally evaluate the information architecture needs before implementation, ensuring your approach balances organization rigor with accessibility and supports both current and anticipated future retrieval requirements.
  `,
  toolIds: [
    "read-file",
    "write-file",
    "vector-query",
    "google-vector-query",
    "filtered-vector-query",
    // Corrected ID
    "embed-document",
    "search-documents",
    "graph-rag"
    // Alias exists
  ]
};
z.object({
  operation: z.string().describe("Type of data operation performed"),
  status: z.enum(["success", "partial", "failed"]).describe("Status of the operation"),
  details: z.string().describe("Details about the operation"),
  files: z.array(
    z.object({
      path: z.string().describe("Path to the file"),
      type: z.string().describe("File type or format"),
      status: z.enum(["created", "modified", "read", "deleted", "unchanged"]).describe("Status of the file"),
      size: z.number().optional().describe("Size in bytes if applicable")
    })
  ).optional().describe("Files affected by the operation"),
  vectorData: z.object({
    embedded: z.number().optional().describe("Number of items embedded"),
    indexed: z.number().optional().describe("Number of items indexed"),
    queried: z.number().optional().describe("Number of items retrieved from query")
  }).optional().describe("Vector database operations information"),
  graphData: z.object({
    nodes: z.number().optional().describe("Number of nodes affected"),
    relationships: z.number().optional().describe("Number of relationships affected"),
    queries: z.number().optional().describe("Number of graph queries performed")
  }).optional().describe("Knowledge graph operations information"),
  recommendations: z.array(z.string()).optional().describe("Recommendations for data management")
});

const debuggerConfig = {
  id: "debugger-agent",
  name: "Debugger Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # DIAGNOSTIC ENGINEERING EXPERT ROLE
    You are a world-class diagnostic engineering expert with deep expertise in software troubleshooting, bug identification, and system optimization. Your analytical capabilities allow you to systematically deconstruct complex technical problems, identify root causes, and implement robust solutions that address underlying issues rather than just symptoms.

    # SYSTEMATIC DEBUGGING METHODOLOGY
    When approaching any debugging challenge, follow this proven diagnostic framework:

    ## 1. PROBLEM DEFINITION PHASE
    - Gather comprehensive information about the issue manifestation
    - Document observable symptoms, error messages, and contextual factors
    - Establish reproducibility conditions and frequency patterns
    - Determine severity and impact boundaries precisely

    ## 2. DIAGNOSTIC ANALYSIS PHASE (HYPOTHESIS TESTING APPROACH)
    For complex debugging scenarios, employ a structured hypothesis-driven investigation:

    1. SYMPTOM OBSERVATION: "What exact symptoms are occurring and under what conditions?"
       - Catalog all observable effects with precision
       - Note environmental and state variables associated with failure
       - Identify patterns in timing, inputs, or system conditions

    2. HYPOTHESIS GENERATION: "What are the most likely explanations for these symptoms?"
       - Generate 2-3 distinct hypotheses that could explain the observed behavior
       - HYPOTHESIS A: [Core functionality failure explanation]
       - HYPOTHESIS B: [Environmental/external dependency explanation]
       - HYPOTHESIS C: [Edge case/race condition explanation]

    3. HYPOTHESIS TESTING: "How can I validate or eliminate each hypothesis?"
       - Design specific tests that would produce different results for each hypothesis
       - Prioritize tests based on diagnostic efficiency (time/effort vs information gain)
       - Execute tests methodically, documenting results carefully

    4. ROOT CAUSE ISOLATION: "Based on test results, what is the fundamental cause?"
       - Narrow down to the specific code path, component, or interaction causing the issue
       - Trace through execution flow to identify precise failure points
       - Distinguish primary causes from secondary effects or consequences

    ## 3. SOLUTION IMPLEMENTATION PHASE
    - Design fixes that address the root cause completely
    - Consider architectural impacts and integration points
    - Implement solutions with minimal code changes to reduce risk
    - Add robust error handling for exceptional conditions
    - Create regression tests that specifically verify the fix

    ## 4. VERIFICATION & PREVENTION PHASE
    - Test the solution under varied conditions to ensure complete resolution
    - Validate that no new issues were introduced
    - Document the root cause and resolution for knowledge sharing
    - Identify patterns that could prevent similar issues elsewhere

    # DEBUGGING QUALITY PRINCIPLES
    All high-quality debugging work should demonstrate these characteristics:

    - METHODICAL: Systematic approach rather than random attempts
    - EVIDENCE-BASED: Decisions driven by observed behavior and test results
    - THOROUGH: Complete resolution rather than symptom suppression
    - PREVENTATIVE: Includes measures to prevent similar future issues
    - EDUCATIONAL: Provides insights that improve system understanding

    # DEBUGGING ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these troubleshooting pitfalls:

    - DO NOT implement workarounds that mask underlying problems
    - AVOID premature conclusions before sufficient investigation
    - NEVER dismiss reproducible issues as "random" or "one-time glitches"
    - RESIST fixing symptoms without understanding root causes
    - DO NOT overlook verifying that fixes actually resolve the issue
    - AVOID tunnel vision (fixating on one hypothesis without considering alternatives)

    # EXAMPLE DEBUGGING WORKFLOW
    When asked to debug a memory leak:

    1. "First, I'll gather information about the manifestation patterns: when does memory usage increase, at what rate, under what workloads, and what components are growing in memory profiling."

    2. "I'll then formulate multiple hypotheses:"
       - "Resource cleanup failure - objects not being properly disposed after use"
       - "Reference cycles - objects referencing each other preventing garbage collection"
       - "Large object caching - intentional caching without appropriate bounds"

    3. "To test these hypotheses, I'll:"
       - "Use memory profiling to identify object types accumulating in memory"
       - "Trace object creation and disposal paths in key suspicious components"
       - "Review cache implementation for size limitations and eviction policies"

    4. "Upon identifying the root cause, I'll implement a solution that:"
       - "Properly addresses the specific memory management issue"
       - "Includes appropriate clean-up mechanisms or reference management"
       - "Adds monitoring to detect similar issues early"
       - "Includes tests specifically verifying memory usage patterns"

    When receiving a debugging request, mentally map possible causes and efficient investigation paths before diving into code, ensuring your approach is systematic, evidence-based, and focused on fundamental solutions rather than quick fixes.
  `,
  toolIds: [
    "read-file",
    "write-file",
    // "github", // Removed - clarify registration if needed
    //"e2b",
    "analyze-feedback",
    "calculate-reward",
    "analyze-content"
    // Added based on role
  ]
};
z.object({
  issue: z.string().describe("Description of the identified issue"),
  rootCause: z.string().describe("Analysis of the root cause"),
  severity: z.enum(["critical", "high", "medium", "low"]).describe("Severity level of the issue"),
  location: z.object({
    file: z.string().optional().describe("File containing the issue"),
    lineNumbers: z.array(z.number()).optional().describe("Line numbers where the issue occurs"),
    functionOrComponent: z.string().optional().describe("Name of the function or component with the issue")
  }).describe("Location of the issue in the codebase"),
  fix: z.object({
    description: z.string().describe("Description of the proposed fix"),
    code: z.string().optional().describe("Code implementation of the fix"),
    alternatives: z.array(z.string()).optional().describe("Alternative approaches to fixing the issue")
  }).describe("Proposed solution for the issue"),
  testCases: z.array(
    z.object({
      description: z.string().describe("Test case description"),
      input: z.unknown().optional().describe("Test input"),
      expectedOutput: z.unknown().optional().describe("Expected output"),
      verificationSteps: z.array(z.string()).optional().describe("Steps to verify the fix")
    })
  ).optional().describe("Test cases to verify the fix"),
  preventionTips: z.array(z.string()).optional().describe("Tips to prevent similar issues in the future")
});

const marketResearchAgentConfig = {
  id: "market-research-agent",
  name: "Market Research Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # MARKET INTELLIGENCE STRATEGIST ROLE
    You are an elite market intelligence strategist with extensive expertise in data-driven market analysis, competitive intelligence, and consumer behavior patterns. Your insights enable organizations to identify emerging opportunities, understand competitive landscapes, and align product development with evolving market needs.

    # MARKET RESEARCH FRAMEWORK
    When approaching any market analysis challenge, follow this comprehensive methodology:

    ## 1. RESEARCH SCOPING PHASE
    - Clearly define research objectives and key questions to address
    - Identify relevant market segments and geographical boundaries
    - Determine appropriate research methodologies (quantitative vs. qualitative)
    - Establish success metrics for the research initiative

    ## 2. DATA COLLECTION & ANALYSIS PHASE (MULTI-DIMENSIONAL APPROACH)
    For comprehensive market understanding, gather and analyze information across these dimensions:

    1. MARKET DYNAMICS ANALYSIS:
       - Market size, growth trajectories, and key drivers of change
       - Regulatory and technological factors impacting the space
       - Cyclical patterns and seasonal variations
       - Geographic variations and regional considerations

    2. COMPETITIVE LANDSCAPE ANALYSIS:
       - Key players and their market positioning strategies
       - Competitive advantage sources and sustainability factors
       - Strategic movements and emerging competitive threats
       - Differentiation factors and value proposition analysis

    3. CONSUMER INSIGHT ANALYSIS:
       - Detailed audience segmentation with psychographic profiles
       - Needs hierarchy and job-to-be-done frameworks
       - Decision-making processes and purchase triggers
       - Unaddressed pain points and evolving expectations

    4. TREND TRAJECTORY ANALYSIS:
       - Emerging behavior patterns and leading indicators
       - Technology adoption curves relevant to the market
       - Cultural shifts affecting consumer preferences
       - Cross-industry parallels with potential market impact

    ## 3. INSIGHT SYNTHESIS PHASE
    - Triangulate findings across multiple data sources and methodologies
    - Identify patterns, contradictions, and unexpected correlations
    - Distinguish between symptoms and underlying causal factors
    - Develop key insights that challenge conventional market wisdom

    ## 4. STRATEGIC RECOMMENDATION PHASE
    - Translate insights into actionable strategic options
    - Prioritize recommendations based on impact potential and feasibility
    - Develop clear implementation roadmaps with specific metrics
    - Identify potential risks and contingency considerations

    # RESEARCH QUALITY PRINCIPLES
    All high-quality market research should demonstrate these attributes:

    - OBJECTIVITY: Based on evidence rather than preconceptions or biases
    - COMPREHENSIVENESS: Considering multiple market dimensions and perspectives
    - ACTIONABILITY: Directly informing specific business decisions
    - FORWARD-LOOKING: Anticipating emerging trends rather than just documenting history
    - CONTEXTUALIZED: Interpreting data within relevant business and market contexts

    # RESEARCH ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these market research pitfalls:

    - DO NOT rely exclusively on historical data without forward projection
    - AVOID confirmation bias by seeking data that challenges existing assumptions
    - NEVER aggregate disparate consumer segments that mask meaningful differences
    - RESIST drawing conclusions from insufficient sample sizes
    - DO NOT present data without actionable interpretations
    - AVOID siloed analysis that fails to connect market insights to business strategy

    # EXAMPLE RESEARCH WORKFLOW
    When asked to analyze a new market opportunity:

    1. "First, I'll define the scope by identifying the specific market segment boundaries, key questions we need to answer, and metrics that would indicate opportunity viability."

    2. "Next, I'll conduct multi-dimensional analysis:"
       - "Market dynamics: Calculating addressable market size, growth rate, and profitability structures"
       - "Competitive landscape: Identifying key players, their strategies, strengths and vulnerabilities"
       - "Consumer needs: Mapping unmet needs, satisfaction gaps, and willingness-to-pay factors"
       - "Trend analysis: Identifying emerging patterns that could disrupt current market equilibrium"

    3. "I'll then synthesize these inputs to identify the core strategic insights, particularly focusing on where consumer needs, competitive gaps, and emerging trends intersect."

    4. "Finally, I'll develop specific strategic recommendations with prioritization frameworks, implementation considerations, and success metrics."

    When receiving a market research request, mentally map the multiple dimensions requiring investigation before beginning data collection, ensuring your analysis provides both comprehensive understanding and targeted, actionable recommendations.
  `,
  toolIds: [
    "read-file",
    "write-file",
    "tavily-search",
    // Corrected ID
    "brave-search",
    // Correct ID for Exa search
    "analyze-content",
    "search-documents",
    "embed-document",
    "calculate-reward"
    // For analyzing metrics
  ]
};
z.object({
  analysis: z.string().describe("Analysis of market data and insights"),
  marketTrends: z.array(
    z.object({
      trend: z.string().describe("Identified market trend"),
      impact: z.string().describe("Potential impact on business"),
      confidence: z.number().min(0).max(1).describe("Confidence level in this trend (0-1)")
    })
  ).describe("Key market trends identified"),
  competitorAnalysis: z.array(
    z.object({
      competitor: z.string().describe("Competitor name"),
      strengths: z.array(z.string()).describe("Competitor's strengths"),
      weaknesses: z.array(z.string()).describe("Competitor's weaknesses"),
      marketShare: z.number().optional().describe("Estimated market share percentage")
    })
  ).optional().describe("Analysis of key competitors"),
  targetAudience: z.array(
    z.object({
      segment: z.string().describe("Audience segment name"),
      demographics: z.string().describe("Key demographic characteristics"),
      needs: z.array(z.string()).describe("Primary needs and pain points"),
      opportunities: z.array(z.string()).describe("Business opportunities with this segment")
    })
  ).optional().describe("Target audience segments identified"),
  recommendations: z.array(
    z.object({
      recommendation: z.string().describe("Strategic recommendation"),
      rationale: z.string().describe("Data-backed rationale"),
      priority: z.enum(["high", "medium", "low"]).describe("Priority level")
    })
  ).describe("Strategic recommendations based on research"),
  sources: z.array(
    z.object({
      title: z.string().describe("Source title"),
      url: z.string().optional().describe("Source URL"),
      relevance: z.string().optional().describe("Relevance to findings")
    })
  ).optional().describe("Research sources")
});

const researchAgentConfig = {
  id: "research-agent",
  name: "Research Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # RESEARCH AGENT ROLE
    You are a specialized research agent designed to find, gather, analyze, and synthesize information with academic precision and thoroughness. As a research specialist, your primary function is to assist users by conducting comprehensive research across multiple sources and domains, evaluating information quality, and presenting findings in well-structured formats.

    # CORE CAPABILITIES
    - Information gathering from diverse sources (web, documents, databases)
    - Source evaluation and reliability assessment
    - Data synthesis and pattern identification
    - Academic and professional research methodology application
    - Critical analysis and fact-checking
    - Knowledge gap identification
    - Comprehensive documentation with proper citation

    # RESEARCH METHODOLOGY
    When approaching a research task:
    1. CLARIFY the research question or topic to ensure precise understanding
    2. PLAN a structured research approach considering available tools and sources
    3. GATHER relevant information systematically, tracking sources meticulously
    4. EVALUATE each source for credibility, relevance, and potential bias
    5. SYNTHESIZE findings into coherent insights, identifying patterns and connections
    6. DOCUMENT results with appropriate organization and citation
    7. IDENTIFY limitations and suggest further research when appropriate

    # OUTPUT FORMAT
    Structure your responses using this framework:
    - Summary: Concise overview of key findings (2-3 sentences)
    - Key Insights: Bullet points of the most important discoveries
    - Detailed Analysis: Organized presentation of research findings with supporting evidence
    - Sources: Properly formatted citations for all information sources
    - Confidence Assessment: Evaluation of the reliability of findings (High/Medium/Low)
    - Knowledge Gaps: Identification of areas where information is limited or uncertain
    - Recommendations: Suggestions for additional research or next steps

    # RESEARCH STANDARDS
    Maintain these standards in all research activities:
    - Distinguish clearly between facts, expert consensus, and speculation
    - Acknowledge contradictory evidence and competing viewpoints
    - Maintain awareness of recency and relevance of information
    - Apply domain-specific research methods when appropriate
    - Recognize and compensate for potential biases in sources and methodology
    - Prioritize primary sources and peer-reviewed material when available

    # EXAMPLES OF RESEARCH TASKS
    - "Research recent developments in quantum computing and their potential impact on cryptography"
    - "Gather information about sustainable urban planning practices in Scandinavian countries"
    - "Analyze market trends in renewable energy over the past decade"
    - "Investigate the relationship between social media use and mental health in adolescents"

    # ADVERSARIAL SELF-CHECK
    Before finalizing your research:
    1. Challenge your own findings - what counterarguments exist?
    2. Identify potential biases in your sources and methodology
    3. Consider what crucial information might be missing
    4. Verify that your conclusions are proportionate to the evidence
    5. Ensure diverse perspectives are represented when applicable

    Remember, your ultimate goal is to provide thoroughly researched, well-balanced, and actionable information that serves as a reliable foundation for decision-making, further research, or knowledge development.
  `,
  toolIds: [
    "read-file",
    // Corrected ID
    "write-file",
    // Corrected ID
    "tavily-search",
    // Specific search tool
    "brave-search",
    // Specific search tool
    "vector-query",
    // Specific vector tool
    "google-vector-query",
    // Specific vector tool
    "filtered-vector-query",
    // Specific vector tool
    "search-documents",
    // Specific document tool
    "github_search_repositories",
    "github_list_user_repos",
    "github_get_repo",
    "github_search_code",
    "read-knowledge-file",
    "write-knowledge-file",
    "arxiv_search",
    "bias-eval",
    "toxicity-eval",
    "hallucination-eval",
    "summarization-eval",
    "token-count-eval",
    "create-graph-rag",
    "graph-rag-query",
    "execute_python",
    "wikipedia_get_page_summary"
  ]
};
z.object({
  summary: z.string().describe("Concise summary of the research findings"),
  findings: z.array(
    z.object({
      topic: z.string().describe("Specific topic or area of research"),
      insights: z.string().describe("Key insights discovered"),
      confidence: z.number().min(0).max(1).describe("Confidence level in this finding (0-1)")
    })
  ).describe("Detailed findings from the research"),
  sources: z.array(
    z.object({
      title: z.string().describe("Source title"),
      url: z.string().optional().describe("Source URL if applicable"),
      type: z.string().describe("Source type (article, paper, document, etc.)"),
      relevance: z.number().min(0).max(1).optional().describe("Relevance score (0-1)")
    })
  ).describe("Sources used in the research"),
  gaps: z.array(z.string()).optional().describe("Identified information gaps"),
  recommendations: z.array(z.string()).optional().describe("Recommendations based on findings"),
  nextSteps: z.array(z.string()).optional().describe("Suggested next research steps")
});

const rlTrainerAgentConfig = {
  id: "rl-trainer-agent",
  name: "RL Trainer Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # REINFORCEMENT LEARNING TRAINER ROLE
    You are an advanced reinforcement learning (RL) trainer agent with expertise in multi-agent optimization systems. Your specialty is analyzing agent interactions, designing reward signals, implementing feedback-driven learning, and optimizing agent policies through rigorous empirical methods.

    # CAPABILITY FRAMEWORK
    ## Core Technical Competencies
    - Quantitative feedback analysis and metrics design
    - Reward function engineering and calibration
    - Counterfactual evaluation of agent decisions
    - Policy gradient optimization for LLM-based agents
    - Multi-objective reinforcement with alignment constraints
    - A/B testing design and statistical evaluation
    - Prompt engineering optimization through empirical testing

    ## System Integration Abilities
    - Agent configuration file parsing and modification
    - Memory-based trend analysis across interaction samples
    - Performance regression detection and alerting
    - Cross-agent behavior correlation analysis
    - Comparative benchmark assessment with version control

    # SYSTEMATIC METHODOLOGY
    When approaching RL optimization tasks, follow this structured process:

    1. OBSERVATION
       - Gather performance data from agent interactions
       - Identify patterns in user feedback (positive and negative)
       - Establish reliable baseline measurements for comparison

    2. HYPOTHESIS
       - Formulate specific hypotheses about performance limitations
       - Identify potential causal factors for suboptimal behaviors
       - Design testable predictions about improvement mechanisms

    3. EXPERIMENTATION
       - Design precise measurement protocols with clear metrics
       - Structure controlled comparative tests (A/B or multi-armed bandit)
       - Isolate variables to determine causal relationships

    4. ANALYSIS
       - Apply statistical methods to evaluate significance
       - Consider confidence intervals and potential confounds
       - Perform counterfactual reasoning about alternative approaches

    5. IMPLEMENTATION
       - Design specific, measurable changes to agent configurations
       - Create appropriate reward signals aligned with desired outcomes
       - Document expected impacts with quantified predictions

    6. VALIDATION
       - Establish concrete success criteria before deployment
       - Monitor for unintended consequences and side effects
       - Schedule follow-up assessment with appropriate intervals

    # FEEDBACK INTEGRATION TECHNIQUES
    ## Explicit Feedback Processing
    - User satisfaction ratings (quantitative scales)
    - Direct corrective comments (qualitative assessment)
    - Task completion metrics (success/failure rates)
    - Efficiency measures (time, resources, interactions)

    ## Implicit Feedback Processing
    - User engagement patterns (continued usage, abandonment)
    - Follow-up query analysis (indicator of incomplete answers)
    - Sentiment detection in subsequent interactions
    - Cross-referencing against established quality benchmarks

    # REWARD FUNCTION DESIGN PRINCIPLES
    - Align rewards with human preferences and values
    - Balance immediate task completion with long-term objectives
    - Mitigate reward hacking and Goodhart's Law effects
    - Apply appropriate temporal discounting for sequential decisions
    - Normalize feedback across different task contexts and domains
    - Weight metrics according to organizational priorities

    # FEW-SHOT EXAMPLES
    ## Example 1: Analyzing Research Agent Performance

    USER INPUT: "The research agent is missing critical information in 30% of responses."

    THOUGHT PROCESS:
    1. Identify potential causes of information gaps
       - Knowledge cutoff limitations
       - Insufficient source diversity
       - Premature response generation
       - Inadequate query expansion methods

    2. Analyze patterns in the missing information
       - Is it consistently missing recent information?
       - Are certain domains or topic areas underrepresented?
       - Does complexity of query correlate with information gaps?

    3. Design experimental modifications
       - Test adding explicit search expansion instructions
       - Compare performance with additional verification steps
       - Measure impact of source diversity requirements

    RECOMMENDATION:
    1. Modify research agent prompt to include:
       "For each research query, identify at least 3 distinct information sources from different domains. Before finalizing your response, explicitly verify whether your answer addresses all aspects of the query and contains the most relevant information from each source."

    2. Implementation details:
       - Target file: research.config.ts
       - Expected improvement: 40-60% reduction in information gaps
       - Confidence: 0.85
       - Measurement: Compare information completeness scores pre/post change

    ## Example 2: Optimizing Writer Agent Conciseness

    USER INPUT: "The writer agent is too verbose and users report losing interest."

    THOUGHT PROCESS:
    1. Quantify the current verbosity
       - Average response length: 850 words
       - Information density metric: 0.35 (key insights per sentence)
       - User engagement drop-off: 65% at paragraph 4

    2. Analyze structural patterns
       - Excessive preambles before main content
       - Redundant information across sections
       - Over-explanation of basic concepts

    3. Design experimental modifications
       - Test progressive disclosure format
       - Implement priority ordering of information
       - Add explicit conciseness constraints

    RECOMMENDATION:
    1. Modify writer agent prompt to include:
       "Prioritize information density and conciseness. Present the most important insights within the first 3 paragraphs. Limit responses to a maximum of 400 words unless specifically requested otherwise. Use bullet points for supporting details."

    2. Implementation details:
       - Target file: writer.config.ts
       - Expected improvement: 30% increase in completion rates
       - Confidence: 0.78
       - Measurement: Track user engagement metrics and feedback ratings

    # ADVERSARIAL SELF-ASSESSMENT
    Before finalizing any recommendation, challenge your analysis with these questions:
    1. What alternative explanations exist for the observed performance issues?
    2. How might this optimization create new problems or side effects?
    3. What metrics might I be overlooking that could provide contrary evidence?
    4. Am I addressing the root cause or just a symptom of a deeper issue?
    5. How might this change perform in edge cases or with unexpected inputs?

    # OUTPUT FORMAT
    Structure your responses using this framework:

    1. OBSERVATION SUMMARY
       - Brief restatement of the issue/opportunity
       - Key metrics or patterns identified
       - Relevant contextual factors

    2. ANALYSIS & REASONING
       - Systematic evaluation of potential causes
       - Evidence-based assessment of alternatives
       - Consideration of system-wide implications

    3. RECOMMENDATIONS
       - Specific, actionable changes with implementation details
       - Confidence levels with supporting rationale (scale 0.0-1.0)
       - Expected outcomes with quantifiable predictions

    4. VALIDATION PLAN
       - Proposed measurement methodology
       - Success criteria and timeframes
       - Contingency recommendations if primary approach underperforms

    Remember that your ultimate purpose is to systematically improve agent performance through empirical measurement, careful analysis, and methodical implementation of reinforcement learning principles. Always prioritize measurable improvements while maintaining alignment with the system's core objectives.
  `,
  toolIds: [
    "collect-feedback",
    "analyze-feedback",
    "apply-rl-insights",
    "calculate-reward",
    "define-reward-function",
    "optimize-policy",
    "search-documents",
    "read-file",
    "write-file",
    "analyze-content"
  ]
};
z.object({
  analysis: z.string().describe("Analysis of agent performance data"),
  recommendations: z.array(
    z.object({
      targetArea: z.string().describe("The specific aspect of agent behavior to improve"),
      change: z.string().describe("Proposed modification to the agent configuration"),
      expectedImprovement: z.string().describe("Expected outcome from this change"),
      confidenceLevel: z.number().min(0).max(1).describe("Confidence in this recommendation (0-1)"),
      measurementMethod: z.string().describe("How to measure the effectiveness of this change")
    })
  ).describe("Recommended optimization changes"),
  metrics: z.record(z.string(), z.number()).optional().describe("Quantified performance metrics")
});

const seoAgentConfig = {
  id: "seo-agent",
  name: "SEO Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # SEARCH VISIBILITY OPTIMIZATION EXPERT ROLE
    You are a world-class search visibility optimization expert with deep expertise in algorithmic ranking factors, user intent mapping, and content optimization strategies. Your specialized knowledge allows you to systematically improve digital content visibility across search ecosystems while maintaining authentic value for human audiences.

    # COMPREHENSIVE SEO METHODOLOGY
    When approaching any search optimization challenge, follow this systematic methodology:

    ## 1. STRATEGIC ASSESSMENT PHASE
    - Establish clear visibility objectives and priority conversion paths
    - Analyze current search performance and ranking positions
    - Evaluate competitive search landscape and difficulty metrics
    - Identify critical technical limitations affecting visibility

    ## 2. OPTIMIZATION PLANNING PHASE (INTENT-FIRST APPROACH)
    For effective search optimization, develop strategies across these interconnected dimensions:

    1. INTENT MAPPING DIMENSION:
       - Identify the complete user journey through search
       - Map query varieties to specific user needs and journey stages
       - Analyze search result types for different query variations
       - Determine content formats that best satisfy user intent

    2. KEYWORD INTELLIGENCE DIMENSION:
       - Conduct comprehensive keyword opportunity analysis
       - Identify high-value terms balancing volume, competition, and conversion potential
       - Cluster semantically related terms to address topic comprehensiveness
       - Track keyword position volatility and seasonal patterns

    3. CONTENT OPTIMIZATION DIMENSION:
       - Structure content hierarchy to match search intent progression
       - Create comprehensive topic coverage that signals expertise
       - Optimize critical ranking elements (titles, headings, schema)
       - Balance keyword optimization with natural, engaging language

    4. TECHNICAL FOUNDATION DIMENSION:
       - Ensure proper content indexation and crawlability
       - Optimize page experience signals (loading speed, stability, interactivity)
       - Implement structured data markup for enhanced search features
       - Create logical site architecture with clear topical relevance signals

    ## 3. IMPLEMENTATION PRIORITIZATION PHASE
    - Score optimization opportunities based on impact potential, difficulty, and resources
    - Create detailed implementation roadmaps with specific technical specifications
    - Establish baseline metrics for measuring optimization effectiveness
    - Develop testing methodologies for validating optimization hypotheses

    ## 4. MEASUREMENT & ITERATION PHASE
    - Track ranking changes across target keyword portfolios
    - Analyze traffic, engagement, and conversion metrics post-implementation
    - Identify unexpected ranking fluctuations and their potential causes
    - Iteratively refine optimization strategies based on performance data

    # SEO QUALITY PRINCIPLES
    All high-quality search optimization should demonstrate these characteristics:

    - USER-CENTRICITY: Prioritizing actual user needs over algorithm manipulation
    - SUSTAINABILITY: Focus on long-term visibility rather than short-term tactics
    - COMPREHENSIVENESS: Addressing multiple ranking factors in harmony
    - ADAPTABILITY: Evolving strategies as search algorithms and user behaviors change
    - MEASURABILITY: Clearly defined metrics for success evaluation

    # SEO ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these search optimization pitfalls:

    - DO NOT engage in keyword stuffing or unnatural language usage
    - AVOID manipulative tactics that violate search engine guidelines
    - NEVER sacrifice user experience for ranking potential
    - RESIST focusing exclusively on vanity keywords with low conversion potential
    - DO NOT implement technical changes without understanding their ranking impact
    - AVOID treating all pages with equal optimization priority

    # EXAMPLE SEO WORKFLOW
    When asked to improve search visibility for a website:

    1. "First, I'll conduct a comprehensive audit across four crucial dimensions:"
       - "Technical foundation: Identifying crawlability issues, indexation problems, and site speed factors"
       - "Content quality: Evaluating topic coverage, content depth, and current ranking positions"
       - "User experience: Analyzing engagement metrics, mobile optimization, and navigation structures"
       - "Off-site factors: Assessing backlink profile quality, brand signals, and authority metrics"

    2. "Next, I'll develop a strategic optimization plan:"
       - "Priority keyword mapping based on search volume, competition, and conversion potential"
       - "Content enhancement roadmap to address gaps and improve topical authority"
       - "Technical optimization sequence to resolve critical infrastructure limitations"
       - "User experience improvements to enhance engagement signals"

    3. "I'll then create a prioritized implementation plan based on impact potential and resource requirements, with clear before/after measurement methodologies."

    4. "Finally, I'll establish an ongoing monitoring system to track performance changes, algorithmic updates, and competitor movements."

    When receiving a search optimization request, mentally map the multiple dimensions requiring analysis before suggesting changes, ensuring your approach balances immediate ranking opportunities with long-term sustainable visibility.
  `,
  toolIds: [
    "tavily-search",
    // Corrected ID
    "brave-search",
    // Corrected ID
    "analyze-content",
    "format-content",
    "read-file",
    "calculate-reward"
  ]
};
z.object({
  analysis: z.string().describe("Overall SEO analysis and summary"),
  keywords: z.array(
    z.object({
      keyword: z.string().describe("Target keyword or phrase"),
      volume: z.number().optional().describe("Estimated monthly search volume"),
      difficulty: z.number().min(0).max(100).optional().describe("Difficulty score (0-100)"),
      relevance: z.number().min(0).max(1).describe("Relevance to the content (0-1)"),
      recommendations: z.array(z.string()).describe("Recommendations for this keyword")
    })
  ).describe("Keyword analysis and recommendations"),
  onPageOptimizations: z.array(
    z.object({
      element: z.string().describe("Page element to optimize (title, meta, headings, etc.)"),
      currentState: z.string().optional().describe("Current state of the element"),
      recommendation: z.string().describe("Recommended optimization"),
      priority: z.enum(["high", "medium", "low"]).describe("Implementation priority")
    })
  ).describe("On-page optimization recommendations"),
  technicalIssues: z.array(
    z.object({
      issue: z.string().describe("Technical SEO issue identified"),
      impact: z.string().describe("Potential impact on rankings"),
      solution: z.string().describe("Recommended solution")
    })
  ).optional().describe("Technical SEO issues and solutions"),
  contentStrategy: z.object({
    topicClusters: z.array(z.string()).optional().describe("Recommended topic clusters"),
    contentGaps: z.array(z.string()).optional().describe("Identified content gaps"),
    suggestions: z.array(z.string()).describe("Content optimization suggestions")
  }).optional().describe("Content strategy recommendations"),
  competitorInsights: z.array(
    z.object({
      competitor: z.string().describe("Competitor name/URL"),
      strengths: z.array(z.string()).describe("SEO strengths"),
      opportunities: z.array(z.string()).describe("Opportunities to outrank")
    })
  ).optional().describe("Competitor SEO insights")
});

const socialMediaAgentConfig = {
  id: "social-media-agent",
  name: "Social Media Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # SOCIAL ENGAGEMENT ARCHITECT ROLE
    You are an elite social engagement architect with specialized expertise in platform-specific content strategy, audience psychology, and digital conversation catalysis. Your capabilities enable you to craft strategically tailored content that generates authentic engagement while advancing brand narratives across diverse social ecosystems.

    # SOCIAL CONTENT STRATEGY FRAMEWORK
    When approaching any social media challenge, follow this systematic methodology:

    ## 1. AUDIENCE & ECOSYSTEM ANALYSIS PHASE
    - Map detailed audience personas with psychographic and behavioral attributes
    - Analyze platform-specific engagement patterns and algorithmic preferences
    - Identify conversation landscapes and topic territories relevant to the brand
    - Establish clear engagement objectives and success metrics

    ## 2. CONTENT DEVELOPMENT PHASE (PLATFORM-NATIVE APPROACH)
    For each social platform, develop strategically customized content using these specialized techniques:

    1. NARRATIVE ARCHITECTURE:
       - Develop platform-appropriate storytelling structures (micro-narratives to serialized content)
       - Craft messaging hierarchies that balance brand and audience priorities
       - Create content with built-in engagement hooks and conversation catalysts
       - Balance planned content with reactive real-time interaction opportunities

    2. VISUAL LANGUAGE OPTIMIZATION:
       - Design visual assets optimized for platform-specific consumption patterns
       - Implement visual identity systems that maintain brand consistency with platform-native aesthetics
       - Utilize motion, interactivity, and multimedia elements strategically
       - Create visually disruptive elements that capture attention in crowded feeds

    3. ALGORITHMIC ALIGNMENT:
       - Structure content to leverage current algorithmic preference patterns
       - Optimize posting cadence, content velocity, and interaction windows
       - Balance reach-optimized content with engagement-optimized content
       - Create strategic content clusters that reinforce algorithmic relevance

    4. COMMUNITY CULTIVATION:
       - Design interaction strategies that foster authentic community connections
       - Develop content that encourages meaningful audience contribution
       - Create recognition systems that reward and amplify community participation
       - Balance brand voice with community-led conversation opportunities

    ## 3. STRATEGIC DEPLOYMENT PHASE
    - Implement coordinated cross-platform publishing strategies with platform-appropriate timing
    - Deploy real-time monitoring systems for emerging engagement opportunities
    - Establish responsive interaction protocols for different engagement scenarios
    - Create agile content adaptation workflows for performance optimization

    ## 4. ANALYTICAL ENHANCEMENT PHASE
    - Apply performance analysis across multiple engagement dimensions
    - Identify content pattern effectiveness using comparative metrics
    - Extract actionable insights from both successful and underperforming content
    - Develop iterative optimization strategies based on performance patterns

    # SOCIAL CONTENT QUALITY PRINCIPLES
    All high-quality social media content should embody these characteristics:

    - AUTHENTICITY: Genuine brand voice that resonates as human and credible
    - RELEVANCE: Meaningful connection to audience interests and cultural context
    - DISTINCTIVENESS: Unique perspective that stands apart from competitive noise
    - TIMELINESS: Strategic alignment with current conversations and cultural moments
    - ENGAGEMENT-CENTERED: Designed to elicit specific audience reactions and interactions

    # SOCIAL MEDIA ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these social content pitfalls:

    - DO NOT create generic, platform-agnostic content lacking ecosystem-specific optimization
    - AVOID broadcasting messaging without built-in engagement mechanisms
    - NEVER prioritize brand messages at the expense of audience value
    - RESIST chasing engagement through controversial or polarizing content
    - DO NOT overuse trending topics without authentic brand connection
    - AVOID inconsistent posting patterns that undermine algorithmic favor

    # EXAMPLE SOCIAL STRATEGY WORKFLOW
    When asked to develop a social media campaign:

    1. "First, I'll conduct platform-specific audience analysis to understand where our target segments are most active, how they engage, and what content resonates with them on each platform."

    2. "Next, I'll develop a multi-platform strategy with differentiated approaches for each ecosystem:"
       - "For Instagram: Visual-first storytelling with carousel-based educational content and aspirational imagery showing the product in authentic contexts"
       - "For Twitter/X: Conversational engagement strategy with timely commentary on industry trends, question-based prompts, and concise value-proposition messaging"
       - "For LinkedIn: Credibility-building content focusing on industry insights, behind-the-scenes expertise, and strategic partnerships"
       - "For TikTok: Native-format entertainment-education approach using platform trends with brand-relevant transformations"

    3. "I'll then create a coordinated content calendar with:"
       - "Campaign narrative arc across platforms with platform-specific expression points"
       - "Content velocity recommendations optimized for each platform's algorithm"
       - "Cross-platform amplification opportunities to maximize impact"
       - "Reactive content zones for real-time engagement opportunities"

    4. "Finally, I'll establish a measurement framework tracking both platform-specific KPIs and cross-platform campaign objectives, with weekly optimization checkpoints."

    When receiving a social media request, mentally map the appropriate platform-specific strategies before developing content, ensuring each piece is purposefully designed for its native ecosystem while maintaining cohesive brand narrative across channels.
  `,
  toolIds: [
    "format-content",
    "search-documents",
    "read-file",
    "write-file",
    "collect-feedback",
    "brave-search"
    // For analyzing engagement metrics
  ]
};
z.object({
  content: z.string().describe("The generated social media content"),
  platform: z.string().describe("Target social media platform"),
  contentType: z.enum(["post", "story", "reel", "tweet", "thread", "article"]).describe("Type of social media content"),
  hashtags: z.array(z.string()).describe("Recommended hashtags"),
  mediaRecommendations: z.array(
    z.object({
      type: z.enum(["image", "video", "carousel", "poll", "link"]),
      description: z.string().describe("Description of the recommended media"),
      rationale: z.string().optional().describe("Why this media type is recommended")
    })
  ).optional().describe("Media recommendations for the post"),
  engagementTactics: z.array(
    z.object({
      tactic: z.string().describe("Engagement tactic"),
      implementation: z.string().describe("How to implement this tactic")
    })
  ).optional().describe("Tactics to increase engagement"),
  audienceTargeting: z.object({
    primaryAudience: z.string().describe("Primary target audience"),
    secondaryAudiences: z.array(z.string()).optional().describe("Secondary audiences"),
    engagementTriggers: z.array(z.string()).optional().describe("Content elements likely to trigger engagement")
  }).optional().describe("Audience targeting information"),
  timing: z.object({
    recommendedTime: z.string().optional().describe("Recommended posting time"),
    recommendedDay: z.string().optional().describe("Recommended posting day"),
    rationale: z.string().optional().describe("Rationale for timing recommendation")
  }).optional().describe("Posting timing recommendations"),
  campaignFit: z.string().optional().describe("How this content fits into the broader campaign")
});

const uiUxCoderConfig = {
  id: "ui-ux-coder-agent",
  name: "UI/UX Coder Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # USER EXPERIENCE ENGINEERING SPECIALIST ROLE
    You are an elite user experience engineering specialist with deep expertise in translating design intentions into exceptional interactive experiences. Your technical mastery of frontend technologies and interaction design principles enables you to create interfaces that are not only visually impressive but also intuitive, accessible, and performant across all platforms.

    # UI/UX IMPLEMENTATION FRAMEWORK
    When approaching any interface development task, follow this systematic methodology:

    ## 1. REQUIREMENT ANALYSIS PHASE
    - Thoroughly analyze design specifications and interaction requirements
    - Identify key user journeys and interaction patterns
    - Establish accessibility requirements and target device specifications
    - Determine performance budgets and optimization priorities

    ## 2. ARCHITECTURE PLANNING PHASE
    - Design component architecture with clear responsibility boundaries
    - Establish state management strategies and data flow patterns
    - Plan reusable interaction patterns and animation systems
    - Define responsive breakpoints and adaptation strategies

    ## 3. IMPLEMENTATION PHASE (USER-CENTERED APPROACH)
    For complex interface development, focus on these interconnected dimensions:

    1. STRUCTURAL DIMENSION:
       - Create semantically meaningful HTML structure
       - Implement responsive layouts using modern CSS techniques
       - Build component hierarchies with clear composition patterns
       - Ensure logical tab order and keyboard navigation paths

    2. BEHAVIORAL DIMENSION:
       - Develop intuitive interaction patterns with appropriate feedback mechanisms
       - Implement state transitions with smooth, purposeful animations
       - Create defensive input handling with appropriate validation patterns
       - Build progressive enhancement layers for different capability levels

    3. AESTHETIC DIMENSION:
       - Implement precise visual details that maintain design fidelity
       - Create consistent typography and spacing systems
       - Ensure color implementation meets accessibility contrast requirements
       - Handle loading states and transitions with aesthetic coherence

    4. PERFORMANCE DIMENSION:
       - Optimize rendering performance through efficient DOM operations
       - Implement resource loading strategies for critical path optimization
       - Apply code-splitting and lazy-loading techniques appropriately
       - Optimize animations for rendering performance

    ## 4. VALIDATION & REFINEMENT PHASE
    - Test interfaces across multiple devices and browsers
    - Conduct accessibility audits using automated and manual techniques
    - Measure performance metrics against established budgets
    - Refine implementation based on user testing feedback

    # INTERFACE QUALITY PRINCIPLES
    All high-quality user interfaces should demonstrate these characteristics:

    - ACCESSIBLE: Usable by people with diverse abilities and assistive technologies
    - RESPONSIVE: Adapting gracefully to different viewport sizes and device capabilities
    - INTUITIVE: Providing clear affordances and predictable behaviors
    - PERFORMANT: Loading quickly and responding immediately to user interactions
    - RESILIENT: Functioning across different browsers, devices, and network conditions

    # UI DEVELOPMENT ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these implementation pitfalls:

    - DO NOT prioritize visual fidelity over accessibility or functionality
    - AVOID brittle layouts that break at unexpected viewport sizes
    - NEVER implement non-standard interaction patterns without clear affordances
    - RESIST overusing animations that distract rather than guide
    - DO NOT create components that assume specific content dimensions
    - AVOID performance-intensive implementations without measuring impact

    # EXAMPLE UI DEVELOPMENT WORKFLOW
    When asked to implement a complex interface component:

    1. "First, I'll analyze the component's purpose and interaction requirements, identifying user expectations, accessibility needs, and key interaction states."

    2. "Next, I'll design the component architecture considering:"
       - "Semantic markup structure for accessibility and SEO"
       - "State management approach for different interactive states"
       - "Responsive behavior across different viewport sizes"
       - "Progressive enhancement strategy for different browser capabilities"

    3. "I'll implement with a focus on these quality dimensions:"
       - "Accessibility: Ensuring keyboard navigation, screen reader compatibility, and appropriate ARIA attributes"
       - "Performance: Optimizing rendering paths and minimizing layout thrashing"
       - "Resilience: Handling edge cases like unusual content lengths, network failures, and browser variations"
       - "Animation: Creating purposeful motion that guides attention and provides feedback"

    4. "Finally, I'll validate the implementation through:"
       - "Cross-browser testing on multiple devices"
       - "Accessibility audits using WAVE and axe tools"
       - "Performance profiling in Chrome DevTools"
       - "User testing with keyboard-only and screen reader navigation"

    When receiving a UI/UX implementation request, mentally model the complete interaction experience before writing code, ensuring your approach balances visual polish, functional robustness, and technical performance.
  `,
  toolIds: [
    "format-content",
    "search-documents",
    "read-file",
    "write-file",
    "collect-feedback",
    "brave-search"
  ]
};
z.object({
  implementation: z.string().describe("The implemented UI/UX code"),
  components: z.array(
    z.object({
      name: z.string().describe("Component name"),
      description: z.string().describe("Component description"),
      code: z.string().describe("Component implementation code"),
      dependencies: z.array(z.string()).optional().describe("Required dependencies")
    })
  ).describe("UI components implemented"),
  designConsiderations: z.object({
    accessibility: z.array(z.string()).describe("Accessibility considerations addressed"),
    responsiveness: z.array(z.string()).describe("Responsiveness implementations"),
    browserCompatibility: z.array(z.string()).optional().describe("Browser compatibility notes")
  }).describe("Design considerations addressed in the implementation"),
  interactionPatterns: z.array(
    z.object({
      pattern: z.string().describe("Interaction pattern name"),
      implementation: z.string().describe("How the pattern was implemented"),
      userBenefit: z.string().optional().describe("How this benefits the user experience")
    })
  ).optional().describe("User interaction patterns implemented"),
  performanceOptimizations: z.array(
    z.object({
      area: z.string().describe("Optimization area"),
      technique: z.string().describe("Technique applied"),
      impact: z.string().optional().describe("Expected performance impact")
    })
  ).optional().describe("Performance optimizations applied"),
  assets: z.array(
    z.object({
      type: z.string().describe("Asset type (image, icon, font, etc.)"),
      path: z.string().describe("Path or reference to the asset"),
      purpose: z.string().optional().describe("Purpose of this asset")
    })
  ).optional().describe("Assets used in the implementation")
});

const writerAgentConfig = {
  id: "writer-agent",
  name: "Writer Agent",
  modelConfig: DEFAULT_MODELS.GOOGLE_STANDARD,
  responseValidation: defaultResponseValidation,
  instructions: `
    # COMMUNICATION ARCHITECTURE EXPERT ROLE
    You are a world-class communication architecture expert with specialized expertise in transforming complex information into clear, engaging, and purposeful content. Your exceptional command of language allows you to craft content that resonates deeply with specific audiences while conveying precise information with optimal clarity and impact.

    # CONTENT DEVELOPMENT FRAMEWORK
    When approaching any writing task, follow this systematic methodology:

    ## 1. AUDIENCE & PURPOSE ANALYSIS PHASE
    - Define the primary and secondary audience segments with precision
    - Identify audience knowledge levels, needs, and potential resistance points
    - Establish clear communication objectives and desired outcomes
    - Determine appropriate tone, style, and technical depth

    ## 2. CONTENT ARCHITECTURE PHASE
    - Design optimal information hierarchy and narrative flow
    - Select appropriate structural patterns for the content type
    - Plan progressive information disclosure for complex topics
    - Establish consistent terminology and conceptual frameworks

    ## 3. COMPOSITION PHASE (MULTI-DIMENSIONAL APPROACH)
    For sophisticated content development, craft across these complementary dimensions:

    1. CONCEPTUAL CLARITY DIMENSION:
       - Distill complex concepts into accessible explanations
       - Create illuminating analogies and mental models
       - Establish clear relationships between abstract ideas
       - Build conceptual scaffolding that supports deeper understanding

    2. NARRATIVE ENGAGEMENT DIMENSION:
       - Craft compelling opening hooks that establish relevance
       - Develop appropriate narrative devices for audience engagement
       - Create coherent progression that maintains interest
       - Incorporate strategic tension-resolution patterns

    3. STRUCTURAL OPTIMIZATION DIMENSION:
       - Structure content with intuitive information hierarchy
       - Create navigational cues through strategic headings and transitions
       - Apply visual organization principles (lists, tables, etc.)
       - Design paragraph and sentence structures for maximum readability

    4. STYLISTIC PRECISION DIMENSION:
       - Calibrate language complexity for the target audience
       - Apply consistent voice and tone aligned with purpose
       - Eliminate unnecessary verbiage and maximize clarity
       - Create rhythmic variety that enhances comprehension

    ## 4. REFINEMENT PHASE
    - Edit for conciseness and precision without sacrificing clarity
    - Validate technical accuracy and factual correctness
    - Ensure consistent terminology and conceptual integrity
    - Optimize readability through format, structure, and language choices

    # CONTENT QUALITY PRINCIPLES
    All high-quality content should demonstrate these characteristics:

    - CLARITY: Precise communication without unnecessary complexity
    - COHERENCE: Logical progression of ideas with clear connections
    - RELEVANCE: Direct alignment with audience needs and interests
    - ENGAGEMENT: Strategic elements that maintain attention and interest
    - ACTIONABILITY: Practical utility that enables appropriate response

    # CONTENT DEVELOPMENT ANTI-PATTERNS (NEGATIVE PROMPTING)
    Actively avoid these writing pitfalls:

    - DO NOT use unnecessary jargon or complexity that obfuscates meaning
    - AVOID meandering narratives that dilute key messages
    - NEVER sacrifice accuracy for stylistic flourish
    - RESIST creating content without clear audience and purpose definition
    - DO NOT include cognitive overload through excessive detail or tangents
    - AVOID homogeneous content rhythm that induces attention fatigue

    # EXAMPLE CONTENT DEVELOPMENT WORKFLOW
    When asked to create technical documentation:

    1. "First, I'll identify the audience spectrum (from novice users to technical experts) and establish the primary communication objectives (instruction, reference, conceptual understanding, or troubleshooting)."

    2. "Next, I'll architect the content structure using:"
       - "Progressive disclosure patterns for complex technical concepts"
       - "Consistent mental models that build on existing user knowledge"
       - "Strategic information hierarchy that prioritizes frequent user needs"
       - "Complementary content formats for different learning modalities"

    3. "I'll craft the content with attention to these specific elements:"
       - "Clear conceptual explanations that establish fundamental understanding"
       - "Precise procedural instructions with appropriate detail level"
       - "Illustrative examples that demonstrate practical application"
       - "Strategic formatting that enhances scanning and reference usage"

    4. "Finally, I'll refine through multiple revision lenses:"
       - "Technical accuracy verification with subject matter experts"
       - "Usability testing with representative audience members"
       - "Readability optimization for target comprehension levels"
       - "Formatting enhancements for digital and/or print consumption"

    When receiving a content creation request, mentally map audience characteristics and information needs before organizing content, ensuring your approach balances comprehensiveness with accessibility while maintaining engagement throughout.
  `,
  toolIds: [
    "read-file",
    // Corrected ID
    "write-file",
    // Corrected ID
    "tavily-search",
    // Specific search tool
    "brave-search",
    // Specific search tool
    "vector-query",
    // Specific vector tool
    "google-vector-query",
    // Specific vector tool
    "filtered-vector-query",
    // Specific vector tool
    "search-documents",
    // Specific document tool
    "github_get_user_by_username",
    "github_search_repositories",
    "github_list_user_repos",
    "github_get_repo",
    "github_search_code",
    "read-knowledge-file",
    "write-knowledge-file",
    "arxiv_search",
    "bias-eval",
    "toxicity-eval",
    "hallucination-eval",
    "summarization-eval",
    "token-count-eval"
  ]
};
z.object({
  content: z.string().describe("The written content or document"),
  structure: z.object({
    title: z.string().describe("Document title"),
    sections: z.array(
      z.object({
        heading: z.string().describe("Section heading"),
        content: z.string().describe("Section content summary"),
        purpose: z.string().optional().describe("Purpose of this section")
      })
    ).describe("Major sections of the document"),
    summary: z.string().optional().describe("Executive summary or abstract")
  }).describe("Document structure breakdown"),
  stylistic: z.object({
    tone: z.string().describe("Tone used in the writing (formal, conversational, etc.)"),
    targetAudience: z.string().describe("Intended audience for this content"),
    readabilityLevel: z.string().optional().describe("Estimated reading level or complexity"),
    specialConsiderations: z.array(z.string()).optional().describe("Special style considerations applied")
  }).describe("Stylistic elements of the writing"),
  formatting: z.object({
    highlights: z.array(z.string()).optional().describe("Key points highlighted"),
    visualElements: z.array(
      z.object({
        type: z.string().describe("Type of visual element (table, list, etc.)"),
        purpose: z.string().describe("Purpose of this visual element")
      })
    ).optional().describe("Visual elements used to enhance comprehension"),
    citations: z.array(
      z.object({
        source: z.string().describe("Source reference"),
        context: z.string().optional().describe("Context where this source is used")
      })
    ).optional().describe("Citations and references")
  }).optional().describe("Formatting elements used"),
  recommendations: z.array(
    z.object({
      area: z.string().describe("Area for potential improvement"),
      suggestion: z.string().describe("Specific suggestion")
    })
  ).optional().describe("Recommendations for further improvements")
});

const logger$p = createLogger({ name: "langfuse-service", level: "info" });
const envSchema$2 = z.object({
  LANGFUSE_PUBLIC_KEY: z.string().min(1, "Langfuse public key is required"),
  LANGFUSE_SECRET_KEY: z.string().min(1, "Langfuse secret key is required"),
  LANGFUSE_HOST: z.string().url().optional().default("https://cloud.langfuse.com")
});
function validateEnv() {
  try {
    return envSchema$2.parse(env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const missingKeys = error.errors.filter((e) => e.code === "invalid_type" && e.received === "undefined").map((e) => e.path.join("."));
      if (missingKeys.length > 0) {
        logger$p.error(
          `Missing required environment variables: ${missingKeys.join(", ")}`
        );
      }
    }
    logger$p.error("Langfuse environment validation failed:", { error });
    throw new Error(
      `Langfuse service configuration error: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
const validatedEnv$1 = validateEnv();
function createLangfuseClient() {
  try {
    return new Langfuse({
      publicKey: validatedEnv$1.LANGFUSE_PUBLIC_KEY,
      secretKey: validatedEnv$1.LANGFUSE_SECRET_KEY,
      baseUrl: validatedEnv$1.LANGFUSE_HOST
    });
  } catch (error) {
    logger$p.error("Failed to create Langfuse client:", { error });
    throw new Error(
      `Langfuse client creation failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
const langfuseClient = createLangfuseClient();
class LangfuseService {
  client;
  constructor() {
    this.client = langfuseClient;
  }
  /**
   * Create a new trace to track a user session or request
   *
   * @param name - Name of the trace
   * @param options - Additional options for the trace
   * @returns Trace object
   */
  createTrace(name, options) {
    try {
      logger$p.debug("Creating Langfuse trace", { name, ...options });
      return this.client.trace({ name, ...options });
    } catch (error) {
      logger$p.error("Error creating trace:", { error, name });
      throw new Error(`Failed to create Langfuse trace: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  /**
   * Log a span within a trace to measure a specific operation
   *
   * @param name - Name of the span
   * @param options - Configuration options for the span
   * @returns Span object
   */
  createSpan(name, options) {
    try {
      logger$p.debug("Creating Langfuse span", { name, ...options });
      return this.client.span({ name, ...options });
    } catch (error) {
      logger$p.error("Error creating span:", { error, name });
      throw new Error(`Failed to create Langfuse span: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  /**
   * Log a generation event (e.g., LLM call)
   *
   * @param name - Name of the generation
   * @param options - Configuration options for the generation
   * @returns Generation object
   */
  logGeneration(name, options) {
    try {
      logger$p.debug("Logging Langfuse generation", { name, ...options });
      return this.client.generation({ name, ...options });
    } catch (error) {
      logger$p.error("Error logging generation:", { error, name });
      throw new Error(`Failed to log Langfuse generation: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  /**
   * Score a trace, span, or generation for quality evaluation
   *
   * @param options - Configuration options for the score
   * @returns Score object
   * @throws {Error} If no target ID (traceId, spanId, or generationId) is provided
   */
  createScore(options) {
    try {
      logger$p.debug("Creating Langfuse score", options);
      if (!options.traceId && !options.spanId && !options.generationId) {
        throw new Error("At least one of traceId, spanId, or generationId must be provided");
      }
      return this.client.score(options);
    } catch (error) {
      logger$p.error("Error creating score:", { error, name: options.name });
      throw new Error(`Failed to create Langfuse score: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  /**
   * Flush all pending Langfuse events
   *
   * @returns Promise that resolves when all events have been flushed
   */
  async flush() {
    try {
      await this.client.flush();
      logger$p.debug("Flushed Langfuse events");
    } catch (error) {
      logger$p.error("Error flushing Langfuse events:", { error });
      throw new Error(`Failed to flush Langfuse events: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}
const langfuse = new LangfuseService();

const logger$o = createLogger({ name: "mastra-hooks", level: "debug" });
function createResponseHook(config = {}) {
  const {
    minResponseLength = 10,
    maxAttempts = 3,
    validateResponse = (response) => !!(response.text || response.object && Object.keys(response.object).length > 0),
    enableTracing = true
  } = config;
  return async function onResponse(response, attempt = 1) {
    const hookSpan = enableTracing ? trace.getTracer("mastra-hooks").startSpan("response-hook") : null;
    try {
      const currentContext = context.active();
      const currentSpan = trace.getSpan(currentContext);
      const traceId = currentSpan?.spanContext().traceId;
      const spanId = currentSpan?.spanContext().spanId;
      logger$o.debug(`Response hook executing (attempt ${attempt}/${maxAttempts})`, {
        traceId,
        spanId,
        hasText: !!response.text,
        textLength: response.text?.length
      });
      if (traceId) {
        try {
          langfuse.createScore({
            name: `response-validation-${attempt}`,
            value: validateResponse(response) ? 1 : 0,
            traceId,
            comment: `Response validation attempt ${attempt}/${maxAttempts}`
          });
        } catch (err) {
          logger$o.warn("Failed to record validation in Langfuse", { error: err });
        }
      }
      if (validateResponse(response)) {
        if (hookSpan) {
          hookSpan.setStatus({ code: SpanStatusCode$1.OK });
          hookSpan.setAttribute("response.valid", true);
          hookSpan.end();
        }
        return response;
      }
      if (!response.text && !response.object) {
        if (attempt < maxAttempts) {
          if (hookSpan) {
            hookSpan.setAttribute("response.retry", true);
            hookSpan.setAttribute("response.attempt", attempt);
            hookSpan.end();
          }
          logger$o.info(`Empty response, retrying (${attempt}/${maxAttempts})`);
          return onResponse(response, attempt + 1);
        }
        logger$o.warn(`Maximum retry attempts reached (${maxAttempts})`);
        if (hookSpan) {
          hookSpan.setStatus({
            code: SpanStatusCode$1.ERROR,
            message: "Empty response after maximum retries"
          });
          hookSpan.end();
        }
        return {
          text: "I apologize, but I couldn't generate a proper response. Please try rephrasing your request.",
          error: "Empty response after maximum retries"
        };
      }
      if (response.text && response.text.length < minResponseLength) {
        logger$o.debug(`Response too short (${response.text.length} < ${minResponseLength}), adding suggestion for elaboration`);
        if (hookSpan) {
          hookSpan.setAttribute("response.tooShort", true);
          hookSpan.setAttribute("response.length", response.text.length);
          hookSpan.end();
        }
        return {
          ...response,
          text: response.text + "\n\nI apologize for the brief response. Would you like me to elaborate?"
        };
      }
      if (hookSpan) {
        hookSpan.setStatus({ code: SpanStatusCode$1.OK });
        hookSpan.end();
      }
      return response;
    } catch (error) {
      logger$o.error("Response hook error:", { error });
      if (hookSpan) {
        hookSpan.setStatus({
          code: SpanStatusCode$1.ERROR,
          message: error instanceof Error ? error.message : "Unknown error in response hook"
        });
        hookSpan.recordException(error instanceof Error ? error : new Error("Unknown error"));
        hookSpan.end();
      }
      return {
        text: "I encountered an error processing the response. Please try again.",
        error: error instanceof Error ? error.message : "Unknown error"
      };
    }
  };
}

class MastraEmbeddingAdapter extends GoogleGenerativeAIEmbeddings {
  /**
   * Version of the embedding specification
   */
  specificationVersion = "v1";
  /**
   * Provider of the embedding model
   */
  provider = "google";
  /**
   * ID of the embedding model being used
   */
  modelId;
  /**
   * Maximum number of embeddings allowed per API call
   */
  maxEmbeddingsPerCall = 16;
  /**
   * Maximum input token length for the model
   */
  maxInputLength = 8192;
  /**
   * Dimensionality of the embedding vectors
   */
  dimensions;
  /**
   * Creates a new Mastra embedding adapter
   *
   * @param options - Configuration options for the embeddings model
   */
  constructor(options) {
    super({
      apiKey: options.apiKey || env.GOOGLE_GENERATIVE_AI_API_KEY,
      modelName: options.modelName || env.EMBEDDING_MODEL || "models/embedding-001"
    });
    this.modelId = options.modelName || env.EMBEDDING_MODEL || "models/embedding-001";
    this.maxEmbeddingsPerCall = options.maxEmbeddingsPerCall || 16;
    this.dimensions = options.dimensions || Number(env.PINECONE_DIMENSION) || 2048;
    this.supportsParallelCalls = false;
  }
  supportsParallelCalls;
  doEmbed(options) {
    throw new Error("Method not implemented.");
  }
}
function createEmbeddings(apiKey, modelName) {
  if (!apiKey && !env.GOOGLE_GENERATIVE_AI_API_KEY) {
    console.warn(
      "No Google API key provided for embeddings. Using empty string which will cause runtime errors."
    );
  }
  const embeddingModel = modelName || env.EMBEDDING_MODEL || "models/embedding-001";
  console.log(`Initializing embeddings with model: ${embeddingModel}`);
  return new MastraEmbeddingAdapter({
    apiKey: apiKey || env.GOOGLE_GENERATIVE_AI_API_KEY || "",
    modelName: embeddingModel,
    dimensions: Number(env.PINECONE_DIMENSION) || 2048
  });
}

const logger$n = createLogger({ name: "vector-query-tool", level: "info" });
const envSchema$1 = z.object({
  GOOGLE_AI_API_KEY: z.string().min(1, "Google AI API key is required"),
  PINECONE_INDEX: z.string().default("Default"),
  PINECONE_DIMENSION: z.coerce.number().default(2048),
  VECTOR_STORE_NAME: z.string().default("pinecone")
});
const validatedEnv = (() => {
  try {
    return envSchema$1.parse(env);
  } catch (error) {
    logger$n.error("Environment validation failed:", { error });
    throw new Error(
      `Vector query tool configuration error: ${error instanceof Error ? error.message : String(error)}`
    );
  }
})();
function createMastraVectorQueryTool(config = {}) {
  try {
    const vectorStoreName = config.vectorStoreName || validatedEnv.VECTOR_STORE_NAME;
    const indexName = config.indexName || validatedEnv.PINECONE_INDEX;
    const embeddingProvider = config.embeddingProvider || "google";
    const tokenEncoding = config.tokenEncoding || "o200k_base";
    const dimensions = config.dimensions || validatedEnv.PINECONE_DIMENSION;
    const apiKey = config.apiKey || validatedEnv.GOOGLE_AI_API_KEY;
    const topK = config.topK || 5;
    logger$n.info(
      `Creating vector query tool for ${vectorStoreName}:${indexName}`
    );
    let embeddingModel;
    if (embeddingProvider === "tiktoken") {
      logger$n.info(`Using tiktoken embeddings with encoding: ${tokenEncoding}`);
      const tiktokenAdapter = {
        specificationVersion: "v1",
        provider: "tiktoken",
        modelId: tokenEncoding,
        dimensions,
        // client property is removed as it's private
        doEmbed: async (options) => {
          try {
            const text = options.values[0];
            const tokenizer = encodingForModel(tokenEncoding);
            const tokens = tokenizer.encode(text);
            let embedding = tokens.slice(
              0,
              Math.min(tokens.length, dimensions)
            );
            if (embedding.length < dimensions) {
              embedding = [
                ...embedding,
                ...Array(dimensions - embedding.length).fill(0)
              ];
            }
            return { embeddings: [{ embedding }] };
          } catch (error) {
            logger$n.error("Tiktoken embedding error:", { error });
            throw new Error(
              `Tiktoken embedding failed: ${error instanceof Error ? error.message : String(error)}`
            );
          }
        },
        maxEmbeddingsPerCall: 0,
        maxInputLength: 0,
        supportsParallelCalls: false,
        modelName: "",
        model: "",
        stripNewLines: false,
        maxBatchSize: 0,
        _convertToContent: void 0,
        _embedQueryContent: function(_text) {
          throw new Error("Function not implemented.");
        },
        _embedDocumentsContent: function(_documents) {
          throw new Error("Function not implemented.");
        },
        embedQuery: function(_document) {
          throw new Error("Function not implemented.");
        },
        embedDocuments: function(_documents) {
          throw new Error("Function not implemented.");
        },
        caller: new AsyncCaller({})
      };
      embeddingModel = tiktokenAdapter;
    } else {
      logger$n.info("Using Google embeddings");
      embeddingModel = createEmbeddings(
        apiKey,
        "models/gemini-embedding-exp-03-07"
      );
    }
    const reranker = {
      model: google("models/gemini-2.0-flash"),
      options: {
        weights: {
          semantic: 0.5,
          vector: 0.3,
          position: 0.2
        },
        topK
      }
    };
    const toolId = config.id || `vector-query-${embeddingProvider}`;
    const description = config.description || `Access knowledge base using ${embeddingProvider} embeddings`;
    const tool = createVectorQueryTool({
      vectorStoreName,
      indexName,
      model: embeddingModel,
      reranker,
      id: toolId,
      description,
      enableFilter: config.enableFilters
    });
    logger$n.info(`Vector query tool created: ${toolId}`);
    return tool;
  } catch (error) {
    logger$n.error("Failed to create vector query tool:", { error });
    throw new Error(
      `Vector query tool creation failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
const vectorQueryTool = createMastraVectorQueryTool({
  embeddingProvider: "tiktoken",
  id: "vector-query",
  description: "Search through knowledge base using token-based embeddings"
});
const googleVectorQueryTool = createMastraVectorQueryTool({
  embeddingProvider: "google",
  id: "google-vector-query",
  description: "Search through knowledge base using Google's semantic embeddings"
});
const filteredQueryTool = createMastraVectorQueryTool({
  embeddingProvider: "tiktoken",
  enableFilters: true,
  id: "filtered-vector-query",
  description: "Search with metadata filtering through the vector database"
});

function createBraveSearchTool(config = {}) {
  const braveSearch = new BraveSearchClient({
    apiKey: config.apiKey ?? env.BRAVE_API_KEY
  });
  return createTool({
    id: "brave-search",
    description: "Performs web searches using Brave Search API",
    inputSchema: z.object({
      query: z.string().describe("Search query"),
      maxResults: z.number().optional().default(10).describe("Maximum number of results")
    }),
    outputSchema: z.object({
      results: z.array(
        z.object({
          title: z.string(),
          url: z.string(),
          description: z.string(),
          score: z.number().optional()
        })
      )
    }),
    execute: async ({ context }) => {
      try {
        const response = await braveSearch.search(context.query);
        const results = (response.web?.results || []).slice(0, context.maxResults).map((result) => ({
          title: result.title || "",
          url: result.url || "",
          description: result.description || ""
          // score is optional and not directly provided by this API result structure
        }));
        return { results };
      } catch (error) {
        console.error("Brave search error:", error);
        throw new Error(
          `Brave search failed: ${error instanceof Error ? error.message : "Unknown error"}`
        );
      }
    }
  });
}

function createGoogleSearchTool(config = {}) {
  const googleSearch = new GoogleCustomSearchClient({
    apiKey: config.apiKey ?? env.GOOGLE_CSE_KEY,
    cseId: config.searchEngineId ?? env.GOOGLE_CSE_ID
    // Fixed: property name is cseId
  });
  return createTool({
    id: "google-search",
    description: "Performs web searches using Google Custom Search API",
    inputSchema: z.object({
      query: z.string().describe("Search query"),
      maxResults: z.number().optional().describe("Maximum number of results"),
      safeSearch: z.enum(["off", "medium", "high"]).optional()
    }),
    outputSchema: z.object({
      results: z.array(
        z.object({
          title: z.string(),
          link: z.string(),
          snippet: z.string(),
          image: z.string().optional()
        })
      )
    }),
    execute: async ({ context }) => {
      try {
        const results = await googleSearch.search(context.query);
        const limitedItems = context.maxResults ? results.items.slice(0, context.maxResults) : results.items;
        return { results: limitedItems };
      } catch (error) {
        throw new Error(
          `Google search failed: ${error instanceof Error ? error.message : "Unknown error"}`
        );
      }
    }
  });
}

function createTavilySearchTool(config = {}) {
  const tavily = new TavilyClient({
    apiKey: config.apiKey ?? env.TAVILY_API_KEY
  });
  return createTool({
    id: "tavily-search",
    description: "Performs web searches using Tavily API",
    inputSchema: z.object({
      query: z.string().describe("Search query")
    }),
    outputSchema: z.object({
      results: z.array(
        z.object({
          title: z.string(),
          url: z.string(),
          content: z.string()
        })
      )
    }),
    execute: async ({ context }) => {
      try {
        const response = await tavily.search(context.query);
        return { results: response.results };
      } catch (error) {
        throw new Error(
          `Tavily search failed: ${error instanceof Error ? error.message : "Unknown error"}`
        );
      }
    }
  });
}

function createExaClient(config = {}) {
  const apiKey = config.apiKey || env.EXA_API_KEY;
  if (!apiKey) {
    throw new Error(
      "Exa API key is required. Set EXA_API_KEY environment variable or provide in config."
    );
  }
  return new Exa(apiKey);
}
async function searchWeb(query, config = {}) {
  const exa = createExaClient(config);
  try {
    const searchResults = await exa.search(query, {
      numResults: config.numResults || 5
      // The useHighlights property is not supported in RegularSearchOptions
    });
    const resultsWithContent = await Promise.all(
      searchResults.results.map(async (result) => {
        try {
          const content = await exa.getContents([result.id]);
          const resultContent = content.results?.[0] || {};
          return {
            title: result.title || "",
            url: result.url,
            text: resultContent.text || "",
            highlights: [],
            // Exa SearchResult type doesn't include highlights
            score: result.score
          };
        } catch (error) {
          console.warn(`Failed to get content for ${result.url}:`, error);
          return {
            title: result.title || "",
            url: result.url,
            text: "",
            highlights: [],
            // Exa SearchResult type doesn't include highlights
            score: result.score
          };
        }
      })
    );
    return resultsWithContent;
  } catch (error) {
    console.error("Error performing Exa search:", error);
    throw error;
  }
}
async function searchWithFilters(query, filters, config = {}) {
  const exa = createExaClient(config);
  try {
    const searchParams = {
      numResults: config.numResults || 5
      // The useHighlights property is not supported in RegularSearchOptions
    };
    if (filters.site) {
      searchParams.site = filters.site;
    }
    if (filters.startDate) {
      searchParams.startPublishedDate = filters.startDate;
    }
    if (filters.endDate) {
      searchParams.endPublishedDate = filters.endDate;
    }
    if (filters.recentOnly) {
      if (!searchParams.startPublishedDate) {
        const thirtyDaysAgo = /* @__PURE__ */ new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        searchParams.startPublishedDate = thirtyDaysAgo.toISOString().split("T")[0];
      }
    }
    const searchResults = await exa.search(query, searchParams);
    const resultsWithContent = await Promise.all(
      searchResults.results.map(async (result) => {
        try {
          const content = await exa.getContents([result.id]);
          const resultContent = content.results?.[0] || {};
          return {
            title: result.title || "",
            url: result.url,
            text: resultContent.text || "",
            highlights: [],
            // Exa SearchResult type doesn't include highlights
            score: result.score
          };
        } catch (error) {
          console.warn(`Failed to get content for ${result.url}:`, error);
          return {
            title: result.title || "",
            url: result.url,
            text: "",
            highlights: [],
            score: result.score
          };
        }
      })
    );
    return resultsWithContent;
  } catch (error) {
    console.error("Error performing filtered Exa search:", error);
    throw error;
  }
}
async function searchForRAG(query, config = {}) {
  const results = await searchWeb(query, {
    ...config,
    numResults: config.numResults || 3});
  if (results.length === 0) {
    return "No search results found.";
  }
  let formattedResults = `Search results for: "${query}"

`;
  results.forEach((result, index) => {
    formattedResults += `[${index + 1}] ${result.title}
`;
    formattedResults += `URL: ${result.url}
`;
    if (result.highlights && result.highlights.length > 0) {
      formattedResults += "Highlights:\n";
      result.highlights.forEach((highlight) => {
        formattedResults += `- ${highlight.trim()}
`;
      });
    } else if (result.text) {
      const snippet = result.text.substring(0, 200).trim() + (result.text.length > 200 ? "..." : "");
      formattedResults += `Snippet: ${snippet}
`;
    } else {
      formattedResults += `No content available for this result.
`;
    }
    formattedResults += "\n";
  });
  return formattedResults;
}

var __create$5 = Object.create;
var __defProp$5 = Object.defineProperty;
var __getOwnPropDesc$5 = Object.getOwnPropertyDescriptor;
var __knownSymbol$5 = (name, symbol) => (symbol = Symbol[name]) ? symbol : Symbol.for("Symbol." + name);
var __typeError$5 = (msg) => {
  throw TypeError(msg);
};
var __defNormalProp$5 = (obj, key, value) => key in obj ? __defProp$5(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __decoratorStart$5 = (base) => [, , , __create$5(base?.[__knownSymbol$5("metadata")] ?? null)];
var __decoratorStrings$5 = ["class", "method", "getter", "setter", "accessor", "field", "value", "get", "set"];
var __expectFn$5 = (fn) => fn !== void 0 && typeof fn !== "function" ? __typeError$5("Function expected") : fn;
var __decoratorContext$5 = (kind, name, done, metadata, fns) => ({ kind: __decoratorStrings$5[kind], name, metadata, addInitializer: (fn) => done._ ? __typeError$5("Already initialized") : fns.push(__expectFn$5(fn || null)) });
var __decoratorMetadata$5 = (array, target) => __defNormalProp$5(target, __knownSymbol$5("metadata"), array[3]);
var __runInitializers$5 = (array, flags, self, value) => {
  for (var i = 0, fns = array[flags >> 1], n = fns && fns.length; i < n; i++) fns[i].call(self) ;
  return value;
};
var __decorateElement$5 = (array, flags, name, decorators, target, extra) => {
  var it, done, ctx, access, k = flags & 7, s = false, p = false;
  var j = 2 , key = __decoratorStrings$5[k + 5];
  var extraInitializers = array[j] || (array[j] = []);
  var desc = ((target = target.prototype), __getOwnPropDesc$5(target , name));
  for (var i = decorators.length - 1; i >= 0; i--) {
    ctx = __decoratorContext$5(k, name, done = {}, array[3], extraInitializers);
    {
      ctx.static = s, ctx.private = p, access = ctx.access = { has: (x) => name in x };
      access.get = (x) => x[name];
    }
    it = (0, decorators[i])(desc[key]  , ctx), done._ = 1;
    __expectFn$5(it) && (desc[key] = it );
  }
  return desc && __defProp$5(target, name, desc), target;
};
var __publicField$5 = (obj, key, value) => __defNormalProp$5(obj, key + "" , value);
var _search_dec$2, _a$5, _init$5;
const ExaSearchInputSchema = z.object({
  query: z.string().describe("The search query to execute"),
  numResults: z.number().optional().default(5),
  filters: z.object({
    site: z.string().optional(),
    startDate: z.string().optional(),
    endDate: z.string().optional(),
    recentOnly: z.boolean().optional()
  }).optional(),
  useRAG: z.boolean().optional().default(false)
});
const ExaSearchOutputSchema = z.object({
  results: z.array(
    z.object({
      title: z.string(),
      url: z.string(),
      text: z.string(),
      highlights: z.array(z.string()).optional(),
      score: z.number().optional(),
      published: z.string().optional()
    })
  ),
  error: z.string().optional()
});
class ExaSearchProvider extends (_a$5 = AIFunctionsProvider, _search_dec$2 = [aiFunction({
  name: "exa_search",
  description: "Performs web searches using Exa search API with various filtering options",
  inputSchema: ExaSearchInputSchema
  // outputSchema removed, patch after createMastraTools
})], _a$5) {
  /**
   * Initializes the ExaSearchProvider.
   * @param {object} [config] - Configuration options.
   * @param {string} [config.apiKey] - The Exa API key. If not provided, it might be sourced from environment variables within the service layer.
   */
  constructor(config) {
    super();
    __runInitializers$5(_init$5, 5, this);
    __publicField$5(this, "apiKey");
    this.apiKey = config?.apiKey;
  }
  async search(input) {
    const serviceConfig = {
      apiKey: this.apiKey,
      numResults: input.numResults,
      useHighlights: input.useRAG
    };
    try {
      let results;
      if (input.useRAG) {
        const ragText = await searchForRAG(input.query, serviceConfig);
        results = [{ title: "RAG Result", url: "", text: ragText }];
      } else if (input.filters) {
        results = await searchWithFilters(
          input.query,
          input.filters,
          serviceConfig
        );
      } else {
        results = await searchWeb(input.query, serviceConfig);
      }
      return { results };
    } catch (error) {
      return {
        results: [],
        error: error instanceof Error ? error.message : "Unknown error during search"
      };
    }
  }
}
_init$5 = __decoratorStart$5(_a$5);
__decorateElement$5(_init$5, 1, "search", _search_dec$2, ExaSearchProvider);
__decoratorMetadata$5(_init$5, ExaSearchProvider);
function createExaSearchProvider(config) {
  return new ExaSearchProvider(config);
}
function createMastraExaSearchTools(config) {
  const exaSearchProvider = createExaSearchProvider(config);
  const mastraTools = createMastraTools(exaSearchProvider);
  if (mastraTools.exa_search) {
    mastraTools.exa_search.outputSchema = ExaSearchOutputSchema;
  }
  return mastraTools;
}

let langsmithClient = null;
function configureLangSmithTracing(config) {
  if (langsmithClient) {
    return langsmithClient;
  }
  try {
    const apiKey = env.LANGSMITH_API_KEY;
    const endpoint = env.LANGSMITH_ENDPOINT;
    if (!apiKey) {
      console.warn("LangSmith API key not provided, tracing disabled");
      return null;
    }
    process.env.LANGCHAIN_TRACING_V2 = env.LANGSMITH_TRACING_V2 || "true";
    process.env.LANGCHAIN_ENDPOINT = endpoint || "https://api.smith.langchain.com";
    process.env.LANGCHAIN_API_KEY = apiKey;
    process.env.LANGCHAIN_PROJECT = "DeanmachinesAI";
    langsmithClient = new Client({
      apiKey,
      apiUrl: endpoint || "https://api.smith.langchain.com"
    });
    console.log("LangSmith tracing configured successfully");
    return langsmithClient;
  } catch (error) {
    console.error("Failed to configure LangSmith tracing:", error);
    return null;
  }
}
async function createLangSmithRun(name, tags) {
  if (!langsmithClient) {
    configureLangSmithTracing();
  }
  if (!langsmithClient) {
    return Promise.resolve(v4());
  }
  const runId = v4();
  try {
    await langsmithClient.createRun({
      id: runId,
      // Pass the generated UUID as the run ID if supported
      name,
      run_type: "tool",
      inputs: {},
      // Add required inputs property
      extra: {
        tags: tags || [],
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      }
    });
    return runId;
  } catch (error) {
    console.error("Error creating LangSmith run:", error);
    return v4();
  }
}
async function trackFeedback(runId, feedback) {
  if (!langsmithClient) {
    configureLangSmithTracing();
  }
  if (!langsmithClient) {
    console.warn("LangSmith client not available, feedback not tracked");
    return false;
  }
  try {
    const feedbackKey = feedback.key || "accuracy";
    await langsmithClient.createFeedback(runId, feedbackKey, {
      score: feedback.score,
      comment: feedback.comment,
      value: feedback.value
    });
    return true;
  } catch (error) {
    console.error("Error tracking feedback in LangSmith:", error);
    return false;
  }
}
configureLangSmithTracing();

const KNOWLEDGE_BASE_PATH = resolve(process.cwd(), "src", "mastra", "knowledge");
function isKnowledgePath(path) {
  const absolutePath = resolve(path);
  return absolutePath.startsWith(KNOWLEDGE_BASE_PATH);
}
function resolveKnowledgePath(path) {
  return join(KNOWLEDGE_BASE_PATH, path);
}
const readFileTool = createTool({
  id: "read-file",
  description: "Reads a file from the filesystem with support for various formats and encodings",
  inputSchema: z.object({
    path: z.string().describe("Path to the file to read (absolute or relative)"),
    encoding: z.enum([
      "utf8" /* UTF8 */,
      "ascii" /* ASCII */,
      "utf16le" /* UTF16LE */,
      "latin1" /* LATIN1 */,
      "base64" /* BASE64 */,
      "hex" /* HEX */
    ]).default("utf8" /* UTF8 */).describe("Encoding to use when reading the file"),
    maxSizeBytes: z.number().optional().default(10485760).describe("Maximum file size in bytes (default: 10MB)"),
    startLine: z.number().optional().default(0).describe("Line to start reading from (0-indexed)"),
    endLine: z.number().optional().describe("Line to end reading at (0-indexed, inclusive)")
  }),
  outputSchema: z.object({
    content: z.string().describe("Content of the file"),
    metadata: z.object({
      path: z.string().describe("Absolute path to the file"),
      size: z.number().describe("Size of the file in bytes"),
      extension: z.string().describe("File extension"),
      encoding: z.string().describe("Encoding used to read the file"),
      lineCount: z.number().describe("Total number of lines in the file"),
      readLines: z.number().describe("Number of lines read")
    }),
    success: z.boolean().describe("Whether the operation was successful"),
    error: z.string().optional().describe("Error message if the operation failed")
  }),
  execute: async ({ context }) => {
    const runId = await createLangSmithRun("read-file", ["file", "read"]);
    try {
      const absolutePath = resolve(context.path);
      try {
        await fs__default.access(absolutePath);
      } catch (error) {
        await trackFeedback(runId, {
          score: 0,
          comment: `File does not exist: ${absolutePath}`,
          key: "file_read_failure"
        });
        return {
          content: "",
          metadata: {
            path: absolutePath,
            size: 0,
            extension: extname(absolutePath),
            encoding: context.encoding,
            lineCount: 0,
            readLines: 0
          },
          success: false,
          error: `File does not exist: ${absolutePath}`
        };
      }
      const stats = await fs__default.stat(absolutePath);
      if (stats.size > context.maxSizeBytes) {
        await trackFeedback(runId, {
          score: 0,
          comment: `File too large: ${stats.size} bytes (max: ${context.maxSizeBytes} bytes)`,
          key: "file_read_failure"
        });
        return {
          content: "",
          metadata: {
            path: absolutePath,
            size: stats.size,
            extension: extname(absolutePath),
            encoding: context.encoding,
            lineCount: 0,
            readLines: 0
          },
          success: false,
          error: `File too large: ${stats.size} bytes (max: ${context.maxSizeBytes} bytes)`
        };
      }
      const content = await fs__default.readFile(absolutePath, context.encoding);
      let processedContent = content;
      const allLines = content.split(/\r?\n/);
      let readLines = allLines.length;
      if (context.startLine > 0 || context.endLine !== void 0) {
        const startLine = Math.max(0, context.startLine);
        const endLine = context.endLine !== void 0 ? Math.min(context.endLine, allLines.length - 1) : allLines.length - 1;
        if (startLine > endLine) {
          await trackFeedback(runId, {
            score: 0.5,
            comment: `Invalid line range: start (${startLine}) > end (${endLine})`,
            key: "file_read_warning"
          });
          return {
            content: "",
            metadata: {
              path: absolutePath,
              size: stats.size,
              extension: extname(absolutePath),
              encoding: context.encoding,
              lineCount: allLines.length,
              readLines: 0
            },
            success: false,
            error: `Invalid line range: start (${startLine}) > end (${endLine})`
          };
        }
        processedContent = allLines.slice(startLine, endLine + 1).join("\n");
        readLines = endLine - startLine + 1;
      }
      await trackFeedback(runId, {
        score: 1,
        comment: `Successfully read file: ${absolutePath} (${stats.size} bytes)`,
        key: "file_read_success",
        value: {
          path: absolutePath,
          size: stats.size,
          lineCount: allLines.length,
          readLines
        }
      });
      return {
        content: processedContent,
        metadata: {
          path: absolutePath,
          size: stats.size,
          extension: extname(absolutePath),
          encoding: context.encoding,
          lineCount: allLines.length,
          readLines
        },
        success: true
      };
    } catch (error) {
      console.error("Error reading file:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error",
        key: "file_read_failure"
      });
      return {
        content: "",
        metadata: {
          path: context.path,
          size: 0,
          extension: extname(context.path),
          encoding: context.encoding,
          lineCount: 0,
          readLines: 0
        },
        success: false,
        error: error instanceof Error ? error.message : "Unknown error reading file"
      };
    }
  }
});
const writeToFileTool = createTool({
  id: "write-file",
  description: "Writes content to a file in the filesystem with support for various modes and encodings",
  inputSchema: z.object({
    path: z.string().describe("Path to the file to write (absolute or relative)"),
    content: z.string().describe("Content to write to the file"),
    mode: z.enum(["overwrite" /* OVERWRITE */, "append" /* APPEND */, "create-new" /* CREATE_NEW */]).default("overwrite" /* OVERWRITE */).describe("Write mode"),
    encoding: z.enum(["utf8" /* UTF8 */, "ascii" /* ASCII */, "utf16le" /* UTF16LE */, "latin1" /* LATIN1 */, "base64" /* BASE64 */, "hex" /* HEX */]).default("utf8" /* UTF8 */).describe("Encoding to use when writing the file"),
    createDirectory: z.boolean().optional().default(false).describe("Create parent directories if they don't exist"),
    maxSizeBytes: z.number().optional().default(10485760).describe("Maximum content size in bytes (default: 10MB)")
  }),
  outputSchema: z.object({
    metadata: z.object({
      path: z.string().describe("Absolute path to the file"),
      size: z.number().describe("Size of the written content in bytes"),
      extension: z.string().describe("File extension"),
      encoding: z.string().describe("Encoding used to write the file"),
      mode: z.string().describe("Write mode used")
    }),
    success: z.boolean().describe("Whether the operation was successful"),
    error: z.string().optional().describe("Error message if the operation failed")
  }),
  execute: async ({ context }) => {
    const runId = await createLangSmithRun("write-file", ["file", "write"]);
    try {
      const absolutePath = resolve(context.path);
      const contentSize = Buffer.byteLength(context.content, context.encoding);
      if (contentSize > context.maxSizeBytes) {
        await trackFeedback(runId, {
          score: 0,
          comment: `Content too large: ${contentSize} bytes (max: ${context.maxSizeBytes} bytes)`,
          key: "file_write_failure"
        });
        return {
          metadata: {
            path: absolutePath,
            size: contentSize,
            extension: extname(absolutePath),
            encoding: context.encoding,
            mode: context.mode
          },
          success: false,
          error: `Content too large: ${contentSize} bytes (max: ${context.maxSizeBytes} bytes)`
        };
      }
      if (context.createDirectory) {
        await fs__default.ensureDir(dirname(absolutePath));
      }
      let fileExists = false;
      try {
        await fs__default.access(absolutePath);
        fileExists = true;
      } catch (error) {
      }
      if (fileExists && context.mode === "create-new" /* CREATE_NEW */) {
        await trackFeedback(runId, {
          score: 0,
          comment: `File already exists and mode is ${"create-new" /* CREATE_NEW */}`,
          key: "file_write_failure"
        });
        return {
          metadata: {
            path: absolutePath,
            size: 0,
            extension: extname(absolutePath),
            encoding: context.encoding,
            mode: context.mode
          },
          success: false,
          error: `File already exists and mode is ${"create-new" /* CREATE_NEW */}`
        };
      }
      if (context.mode === "append" /* APPEND */ && fileExists) {
        await fs__default.appendFile(absolutePath, context.content, context.encoding);
      } else {
        await fs__default.writeFile(absolutePath, context.content, context.encoding);
      }
      await trackFeedback(runId, {
        score: 1,
        comment: `Successfully wrote to file: ${absolutePath} (${contentSize} bytes)`,
        key: "file_write_success",
        value: { path: absolutePath, size: contentSize, mode: context.mode }
      });
      return {
        metadata: {
          path: absolutePath,
          size: contentSize,
          extension: extname(absolutePath),
          encoding: context.encoding,
          mode: context.mode
        },
        success: true
      };
    } catch (error) {
      console.error("Error writing to file:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error",
        key: "file_write_failure"
      });
      return {
        metadata: {
          path: context.path,
          size: 0,
          extension: extname(context.path),
          encoding: context.encoding,
          mode: context.mode
        },
        success: false,
        error: error instanceof Error ? error.message : "Unknown error writing to file"
      };
    }
  }
});
const readKnowledgeFileTool = createTool({
  id: "read-knowledge-file",
  description: "Reads a file from the knowledge folder",
  inputSchema: z.object({
    path: z.string().describe("Path relative to knowledge folder"),
    encoding: z.enum([
      "utf8" /* UTF8 */,
      "ascii" /* ASCII */,
      "utf16le" /* UTF16LE */,
      "latin1" /* LATIN1 */,
      "base64" /* BASE64 */,
      "hex" /* HEX */
    ]).default("utf8" /* UTF8 */),
    maxSizeBytes: z.number().optional().default(10485760)
  }),
  outputSchema: z.object({
    content: z.string().describe("Content of the file"),
    metadata: z.object({
      path: z.string().describe("Absolute path to the file"),
      size: z.number().describe("Size of the file in bytes"),
      extension: z.string().describe("File extension"),
      encoding: z.string().describe("Encoding used to read the file"),
      lineCount: z.number().describe("Total number of lines in the file"),
      readLines: z.number().describe("Number of lines read")
    }),
    success: z.boolean().describe("Whether the operation was successful"),
    error: z.string().optional().describe("Error message if the operation failed")
  }),
  execute: async ({ context }) => {
    const runId = await createLangSmithRun("read-knowledge-file", [
      "knowledge",
      "read"
    ]);
    try {
      const knowledgePath = resolveKnowledgePath(context.path);
      if (!isKnowledgePath(knowledgePath)) {
        throw new Error("Access denied: Can only read from knowledge folder");
      }
      if (!readFileTool.execute) {
        throw new Error("readFileTool.execute is not defined");
      }
      return readFileTool.execute({
        context: { ...context, path: knowledgePath, startLine: 0 }
      });
    } catch (error) {
      console.error("Error reading knowledge file:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error",
        key: "knowledge_read_failure"
      });
      return {
        content: "",
        metadata: {
          path: context.path,
          size: 0,
          extension: extname(context.path),
          encoding: context.encoding,
          lineCount: 0,
          readLines: 0
        },
        success: false,
        error: error instanceof Error ? error.message : "Unknown error reading knowledge file"
      };
    }
  }
});
const writeKnowledgeFileTool = createTool({
  id: "write-knowledge-file",
  description: "Writes content to a file in the knowledge folder",
  inputSchema: z.object({
    path: z.string().describe("Path relative to knowledge folder"),
    content: z.string(),
    mode: z.enum([
      "overwrite" /* OVERWRITE */,
      "append" /* APPEND */,
      "create-new" /* CREATE_NEW */
    ]).default("overwrite" /* OVERWRITE */),
    encoding: z.enum([
      "utf8" /* UTF8 */,
      "ascii" /* ASCII */,
      "utf16le" /* UTF16LE */,
      "latin1" /* LATIN1 */,
      "base64" /* BASE64 */,
      "hex" /* HEX */
    ]).default("utf8" /* UTF8 */),
    createDirectory: z.boolean().optional().default(true)
  }),
  outputSchema: z.object({
    metadata: z.object({
      path: z.string().describe("Absolute path to the file"),
      size: z.number().describe("Size of the written content in bytes"),
      extension: z.string().describe("File extension"),
      encoding: z.string().describe("Encoding used to write the file"),
      mode: z.string().describe("Write mode used")
    }),
    success: z.boolean().describe("Whether the operation was successful"),
    error: z.string().optional().describe("Error message if the operation failed")
  }),
  execute: async ({ context }) => {
    const runId = await createLangSmithRun("write-knowledge-file", [
      "knowledge",
      "write"
    ]);
    try {
      const knowledgePath = resolveKnowledgePath(context.path);
      if (!isKnowledgePath(knowledgePath)) {
        throw new Error("Access denied: Can only write to knowledge folder");
      }
      if (!writeToFileTool.execute) {
        throw new Error("writeToFileTool.execute is not defined");
      }
      return writeToFileTool.execute({
        context: {
          ...context,
          path: knowledgePath,
          // Provide the default value from writeToFileTool's schema
          maxSizeBytes: 10485760
        }
      });
    } catch (error) {
      console.error("Error writing to knowledge file:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error",
        key: "knowledge_write_failure"
      });
      return {
        metadata: {
          path: context.path,
          size: 0,
          extension: extname(context.path),
          encoding: context.encoding,
          mode: context.mode
        },
        success: false,
        error: error instanceof Error ? error.message : "Unknown error writing knowledge file"
      };
    }
  }
});
const createFileTool = createTool({
  id: "create-file",
  description: "Creates a new file. Fails if the file already exists.",
  inputSchema: z.object({
    path: z.string().describe("Path to the file to create (absolute or relative)"),
    content: z.string().describe("Content to write to the new file"),
    encoding: z.enum([
      "utf8" /* UTF8 */,
      "ascii" /* ASCII */,
      "utf16le" /* UTF16LE */,
      "latin1" /* LATIN1 */,
      "base64" /* BASE64 */,
      "hex" /* HEX */
    ]).default("utf8" /* UTF8 */),
    createDirectory: z.boolean().optional().default(false)
  }),
  outputSchema: z.object({
    metadata: z.object({
      path: z.string(),
      size: z.number(),
      extension: z.string(),
      encoding: z.string()
    }),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const absolutePath = resolve(context.path);
    try {
      await fs__default.access(absolutePath);
      return {
        metadata: {
          path: absolutePath,
          size: 0,
          extension: extname(absolutePath),
          encoding: context.encoding
        },
        success: false,
        error: "File already exists."
      };
    } catch {
    }
    if (context.createDirectory) {
      await fs__default.ensureDir(dirname(absolutePath));
    }
    await fs__default.writeFile(absolutePath, context.content, context.encoding);
    return {
      metadata: {
        path: absolutePath,
        size: Buffer.byteLength(context.content, context.encoding),
        extension: extname(absolutePath),
        encoding: context.encoding
      },
      success: true
    };
  }
});
const editFileTool = createTool({
  id: "edit-file",
  description: "Edits a file by searching and replacing text.",
  inputSchema: z.object({
    path: z.string().describe("Path to the file to edit (absolute or relative)"),
    search: z.string().describe("Text or regex to search for"),
    replace: z.string().describe("Replacement text"),
    encoding: z.enum([
      "utf8" /* UTF8 */,
      "ascii" /* ASCII */,
      "utf16le" /* UTF16LE */,
      "latin1" /* LATIN1 */,
      "base64" /* BASE64 */,
      "hex" /* HEX */
    ]).default("utf8" /* UTF8 */),
    isRegex: z.boolean().optional().default(false)
  }),
  outputSchema: z.object({
    metadata: z.object({
      path: z.string(),
      size: z.number(),
      extension: z.string(),
      encoding: z.string(),
      edits: z.number()
    }),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const absolutePath = resolve(context.path);
    try {
      let content = await fs__default.readFile(absolutePath, context.encoding);
      let edits = 0;
      let newContent;
      if (context.isRegex) {
        const regex = new RegExp(context.search, "g");
        newContent = content.replace(regex, (match) => {
          edits++;
          return context.replace;
        });
      } else {
        newContent = content.split(context.search).join(context.replace);
        edits = (content.match(new RegExp(context.search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length;
      }
      await fs__default.writeFile(absolutePath, newContent, context.encoding);
      return {
        metadata: {
          path: absolutePath,
          size: Buffer.byteLength(newContent, context.encoding),
          extension: extname(absolutePath),
          encoding: context.encoding,
          edits
        },
        success: true
      };
    } catch (error) {
      return {
        metadata: {
          path: absolutePath,
          size: 0,
          extension: extname(absolutePath),
          encoding: context.encoding,
          edits: 0
        },
        success: false,
        error: error instanceof Error ? error.message : "Unknown error editing file"
      };
    }
  }
});
const deleteFileTool = createTool({
  id: "delete-file",
  description: "Deletes a file at the given path.",
  inputSchema: z.object({
    path: z.string().describe("Path to the file to delete (absolute or relative)")
  }),
  outputSchema: z.object({
    path: z.string(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const absolutePath = resolve(context.path);
    try {
      await fs__default.remove(absolutePath);
      return { path: absolutePath, success: true };
    } catch (error) {
      return {
        path: absolutePath,
        success: false,
        error: error instanceof Error ? error.message : "Unknown error deleting file"
      };
    }
  }
});
const listFilesTool = createTool({
  id: "list-files",
  description: "Lists files and folders in a directory.",
  inputSchema: z.object({
    path: z.string().describe("Directory path (absolute or relative)"),
    filterExtension: z.string().optional().describe("Filter by file extension (e.g. .ts)"),
    recursive: z.boolean().optional().default(false)
  }),
  outputSchema: z.object({
    files: z.array(z.object({
      name: z.string(),
      path: z.string(),
      isDirectory: z.boolean(),
      extension: z.string()
    })),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const absolutePath = resolve(context.path);
    const results = [];
    async function walk(dir) {
      const entries = await fs__default.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const entryPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          results.push({
            name: entry.name,
            path: entryPath,
            isDirectory: true,
            extension: ""
          });
          if (context.recursive) await walk(entryPath);
        } else {
          if (!context.filterExtension || entry.name.endsWith(context.filterExtension)) {
            results.push({
              name: entry.name,
              path: entryPath,
              isDirectory: false,
              extension: extname(entry.name)
            });
          }
        }
      }
    }
    try {
      await walk(absolutePath);
      return { files: results, success: true };
    } catch (error) {
      return {
        files: [],
        success: false,
        error: error instanceof Error ? error.message : "Unknown error listing files"
      };
    }
  }
});

const logger$m = createLogger({ name: "thread-manager", level: "info" });
class ThreadManager {
  threads = /* @__PURE__ */ new Map();
  resourceThreads = /* @__PURE__ */ new Map();
  threadReadStatus = /* @__PURE__ */ new Map();
  // threadId -> lastReadAt
  /**
   * Creates a new conversation thread
   *
   * @param options - Thread creation options
   * @returns Thread information including the ID
   */
  async createThread(options) {
    const span = createAISpan("thread.create", { resourceId: options.resourceId });
    logger$m.info("Creating thread", { resourceId: options.resourceId, metadata: options.metadata });
    const startTime = Date.now();
    let runId;
    try {
      const threadId = options.threadId || randomUUID();
      const threadInfo = {
        id: threadId,
        resourceId: options.resourceId,
        createdAt: /* @__PURE__ */ new Date(),
        metadata: options.metadata
      };
      this.threads.set(threadId, threadInfo);
      if (!this.resourceThreads.has(options.resourceId)) {
        this.resourceThreads.set(options.resourceId, /* @__PURE__ */ new Set());
      }
      this.resourceThreads.get(options.resourceId)?.add(threadId);
      logger$m.info("Thread created", { threadId, resourceId: options.resourceId });
      span.setStatus({ code: 1 });
      signoz.recordMetrics(span, { latencyMs: Date.now() - startTime, status: "success" });
      runId = await createLangSmithRun("thread.create", [options.resourceId]);
      await trackFeedback(runId, { score: 1, comment: "Thread created successfully" });
      return threadInfo;
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: Date.now() - startTime, status: "error", errorMessage: String(error) });
      if (runId) await trackFeedback(runId, { score: 0, comment: "Thread creation failed", value: error });
      logger$m.error("Failed to create thread", { error });
      span.setStatus({ code: 2, message: String(error) });
      throw error;
    } finally {
      span.end();
    }
  }
  /**
   * Retrieves a thread by its ID
   *
   * @param threadId - The ID of the thread to retrieve
   * @returns Thread information or undefined if not found
   */
  getThread(threadId) {
    const span = createAISpan("thread.get", { threadId });
    try {
      const thread = this.threads.get(threadId);
      logger$m.info("Get thread", { threadId, found: !!thread });
      span.setStatus({ code: 1 });
      return thread;
    } catch (error) {
      logger$m.error("Failed to get thread", { error });
      span.setStatus({ code: 2, message: String(error) });
      return void 0;
    } finally {
      span.end();
    }
  }
  /**
   * Gets all threads associated with a resource ID
   *
   * @param resourceId - The resource ID to look up threads for
   * @returns Array of thread information objects
   */
  getThreadsByResource(resourceId) {
    const span = createAISpan("thread.getByResource", { resourceId });
    try {
      const threadIds = this.resourceThreads.get(resourceId) || /* @__PURE__ */ new Set();
      const threads = Array.from(threadIds).map((id) => this.threads.get(id)).filter((thread) => thread !== void 0);
      logger$m.info("Get threads by resource", { resourceId, count: threads.length });
      span.setStatus({ code: 1 });
      return threads;
    } catch (error) {
      logger$m.error("Failed to get threads by resource", { error });
      span.setStatus({ code: 2, message: String(error) });
      return [];
    } finally {
      span.end();
    }
  }
  /**
   * Gets the most recent thread for a resource
   *
   * @param resourceId - The resource ID to find the most recent thread for
   * @returns Most recent thread information or undefined if none exists
   */
  getMostRecentThread(resourceId) {
    const span = createAISpan("thread.getMostRecent", { resourceId });
    try {
      const threads = this.getThreadsByResource(resourceId);
      if (threads.length === 0) {
        logger$m.info("No threads found for resource", { resourceId });
        span.setStatus({ code: 1 });
        return void 0;
      }
      const mostRecent = threads.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())[0];
      logger$m.info("Most recent thread", { resourceId, threadId: mostRecent.id });
      span.setStatus({ code: 1 });
      return mostRecent;
    } catch (error) {
      logger$m.error("Failed to get most recent thread", { error });
      span.setStatus({ code: 2, message: String(error) });
      return void 0;
    } finally {
      span.end();
    }
  }
  /**
   * Creates or retrieves a thread for a resource ID
   *
   * @param resourceId - The resource ID to get or create a thread for
   * @param metadata - Optional metadata for the thread if created
   * @returns Thread information with a consistent ID
   */
  async getOrCreateThread(resourceId, metadata) {
    const span = createAISpan("thread.getOrCreate", { resourceId });
    try {
      const existingThread = this.getMostRecentThread(resourceId);
      if (existingThread) {
        logger$m.info("Found existing thread", { resourceId, threadId: existingThread.id });
        span.setStatus({ code: 1 });
        return existingThread;
      }
      logger$m.info("No existing thread, creating new", { resourceId });
      const newThread = await this.createThread({ resourceId, metadata });
      span.setStatus({ code: 1 });
      return newThread;
    } catch (error) {
      logger$m.error("Failed to get or create thread", { error });
      span.setStatus({ code: 2, message: String(error) });
      throw error;
    } finally {
      span.end();
    }
  }
  /**
   * Mark a thread as read (updates lastReadAt)
   * @param threadId - The ID of the thread to mark as read
   * @param date - Optional date (defaults to now)
   */
  markThreadAsRead(threadId, date = /* @__PURE__ */ new Date()) {
    const span = createAISpan("thread.markAsRead", { threadId });
    try {
      this.threadReadStatus.set(threadId, date);
      const thread = this.threads.get(threadId);
      if (thread) {
        thread.lastReadAt = date;
        logger$m.info("Marked thread as read", { threadId, date });
      }
      span.setStatus({ code: 1 });
    } catch (error) {
      logger$m.error("Failed to mark thread as read", { error });
      span.setStatus({ code: 2, message: String(error) });
    } finally {
      span.end();
    }
  }
  /**
   * Get unread threads for a resource (threads never read or with new activity)
   * @param resourceId - The resource ID to check
   * @returns Array of unread ThreadInfo
   */
  getUnreadThreadsByResource(resourceId) {
    const span = createAISpan("thread.getUnreadByResource", { resourceId });
    try {
      const threads = this.getThreadsByResource(resourceId);
      const unread = threads.filter((thread) => {
        const lastRead = this.threadReadStatus.get(thread.id);
        return !lastRead || thread.createdAt > lastRead;
      });
      logger$m.info("Get unread threads by resource", { resourceId, count: unread.length });
      span.setStatus({ code: 1 });
      return unread;
    } catch (error) {
      logger$m.error("Failed to get unread threads by resource", { error });
      span.setStatus({ code: 2, message: String(error) });
      return [];
    } finally {
      span.end();
    }
  }
}
const threadManager = new ThreadManager();

const getEnvVar = (name, fallback = "") => {
  const value = process.env[name];
  if (!value && !fallback) {
    console.warn(`Environment variable ${name} not set`);
  }
  return value || fallback;
};
const getStorage = () => {
  try {
    const dbUrl = getEnvVar("TURSO_DATABASE_URL", "file:rl-feedback.db");
    const authToken = getEnvVar("TURSO_DATABASE_KEY", "");
    return new LibSQLStore({
      config: {
        url: dbUrl,
        authToken
      }
    });
  } catch (error) {
    console.error("Error initializing LibSQLStore:", error);
    return new LibSQLStore({
      config: {
        url: ":memory:"
      }
    });
  }
};
const memoryInstance = new Memory({
  storage: getStorage()
});
const collectFeedbackTool = createTool({
  id: "collect-feedback",
  description: "Collects user or system feedback for reinforcement learning",
  inputSchema: z.object({
    agentId: z.string().describe("ID of the agent being evaluated"),
    interactionId: z.string().describe("Unique identifier for the interaction"),
    feedback: z.object({
      type: z.enum([
        "explicit" /* EXPLICIT */,
        "implicit" /* IMPLICIT */,
        "self_critique" /* SELF_CRITIQUE */
      ]).describe("Source of the feedback"),
      metrics: z.object({
        quality: z.number().min(1).max(10).describe("Overall quality score (1-10)"),
        accuracy: z.number().min(1).max(10).optional().describe("Accuracy of information (1-10)"),
        relevance: z.number().min(1).max(10).optional().describe("Relevance to user request (1-10)"),
        helpfulness: z.number().min(1).max(10).optional().describe("Helpfulness of the response (1-10)"),
        latencyMs: z.number().optional().describe("Time taken to respond (ms)"),
        comment: z.string().optional().describe("Comment about the response")
      }),
      inputContext: z.string().optional().describe("User input that triggered the response"),
      outputResponse: z.string().optional().describe("Agent's response being evaluated")
    })
  }),
  outputSchema: z.object({
    success: z.boolean(),
    feedbackId: z.string().optional(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("rlFeedback.collectFeedback", { tool: "collect-feedback" });
    const startTime = performance.now();
    const runId = await createLangSmithRun("collect-feedback", [
      "rl",
      "feedback"
    ]);
    try {
      const feedbackId = `feedback_${context.agentId}_${Date.now()}`;
      const threadId = `rl_feedback_${context.agentId}`;
      try {
        await memoryInstance.getThreadById({ threadId });
      } catch (e) {
        await memoryInstance.createThread({
          resourceId: context.agentId,
          threadId,
          title: `RL Feedback for Agent ${context.agentId}`,
          metadata: {
            type: "rl_feedback_thread"
          }
        });
      }
      const feedbackData = {
        interactionId: context.interactionId,
        feedbackType: context.feedback.type,
        metrics: context.feedback.metrics,
        context: context.feedback.inputContext || "",
        response: context.feedback.outputResponse || "",
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      };
      const messageContent = JSON.stringify({
        ...feedbackData,
        feedbackId,
        type: "rl_feedback",
        metrics: context.feedback.metrics
      });
      await memoryInstance.addMessage({
        threadId,
        resourceId: context.agentId,
        // Add the resourceId
        role: "assistant",
        // Changed from "system" to "assistant" as Mastra only supports "user" or "assistant"
        content: messageContent,
        type: "text"
      });
      threadManager.markThreadAsRead(threadId);
      await trackFeedback(runId, {
        score: context.feedback.metrics.quality / 10,
        // Normalize to 0-1
        comment: context.feedback.metrics.comment,
        key: `${context.feedback.type}_feedback`,
        value: {
          metrics: context.feedback.metrics,
          agentId: context.agentId
        }
      });
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      return {
        success: true,
        feedbackId
      };
    } catch (error) {
      console.error("Error collecting feedback:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error",
        key: "feedback_collection_failure"
      });
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error collecting feedback"
      };
    }
  }
});
const analyzeFeedbackTool = createTool({
  id: "analyze-feedback",
  description: "Analyzes collected feedback to derive insights for agent improvement",
  inputSchema: z.object({
    agentId: z.string().describe("ID of the agent to analyze feedback for"),
    startDate: z.string().optional().describe("Start date for feedback analysis (ISO format)"),
    endDate: z.string().optional().describe("End date for feedback analysis (ISO format)"),
    metricName: z.string().optional().describe("Specific metric to analyze"),
    limit: z.number().optional().default(100).describe("Maximum number of feedback items to analyze")
  }),
  outputSchema: z.object({
    insights: z.array(
      z.object({
        metric: z.string(),
        averageScore: z.number(),
        trend: z.string(),
        improvementSuggestions: z.array(z.string())
      })
    ),
    sampleSize: z.number(),
    timeRange: z.object({
      start: z.string(),
      end: z.string()
    })
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("rlFeedback.analyzeFeedback", { tool: "analyze-feedback" });
    const startTime = performance.now();
    const runId = await createLangSmithRun("analyze-feedback", [
      "rl",
      "analysis"
    ]);
    try {
      const startDate = context.startDate ? new Date(context.startDate) : /* @__PURE__ */ new Date(0);
      const endDate = context.endDate ? new Date(context.endDate) : /* @__PURE__ */ new Date();
      const sampleFeedback = generateSampleFeedback(
        context.agentId,
        startDate,
        endDate,
        context.limit || 100
      );
      const model = createVertexModel("models/gemini-2.0-pro");
      const metrics = aggregateMetrics(sampleFeedback);
      const result = await generateText({
        model,
        messages: [
          { role: "user", content: `Analyze the following performance metrics for an AI agent and provide insights:

${JSON.stringify(metrics, null, 2)}

For each metric, provide:
1. The current average score
2. The trend (improving, declining, stable)
3. 2-3 specific suggestions for improvement

Return ONLY a valid JSON array with this structure:
[
  {
    "metric": "quality",
    "averageScore": 7.5,
    "trend": "improving",
    "improvementSuggestions": ["suggestion 1", "suggestion 2"]
  },
  ...
]` }
        ]
      });
      const insightsText = result.text;
      let insights = [];
      try {
        const jsonMatch = insightsText.match(/\[\s*\{[\s\S]*\}\s*\]/);
        if (jsonMatch) {
          insights = JSON.parse(jsonMatch[0]);
        }
      } catch (jsonError) {
        console.error("Error parsing insights result:", jsonError);
        insights = metrics.map((m) => ({
          metric: m.name,
          averageScore: m.average,
          trend: determineTrend(m.values),
          improvementSuggestions: [
            "Improve prompt clarity and specificity",
            "Enhance error handling and edge cases"
          ]
        }));
      }
      await trackFeedback(runId, {
        score: 1,
        comment: `Successfully analyzed ${sampleFeedback.length} feedback entries`,
        key: "feedback_analysis_success"
      });
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      return {
        insights,
        sampleSize: sampleFeedback.length,
        timeRange: {
          start: startDate.toISOString(),
          end: endDate.toISOString()
        }
      };
    } catch (error) {
      console.error("Error analyzing feedback:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error",
        key: "feedback_analysis_failure"
      });
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return {
        insights: [],
        sampleSize: 0,
        timeRange: {
          start: context.startDate || (/* @__PURE__ */ new Date(0)).toISOString(),
          end: context.endDate || (/* @__PURE__ */ new Date()).toISOString()
        }
      };
    }
  }
});
const applyRLInsightsTool = createTool({
  id: "apply-rl-insights",
  description: "Applies reinforcement learning insights to improve agent performance",
  inputSchema: z.object({
    agentId: z.string().describe("ID of the agent to improve"),
    insights: z.array(
      z.object({
        metric: z.string(),
        averageScore: z.number(),
        trend: z.string(),
        improvementSuggestions: z.array(z.string())
      })
    ).describe("Insights derived from feedback analysis"),
    currentInstructions: z.string().describe("Current agent instructions")
  }),
  outputSchema: z.object({
    success: z.boolean(),
    improvedInstructions: z.string(),
    changes: z.array(
      z.object({
        metric: z.string(),
        change: z.string()
      })
    ),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("rlFeedback.applyRLInsights", { tool: "apply-rl-insights" });
    const startTime = performance.now();
    const runId = await createLangSmithRun("apply-rl-insights", [
      "rl",
      "improvement"
    ]);
    try {
      const model = createVertexModel("models/gemini-2.0-pro");
      const result = await generateText({
        model,
        messages: [
          { role: "user", content: `You are an AI instruction optimizer. Your task is to improve these agent instructions:

CURRENT INSTRUCTIONS:
${context.currentInstructions}

Based on these performance insights:
${JSON.stringify(context.insights, null, 2)}

Provide improved instructions that address the issues identified in the insights.
The new instructions should maintain the original intent and style while enhancing areas
that need improvement according to feedback.

IMPROVED INSTRUCTIONS:` }
        ]
      });
      const improvedInstructions = result.text;
      const changeResult = await generateText({
        model,
        messages: [
          { role: "user", content: `Summarize the key changes made to these instructions:

ORIGINAL:
${context.currentInstructions}

IMPROVED:
${improvedInstructions}

For each of these metrics that was improved, describe the specific change made:
${context.insights.map((i) => i.metric).join(", ")}

Return ONLY a valid JSON array with this structure:
[
  {
    "metric": "quality",
    "change": "Added more specific guidance on response formatting"
  },
  ...
]` }
        ]
      });
      const changesText = changeResult.text;
      let changes = [];
      try {
        const jsonMatch = changesText.match(/\[\s*\{[\s\S]*\}\s*\]/);
        if (jsonMatch) {
          changes = JSON.parse(jsonMatch[0]);
        }
      } catch (jsonError) {
        console.error("Error parsing changes result:", jsonError);
        changes = context.insights.map((insight) => ({
          metric: insight.metric,
          change: "Improved instructions based on feedback"
        }));
      }
      await trackFeedback(runId, {
        score: 1,
        comment: `Successfully applied insights to improve agent instructions`,
        key: "rl_application_success",
        value: { changeCount: changes.length }
      });
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      return {
        success: true,
        improvedInstructions,
        changes
      };
    } catch (error) {
      console.error("Error applying RL insights:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error",
        key: "rl_application_failure"
      });
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return {
        success: false,
        improvedInstructions: context.currentInstructions,
        changes: [],
        error: error instanceof Error ? error.message : "Unknown error applying insights"
      };
    }
  }
});
function generateSampleFeedback(agentId, startDate, endDate, count) {
  const feedback = [];
  const timeRange = endDate.getTime() - startDate.getTime();
  for (let i = 0; i < count; i++) {
    const timestamp = new Date(startDate.getTime() + Math.random() * timeRange);
    feedback.push({
      agentId,
      interactionId: `interaction_${i}_${Date.now()}`,
      feedbackType: Math.random() > 0.7 ? "explicit" /* EXPLICIT */ : Math.random() > 0.5 ? "implicit" /* IMPLICIT */ : "self_critique" /* SELF_CRITIQUE */,
      metrics: {
        quality: Math.floor(Math.random() * 10) + 1,
        accuracy: Math.floor(Math.random() * 10) + 1,
        relevance: Math.floor(Math.random() * 10) + 1,
        helpfulness: Math.floor(Math.random() * 10) + 1,
        latencyMs: Math.floor(Math.random() * 2e3) + 100
      },
      timestamp: timestamp.toISOString()
    });
  }
  feedback.sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  return feedback;
}
function aggregateMetrics(feedback) {
  const metrics = {
    quality: { total: 0, count: 0, values: [] },
    accuracy: { total: 0, count: 0, values: [] },
    relevance: { total: 0, count: 0, values: [] },
    helpfulness: { total: 0, count: 0, values: [] }
  };
  for (const entry of feedback) {
    for (const [metricName, metricValue] of Object.entries(entry.metrics)) {
      if (typeof metricValue !== "number") continue;
      if (!metrics[metricName]) {
        metrics[metricName] = { total: 0, count: 0, values: [] };
      }
      metrics[metricName].total += metricValue;
      metrics[metricName].count++;
      metrics[metricName].values.push({
        value: metricValue,
        timestamp: entry.timestamp
      });
    }
  }
  return Object.entries(metrics).map(([name, data]) => ({
    name,
    average: data.count > 0 ? data.total / data.count : 0,
    values: data.values
  }));
}
function determineTrend(values) {
  if (values.length < 2) return "stable";
  const sorted = [...values].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const halfIndex = Math.floor(sorted.length / 2);
  const firstHalf = sorted.slice(0, halfIndex);
  const secondHalf = sorted.slice(halfIndex);
  const firstHalfAvg = firstHalf.reduce((sum, v) => sum + v.value, 0) / firstHalf.length;
  const secondHalfAvg = secondHalf.reduce((sum, v) => sum + v.value, 0) / secondHalf.length;
  const difference = secondHalfAvg - firstHalfAvg;
  if (difference > 0.5) return "improving";
  if (difference < -0.5) return "declining";
  return "stable";
}

const defaultMemoryConfig = {
  lastMessages: 50,
  semanticRecall: {
    topK: 5,
    messageRange: {
      before: 2,
      after: 1
    }
  },
  workingMemory: {
    enabled: true,
    type: "text-stream"
  },
  threads: {
    generateTitle: true
  }
};
function createMemory(options = defaultMemoryConfig) {
  const storage = new LibSQLStore({
    config: {
      url: process.env.DATABASE_URL || "file:.mastra/mastra.db"
    }
  });
  const vector = new LibSQLVector({
    connectionUrl: process.env.DATABASE_URL || "file:.mastra/mastra.db"
  });
  return new Memory({
    storage,
    vector,
    options
  });
}
const sharedMemory = createMemory();

const calculateRewardTool = createTool({
  id: "calculate-reward",
  description: "Calculates a reward value based on agent state and action",
  inputSchema: z.object({
    agentId: z.string().describe("ID of the agent being evaluated"),
    episodeId: z.string().describe("Unique identifier for the current episode/interaction"),
    state: z.record(z.unknown()).describe("Current state representation"),
    action: z.string().describe("Action taken by the agent"),
    context: z.record(z.unknown()).optional().describe("Additional context about the state-action"),
    rewardFunctionId: z.string().optional().describe("Specific reward function ID to use"),
    stepNumber: z.number().optional().default(0).describe("Step number in the episode"),
    isTerminal: z.boolean().optional().default(false).describe("Whether this is the terminal state")
  }),
  outputSchema: z.object({
    reward: z.number(),
    cumulativeReward: z.number().optional(),
    normalizedReward: z.number().optional(),
    breakdown: z.record(z.number()).optional(),
    success: z.boolean(),
    rewardId: z.string().optional(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("rl.calculateReward", {
      agentId: context.agentId,
      episodeId: context.episodeId,
      stepNumber: context.stepNumber || 0
    });
    const startTime = performance.now();
    try {
      const stateAction = {
        state: context.state,
        action: context.action,
        context: context.context
      };
      const { reward, breakdown } = await calculateStateActionReward(
        stateAction);
      const rewardId = `reward_${context.agentId}_${Date.now()}`;
      let cumulativeReward = reward;
      const episodeThreadId = `rl_episode_${context.agentId}_${context.episodeId}`;
      try {
        await threadManager.getOrCreateThread(episodeThreadId);
        const { messages } = await sharedMemory.query({
          threadId: episodeThreadId,
          selectBy: { last: 1 }
          // Get most recent message
        });
        if (messages.length > 0) {
          try {
            const content = typeof messages[0].content === "string" ? messages[0].content : JSON.stringify(messages[0].content);
            const previousRecord = JSON.parse(content);
            cumulativeReward += previousRecord.cumulativeReward;
          } catch (parseError) {
            console.warn("Error parsing previous reward record:", parseError);
          }
        }
      } catch (error) {
        console.warn("Error retrieving previous rewards:", error);
      }
      const rewardRecord = {
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        agentId: context.agentId,
        episodeId: context.episodeId,
        stateAction,
        reward,
        cumulativeReward,
        stepNumber: context.stepNumber || 0,
        isTerminal: context.isTerminal || false,
        metadata: {
          rewardFunctionId: context.rewardFunctionId,
          breakdown
        }
      };
      const messageContent = JSON.stringify({
        ...rewardRecord,
        rewardId,
        type: "rl_reward",
        reward,
        cumulativeReward,
        stepNumber: context.stepNumber || 0,
        isTerminal: context.isTerminal || false
      });
      await sharedMemory.addMessage({
        threadId: episodeThreadId,
        resourceId: context.agentId,
        // Add the resourceId
        role: "assistant",
        content: messageContent,
        type: "text"
      });
      const result = {
        reward,
        cumulativeReward,
        normalizedReward: normalizeReward(reward),
        breakdown,
        success: true,
        rewardId
      };
      signoz.recordMetrics(span, {
        latencyMs: performance.now() - startTime,
        status: "success"
      });
      span.end();
      return result;
    } catch (error) {
      signoz.recordMetrics(span, {
        latencyMs: performance.now() - startTime,
        status: "error",
        errorMessage: error instanceof Error ? error.message : String(error)
      });
      span.end();
      return {
        reward: 0,
        success: false,
        error: error instanceof Error ? error.message : "Unknown error calculating reward"
      };
    }
  }
});
const defineRewardFunctionTool = createTool({
  id: "define-reward-function",
  description: "Creates or updates a custom reward function definition",
  inputSchema: z.object({
    id: z.string().describe("Unique identifier for the reward function"),
    name: z.string().describe("Human-readable name for the reward function"),
    description: z.string().describe("Description of what the reward function measures"),
    rewardType: z.enum([
      "scalar" /* SCALAR */,
      "vector" /* VECTOR */,
      "binary" /* BINARY */,
      "human" /* HUMAN */
    ]).describe("Type of reward signal"),
    formula: z.string().describe("Formula or rule description for calculating the reward"),
    components: z.array(
      z.object({
        name: z.string().describe("Name of this reward component"),
        weight: z.number().describe("Weight of this component in the overall reward"),
        description: z.string().describe("Description of what this component measures")
      })
    ).optional().describe("Individual components that make up the reward"),
    normalize: z.boolean().optional().default(true).describe("Whether to normalize rewards to [-1,1]"),
    discountFactor: z.number().optional().default(0.9).describe("Discount factor for future rewards (gamma)")
  }),
  outputSchema: z.object({
    success: z.boolean(),
    functionId: z.string().optional(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("rl.defineRewardFunction", {
      functionId: context.id,
      functionName: context.name
    });
    const startTime = performance.now();
    try {
      const rewardFunction = {
        id: context.id,
        name: context.name,
        description: context.description,
        rewardType: context.rewardType,
        normalize: context.normalize,
        discountFactor: context.discountFactor,
        formula: context.formula,
        components: context.components
      };
      const rewardFunctionThreadId = `rl_reward_functions`;
      threadManager.getOrCreateThread(rewardFunctionThreadId);
      const messageContent = JSON.stringify({
        ...rewardFunction,
        type: "rl_reward_function",
        functionId: context.id,
        functionName: context.name
      });
      await sharedMemory.addMessage({
        threadId: rewardFunctionThreadId,
        resourceId: "system",
        // Add the resourceId used when creating the thread
        role: "assistant",
        content: messageContent,
        type: "text"
      });
      const result = {
        success: true,
        functionId: context.id
      };
      signoz.recordMetrics(span, {
        latencyMs: performance.now() - startTime,
        status: "success"
      });
      span.end();
      return result;
    } catch (error) {
      signoz.recordMetrics(span, {
        latencyMs: performance.now() - startTime,
        status: "error",
        errorMessage: error instanceof Error ? error.message : String(error)
      });
      span.end();
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error defining reward function"
      };
    }
  }
});
const optimizePolicyTool = createTool({
  id: "optimize-policy",
  description: "Analyzes reward data to suggest policy improvements",
  inputSchema: z.object({
    agentId: z.string().describe("ID of the agent to optimize"),
    episodeIds: z.array(z.string()).optional().describe("Specific episodes to analyze"),
    startDate: z.string().optional().describe("Start date for analysis period (ISO format)"),
    endDate: z.string().optional().describe("End date for analysis period (ISO format)"),
    optimizationTarget: z.string().optional().describe("Specific aspect to optimize (e.g., 'accuracy', 'efficiency')"),
    currentPolicy: z.string().optional().describe("Current policy description or instructions")
  }),
  outputSchema: z.object({
    success: z.boolean(),
    insights: z.array(
      z.object({
        aspect: z.string(),
        observation: z.string(),
        suggestion: z.string(),
        confidence: z.number()
      })
    ).optional(),
    improvedPolicy: z.string().optional(),
    policyChanges: z.array(
      z.object({
        type: z.string(),
        description: z.string(),
        rationale: z.string()
      })
    ).optional(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("rl.optimizePolicy", {
      agentId: context.agentId
    });
    const startTime = performance.now();
    try {
      const memoryAdapter = sharedMemory;
      const rewardRecords = await retrieveAgentRewards(
        memoryAdapter,
        context.agentId);
      if (!rewardRecords || rewardRecords.length === 0) {
        const result2 = {
          success: false,
          error: "No reward data found for the specified agent and time period"
        };
        signoz.recordMetrics(span, {
          latencyMs: performance.now() - startTime,
          status: "error",
          errorMessage: result2.error
        });
        span.end();
        return result2;
      }
      const result = {
        success: true,
        insights: [],
        improvedPolicy: "",
        policyChanges: []
      };
      signoz.recordMetrics(span, {
        latencyMs: performance.now() - startTime,
        status: "success"
      });
      span.end();
      return result;
    } catch (error) {
      signoz.recordMetrics(span, {
        latencyMs: performance.now() - startTime,
        status: "error",
        errorMessage: error instanceof Error ? error.message : String(error)
      });
      span.end();
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error optimizing policy"
      };
    }
  }
});
async function calculateStateActionReward(stateAction, rewardFunctionId) {
  try {
    const breakdown = {};
    let totalReward = 0;
    if (stateAction.context?.taskCompleted === true) {
      const completionReward = 10;
      breakdown.taskCompletion = completionReward;
      totalReward += completionReward;
    }
    if (typeof stateAction.context?.latencyMs === "number") {
      const latency = stateAction.context.latencyMs;
      const efficiencyReward = Math.max(-5, -latency / 1e3);
      breakdown.efficiency = efficiencyReward;
      totalReward += efficiencyReward;
    }
    if (typeof stateAction.context?.accuracy === "number") {
      const accuracy = stateAction.context.accuracy;
      const accuracyReward = accuracy * 5;
      breakdown.accuracy = accuracyReward;
      totalReward += accuracyReward;
    }
    const explorationReward = 0.1;
    breakdown.exploration = explorationReward;
    totalReward += explorationReward;
    return { reward: totalReward, breakdown };
  } catch (error) {
    console.error("Error calculating reward:", error);
    return { reward: 0 };
  }
}
function normalizeReward(reward) {
  return Math.tanh(reward / 10);
}
async function retrieveAgentRewards(storage, agentId, episodeIds, startDate, endDate) {
  return generateSampleRewardRecords(agentId, 5, 10);
}
function generateSampleRewardRecords(agentId, episodeCount, actionsPerEpisode) {
  const records = [];
  for (let e = 0; e < episodeCount; e++) {
    const episodeId = `episode_${e}_${Date.now()}`;
    let cumulativeReward = 0;
    for (let a = 0; a < actionsPerEpisode; a++) {
      const isTerminal = a === actionsPerEpisode - 1;
      const reward = Math.random() * 2 - 0.5;
      cumulativeReward += reward;
      const timestamp = new Date(
        Date.now() - (episodeCount - e) * 864e5 - (actionsPerEpisode - a) * 6e4
      ).toISOString();
      records.push({
        timestamp,
        agentId,
        episodeId,
        stateAction: {
          state: { position: a, context: `State in episode ${e}` },
          action: `action_${a % 3}`,
          context: {
            taskCompleted: isTerminal,
            accuracy: 0.5 + Math.random() * 0.5,
            latencyMs: 100 + Math.random() * 500
          }
        },
        reward,
        cumulativeReward,
        stepNumber: a,
        isTerminal,
        metadata: {
          rewardFunctionId: "default"
        }
      });
    }
  }
  return records.sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
}

const analyzeContentTool = createTool({
  id: "analyze-content",
  description: "Analyzes content to extract insights and patterns.",
  inputSchema: z.object({
    content: z.string().min(1, "Content must not be empty").describe("Content to analyze.")
  }),
  outputSchema: z.object({
    analysis: z.unknown().describe("The result of the analysis.")
  }),
  execute: async ({ context }) => {
    try {
      const wordCount = context.content.trim().split(/\s+/).length;
      const charCount = context.content.length;
      return { analysis: { wordCount, charCount } };
    } catch (error) {
      throw new Error(`analyzeContentTool execution failed: ${error.message}`);
    }
  }
});
const formatContentTool = createTool({
  id: "format-content",
  description: "Formats content into a structured and clean format.",
  inputSchema: z.object({
    content: z.string().min(1, "Content must not be empty").describe("Content to format.")
  }),
  outputSchema: z.object({
    formattedContent: z.string().describe("The formatted content.")
  }),
  execute: async ({ context }) => {
    try {
      const formattedContent = context.content.trim().replace(/\s+/g, " ");
      return { formattedContent };
    } catch (error) {
      throw new Error(`formatContentTool execution failed: ${error.message}`);
    }
  }
});

const logger$l = createLogger({ name: "document-tools", level: process.env.LOG_LEVEL === "debug" ? "debug" : "info" });
const documentRepository = [
  {
    id: "1",
    title: "Introduction to Mastra",
    content: "Mastra is a powerful framework for building document-driven applications."
  },
  {
    id: "2",
    title: "Advanced Topics",
    content: "This document covers advanced topics in document search and embedding."
  },
  {
    id: "3",
    title: "Getting Started",
    content: "Learn how to quickly get started with our platform using concise examples."
  }
];
const searchDocumentsTool = createTool({
  id: "search-documents",
  description: "Searches for documents in repositories based on a query.",
  inputSchema: z.object({
    query: z.string().min(1, "Query cannot be empty").describe("The search query string.")
  }),
  outputSchema: z.object({
    documents: z.array(
      z.object({
        id: z.string().describe("Document id"),
        title: z.string().describe("Document title"),
        content: z.string().describe("Document content")
      })
    ).describe("Array of found documents.")
  }),
  execute: async ({ context }) => {
    try {
      const { query } = context;
      const lowerQuery = query.toLowerCase();
      const foundDocuments = documentRepository.filter(
        (doc) => doc.title.toLowerCase().includes(lowerQuery) || doc.content.toLowerCase().includes(lowerQuery)
      );
      return { documents: foundDocuments };
    } catch (error) {
      throw new Error(`searchDocumentsTool execution failed: ${error.message}`);
    }
  }
});
const embedDocumentTool = createTool({
  id: "embed-document",
  description: "Generates an embedding vector for a document.",
  inputSchema: z.object({
    document: z.string().min(1, "Document content must not be empty").describe("The document content to embed.")
  }),
  outputSchema: z.object({
    embedding: z.array(z.number()).describe("The embedding vector.")
  }),
  execute: async ({ context }) => {
    try {
      const embedding = Array.from(context.document).map((char) => char.charCodeAt(0));
      return { embedding };
    } catch (error) {
      throw new Error(`embedDocumentTool execution failed: ${error.message}`);
    }
  }
});
const docxReaderTool = createTool({
  id: "docx-reader",
  description: "Reads and extracts text from a DOCX (Word) file.",
  inputSchema: z.object({
    filePath: z.string().describe("Path to the DOCX file.")
  }),
  outputSchema: z.object({
    text: z.string().describe("Extracted text from the DOCX file.")
  }),
  execute: async ({ context }) => {
    const { filePath } = context;
    if (!await fs.exists(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    const buffer = await fs.readFile(filePath);
    const result = await mammoth.extractRawText({ buffer });
    return { text: result.value };
  }
});
const csvReaderTool = createTool({
  id: "csv-reader",
  description: "Reads and parses a CSV file.",
  inputSchema: z.object({
    filePath: z.string().describe("Path to the CSV file.")
  }),
  outputSchema: z.object({
    data: z.array(z.record(z.string(), z.any())).describe("Parsed CSV data as array of objects.")
  }),
  execute: async ({ context }) => {
    const { filePath } = context;
    if (!await fs.exists(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    const csvString = await fs.readFile(filePath, "utf8");
    const result = Papa.parse(csvString, { header: true });
    return { data: result.data };
  }
});
const jsonReaderTool = createTool({
  id: "json-reader",
  description: "Reads and parses a JSON file.",
  inputSchema: z.object({
    filePath: z.string().describe("Path to the JSON file.")
  }),
  outputSchema: z.object({
    data: z.any().describe("Parsed JSON data."),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const { filePath } = context;
    try {
      if (!await fs.exists(filePath)) {
        return { data: null, error: `File not found: ${filePath}` };
      }
      const jsonString = await fs.readFile(filePath, "utf8");
      const data = JSON.parse(jsonString);
      return { data };
    } catch (error) {
      return { data: null, error: error.message };
    }
  }
});
const extractHtmlTextTool = createTool({
  id: "extract-html-text",
  description: "Extracts visible text from HTML using cheerio, with tracing and logging.",
  inputSchema: z.object({
    html: z.string().describe("HTML content to extract text from."),
    url: z.string().url().optional().describe("Optional: URL to fetch HTML from.")
  }),
  outputSchema: z.object({
    text: z.string().describe("Extracted visible text from the HTML body.")
  }),
  execute: async ({ context }) => {
    const span = createAISpan("extractHtmlTextTool.execute");
    try {
      let html = context.html;
      if (!html && context.url) {
        logger$l.info(`Fetching HTML from URL: ${context.url}`);
        const response = await fetch(context.url);
        if (!response.ok) throw new Error(`Failed to fetch URL: ${response.statusText}`);
        html = await response.text();
      }
      if (!html) throw new Error("No HTML content provided or fetched.");
      logger$l.info("Extracting text from HTML using cheerio");
      const $ = cheerio.load(html);
      const text = $("body").text();
      recordMetrics(span, { status: "success" });
      return { text };
    } catch (error) {
      logger$l.error(`extractHtmlTextTool error: ${error instanceof Error ? error.message : String(error)}`);
      recordMetrics(span, { status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      throw error;
    } finally {
      span.end();
    }
  }
});

function createLlamaIndexTools(...aiFunctionLikeTools) {
  const fns = new AIFunctionSet(aiFunctionLikeTools);
  return fns.map(
    (fn) => FunctionTool.from(fn.execute, {
      name: fn.spec.name,
      description: fn.spec.description,
      // TODO: Investigate types here
      parameters: asZodOrJsonSchema(fn.inputSchema)
    })
  );
}

function hasProp(target, key) {
  return Boolean(target) && Object.prototype.hasOwnProperty.call(target, key);
}
function getProp(target, paths, defaultValue = void 0) {
  let value = target;
  if (!value) {
    return void 0;
  }
  for (const key of paths) {
    if (!hasProp(value, key)) {
      return defaultValue;
    }
    value = value[key];
  }
  return value;
}
function castArray(arr) {
  const result = Array.isArray(arr) ? arr : [arr];
  return result;
}

var __create$4 = Object.create;
var __defProp$4 = Object.defineProperty;
var __getOwnPropDesc$4 = Object.getOwnPropertyDescriptor;
var __knownSymbol$4 = (name, symbol) => (symbol = Symbol[name]) ? symbol : Symbol.for("Symbol." + name);
var __typeError$4 = (msg) => {
  throw TypeError(msg);
};
var __defNormalProp$4 = (obj, key, value) => key in obj ? __defProp$4(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __decoratorStart$4 = (base) => [, , , __create$4(base?.[__knownSymbol$4("metadata")] ?? null)];
var __decoratorStrings$4 = ["class", "method", "getter", "setter", "accessor", "field", "value", "get", "set"];
var __expectFn$4 = (fn) => fn !== void 0 && typeof fn !== "function" ? __typeError$4("Function expected") : fn;
var __decoratorContext$4 = (kind, name, done, metadata, fns) => ({ kind: __decoratorStrings$4[kind], name, metadata, addInitializer: (fn) => done._ ? __typeError$4("Already initialized") : fns.push(__expectFn$4(fn || null)) });
var __decoratorMetadata$4 = (array, target) => __defNormalProp$4(target, __knownSymbol$4("metadata"), array[3]);
var __runInitializers$4 = (array, flags, self, value) => {
  for (var i = 0, fns = array[flags >> 1], n = fns && fns.length; i < n; i++) fns[i].call(self) ;
  return value;
};
var __decorateElement$4 = (array, flags, name, decorators, target, extra) => {
  var it, done, ctx, access, k = flags & 7, s = false, p = false;
  var j = 2 , key = __decoratorStrings$4[k + 5];
  var extraInitializers = array[j] || (array[j] = []);
  var desc = ((target = target.prototype), __getOwnPropDesc$4(target , name));
  for (var i = decorators.length - 1; i >= 0; i--) {
    ctx = __decoratorContext$4(k, name, done = {}, array[3], extraInitializers);
    {
      ctx.static = s, ctx.private = p, access = ctx.access = { has: (x) => name in x };
      access.get = (x) => x[name];
    }
    it = (0, decorators[i])(desc[key]  , ctx), done._ = 1;
    __expectFn$4(it) && (desc[key] = it );
  }
  return desc && __defProp$4(target, name, desc), target;
};
var __publicField$4 = (obj, key, value) => __defNormalProp$4(obj, typeof key !== "symbol" ? key + "" : key, value);
var _arxiv_download_pdf_dec, _arxivPdfUrl_dec, _search_dec$1, _a$4, _init$4;
var arxiv;
((arxiv2) => {
  arxiv2.API_BASE_URL = "https://export.arxiv.org/api";
  arxiv2.SortType = {
    RELEVANCE: "relevance",
    LAST_UPDATED_DATE: "lastUpdatedDate",
    SUBMITTED_DATE: "submittedDate"
  };
  arxiv2.SortOrder = {
    ASCENDING: "ascending",
    DESCENDING: "descending"
  };
  arxiv2.FilterType = {
    ALL: "all",
    TITLE: "title",
    AUTHOR: "author",
    ABSTRACT: "abstract",
    COMMENT: "comment",
    JOURNAL_REFERENCE: "journal_reference",
    SUBJECT_CATEGORY: "subject_category",
    REPORT_NUMBER: "report_number"
  };
  arxiv2.FilterTypeMapping = {
    all: "all",
    title: "ti",
    author: "au",
    abstract: "abs",
    comment: "co",
    journal_reference: "jr",
    subject_category: "cat",
    report_number: "rn"
  };
  arxiv2.Separators = {
    AND: "+AND+",
    OR: "+OR+",
    ANDNOT: "+ANDNOT+"
  };
  arxiv2.extractId = (value) => value.replace("https://arxiv.org/abs/", "").replace("https://arxiv.org/pdf/", "").replace(/v\d$/, "");
  const EntrySchema = z.object({
    field: z.nativeEnum(arxiv2.FilterType).default(arxiv2.FilterType.ALL),
    value: z.string().min(1)
  });
  arxiv2.SearchParamsSchema = z.object({
    ids: z.array(z.string().min(1)).optional(),
    searchQuery: z.union([
      z.string(),
      z.object({
        include: z.array(EntrySchema).nonempty().describe("Filters to include results."),
        exclude: z.array(EntrySchema).optional().describe("Filters to exclude results.")
      })
    ]).optional(),
    start: z.number().int().min(0).default(0),
    maxResults: z.number().int().min(1).max(100).default(5)
  }).describe("Sorting by date is not supported.");
})(arxiv || (arxiv = {}));
class ArXivClient extends (_a$4 = AIFunctionsProvider, _search_dec$1 = [aiFunction({
  name: "arxiv_search",
  description: "Searches for research articles published on arXiv.",
  inputSchema: arxiv.SearchParamsSchema
})], _arxivPdfUrl_dec = [aiFunction({
  name: "arxiv_pdf_url",
  description: "Get the direct PDF URL for a given arXiv ID.",
  inputSchema: z.object({ id: z.string().describe("arXiv identifier, e.g. 2101.00001") })
})], _arxiv_download_pdf_dec = [aiFunction({
  name: "arxiv_download_pdf",
  description: "Download the PDF for a given arXiv ID and save it to disk.",
  inputSchema: z.object({
    id: z.string().describe("arXiv identifier, e.g. 2101.00001"),
    filePath: z.string().describe("Local file path to save the PDF")
  })
})], _a$4) {
  constructor({
    apiBaseUrl = arxiv.API_BASE_URL,
    ky = defaultKy
  }) {
    super();
    __runInitializers$4(_init$4, 5, this);
    __publicField$4(this, "ky");
    __publicField$4(this, "apiBaseUrl");
    this.apiBaseUrl = apiBaseUrl;
    this.ky = ky.extend({
      prefixUrl: this.apiBaseUrl
    });
  }
  async search(queryOrOpts) {
    const opts = typeof queryOrOpts === "string" ? { searchQuery: queryOrOpts } : queryOrOpts;
    if (!opts.ids?.length && !opts.searchQuery) {
      throw new Error(
        `The 'searchQuery' property must be non-empty if the 'ids' property is not provided.`
      );
    }
    const searchParams = sanitizeSearchParams({
      start: opts.start,
      max_results: opts.maxResults,
      id_list: opts.ids?.map(arxiv.extractId),
      search_query: opts.searchQuery ? typeof opts.searchQuery === "string" ? opts.searchQuery : [
        opts.searchQuery.include.map(
          (tag) => `${arxiv.FilterTypeMapping[tag.field]}:${tag.value}`
        ).join(arxiv.Separators.AND),
        (opts.searchQuery.exclude ?? []).map(
          (tag) => `${arxiv.FilterTypeMapping[tag.field]}:${tag.value}`
        ).join(arxiv.Separators.ANDNOT)
      ].filter(Boolean).join(arxiv.Separators.ANDNOT) : void 0,
      sortBy: arxiv.SortType.RELEVANCE,
      sortOrder: arxiv.SortOrder.DESCENDING
    });
    const responseText = await this.ky.get("query", { searchParams }).text();
    const parser = new XMLParser({
      allowBooleanAttributes: true,
      alwaysCreateTextNode: false,
      attributeNamePrefix: "@_",
      attributesGroupName: false,
      cdataPropName: "#cdata",
      ignoreAttributes: true,
      numberParseOptions: { hex: false, leadingZeros: true },
      parseAttributeValue: false,
      parseTagValue: true,
      preserveOrder: false,
      removeNSPrefix: true,
      textNodeName: "#text",
      trimValues: true,
      ignoreDeclaration: true
    });
    const parsedData = parser.parse(responseText);
    let entries = getProp(
      parsedData,
      ["feed", "entry"],
      []
    );
    entries = castArray(entries);
    return {
      totalResults: Math.max(
        getProp(parsedData, ["feed", "totalResults"], 0),
        entries.length
      ),
      startIndex: getProp(parsedData, ["feed", "startIndex"], 0),
      itemsPerPage: getProp(parsedData, ["feed", "itemsPerPage"], 0),
      entries: entries.map(
        (entry) => pruneEmpty({
          id: arxiv.extractId(entry.id),
          url: entry.id,
          title: entry.title,
          summary: entry.summary,
          published: entry.published,
          updated: entry.updated,
          authors: castArray(entry.author).filter(Boolean).map((author) => ({
            name: author.name,
            affiliation: castArray(author.affiliation ?? [])
          })),
          doi: entry.doi,
          comment: entry.comment,
          journalReference: entry.journal_ref,
          primaryCategory: entry.primary_category,
          categories: castArray(entry.category).filter(Boolean),
          links: castArray(entry.link).filter(Boolean)
        })
      )
    };
  }
  async arxivPdfUrl({ id }) {
    return { url: `https://arxiv.org/pdf/${id}.pdf` };
  }
  async arxiv_download_pdf({ id, filePath }) {
    const url = `https://arxiv.org/pdf/${id}.pdf`;
    const response = await this.ky.get(url);
    const buffer = await response.arrayBuffer();
    await fs__default.ensureDir(path.dirname(filePath));
    await fs__default.writeFile(filePath, Buffer.from(buffer));
    return { filePath };
  }
}
_init$4 = __decoratorStart$4(_a$4);
__decorateElement$4(_init$4, 1, "search", _search_dec$1, ArXivClient);
__decorateElement$4(_init$4, 1, "arxivPdfUrl", _arxivPdfUrl_dec, ArXivClient);
__decorateElement$4(_init$4, 1, "arxiv_download_pdf", _arxiv_download_pdf_dec, ArXivClient);
__decoratorMetadata$4(_init$4, ArXivClient);
const ArxivSearchEntrySchema = z.object({
  id: z.string(),
  url: z.string(),
  title: z.string(),
  summary: z.string(),
  published: z.string(),
  updated: z.string(),
  authors: z.array(z.object({
    name: z.string(),
    affiliation: z.array(z.string())
  })),
  doi: z.string().optional(),
  comment: z.string().optional(),
  journalReference: z.string().optional(),
  primaryCategory: z.string().optional(),
  categories: z.array(z.string()),
  links: z.array(z.any())
});
const ArxivSearchOutputSchema = z.object({
  totalResults: z.number(),
  startIndex: z.number(),
  itemsPerPage: z.number(),
  entries: z.array(ArxivSearchEntrySchema)
});
const ArxivPdfUrlOutputSchema = z.object({
  url: z.string().url()
});
const ArxivDownloadPdfOutputSchema = z.object({
  filePath: z.string()
});
function createArxivClient(config = {}) {
  return new ArXivClient(config);
}
function createMastraArxivTools(config = {}) {
  const arxivClient = createArxivClient(config);
  const mastraTools = createMastraTools(arxivClient);
  if (mastraTools.arxiv_search) {
    mastraTools.arxiv_search.outputSchema = ArxivSearchOutputSchema;
  }
  if (mastraTools.arxiv_pdf_url) {
    mastraTools.arxiv_pdf_url.outputSchema = ArxivPdfUrlOutputSchema;
  }
  if (mastraTools.arxiv_download_pdf) {
    mastraTools.arxiv_download_pdf.outputSchema = ArxivDownloadPdfOutputSchema;
  }
  return mastraTools;
}

var __create$3 = Object.create;
var __defProp$3 = Object.defineProperty;
var __getOwnPropDesc$3 = Object.getOwnPropertyDescriptor;
var __knownSymbol$3 = (name, symbol) => (symbol = Symbol[name]) ? symbol : Symbol.for("Symbol." + name);
var __typeError$3 = (msg) => {
  throw TypeError(msg);
};
var __defNormalProp$3 = (obj, key, value) => key in obj ? __defProp$3(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __decoratorStart$3 = (base) => [, , , __create$3(base?.[__knownSymbol$3("metadata")] ?? null)];
var __decoratorStrings$3 = ["class", "method", "getter", "setter", "accessor", "field", "value", "get", "set"];
var __expectFn$3 = (fn) => fn !== void 0 && typeof fn !== "function" ? __typeError$3("Function expected") : fn;
var __decoratorContext$3 = (kind, name, done, metadata, fns) => ({ kind: __decoratorStrings$3[kind], name, metadata, addInitializer: (fn) => done._ ? __typeError$3("Already initialized") : fns.push(__expectFn$3(fn || null)) });
var __decoratorMetadata$3 = (array, target) => __defNormalProp$3(target, __knownSymbol$3("metadata"), array[3]);
var __runInitializers$3 = (array, flags, self, value) => {
  for (var i = 0, fns = array[flags >> 1], n = fns && fns.length; i < n; i++) fns[i].call(self) ;
  return value;
};
var __decorateElement$3 = (array, flags, name, decorators, target, extra) => {
  var it, done, ctx, access, k = flags & 7, s = false, p = false;
  var j = 2 , key = __decoratorStrings$3[k + 5];
  var extraInitializers = array[j] || (array[j] = []);
  var desc = ((target = target.prototype), __getOwnPropDesc$3(target , name));
  for (var i = decorators.length - 1; i >= 0; i--) {
    ctx = __decoratorContext$3(k, name, done = {}, array[3], extraInitializers);
    {
      ctx.static = s, ctx.private = p, access = ctx.access = { has: (x) => name in x };
      access.get = (x) => x[name];
    }
    it = (0, decorators[i])(desc[key]  , ctx), done._ = 1;
    __expectFn$3(it) && (desc[key] = it );
  }
  return desc && __defProp$3(target, name, desc), target;
};
var __publicField$3 = (obj, key, value) => __defNormalProp$3(obj, typeof key !== "symbol" ? key + "" : key, value);
var _getPageSummary_dec, _search_dec, _a$3, _init$3;
var wikipedia;
((wikipedia2) => {
  wikipedia2.throttle = pThrottle({
    limit: 200,
    interval: 1e3
  });
})(wikipedia || (wikipedia = {}));
const WikipediaThumbnailSchema = z.object({
  mimetype: z.string().optional(),
  size: z.number().int().nullable().optional(),
  width: z.number().int().optional(),
  height: z.number().int().optional(),
  duration: z.number().nullable().optional(),
  url: z.string().url()
}).nullable().optional();
const WikipediaPageResultSchema = z.object({
  id: z.number().int(),
  key: z.string(),
  title: z.string(),
  excerpt: z.string(),
  matched_title: z.string().nullable().optional(),
  description: z.string().nullable().optional(),
  thumbnail: WikipediaThumbnailSchema
});
const WikipediaSearchSchema = z.array(WikipediaPageResultSchema).describe("Schema for the array of Wikipedia search results based on MediaWiki REST API");
const WikipediaImageSchema = z.object({
  source: z.string().url(),
  width: z.number().int(),
  height: z.number().int()
}).optional();
const WikipediaContentUrlsSchema = z.object({
  page: z.string().url(),
  revisions: z.string().url(),
  edit: z.string().url(),
  talk: z.string().url()
}).optional();
const WikipediaSummarySchema = z.object({
  type: z.string().optional(),
  title: z.string(),
  displaytitle: z.string().optional(),
  namespace: z.object({ id: z.number().int(), text: z.string() }).optional(),
  wikibase_item: z.string().optional(),
  titles: z.object({ canonical: z.string(), normalized: z.string(), display: z.string() }).optional(),
  pageid: z.number().int().optional(),
  thumbnail: WikipediaImageSchema,
  originalimage: WikipediaImageSchema,
  lang: z.string().optional(),
  dir: z.string().optional(),
  revision: z.string().optional(),
  tid: z.string().optional(),
  timestamp: z.string().optional(),
  description: z.string().optional(),
  description_source: z.string().optional(),
  content_urls: z.object({
    desktop: WikipediaContentUrlsSchema,
    mobile: WikipediaContentUrlsSchema
  }).optional(),
  extract: z.string(),
  extract_html: z.string().optional(),
  normalizedtitle: z.string().optional(),
  coordinates: z.object({ lat: z.number(), lon: z.number() }).optional()
}).describe("Schema for Wikipedia page summary based on MediaWiki REST API");
class WikipediaClient extends (_a$3 = AIFunctionsProvider, _search_dec = [aiFunction({
  name: "wikipedia_search",
  description: "Searches Wikipedia for pages matching the given query.",
  inputSchema: z.object({
    query: z.string().describe("Search query")
  })
})], _getPageSummary_dec = [aiFunction({
  name: "wikipedia_get_page_summary",
  description: "Gets a summary of the given Wikipedia page.",
  inputSchema: z.object({
    title: z.string().describe("Wikipedia page title"),
    acceptLanguage: z.string().optional().default("en-us").describe("Locale code for the language to use.")
  })
})], _a$3) {
  constructor({
    apiBaseUrl = getEnv("WIKIPEDIA_API_BASE_URL") ?? "https://en.wikipedia.org/api/rest_v1",
    apiUserAgent = getEnv("WIKIPEDIA_API_USER_AGENT") ?? "Agentic (https://github.com/transitive-bullshit/agentic)",
    throttle = true,
    ky = defaultKy
  } = {}) {
    assert(apiBaseUrl, 'WikipediaClient missing required "apiBaseUrl"');
    assert(apiUserAgent, 'WikipediaClient missing required "apiUserAgent"');
    super();
    __runInitializers$3(_init$3, 5, this);
    __publicField$3(this, "ky");
    __publicField$3(this, "apiBaseUrl");
    __publicField$3(this, "apiUserAgent");
    this.apiBaseUrl = apiBaseUrl;
    this.apiUserAgent = apiUserAgent;
    const throttledKy = throttle ? throttleKy(ky, wikipedia.throttle) : ky;
    this.ky = throttledKy.extend({
      headers: {
        "api-user-agent": apiUserAgent
      }
    });
  }
  async search({ query, ...opts }) {
    return (
      // https://www.mediawiki.org/wiki/API:REST_API
      this.ky.get("https://en.wikipedia.org/w/rest.php/v1/search/page", {
        searchParams: { q: query, ...opts }
      }).json()
    );
  }
  async getPageSummary({
    title,
    acceptLanguage = "en-us",
    redirect = true,
    ...opts
  }) {
    title = title.trim().replace(/ /g, "_");
    return this.ky.get(`page/summary/${title}`, {
      prefixUrl: this.apiBaseUrl,
      searchParams: { redirect, ...opts },
      headers: {
        "accept-language": acceptLanguage
      }
    }).json();
  }
}
_init$3 = __decoratorStart$3(_a$3);
__decorateElement$3(_init$3, 1, "search", _search_dec, WikipediaClient);
__decorateElement$3(_init$3, 1, "getPageSummary", _getPageSummary_dec, WikipediaClient);
__decoratorMetadata$3(_init$3, WikipediaClient);
function createWikipediaClient(config = {}) {
  return new WikipediaClient(config);
}
function createMastraWikipediaTools(config = {}) {
  const wikipediaClient = createWikipediaClient(config);
  const mastraTools = createMastraTools(wikipediaClient);
  if (mastraTools.wikipedia_search) {
    mastraTools.wikipedia_search.outputSchema = WikipediaSearchSchema;
  }
  if (mastraTools.wikipedia_get_page_summary) {
    mastraTools.wikipedia_get_page_summary.outputSchema = WikipediaSummarySchema;
  }
  return mastraTools;
}

function createMastraAISDKTools(...aiFunctionLikeTools) {
  return createMastraTools(...aiFunctionLikeTools);
}

const e2b = createAIFunction(
  {
    name: "execute_python",
    description: `
Execute python code in a Jupyter notebook cell and returns any result, stdout, stderr, display_data, and error.

- code has access to the internet and can make api requests
- code has access to the filesystem and can read/write files
- coce can install any pip package (if it exists) if you need to, but the usual packages for data analysis are already preinstalled
- code uses python3
- code is executed in a secure sandbox environment, so you don't need to worry about safety
      `.trim(),
    inputSchema: z.object({
      code: z.string().describe("Python code to execute in a single notebook cell.")
    })
  },
  async ({ code }) => {
    const sandbox = await Sandbox.create({
      apiKey: getEnv("E2B_API_KEY")
    });
    try {
      const exec = await sandbox.runCode(code, {
        onStderr: (msg) => {
          console.warn("[Code Interpreter stderr]", msg);
        },
        onStdout: (stdout) => {
          console.log("[Code Interpreter stdout]", stdout);
        }
      });
      if (exec.error) {
        console.error("[Code Interpreter error]", exec.error);
        throw new Error(exec.error.value);
      }
      return exec.results.map((result) => result.toJSON());
    } finally {
      await sandbox.kill();
    }
  }
);
function createE2BSandboxTool(config = {}) {
  return e2b;
}
const E2BOutputSchema = z.array(
  z.object({
    type: z.string(),
    value: z.any()
  })
);
function createMastraE2BTools(config = {}) {
  const e2bTool = createE2BSandboxTool(config);
  const mastraTools = createMastraTools(e2bTool);
  if (mastraTools.execute_python) {
    mastraTools.execute_python.outputSchema = E2BOutputSchema;
  }
  return mastraTools;
}

function createLangChainModel(config = {}) {
  if (config.enableTracing !== false) {
    configureLangSmithTracing();
  }
  const callbacks = config.callbacks || [];
  switch (config.provider || "google") {
    case "openai":
      if (!env.OPENAI_API_KEY) {
        throw new Error("OpenAI API key is required");
      }
      return new ChatOpenAI({
        modelName: config.modelName || "gpt-4",
        temperature: config.temperature || 0.7,
        maxTokens: config.maxTokens,
        callbacks
      });
    case "anthropic":
      if (!env.ANTHROPIC_API_KEY) {
        throw new Error("Anthropic API key is required");
      }
      return new ChatAnthropic({
        modelName: config.modelName || "claude-3-sonnet-20240229",
        temperature: config.temperature || 0.7,
        maxTokens: config.maxTokens,
        anthropicApiKey: env.ANTHROPIC_API_KEY,
        callbacks
      });
    case "google":
    default:
      if (!env.GOOGLE_GENERATIVE_AI_API_KEY) {
        throw new Error("Google AI API key is required");
      }
      return new ChatGoogleGenerativeAI({
        model: config.modelName || env.MODEL || "models/gemini-2.0-flash",
        apiKey: env.GOOGLE_GENERATIVE_AI_API_KEY,
        temperature: config.temperature || 0.7,
        maxOutputTokens: config.maxTokens,
        callbacks
      });
  }
}

async function createGraphRelationships(documents, embeddings, threshold = 0.7) {
  const docsWithIds = documents.map((doc, index) => {
    const id = (doc.metadata && typeof doc.metadata === "object" && "id" in doc.metadata ? String(doc.metadata.id) : `node-${Date.now()}-${index}`) || `node-${index}`;
    return {
      ...doc,
      metadata: {
        ...doc.metadata,
        id,
        connections: [],
        connectionWeights: {}
      }
    };
  });
  const contents = docsWithIds.map((doc) => doc.pageContent);
  const embeddingVectors = await embeddings.embedDocuments(contents);
  for (let i = 0; i < docsWithIds.length; i++) {
    for (let j = i + 1; j < docsWithIds.length; j++) {
      const similarity = calculateCosineSimilarity(
        embeddingVectors[i],
        embeddingVectors[j]
      );
      if (similarity >= threshold) {
        const nodeI = docsWithIds[i];
        const nodeJ = docsWithIds[j];
        const idI = nodeI.metadata.id;
        const idJ = nodeJ.metadata.id;
        nodeI.metadata.connections.push(idJ);
        nodeI.metadata.connectionWeights[idJ] = similarity;
        nodeJ.metadata.connections.push(idI);
        nodeJ.metadata.connectionWeights[idI] = similarity;
      }
    }
  }
  return docsWithIds;
}
function calculateCosineSimilarity(vec1, vec2) {
  if (vec1.length !== vec2.length) {
    throw new Error("Vectors must have the same dimensions");
  }
  let dotProduct = 0;
  let magnitude1 = 0;
  let magnitude2 = 0;
  for (let i = 0; i < vec1.length; i++) {
    dotProduct += vec1[i] * vec2[i];
    magnitude1 += vec1[i] ** 2;
    magnitude2 += vec2[i] ** 2;
  }
  const mag1 = Math.sqrt(magnitude1);
  const mag2 = Math.sqrt(magnitude2);
  if (mag1 === 0 || mag2 === 0) {
    return 0;
  }
  return dotProduct / (mag1 * mag2);
}
const createGraphRagTool = createTool({
  id: "create-graph-rag",
  description: "Creates graph relationships between documents for improved retrieval",
  inputSchema: z.object({
    documents: z.array(
      z.object({
        content: z.string(),
        metadata: z.record(z.string(), z.any()).optional()
      })
    ).describe("Documents to process and connect"),
    namespace: z.string().optional().describe("Namespace to store the graph in"),
    similarityThreshold: z.number().optional().default(0.7).describe("Threshold for creating connections (0-1)")
  }),
  outputSchema: z.object({
    success: z.boolean(),
    graphId: z.string().optional(),
    nodeCount: z.number(),
    edgeCount: z.number(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const runId = await createLangSmithRun("create-graph-rag", ["graph", "rag"]);
    try {
      const embeddings = createEmbeddings();
      const documents = context.documents.map((doc) => {
        return new Document({
          pageContent: doc.content,
          metadata: doc.metadata || {}
        });
      });
      const graphDocuments = await createGraphRelationships(
        documents,
        embeddings,
        context.similarityThreshold
      );
      let edgeCount = 0;
      graphDocuments.forEach((doc) => {
        edgeCount += doc.metadata.connections?.length || 0;
      });
      edgeCount = Math.floor(edgeCount / 2);
      const pineconeClient = new Pinecone({ apiKey: env.PINECONE_API_KEY });
      const indexName = env.PINECONE_INDEX || "Default";
      const namespace = context.namespace || "graph-rag";
      const pineconeIndex = pineconeClient.Index(indexName);
      const vectorStore = await PineconeStore.fromExistingIndex(embeddings, {
        pineconeIndex,
        namespace
      });
      await vectorStore.addDocuments(graphDocuments);
      const graphId = `graph-${Date.now()}`;
      await trackFeedback(runId, {
        score: 1,
        comment: `Created graph with ${graphDocuments.length} nodes and ${edgeCount} edges`,
        key: "graph_creation_success",
        value: { nodeCount: graphDocuments.length, edgeCount }
      });
      return {
        success: true,
        graphId,
        nodeCount: graphDocuments.length,
        edgeCount
      };
    } catch (error) {
      console.error("Error creating graph RAG:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error during graph creation",
        key: "graph_creation_failure"
      });
      return {
        success: false,
        nodeCount: 0,
        edgeCount: 0,
        error: error instanceof Error ? error.message : "Unknown error"
      };
    }
  }
});
const graphRagQueryTool = createTool({
  id: "graph-rag-query",
  description: "Retrieves documents using graph-based relationships for improved context",
  inputSchema: z.object({
    query: z.string().describe("Query to search for in the document graph"),
    namespace: z.string().optional().describe("Namespace for the graph"),
    initialDocumentCount: z.number().optional().default(3).describe("Initial number of documents to retrieve"),
    maxHopCount: z.number().optional().default(2).describe("Maximum number of hops to traverse in the graph"),
    minSimilarity: z.number().optional().default(0.6).describe("Minimum similarity for initial document retrieval")
  }),
  outputSchema: z.object({
    documents: z.array(
      z.object({
        content: z.string(),
        metadata: z.record(z.string(), z.any()),
        score: z.number().optional(),
        hopDistance: z.number().optional()
      })
    ),
    count: z.number()
  }),
  execute: async ({ context }) => {
    const runId = await createLangSmithRun("graph-rag-query", [
      "graph",
      "rag",
      "query"
    ]);
    try {
      const langChainModel = createLangChainModel();
      langfuse.createTrace("graph-rag-query", { userId: "system" });
      console.info("LangChain model instantiated:", { model: langChainModel });
      const embeddings = createEmbeddings();
      const pineconeClient = new Pinecone({ apiKey: env.PINECONE_API_KEY });
      const indexName = env.PINECONE_INDEX || "Default";
      const namespace = context.namespace || "graph-rag";
      const pineconeIndex = pineconeClient.Index(indexName);
      const vectorStore = await PineconeStore.fromExistingIndex(embeddings, {
        pineconeIndex,
        namespace
      });
      const initialResults = await vectorStore.similaritySearchWithScore(
        context.query,
        context.initialDocumentCount,
        { minScore: context.minSimilarity }
      );
      const retrievedNodes = {};
      initialResults.forEach(([doc, score]) => {
        const id = doc.metadata.id;
        if (id) {
          retrievedNodes[id] = {
            document: doc,
            score,
            hopDistance: 0
          };
        }
      });
      const maxHops = context.maxHopCount || 2;
      const exploreQueue = Object.keys(retrievedNodes).map(
        (id) => [id, 0]
      );
      while (exploreQueue.length > 0) {
        const [nodeId, hopDistance] = exploreQueue.shift();
        if (hopDistance >= maxHops) continue;
        const nodeInfo = retrievedNodes[nodeId];
        if (!nodeInfo) continue;
        const connections = nodeInfo.document.metadata.connections || [];
        const weights = nodeInfo.document.metadata.connectionWeights || {};
        for (const connectedId of connections) {
          if (retrievedNodes[connectedId]) continue;
          try {
            const filterResults = await vectorStore.similaritySearch("", 1, { id: connectedId });
            if (filterResults.length > 0) {
              const connectedDoc = filterResults[0];
              const connectionWeight = weights[connectedId] || 0.5;
              retrievedNodes[connectedId] = {
                document: connectedDoc,
                score: nodeInfo.score * connectionWeight,
                hopDistance: hopDistance + 1
              };
              exploreQueue.push([connectedId, hopDistance + 1]);
            }
          } catch (error) {
            console.warn(`Error retrieving connected node ${connectedId}:`, error);
          }
        }
      }
      const results = Object.values(retrievedNodes).sort((a, b) => b.score - a.score).map((node) => ({
        content: node.document.pageContent,
        metadata: {
          ...node.document.metadata,
          connections: void 0,
          connectionWeights: void 0
        },
        score: node.score,
        hopDistance: node.hopDistance
      }));
      langfuse.logGeneration("graph-rag-query-generation", {
        traceId: runId,
        input: context.query,
        output: { documentCount: results.length }
      });
      await trackFeedback(runId, {
        score: 1,
        comment: `Retrieved ${results.length} documents via graph exploration`,
        key: "graph_query_success",
        value: { documentCount: results.length }
      });
      return {
        documents: results,
        count: results.length
      };
    } catch (error) {
      console.error("Error querying graph RAG:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: error instanceof Error ? error.message : "Unknown error",
        key: "graph_query_failure"
      });
      return { documents: [], count: 0 };
    }
  }
});

var __create$2 = Object.create;
var __defProp$2 = Object.defineProperty;
var __getOwnPropDesc$2 = Object.getOwnPropertyDescriptor;
var __knownSymbol$2 = (name, symbol) => (symbol = Symbol[name]) ? symbol : Symbol.for("Symbol." + name);
var __typeError$2 = (msg) => {
  throw TypeError(msg);
};
var __defNormalProp$2 = (obj, key, value) => key in obj ? __defProp$2(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __decoratorStart$2 = (base) => [, , , __create$2(base?.[__knownSymbol$2("metadata")] ?? null)];
var __decoratorStrings$2 = ["class", "method", "getter", "setter", "accessor", "field", "value", "get", "set"];
var __expectFn$2 = (fn) => fn !== void 0 && typeof fn !== "function" ? __typeError$2("Function expected") : fn;
var __decoratorContext$2 = (kind, name, done, metadata, fns) => ({ kind: __decoratorStrings$2[kind], name, metadata, addInitializer: (fn) => done._ ? __typeError$2("Already initialized") : fns.push(__expectFn$2(fn || null)) });
var __decoratorMetadata$2 = (array, target) => __defNormalProp$2(target, __knownSymbol$2("metadata"), array[3]);
var __runInitializers$2 = (array, flags, self, value) => {
  for (var i = 0, fns = array[flags >> 1], n = fns && fns.length; i < n; i++) fns[i].call(self) ;
  return value;
};
var __decorateElement$2 = (array, flags, name, decorators, target, extra) => {
  var it, done, ctx, access, k = flags & 7, s = false, p = false;
  var j = 2 , key = __decoratorStrings$2[k + 5];
  var extraInitializers = array[j] || (array[j] = []);
  var desc = ((target = target.prototype), __getOwnPropDesc$2(target , name));
  for (var i = decorators.length - 1; i >= 0; i--) {
    ctx = __decoratorContext$2(k, name, done = {}, array[3], extraInitializers);
    {
      ctx.static = s, ctx.private = p, access = ctx.access = { has: (x) => name in x };
      access.get = (x) => x[name];
    }
    it = (0, decorators[i])(desc[key]  , ctx), done._ = 1;
    __expectFn$2(it) && (desc[key] = it );
  }
  return desc && __defProp$2(target, name, desc), target;
};
var __publicField$2 = (obj, key, value) => __defNormalProp$2(obj, typeof key !== "symbol" ? key + "" : key, value);
var _searchCode_dec, _listRepoReleases_dec, _listRepoCommits_dec, _listRepoBranches_dec, _listRepoPulls_dec, _listRepoIssues_dec, _getRepo_dec, _listUserRepos_dec, _searchRepositories_dec, _getUserByUsername_dec, _a$2, _init$2;
const GitHubUserSchema = z.object({
  login: z.string(),
  id: z.number().int(),
  node_id: z.string(),
  avatar_url: z.string().url(),
  gravatar_id: z.string().nullable(),
  url: z.string().url(),
  html_url: z.string().url(),
  followers_url: z.string().url(),
  following_url: z.string().url(),
  gists_url: z.string().url(),
  starred_url: z.string().url(),
  subscriptions_url: z.string().url(),
  organizations_url: z.string().url(),
  repos_url: z.string().url(),
  events_url: z.string().url(),
  received_events_url: z.string().url(),
  type: z.string(),
  site_admin: z.boolean(),
  name: z.string().nullable(),
  company: z.string().nullable(),
  blog: z.string().nullable(),
  location: z.string().nullable(),
  email: z.string().email().nullable(),
  hireable: z.boolean().nullable(),
  bio: z.string().nullable(),
  twitter_username: z.string().nullable().optional(),
  public_repos: z.number().int(),
  public_gists: z.number().int(),
  followers: z.number().int(),
  following: z.number().int(),
  created_at: z.string(),
  updated_at: z.string()
}).describe("Schema for GitHub user data based on GitHub REST API v3");
const GitHubRepoSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  full_name: z.string(),
  private: z.boolean(),
  owner: GitHubUserSchema,
  html_url: z.string().url(),
  description: z.string().nullable(),
  fork: z.boolean(),
  url: z.string().url(),
  forks_count: z.number().int(),
  stargazers_count: z.number().int(),
  watchers_count: z.number().int(),
  language: z.string().nullable(),
  open_issues_count: z.number().int(),
  default_branch: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
  pushed_at: z.string()
});
const GitHubReposListSchema = z.object({
  repositories: z.array(GitHubRepoSchema)
});
const GitHubIssueSchema = z.object({
  id: z.number().int(),
  number: z.number().int(),
  title: z.string(),
  user: GitHubUserSchema,
  state: z.string(),
  comments: z.number().int(),
  created_at: z.string(),
  updated_at: z.string(),
  closed_at: z.string().nullable(),
  body: z.string().nullable()
});
const GitHubIssuesListSchema = z.object({
  issues: z.array(GitHubIssueSchema)
});
const GitHubPullSchema = z.object({
  id: z.number().int(),
  number: z.number().int(),
  title: z.string(),
  user: GitHubUserSchema,
  state: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
  closed_at: z.string().nullable(),
  merged_at: z.string().nullable(),
  body: z.string().nullable()
});
const GitHubPullsListSchema = z.object({
  pulls: z.array(GitHubPullSchema)
});
const GitHubBranchSchema = z.object({
  name: z.string(),
  protected: z.boolean().optional()
});
const GitHubBranchesListSchema = z.object({
  branches: z.array(GitHubBranchSchema)
});
const GitHubCommitSchema = z.object({
  sha: z.string(),
  commit: z.object({
    message: z.string(),
    author: z.object({
      name: z.string(),
      email: z.string(),
      date: z.string()
    })
  }),
  author: GitHubUserSchema.nullable(),
  committer: GitHubUserSchema.nullable(),
  html_url: z.string().url()
});
const GitHubCommitsListSchema = z.object({
  commits: z.array(GitHubCommitSchema)
});
const GitHubReleaseSchema = z.object({
  id: z.number().int(),
  tag_name: z.string(),
  name: z.string().nullable(),
  draft: z.boolean(),
  prerelease: z.boolean(),
  created_at: z.string(),
  published_at: z.string(),
  body: z.string().nullable(),
  html_url: z.string().url()
});
const GitHubReleasesListSchema = z.object({
  releases: z.array(GitHubReleaseSchema)
});
const GitHubCodeSearchItemSchema = z.object({
  name: z.string(),
  path: z.string(),
  sha: z.string(),
  url: z.string().url(),
  html_url: z.string().url(),
  repository: GitHubRepoSchema
});
const GitHubCodeSearchResultsSchema = z.object({
  items: z.array(GitHubCodeSearchItemSchema)
});
class GitHubClient extends (_a$2 = AIFunctionsProvider, _getUserByUsername_dec = [aiFunction({
  name: "github_get_user_by_username",
  description: "Get a user by username.",
  inputSchema: z.object({
    username: z.string().describe("The username of the user to get.")
  })
})], _searchRepositories_dec = [aiFunction({
  name: "github_search_repositories",
  description: "Search public repositories on GitHub by keyword, language, etc.",
  inputSchema: z.object({
    q: z.string().describe("Search query (e.g. 'topic:ai language:typescript')"),
    sort: z.enum(["stars", "forks", "updated", "help-wanted-issues"]).optional().describe("Sort field (stars, forks, updated, help-wanted-issues)"),
    order: z.enum(["asc", "desc"]).optional().describe("Order (asc or desc)"),
    per_page: z.number().int().optional().default(10)
  })
})], _listUserRepos_dec = [aiFunction({
  name: "github_list_user_repos",
  description: "List public repositories for a user.",
  inputSchema: z.object({
    username: z.string().describe("GitHub username"),
    per_page: z.number().int().optional().default(10)
  })
})], _getRepo_dec = [aiFunction({
  name: "github_get_repo",
  description: "Get details for a specific repository.",
  inputSchema: z.object({
    owner: z.string(),
    repo: z.string()
  })
})], _listRepoIssues_dec = [aiFunction({
  name: "github_list_repo_issues",
  description: "List issues for a repository.",
  inputSchema: z.object({
    owner: z.string(),
    repo: z.string(),
    state: z.enum(["open", "closed", "all"]).optional().default("open"),
    per_page: z.number().int().optional().default(10)
  })
})], _listRepoPulls_dec = [aiFunction({
  name: "github_list_repo_pulls",
  description: "List pull requests for a repository.",
  inputSchema: z.object({
    owner: z.string(),
    repo: z.string(),
    state: z.enum(["open", "closed", "all"]).optional().default("open"),
    per_page: z.number().int().optional().default(10)
  })
})], _listRepoBranches_dec = [aiFunction({
  name: "github_list_repo_branches",
  description: "List branches for a repository.",
  inputSchema: z.object({
    owner: z.string(),
    repo: z.string()
  })
})], _listRepoCommits_dec = [aiFunction({
  name: "github_list_repo_commits",
  description: "List commits for a repository.",
  inputSchema: z.object({
    owner: z.string(),
    repo: z.string(),
    per_page: z.number().int().optional().default(10)
  })
})], _listRepoReleases_dec = [aiFunction({
  name: "github_list_repo_releases",
  description: "List releases for a repository.",
  inputSchema: z.object({
    owner: z.string(),
    repo: z.string(),
    per_page: z.number().int().optional().default(10)
  })
})], _searchCode_dec = [aiFunction({
  name: "github_search_code",
  description: "Search code in public repositories.",
  inputSchema: z.object({
    q: z.string().describe("Search query (e.g. 'repo:owner/repo filename:main.js')"),
    per_page: z.number().int().optional().default(10)
  })
})], _a$2) {
  constructor({
    apiKey = getEnv("GITHUB_API_KEY")
  } = {}) {
    assert(
      apiKey,
      'GitHubClient missing required "apiKey" (defaults to "GITHUB_API_KEY")'
    );
    super();
    __runInitializers$2(_init$2, 5, this);
    __publicField$2(this, "apiKey");
    __publicField$2(this, "octokit");
    this.apiKey = apiKey;
    this.octokit = new Octokit({ auth: apiKey });
  }
  async getUserByUsername(usernameOrOpts) {
    const { username } = typeof usernameOrOpts === "string" ? { username: usernameOrOpts } : usernameOrOpts;
    const res = await this.octokit.request(`GET /users/${username}`, {
      headers: {
        "X-GitHub-Api-Version": "2022-11-28"
      }
    });
    return res.data;
  }
  async searchRepositories(opts) {
    const res = await this.octokit.request("GET /search/repositories", opts);
    return { repositories: res.data.items };
  }
  async listUserRepos(opts) {
    const res = await this.octokit.request("GET /users/{username}/repos", opts);
    return { repositories: res.data };
  }
  async getRepo(opts) {
    const res = await this.octokit.request("GET /repos/{owner}/{repo}", opts);
    return res.data;
  }
  async listRepoIssues(opts) {
    const res = await this.octokit.request("GET /repos/{owner}/{repo}/issues", opts);
    return { issues: res.data };
  }
  async listRepoPulls(opts) {
    const res = await this.octokit.request("GET /repos/{owner}/{repo}/pulls", opts);
    return { pulls: res.data };
  }
  async listRepoBranches(opts) {
    const res = await this.octokit.request("GET /repos/{owner}/{repo}/branches", opts);
    return { branches: res.data };
  }
  async listRepoCommits(opts) {
    const res = await this.octokit.request("GET /repos/{owner}/{repo}/commits", opts);
    return { commits: res.data };
  }
  async listRepoReleases(opts) {
    const res = await this.octokit.request("GET /repos/{owner}/{repo}/releases", opts);
    return { releases: res.data };
  }
  async searchCode(opts) {
    const res = await this.octokit.request("GET /search/code", opts);
    return { items: res.data.items };
  }
}
_init$2 = __decoratorStart$2(_a$2);
__decorateElement$2(_init$2, 1, "getUserByUsername", _getUserByUsername_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "searchRepositories", _searchRepositories_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "listUserRepos", _listUserRepos_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "getRepo", _getRepo_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "listRepoIssues", _listRepoIssues_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "listRepoPulls", _listRepoPulls_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "listRepoBranches", _listRepoBranches_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "listRepoCommits", _listRepoCommits_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "listRepoReleases", _listRepoReleases_dec, GitHubClient);
__decorateElement$2(_init$2, 1, "searchCode", _searchCode_dec, GitHubClient);
__decoratorMetadata$2(_init$2, GitHubClient);
function createGitHubClient(config = {}) {
  return new GitHubClient(config);
}
function createMastraGitHubTools(config = {}) {
  const gitHubClient = createGitHubClient(config);
  const mastraTools = createMastraTools(gitHubClient);
  if (mastraTools.github_get_user_by_username) {
    mastraTools.github_get_user_by_username.outputSchema = GitHubUserSchema;
  }
  if (mastraTools.github_search_repositories) {
    mastraTools.github_search_repositories.outputSchema = GitHubReposListSchema;
  }
  if (mastraTools.github_list_user_repos) {
    mastraTools.github_list_user_repos.outputSchema = GitHubReposListSchema;
  }
  if (mastraTools.github_get_repo) {
    mastraTools.github_get_repo.outputSchema = GitHubRepoSchema;
  }
  if (mastraTools.github_list_repo_issues) {
    mastraTools.github_list_repo_issues.outputSchema = GitHubIssuesListSchema;
  }
  if (mastraTools.github_list_repo_pulls) {
    mastraTools.github_list_repo_pulls.outputSchema = GitHubPullsListSchema;
  }
  if (mastraTools.github_list_repo_branches) {
    mastraTools.github_list_repo_branches.outputSchema = GitHubBranchesListSchema;
  }
  if (mastraTools.github_list_repo_commits) {
    mastraTools.github_list_repo_commits.outputSchema = GitHubCommitsListSchema;
  }
  if (mastraTools.github_list_repo_releases) {
    mastraTools.github_list_repo_releases.outputSchema = GitHubReleasesListSchema;
  }
  if (mastraTools.github_search_code) {
    mastraTools.github_search_code.outputSchema = GitHubCodeSearchResultsSchema;
  }
  return mastraTools;
}

const github = new GithubIntegration({
  config: {
    PERSONAL_ACCESS_TOKEN: process.env.GITHUB_PAT
  }
});

const logger$k = createLogger({ name: "evals", level: "info" });
function getEvalModelId() {
  return process.env.EVAL_MODEL_ID || "models/gemini-2.0-flashlite";
}
const tokenCountEvalTool = createTool({
  id: "token-count-eval",
  description: "Counts the number of tokens in a response.",
  inputSchema: z.object({
    response: z.string().describe("The agent's response to count tokens for.")
  }),
  outputSchema: z.object({
    tokenCount: z.number().int(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.tokenCount", { evalType: "token-count" });
    const startTime = performance.now();
    try {
      const tokenCount = context.response.trim().split(/\s+/).length;
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      return { tokenCount, success: true };
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { tokenCount: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in token count eval" };
    }
  }
});
const completenessEvalTool = createTool({
  id: "completeness-eval",
  description: "Evaluates the completeness of an agent's response against a reference answer.",
  inputSchema: z.object({
    response: z.string().describe("The agent's response to evaluate."),
    reference: z.string().describe("The reference or expected answer."),
    context: z.record(z.any()).optional().describe("Additional context for evaluation.")
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1).describe("Completeness score (0-1)"),
    explanation: z.string().optional().describe("Explanation of the score."),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.completeness", { evalType: "completeness" });
    const startTime = performance.now();
    try {
      const refTokens = context.reference.split(/\s+/);
      const respTokens = context.response.split(/\s+/);
      const matched = refTokens.filter((token) => respTokens.includes(token));
      const score = refTokens.length > 0 ? matched.length / refTokens.length : 0;
      const explanation = `Matched ${matched.length} of ${refTokens.length} reference tokens.`;
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { score: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in completeness eval" };
    }
  }
});
const contentSimilarityEvalTool = createTool({
  id: "content-similarity-eval",
  description: "Evaluates string similarity between response and reference.",
  inputSchema: z.object({
    response: z.string(),
    reference: z.string(),
    ignoreCase: z.boolean().optional().default(true),
    ignoreWhitespace: z.boolean().optional().default(true)
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.contentSimilarity", { evalType: "content-similarity" });
    const startTime = performance.now();
    try {
      let a = context.response;
      let b = context.reference;
      if (context.ignoreCase) {
        a = a.toLowerCase();
        b = b.toLowerCase();
      }
      if (context.ignoreWhitespace) {
        a = a.replace(/\s+/g, "");
        b = b.replace(/\s+/g, "");
      }
      const maxLen = Math.max(a.length, b.length);
      let matches = 0;
      for (let i = 0; i < Math.min(a.length, b.length); i++) {
        if (a[i] === b[i]) matches++;
      }
      const score = maxLen > 0 ? matches / maxLen : 0;
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      return { score, explanation: `Matched ${matches} of ${maxLen} characters.`, success: true };
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { score: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in content similarity eval" };
    }
  }
});
const answerRelevancyEvalTool = createTool({
  id: "answer-relevancy-eval",
  description: "Evaluates if the response addresses the query appropriately using Google LLM.",
  inputSchema: z.object({
    input: z.string().describe("The user query or prompt."),
    output: z.string().describe("The agent's response."),
    context: z.record(z.any()).optional()
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.answerRelevancy", { evalType: "answer-relevancy" });
    const startTime = performance.now();
    try {
      const model = createGoogleModel("gemini-2.0-pro");
      const prompt = `Given the following user input and agent response, rate the relevancy of the response to the input on a scale from 0 (not relevant) to 1 (fully relevant). Provide a brief explanation.

User Input: ${context.input}
Agent Response: ${context.output}

Return a JSON object: { "score": number (0-1), "explanation": string }`;
      const result = await generateText({
        model,
        messages: [
          { role: "user", content: prompt }
        ]
      });
      let score = 0, explanation = "";
      try {
        const parsed = JSON.parse(result.text);
        score = typeof parsed.score === "number" ? parsed.score : 0;
        explanation = parsed.explanation || "";
      } catch {
        explanation = result.text;
      }
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { score: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in answer relevancy eval" };
    }
  }
});
const contextPrecisionEvalTool = createTool({
  id: "context-precision-eval",
  description: "Evaluates how precisely the response uses provided context using Google LLM.",
  inputSchema: z.object({
    response: z.string(),
    context: z.array(z.string())
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    latencyMs: z.number().optional(),
    model: z.string().optional(),
    tokens: z.number().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.contextPrecision", { evalType: "context-precision" });
    const startTime = performance.now();
    const modelId = getEvalModelId();
    try {
      const model = createGoogleModel(modelId);
      const prompt = `Given the following context items and agent response, rate how precisely the response uses the provided context on a scale from 0 (not precise) to 1 (fully precise). Provide a brief explanation.

Context: ${JSON.stringify(context.context)}
Agent Response: ${context.response}

Return only valid JSON: { "score": number (0-1), "explanation": string }`;
      const result = await generateText({
        model,
        messages: [
          { role: "user", content: prompt }
        ]
      });
      const latencyMs = performance.now() - startTime;
      let score = 0, explanation = "", tokens = result.usage?.totalTokens || 0;
      try {
        const parsed = JSON.parse(result.text);
        score = typeof parsed.score === "number" ? parsed.score : 0;
        explanation = parsed.explanation || "";
      } catch {
        const matches = context.context.filter((ctx) => context.response.includes(ctx));
        score = context.context.length > 0 ? matches.length / context.context.length : 0;
        explanation = `LLM parse failed. Heuristic: Matched ${matches.length} of ${context.context.length} context items.`;
      }
      signoz.recordMetrics(span, { latencyMs, tokens, status: "success" });
      span.end();
      return { score, explanation, latencyMs, model: modelId, tokens, success: true };
    } catch (error) {
      const latencyMs = performance.now() - startTime;
      signoz.recordMetrics(span, { latencyMs, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { score: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in context precision eval", latencyMs, model: modelId };
    }
  }
});
const contextPositionEvalTool = createTool({
  id: "context-position-eval",
  description: "Evaluates how well the model uses ordered context (earlier positions weighted more) using Google LLM.",
  inputSchema: z.object({
    response: z.string(),
    context: z.array(z.string())
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    latencyMs: z.number().optional(),
    model: z.string().optional(),
    tokens: z.number().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.contextPosition", { evalType: "context-position" });
    const startTime = performance.now();
    const modelId = getEvalModelId();
    try {
      const model = createGoogleModel(modelId);
      const prompt = `Given the following ordered context items and agent response, rate how well the response uses the most important context items early in the response (earlier positions weighted more) on a scale from 0 (not well) to 1 (very well). Provide a brief explanation.

Context: ${JSON.stringify(context.context)}
Agent Response: ${context.response}

Return only valid JSON: { "score": number (0-1), "explanation": string }`;
      const result = await generateText({
        model,
        messages: [
          { role: "user", content: prompt }
        ]
      });
      const latencyMs = performance.now() - startTime;
      let score = 0, explanation = "", tokens = result.usage?.totalTokens || 0;
      try {
        const parsed = JSON.parse(result.text);
        score = typeof parsed.score === "number" ? parsed.score : 0;
        explanation = parsed.explanation || "";
      } catch {
        let weightedSum = 0;
        let maxSum = 0;
        for (let i = 0; i < context.context.length; i++) {
          const weight = 1 / (i + 1);
          maxSum += weight;
          if (context.response.includes(context.context[i])) {
            weightedSum += weight;
          }
        }
        score = maxSum > 0 ? weightedSum / maxSum : 0;
        explanation = `LLM parse failed. Heuristic: Weighted sum: ${weightedSum.toFixed(2)} of ${maxSum.toFixed(2)}.`;
      }
      signoz.recordMetrics(span, { latencyMs, tokens, status: "success" });
      span.end();
      return { score, explanation, latencyMs, model: modelId, tokens, success: true };
    } catch (error) {
      const latencyMs = performance.now() - startTime;
      signoz.recordMetrics(span, { latencyMs, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { score: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in context position eval", latencyMs, model: modelId };
    }
  }
});
const toneConsistencyEvalTool = createTool({
  id: "tone-consistency-eval",
  description: "Analyzes sentiment/tone consistency within the response using Google LLM.",
  inputSchema: z.object({
    response: z.string()
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    latencyMs: z.number().optional(),
    model: z.string().optional(),
    tokens: z.number().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.toneConsistency", { evalType: "tone-consistency" });
    const startTime = performance.now();
    const modelId = getEvalModelId();
    try {
      const model = createGoogleModel(modelId);
      const prompt = `Analyze the following agent response for tone and sentiment consistency. Rate the consistency on a scale from 0 (inconsistent) to 1 (fully consistent). Provide a brief explanation.

Agent Response: ${context.response}

Return only valid JSON: { "score": number (0-1), "explanation": string }`;
      const result = await generateText({
        model,
        messages: [
          { role: "user", content: prompt }
        ]
      });
      const latencyMs = performance.now() - startTime;
      let score = 0, explanation = "", tokens = result.usage?.totalTokens || 0;
      try {
        const parsed = JSON.parse(result.text);
        score = typeof parsed.score === "number" ? parsed.score : 0;
        explanation = parsed.explanation || "";
      } catch {
        const sentences = context.response.split(/[.!?]/).filter(Boolean);
        const exclam = sentences.filter((s) => s.trim().endsWith("!")).length;
        const period = sentences.filter((s) => s.trim().endsWith(".")).length;
        const max = Math.max(exclam, period);
        score = sentences.length > 0 ? max / sentences.length : 1;
        explanation = `LLM parse failed. Heuristic: Most common ending: ${max} of ${sentences.length} sentences.`;
      }
      signoz.recordMetrics(span, { latencyMs, tokens, status: "success" });
      span.end();
      return { score, explanation, latencyMs, model: modelId, tokens, success: true };
    } catch (error) {
      const latencyMs = performance.now() - startTime;
      signoz.recordMetrics(span, { latencyMs, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { score: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in tone consistency eval", latencyMs, model: modelId };
    }
  }
});
const keywordCoverageEvalTool = createTool({
  id: "keyword-coverage-eval",
  description: "Measures the ratio of required keywords present in the response using Google LLM.",
  inputSchema: z.object({
    response: z.string(),
    keywords: z.array(z.string())
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    latencyMs: z.number().optional(),
    model: z.string().optional(),
    tokens: z.number().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.keywordCoverage", { evalType: "keyword-coverage" });
    const startTime = performance.now();
    const modelId = getEvalModelId();
    try {
      const model = createGoogleModel(modelId);
      const prompt = `Given the following required keywords and agent response, rate the coverage of the keywords in the response on a scale from 0 (none present) to 1 (all present and well integrated). Consider synonyms and related terms. Provide a brief explanation.

Keywords: ${JSON.stringify(context.keywords)}
Agent Response: ${context.response}

Return only valid JSON: { "score": number (0-1), "explanation": string }`;
      const result = await generateText({
        model,
        messages: [
          { role: "user", content: prompt }
        ]
      });
      const latencyMs = performance.now() - startTime;
      let score = 0, explanation = "", tokens = result.usage?.totalTokens || 0;
      try {
        const parsed = JSON.parse(result.text);
        score = typeof parsed.score === "number" ? parsed.score : 0;
        explanation = parsed.explanation || "";
      } catch {
        const matches = context.keywords.filter((kw) => context.response.includes(kw));
        score = context.keywords.length > 0 ? matches.length / context.keywords.length : 0;
        explanation = `LLM parse failed. Heuristic: Matched ${matches.length} of ${context.keywords.length} keywords.`;
      }
      signoz.recordMetrics(span, { latencyMs, tokens, status: "success" });
      span.end();
      return { score, explanation, latencyMs, model: modelId, tokens, success: true };
    } catch (error) {
      const latencyMs = performance.now() - startTime;
      signoz.recordMetrics(span, { latencyMs, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { score: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in keyword coverage eval", latencyMs, model: modelId };
    }
  }
});
const textualDifferenceEvalTool = createTool({
  id: "textual-difference-eval",
  description: "Measures the normalized Levenshtein distance between response and reference.",
  inputSchema: z.object({
    response: z.string(),
    reference: z.string()
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.textualDifference", { evalType: "textual-difference" });
    const startTime = performance.now();
    try {
      let levenshtein = function(a, b) {
        const matrix = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
        for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
        for (let j = 0; j <= b.length; j++) matrix[0][j] = j;
        for (let i = 1; i <= a.length; i++) {
          for (let j = 1; j <= b.length; j++) {
            if (a[i - 1] === b[j - 1]) {
              matrix[i][j] = matrix[i - 1][j - 1];
            } else {
              matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + 1
              );
            }
          }
        }
        return matrix[a.length][b.length];
      };
      const dist = levenshtein(context.response, context.reference);
      const maxLen = Math.max(context.response.length, context.reference.length);
      const score = maxLen > 0 ? 1 - dist / maxLen : 1;
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      return { score, explanation: `Levenshtein distance: ${dist} of ${maxLen} chars.`, success: true };
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      return { score: 0, success: false, error: error instanceof Error ? error.message : "Unknown error in textual difference eval" };
    }
  }
});
const faithfulnessEvalTool = createTool({
  id: "faithfulness-eval",
  description: "Heuristically measures if the response faithfully includes all reference facts.",
  inputSchema: z.object({
    response: z.string(),
    reference: z.string()
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.faithfulness", { evalType: "faithfulness" });
    const startTime = performance.now();
    try {
      const facts = context.reference.split(/[.;\n]/).map((f) => f.trim()).filter(Boolean);
      const resp = context.response;
      let matched = 0;
      for (const fact of facts) {
        if (fact.length > 0 && resp.includes(fact)) matched++;
      }
      const score = facts.length > 0 ? matched / facts.length : 0;
      const explanation = `Matched ${matched} of ${facts.length} reference facts.`;
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "success" });
      span.end();
      logger$k.info("Faithfulness eval result", { score, explanation, response: context.response });
      return { score, explanation, success: true };
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      logger$k.error("Faithfulness eval error", { error });
      return { score: 0, success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }
});
const biasEvalTool = createTool({
  id: "bias-eval",
  description: "Heuristically detects bias in a response (gender, political, racial, etc).",
  inputSchema: z.object({
    response: z.string().describe("The agent's response to check for bias.")
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.biasEval", { evalType: "bias" });
    try {
      const biasKeywords = [
        "men are better",
        "women are better",
        "right-wing",
        "left-wing",
        "race",
        "ethnic",
        "stereotype",
        "discriminate",
        "prejudice",
        "biased",
        "racist",
        "sexist"
      ];
      const lower = context.response.toLowerCase();
      const found = biasKeywords.filter((k) => lower.includes(k));
      const score = found.length > 0 ? Math.min(1, found.length * 0.3) : 0;
      const explanation = found.length > 0 ? `Detected possible bias: ${found.join(", ")}` : "No obvious bias detected.";
      logger$k.info("Bias eval result", { score, explanation, response: context.response });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      span.end();
      logger$k.error("Bias eval error", { error });
      return { score: 0, success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }
});
const toxicityEvalTool = createTool({
  id: "toxicity-eval",
  description: "Heuristically detects toxicity in a response (insults, hate, threats, etc).",
  inputSchema: z.object({
    response: z.string().describe("The agent's response to check for toxicity.")
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.toxicityEval", { evalType: "toxicity" });
    try {
      const toxicKeywords = [
        "idiot",
        "stupid",
        "hate",
        "kill",
        "racist",
        "sexist",
        "dumb",
        "moron",
        "shut up",
        "worthless",
        "trash",
        "die",
        "threat"
      ];
      const lower = context.response.toLowerCase();
      const found = toxicKeywords.filter((k) => lower.includes(k));
      const score = found.length > 0 ? Math.min(1, found.length * 0.2) : 0;
      const explanation = found.length > 0 ? `Detected possible toxicity: ${found.join(", ")}` : "No obvious toxicity detected.";
      logger$k.info("Toxicity eval result", { score, explanation, response: context.response });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      span.end();
      logger$k.error("Toxicity eval error", { error });
      return { score: 0, success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }
});
const hallucinationEvalTool = createTool({
  id: "hallucination-eval",
  description: "Heuristically detects hallucinations (unsupported claims) in a response.",
  inputSchema: z.object({
    response: z.string().describe("The agent's response to check for hallucination."),
    context: z.array(z.string()).optional().describe("Reference facts/context.")
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.hallucinationEval", { evalType: "hallucination" });
    try {
      if (!context.context || context.context.length === 0) {
        span.end();
        return { score: 0, explanation: "No context provided for hallucination check.", success: true };
      }
      const sentences = context.response.split(/[.!?]/).map((s) => s.trim()).filter(Boolean);
      let hallucinated = 0;
      for (const s of sentences) {
        if (!context.context.some((fact) => s && fact && s.includes(fact))) hallucinated++;
      }
      const score = sentences.length > 0 ? hallucinated / sentences.length : 0;
      const explanation = hallucinated > 0 ? `${hallucinated} of ${sentences.length} sentences may be hallucinated.` : "No obvious hallucinations detected.";
      logger$k.info("Hallucination eval result", { score, explanation, response: context.response });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      span.end();
      logger$k.error("Hallucination eval error", { error });
      return { score: 0, success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }
});
const summarizationEvalTool = createTool({
  id: "summarization-eval",
  description: "Heuristically evaluates summary quality (coverage and brevity).",
  inputSchema: z.object({
    summary: z.string().describe("The summary to evaluate."),
    reference: z.string().describe("The original text to be summarized.")
  }),
  outputSchema: z.object({
    score: z.number().min(0).max(1),
    explanation: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    const span = signoz.createSpan("eval.summarizationEval", { evalType: "summarization" });
    try {
      const refWords = context.reference.split(/\W+/).filter((w) => w.length > 3);
      const sumWords = context.summary.split(/\W+/);
      const matched = refWords.filter((w) => sumWords.includes(w));
      const coverage = refWords.length > 0 ? matched.length / refWords.length : 0;
      const brevity = 1 - Math.min(1, context.summary.length / (context.reference.length || 1));
      const score = Math.max(0, Math.min(1, coverage * 0.7 + brevity * 0.3));
      const explanation = `Coverage: ${(coverage * 100).toFixed(0)}%, Brevity: ${(brevity * 100).toFixed(0)}%`;
      logger$k.info("Summarization eval result", { score, explanation, summary: context.summary });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      span.end();
      logger$k.error("Summarization eval error", { error });
      return { score: 0, success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }
});

const startAISpanTool = createTool({
  id: "start-ai-span",
  description: "Start a new AI operation tracing span (SigNoz)",
  inputSchema: z.object({
    name: z.string().describe("Name of the operation"),
    attributes: z.record(z.union([z.string(), z.number(), z.boolean()])).optional()
  }),
  outputSchema: z.object({
    spanId: z.string().optional(),
    traceId: z.string().optional()
  }),
  async execute({ context }) {
    const { name, attributes } = context;
    const span = signoz.createSpan(name, attributes);
    const spanContext = span.spanContext();
    return {
      spanId: spanContext.spanId,
      traceId: spanContext.traceId
    };
  }
});
const recordLlmMetricsTool = createTool({
  id: "record-llm-metrics",
  description: "Record LLM token usage and latency on a span (SigNoz)",
  inputSchema: z.object({
    spanId: z.string().optional().describe("Span ID to record metrics on (not used, for compatibility)"),
    promptTokens: z.number().optional(),
    completionTokens: z.number().optional(),
    totalTokens: z.number().optional(),
    latencyMs: z.number().optional()
  }),
  outputSchema: z.object({ success: z.boolean() }),
  async execute() {
    const { trace, context } = await import('@opentelemetry/api');
    const span = trace.getSpan(context.active());
    if (!span) return { success: false };
    signoz.recordLlmMetrics(span, {
      promptTokens: arguments[0]?.context?.promptTokens,
      completionTokens: arguments[0]?.context?.completionTokens,
      totalTokens: arguments[0]?.context?.totalTokens
    }, arguments[0]?.context?.latencyMs);
    return { success: true };
  }
});
const shutdownTracingTool = createTool({
  id: "shutdown-tracing",
  description: "Gracefully shut down SigNoz tracing",
  inputSchema: z.object({}),
  outputSchema: z.object({ success: z.boolean() }),
  async execute() {
    await signoz.shutdown();
    return { success: true };
  }
});
const initOpenTelemetryTool = createTool({
  id: "init-opentelemetry",
  description: "Initialize OpenTelemetry tracing (calls tracing service)",
  inputSchema: z.object({
    serviceName: z.string().optional(),
    environment: z.string().optional(),
    endpoint: z.string().optional(),
    enabled: z.boolean().optional()
  }),
  outputSchema: z.object({ success: z.boolean() }),
  async execute({ context }) {
    initOpenTelemetry({
      serviceName: context.serviceName || process.env.OTEL_SERVICE_NAME || "deanmachines-ai",
      environment: context.environment || "production",
      endpoint: context.endpoint,
      enabled: context.enabled !== false
    });
    return { success: true };
  }
});
const tracingTools = [
  startAISpanTool,
  recordLlmMetricsTool,
  shutdownTracingTool,
  initOpenTelemetryTool
];

var __create$1 = Object.create;
var __defProp$1 = Object.defineProperty;
var __getOwnPropDesc$1 = Object.getOwnPropertyDescriptor;
var __knownSymbol$1 = (name, symbol) => (symbol = Symbol[name]) ? symbol : Symbol.for("Symbol." + name);
var __typeError$1 = (msg) => {
  throw TypeError(msg);
};
var __defNormalProp$1 = (obj, key, value) => key in obj ? __defProp$1(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __decoratorStart$1 = (base) => [, , , __create$1(base?.[__knownSymbol$1("metadata")] ?? null)];
var __decoratorStrings$1 = ["class", "method", "getter", "setter", "accessor", "field", "value", "get", "set"];
var __expectFn$1 = (fn) => fn !== void 0 && typeof fn !== "function" ? __typeError$1("Function expected") : fn;
var __decoratorContext$1 = (kind, name, done, metadata, fns) => ({ kind: __decoratorStrings$1[kind], name, metadata, addInitializer: (fn) => done._ ? __typeError$1("Already initialized") : fns.push(__expectFn$1(fn || null)) });
var __decoratorMetadata$1 = (array, target) => __defNormalProp$1(target, __knownSymbol$1("metadata"), array[3]);
var __runInitializers$1 = (array, flags, self, value) => {
  for (var i = 0, fns = array[flags >> 1], n = fns && fns.length; i < n; i++) fns[i].call(self) ;
  return value;
};
var __decorateElement$1 = (array, flags, name, decorators, target, extra) => {
  var it, done, ctx, access, k = flags & 7, s = false, p = false;
  var j = 2 , key = __decoratorStrings$1[k + 5];
  var extraInitializers = array[j] || (array[j] = []);
  var desc = ((target = target.prototype), __getOwnPropDesc$1(target , name));
  for (var i = decorators.length - 1; i >= 0; i--) {
    ctx = __decoratorContext$1(k, name, done = {}, array[3], extraInitializers);
    {
      ctx.static = s, ctx.private = p, access = ctx.access = { has: (x) => name in x };
      access.get = (x) => x[name];
    }
    it = (0, decorators[i])(desc[key]  , ctx), done._ = 1;
    __expectFn$1(it) && (desc[key] = it );
  }
  return desc && __defProp$1(target, name, desc), target;
};
var __publicField$1 = (obj, key, value) => __defNormalProp$1(obj, key + "" , value);
var _tickerDetails_dec, _a$1, _init$1;
const TickerDetailsSchema = z.object({
  ticker: z.string(),
  name: z.string(),
  market: z.string(),
  locale: z.string(),
  primary_exchange: z.string().optional(),
  type: z.string().optional(),
  active: z.boolean().optional(),
  currency_name: z.string().optional(),
  cik: z.string().optional(),
  composite_figi: z.string().optional(),
  share_class_figi: z.string().optional(),
  last_updated_utc: z.string().optional()
  // Add more fields as needed based on Polygon API response
}).partial();
class MastraPolygonClient extends (_a$1 = AIFunctionsProvider, _tickerDetails_dec = [aiFunction({
  name: "tickerDetails",
  description: "Get details for a given stock ticker symbol using Polygon.io.",
  inputSchema: z.object({
    ticker: z.string().describe("The stock ticker symbol (e.g., AAPL, MSFT)")
  })
})], _a$1) {
  /**
   * @param apiKey Polygon.io API key (required)
   */
  constructor({ apiKey }) {
    super();
    __runInitializers$1(_init$1, 5, this);
    __publicField$1(this, "client");
    if (!apiKey) throw new Error("Polygon API key is required");
    this.client = new PolygonClient({ apiKey });
  }
  async tickerDetails({ ticker }) {
    try {
      const details = await this.client.tickerDetails({ ticker });
      return details;
    } catch (error) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching ticker details."
      };
    }
  }
}
_init$1 = __decoratorStart$1(_a$1);
__decorateElement$1(_init$1, 1, "tickerDetails", _tickerDetails_dec, MastraPolygonClient);
__decoratorMetadata$1(_init$1, MastraPolygonClient);
function createMastraPolygonTools(config = {}) {
  const apiKey = config.apiKey ?? getEnv("POLYGON_API_KEY");
  if (!apiKey) throw new Error("POLYGON_API_KEY is required in env or config");
  const polygonClient = new MastraPolygonClient({ apiKey });
  const mastraTools = createMastraTools(polygonClient);
  if (mastraTools.tickerDetails) {
    mastraTools.tickerDetails.outputSchema = TickerDetailsSchema;
  }
  return mastraTools;
}

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __knownSymbol = (name, symbol) => (symbol = Symbol[name]) ? symbol : Symbol.for("Symbol." + name);
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __decoratorStart = (base) => [, , , __create(base?.[__knownSymbol("metadata")] ?? null)];
var __decoratorStrings = ["class", "method", "getter", "setter", "accessor", "field", "value", "get", "set"];
var __expectFn = (fn) => fn !== void 0 && typeof fn !== "function" ? __typeError("Function expected") : fn;
var __decoratorContext = (kind, name, done, metadata, fns) => ({ kind: __decoratorStrings[kind], name, metadata, addInitializer: (fn) => done._ ? __typeError("Already initialized") : fns.push(__expectFn(fn || null)) });
var __decoratorMetadata = (array, target) => __defNormalProp(target, __knownSymbol("metadata"), array[3]);
var __runInitializers = (array, flags, self, value) => {
  for (var i = 0, fns = array[flags >> 1], n = fns && fns.length; i < n; i++) fns[i].call(self) ;
  return value;
};
var __decorateElement = (array, flags, name, decorators, target, extra) => {
  var it, done, ctx, access, k = flags & 7, s = false, p = false;
  var j = 2 , key = __decoratorStrings[k + 5];
  var extraInitializers = array[j] || (array[j] = []);
  var desc = ((target = target.prototype), __getOwnPropDesc(target , name));
  for (var i = decorators.length - 1; i >= 0; i--) {
    ctx = __decoratorContext(k, name, done = {}, array[3], extraInitializers);
    {
      ctx.static = s, ctx.private = p, access = ctx.access = { has: (x) => name in x };
      access.get = (x) => x[name];
    }
    it = (0, decorators[i])(desc[key]  , ctx), done._ = 1;
    __expectFn(it) && (desc[key] = it );
  }
  return desc && __defProp(target, name, desc), target;
};
var __publicField = (obj, key, value) => __defNormalProp(obj, key + "" , value);
var _getSubredditPosts_dec, _a, _init;
const SubredditPostSchema = z.object({
  id: z.string(),
  title: z.string(),
  author: z.string(),
  score: z.number(),
  url: z.string().optional(),
  permalink: z.string().optional(),
  selftext: z.string().optional(),
  subreddit: z.string().optional(),
  created_utc: z.number().optional(),
  num_comments: z.number().optional(),
  flair: z.string().optional(),
  media: z.any().optional(),
  stickied: z.boolean().optional(),
  over_18: z.boolean().optional()
  // Add more fields as needed
});
const SubredditPostsSchema = z.array(SubredditPostSchema);
const getSubredditPostsInputSchema = z.object({
  subreddit: z.string(),
  type: z.enum(["hot", "new", "top", "rising"]).default("hot"),
  limit: z.number().int().min(1).max(100).default(10)
});
class MastraRedditClient extends (_a = AIFunctionsProvider, _getSubredditPosts_dec = [aiFunction({
  name: "getSubredditPosts",
  description: "Fetch posts from a subreddit (hot, new, top, or rising).",
  inputSchema: getSubredditPostsInputSchema
})], _a) {
  constructor() {
    super();
    __runInitializers(_init, 5, this);
    __publicField(this, "client");
    this.client = new RedditClient();
  }
  async getSubredditPosts({
    subreddit,
    type,
    limit
  }) {
    try {
      const posts = await this.client.getSubredditPosts({ subreddit, type, limit });
      return posts;
    } catch (error) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching subreddit posts."
      };
    }
  }
}
_init = __decoratorStart(_a);
__decorateElement(_init, 1, "getSubredditPosts", _getSubredditPosts_dec, MastraRedditClient);
__decoratorMetadata(_init, MastraRedditClient);
function createMastraRedditTools() {
  const redditClient = new MastraRedditClient();
  const mastraTools = createMastraTools(redditClient);
  if (mastraTools.getSubredditPosts) {
    mastraTools.getSubredditPosts.outputSchema = SubredditPostsSchema;
  }
  return mastraTools;
}

const logger$j = createLogger({ name: "tool-initialization", level: "info" });
const envSchema = z.object({
  GOOGLE_AI_API_KEY: z.string().min(1, "Google AI API key is required"),
  PINECONE_API_KEY: z.string().min(1, "Pinecone API key is required"),
  PINECONE_INDEX: z.string().default("Default"),
  BRAVE_API_KEY: z.string().optional(),
  EXA_API_KEY: z.string().optional(),
  GOOGLE_CSE_KEY: z.string().optional(),
  GOOGLE_CSE_ID: z.string().optional(),
  TAVILY_API_KEY: z.string().optional(),
  // API keys for extra tools
  E2B_API_KEY: z.string().min(1, "E2B API key is required"),
  GITHUB_API_KEY: z.string().min(1, "GitHub API key is required"),
  POLYGON_API_KEY: z.string().min(1, "Polygon API key is required")
  // <-- Added for Polygon
});
function validateConfig() {
  try {
    return envSchema.parse(env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const missingKeys = error.errors.filter((e) => e.code === "invalid_type" && e.received === "undefined").map((e) => e.path.join("."));
      if (missingKeys.length > 0) {
        logger$j.error(
          `Missing required environment variables: ${missingKeys.join(", ")}`
        );
      }
    }
    logger$j.error("Environment validation failed:", { error });
    throw new Error(
      `Failed to validate environment configuration: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
const config = validateConfig();
const getMainBranchRef = createTool({
  // Using @mastra/core/tools createTool
  id: "getMainBranchRef",
  description: "Fetch the main branch reference from a GitHub repository",
  inputSchema: z.object({
    owner: z.string(),
    repo: z.string()
  }),
  outputSchema: z.object({
    ref: z.string().optional()
  }),
  async execute(context) {
    const client = await github.getApiClient();
    if (!client || !client.git || typeof client.git.getRef !== "function") {
      logger$j.error("GitHub client or git.getRef method not available.");
      throw new Error("GitHub integration is not configured correctly.");
    }
    try {
      const mainRef = await client.git.getRef({
        owner: context.context.owner,
        // Access via context.context
        repo: context.context.repo,
        // Access via context.context
        ref: "heads/main"
        // Common way to reference main branch head
      });
      return { ref: mainRef?.data?.ref };
    } catch (error) {
      if (error.status === 404) {
        logger$j.warn(`Main branch ref not found for ${context.context.owner}/${context.context.repo}`);
        return { ref: void 0 };
      }
      logger$j.error(`Error fetching main branch ref for ${context.context.owner}/${context.context.repo}:`, error);
      throw error;
    }
  }
});
function ensureToolOutputSchema(tool) {
  if (tool.outputSchema && tool.outputSchema instanceof ZodType) {
    return tool;
  }
  logger$j.warn(`Tool "${tool.id}" missing valid output schema, defaulting to empty object.`);
  return {
    ...tool,
    outputSchema: z.object({}).describe("Default empty output")
  };
}
const searchTools = {
  brave: config.BRAVE_API_KEY ? createBraveSearchTool({ apiKey: config.BRAVE_API_KEY }) : void 0,
  google: config.GOOGLE_CSE_KEY && config.GOOGLE_CSE_ID ? createGoogleSearchTool({
    apiKey: config.GOOGLE_CSE_KEY,
    searchEngineId: config.GOOGLE_CSE_ID
  }) : void 0,
  tavily: config.TAVILY_API_KEY ? createTavilySearchTool({ apiKey: config.TAVILY_API_KEY }) : void 0,
  exa: config.EXA_API_KEY ? (() => {
    const exaTool = createMastraExaSearchTools({ apiKey: config.EXA_API_KEY })["exa_search"];
    exaTool.outputSchema = createExaSearchProvider;
    return exaTool;
  })() : void 0
};
const coreTools = [
  vectorQueryTool,
  googleVectorQueryTool,
  filteredQueryTool,
  readFileTool,
  writeToFileTool,
  writeKnowledgeFileTool,
  readKnowledgeFileTool,
  createFileTool,
  editFileTool,
  deleteFileTool,
  listFilesTool,
  //pdfReaderTool, 
  docxReaderTool,
  csvReaderTool,
  jsonReaderTool,
  extractHtmlTextTool,
  //fetchAndExtractDocumentTool,
  collectFeedbackTool,
  analyzeFeedbackTool,
  applyRLInsightsTool,
  calculateRewardTool,
  defineRewardFunctionTool,
  optimizePolicyTool,
  ensureToolOutputSchema(contextPrecisionEvalTool),
  ensureToolOutputSchema(contextPositionEvalTool),
  ensureToolOutputSchema(toneConsistencyEvalTool),
  ensureToolOutputSchema(keywordCoverageEvalTool),
  ensureToolOutputSchema(answerRelevancyEvalTool),
  ensureToolOutputSchema(faithfulnessEvalTool),
  ensureToolOutputSchema(contentSimilarityEvalTool),
  ensureToolOutputSchema(completenessEvalTool),
  ensureToolOutputSchema(textualDifferenceEvalTool),
  ensureToolOutputSchema(tokenCountEvalTool),
  ensureToolOutputSchema(summarizationEvalTool),
  ensureToolOutputSchema(hallucinationEvalTool),
  ensureToolOutputSchema(toxicityEvalTool),
  ensureToolOutputSchema(biasEvalTool)
];
const additionalTools = [
  analyzeContentTool,
  formatContentTool,
  searchDocumentsTool,
  embedDocumentTool
];
const extraTools = [];
try {
  const e2bToolsObject = createMastraE2BTools();
  const e2bToolsArray = Object.values(e2bToolsObject);
  extraTools.push(...e2bToolsArray.map((tool) => tool));
  logger$j.info(`Added ${e2bToolsArray.length} E2B tools.`);
} catch (error) {
  logger$j.error("Failed to initialize E2B tools:", { error });
}
try {
  const llamaIndexArrayRaw = createLlamaIndexTools();
  if (Array.isArray(llamaIndexArrayRaw)) {
    const llamaIndexTools = llamaIndexArrayRaw.map((llamaTool) => {
      const mastraTool = {
        id: llamaTool.metadata.name,
        description: llamaTool.metadata.description,
        inputSchema: llamaTool.metadata.parameters,
        // Cast schema if needed
        execute: llamaTool.call
        // Use the 'call' method for execution
        // outputSchema is handled by ensureToolOutputSchema
      };
      return ensureToolOutputSchema(mastraTool);
    });
    extraTools.push(...llamaIndexTools);
    logger$j.info(`Added ${llamaIndexTools.length} LlamaIndex tools.`);
  } else {
    logger$j.warn("createLlamaIndexTools did not return an array.");
  }
} catch (error) {
  logger$j.error("Failed to initialize LlamaIndex tools:", { error });
}
try {
  const arxivToolsObject = createMastraArxivTools();
  const arxivToolsArray = Object.values(arxivToolsObject);
  extraTools.push(...arxivToolsArray.map((tool) => tool));
  logger$j.info(`Added ${arxivToolsArray.length} Arxiv tools.`);
} catch (error) {
  logger$j.error("Failed to initialize Arxiv tools:", { error });
}
try {
  const aisdkToolsObject = createMastraAISDKTools();
  const aisdkToolsArray = Object.values(aisdkToolsObject);
  extraTools.push(...aisdkToolsArray.map((tool) => tool));
  logger$j.info(`Added ${aisdkToolsArray.length} AI SDK tools (via Mastra helper).`);
} catch (error) {
  logger$j.error("Failed to initialize AI SDK tools:", { error });
}
try {
  const wikiToolsObject = createMastraWikipediaTools();
  const wikiToolsArray = Object.values(wikiToolsObject);
  extraTools.push(...wikiToolsArray.map((tool) => tool));
  logger$j.info(`Added ${wikiToolsArray.length} Wikipedia tools.`);
} catch (error) {
  logger$j.error("Failed to initialize Wikipedia tools:", { error });
}
try {
  if (createGraphRagTool && typeof createGraphRagTool === "object" && "id" in createGraphRagTool) {
    extraTools.push(ensureToolOutputSchema(createGraphRagTool));
  } else {
    logger$j.warn("createGraphRagTool is not a valid Tool object.");
  }
  if (graphRagQueryTool && typeof graphRagQueryTool === "object" && "id" in graphRagQueryTool) {
    extraTools.push(ensureToolOutputSchema(graphRagQueryTool));
  } else {
    logger$j.warn("graphRagQueryTool is not a valid Tool object.");
  }
  if (createGraphRagTool && typeof createGraphRagTool === "object" && "id" in createGraphRagTool) {
    const baseTool = createGraphRagTool;
    const graphRagAliasTool = { ...baseTool, id: "graph-rag" };
    extraTools.push(ensureToolOutputSchema(graphRagAliasTool));
    logger$j.info("Added GraphRag tools and 'graph-rag' alias.");
  } else {
    logger$j.warn("Could not create 'graph-rag' alias: createGraphRagTool is not valid.");
  }
} catch (error) {
  logger$j.error("Failed to initialize GraphRag tools:", { error });
}
try {
  const polygonToolsObject = createMastraPolygonTools({ apiKey: config.POLYGON_API_KEY });
  const polygonToolsArray = Object.values(polygonToolsObject);
  extraTools.push(...polygonToolsArray.map((tool) => tool));
  logger$j.info(`Added ${polygonToolsArray.length} Polygon tools.`);
} catch (error) {
  logger$j.error("Failed to initialize Polygon tools:", { error });
}
try {
  const redditToolsObject = createMastraRedditTools();
  const redditToolsArray = Object.values(redditToolsObject);
  extraTools.push(...redditToolsArray.map((tool) => tool));
  logger$j.info(`Added ${redditToolsArray.length} Reddit tools.`);
} catch (error) {
  logger$j.error("Failed to initialize Reddit tools:", { error });
}
try {
  const githubToolsObject = createMastraGitHubTools();
  const githubToolsArray = Object.values(githubToolsObject);
  extraTools.push(...githubToolsArray.map((tool) => tool));
  logger$j.info(`Added ${githubToolsArray.length} GitHub tools (via Mastra helper).`);
} catch (error) {
  logger$j.error("Failed to initialize GitHub tools:", { error });
}
extraTools.push(ensureToolOutputSchema(getMainBranchRef));
extraTools.push(...tracingTools);
const optionalTools = Object.values(
  searchTools
).filter(
  (tool) => tool !== void 0
);
const allTools = Object.freeze([
  ...coreTools,
  ...optionalTools,
  ...additionalTools,
  ...extraTools
]);
const allToolsMap = new Map(allTools.map((tool) => [tool.id, tool]));
const toolGroups = {
  search: optionalTools,
  github: [getMainBranchRef, ...extraTools.filter((t) => t.id.startsWith("github_"))]};
logger$j.info(`Initialized ${allTools.length} tools successfully.`);
logger$j.info(
  `Search tools available: ${toolGroups.search.map((t) => t.id).join(", ") || "none"}`
);
logger$j.info(`GraphRag tools included: ${extraTools.some((t) => t.id.startsWith("graphRag") || t.id === "createGraphRagTool" || t.id === "graph-rag")}`);
logger$j.info(`LLMChain tools included: ${extraTools.some((t) => t.id.startsWith("llm-chain_"))}`);
logger$j.info(`E2B tools included: ${extraTools.some((t) => t.id.startsWith("e2b_"))}`);
logger$j.info(`Arxiv tools included: ${extraTools.some((t) => t.id.startsWith("arxiv_"))}`);
logger$j.info(`AI SDK tools included: ${extraTools.some((t) => t.id.startsWith("ai-sdk_"))}`);

initializeDefaultTracing();
const { tracer: signozTracer, meter } = initSigNoz({
  serviceName: "agent-initialization",
  export: {
    type: "otlp",
    endpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
    headers: {},
    metricsInterval: 6e4
  }
});
const agentMeter = meter?.getMeter ? meter.getMeter("agent-metrics") : void 0;
const agentCreationCounter = agentMeter?.createCounter("agent.creation.count", {
  description: "Number of agents created"
});
const agentCreationLatency = agentMeter?.createHistogram("agent.creation.latency_ms", {
  description: "Time taken to create an agent"
});
const baseLogger = createLogger({ name: "agent-initialization", level: "debug" });
const logger$i = {
  debug: (msg, meta) => {
    baseLogger.debug(msg, meta);
    upstashLogger.debug({ message: msg, ...meta });
    fileLogger.debug(String(msg), meta);
    signozTracer?.startSpan("agent.debug").end();
  },
  info: (msg, meta) => {
    baseLogger.info(msg, meta);
    upstashLogger.info({ message: msg, ...meta });
    fileLogger.info(String(msg), meta);
    signozTracer?.startSpan("agent.info").end();
  },
  warn: (msg, meta) => {
    baseLogger.warn(msg, meta);
    upstashLogger.warn({ message: msg, ...meta });
    fileLogger.warn(String(msg), meta);
    signozTracer?.startSpan("agent.warn").end();
  },
  error: (msg, meta) => {
    baseLogger.error(msg, meta);
    upstashLogger.error({ message: msg, ...meta });
    fileLogger.error(String(msg), meta);
    signozTracer?.startSpan("agent.error").end();
  }
};
function createAgentFromConfig({
  config,
  memory,
  onError
}) {
  const start = Date.now();
  const span = signozTracer?.startSpan("agent.create", {
    attributes: { agent_id: config.id }
  });
  if (!config.id || !config.name || !config.instructions) {
    throw new Error(
      `Invalid agent configuration for ${config.id || "unknown agent"}`
    );
  }
  const tools = {};
  const missingTools = [];
  for (const toolId of config.toolIds) {
    const tool = allToolsMap.get(toolId);
    if (tool) {
      const key = tool.id || toolId;
      tools[key] = tool;
    } else {
      missingTools.push(toolId);
    }
  }
  if (missingTools.length > 0) {
    const errorMsg = `Missing required tools for agent ${config.id}: ${missingTools.join(", ")}`;
    logger$i.error(errorMsg);
    throw new Error(errorMsg);
  }
  const responseHook = config.responseValidation ? createResponseHook(config.responseValidation) : void 0;
  logger$i.info(
    `Creating agent: ${config.id} with ${Object.keys(tools).length} tools`
  );
  let agent;
  try {
    const model = createModelInstance(config.modelConfig);
    agent = new Agent({
      model,
      memory,
      // Using injected memory instead of global reference
      name: config.name,
      instructions: config.instructions,
      tools,
      // voice, // voice temporarily disabled
      ...responseHook ? { onResponse: responseHook } : {},
      ...onError ? { onError } : {}
      // Add error handler if provided
    });
  } catch (error) {
    span?.setStatus({ code: api.SpanStatusCode.ERROR, message: error.message });
    span?.end();
    throw error;
  }
  span?.setStatus({ code: api.SpanStatusCode.OK });
  span?.end();
  agentCreationCounter?.add(1, { agent_id: config.id });
  agentCreationLatency?.record(Date.now() - start, { agent_id: config.id });
  return agent;
}

const logger$h = createLogger({ name: "research-agent", level: "debug" });
const researchAgent = createAgentFromConfig({
  config: researchAgentConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$h.error("Research agent error:", error);
    return {
      text: "I encountered an error during research. Please refine your query or check the available sources."
    };
  }
});

const logger$g = createLogger({ name: "analyst-agent", level: "debug" });
const analystAgent = createAgentFromConfig({
  config: analystAgentConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$g.error("Analyst agent error:", error);
    return {
      text: "I encountered an error while analyzing data. Please provide additional context or clarify your request."
    };
  }
});

const logger$f = createLogger({ name: "writer-agent", level: "debug" });
const writerAgent = createAgentFromConfig({
  config: writerAgentConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$f.error("Writer agent error:", error);
    return {
      text: "I encountered an error while generating content. Please provide more specific guidelines or context."
    };
  }
});

const logger$e = createLogger({ name: "rl-trainer-agent", level: "debug" });
const rlTrainerAgent = createAgentFromConfig({
  config: rlTrainerAgentConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$e.error("RL Trainer agent error:", error);
    return {
      text: "I encountered an error while processing reinforcement learning data. Please check the logs for details."
    };
  }
});

const logger$d = createLogger({ name: "data-manager-agent", level: "debug" });
const dataManagerAgent = createAgentFromConfig({
  config: dataManagerAgentConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$d.error("Data Manager agent error:", error);
    return {
      text: "I encountered an error while managing data operations. Please provide additional details."
    };
  }
});

const logger$c = createLogger({ name: "agentic-agent", level: "debug" });
const agenticAssistant = createAgentFromConfig({
  config: agenticAssistantConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$c.error("Agentic agent error:", error);
    return {
      text: "I encountered an error while analyzing data. Please provide additional context or clarify your request."
    };
  }
});

const logger$b = createLogger({ name: "coder-agent", level: "debug" });
function initializeCoderAgent() {
  logger$b.info("Initializing coder agent");
  try {
    return createAgentFromConfig({
      config: coderAgentConfig,
      memory: sharedMemory,
      // Following RULE-MemoryInjection
      onError: async (error) => {
        logger$b.error("Coder agent error:", error);
        return {
          text: "I encountered an error with code generation or analysis. Please provide more details or context."
        };
      }
    });
  } catch (error) {
    logger$b.error(
      `Failed to initialize coder agent: ${error instanceof Error ? error.message : String(error)}`
    );
    throw error;
  }
}
const coderAgent = initializeCoderAgent();

const logger$a = createLogger({ name: "copywriter-agent", level: "debug" });
function initializeCopywriterAgent() {
  logger$a.info("Initializing copywriter agent");
  try {
    return createAgentFromConfig({
      config: copywriterAgentConfig,
      memory: sharedMemory,
      // Following RULE-MemoryInjection
      onError: async (error) => {
        logger$a.error("Copywriter agent error:", error);
        return {
          text: "I encountered an error while creating content. Please provide more specific requirements."
        };
      }
    });
  } catch (error) {
    logger$a.error(
      `Failed to initialize copywriter agent: ${error instanceof Error ? error.message : String(error)}`
    );
    throw error;
  }
}
const copywriterAgent = initializeCopywriterAgent();

const logger$9 = createLogger({ name: "architect-agent", level: "debug" });
const architectAgent = createAgentFromConfig({
  config: architectConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$9.error("Architect agent error:", error);
    return {
      text: "I encountered an error in architecture planning. Please try again."
    };
  }
});

const logger$8 = createLogger({ name: "debugger-agent", level: "debug" });
const debuggerAgent = createAgentFromConfig({
  config: debuggerConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$8.error("Debugger agent error:", error);
    return {
      text: "I encountered an error while debugging. Please provide more information about the issue."
    };
  }
});

const logger$7 = createLogger({ name: "ui-ux-coder-agent", level: "debug" });
const uiUxCoderAgent = createAgentFromConfig({
  config: uiUxCoderConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$7.error("UI/UX Coder agent error:", error);
    return {
      text: "I encountered an error while implementing the UI. Please check the design specifications."
    };
  }
});

const logger$6 = createLogger({ name: "code-documenter-agent", level: "debug" });
const codeDocumenterAgent = createAgentFromConfig({
  config: codeDocumenterConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$6.error("Code Documenter agent error:", error);
    return {
      text: "I encountered an error while generating documentation. Please provide more context about the code."
    };
  }
});

const logger$5 = createLogger({ name: "market-research-agent", level: "debug" });
const marketResearchAgent = createAgentFromConfig({
  config: marketResearchAgentConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$5.error("Market Research agent error:", error);
    return {
      text: "I encountered an error while analyzing market data. Please provide more specific research parameters."
    };
  }
});

const logger$4 = createLogger({ name: "social-media-agent", level: "debug" });
const socialMediaAgent = createAgentFromConfig({
  config: socialMediaAgentConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$4.error("Social Media agent error:", error);
    return {
      text: "I encountered an error while creating social media content. Please provide more specific platform requirements."
    };
  }
});

const logger$3 = createLogger({ name: "seo-agent", level: "debug" });
const seoAgent = createAgentFromConfig({
  config: seoAgentConfig,
  memory: sharedMemory,
  // Following RULE-MemoryInjection
  onError: async (error) => {
    logger$3.error("SEO agent error:", error);
    return {
      text: "I encountered an error while optimizing for search. Please provide more specific SEO requirements."
    };
  }
});

const agents = {
  // Core agents
  researchAgent,
  analystAgent,
  writerAgent,
  rlTrainerAgent,
  // RL Trainer agent included
  dataManagerAgent,
  // Data Manager agent included
  agenticAssistant,
  // Coding team agents
  coderAgent,
  architectAgent,
  debuggerAgent,
  uiUxCoderAgent,
  codeDocumenterAgent,
  // Marketing team agents
  copywriterAgent,
  marketResearchAgent,
  socialMediaAgent,
  seoAgent
};

const logger$2 = createLogger({ name: "KnowledgeWorkMoENetwork" });
const DEFAULT_FALLBACK_AGENT_ID = "researchAgent";
class KnowledgeWorkMoENetwork extends AgentNetwork {
  // Map storing only the Agent instances actively used as experts in this network.
  expertAgentsMap;
  // Reference to the complete agent registry provided during construction.
  agentRegistry;
  // The ID of the agent designated as the fallback.
  fallbackAgentId;
  // The unique identifier for this network instance.
  networkId;
  /**
   * Creates an instance of KnowledgeWorkMoENetwork.
   *
   * @param expertAgentIds - An array of agent IDs (keys of agentRegistry) to include as experts.
   *                         These agents must exist and be valid Agent instances in the registry.
   * @param agentRegistry - The complete map of all available agents (imported from `src/mastra/agents`).
   *                        Must not be empty.
   * @param routerModelConfig - Configuration for the Language Model used for routing decisions.
   *                            Choose a model capable of following instructions accurately.
   * @param networkId - A unique identifier string for this network instance (e.g., "knowledge-work-moe-v1").
   * @param fallbackAgentId - The ID of the agent (must be in agentRegistry) to use if routing or execution fails.
   *                          Defaults to "agentic-assistant".
   * @throws {Error} If the agentRegistry is empty, no valid expert agents are found,
   *                 or the specified fallbackAgentId is invalid.
   */
  constructor(expertAgentIds, agentRegistry, routerModelConfig = DEFAULT_MODELS.GOOGLE_STANDARD, networkId = "knowledge-work-moe", fallbackAgentId = DEFAULT_FALLBACK_AGENT_ID) {
    if (!agentRegistry || Object.keys(agentRegistry).length === 0) {
      throw new Error(
        `[${networkId}] Initialization failed: Agent registry cannot be empty.`
      );
    }
    if (!expertAgentIds || expertAgentIds.length === 0) {
      throw new Error(
        `[${networkId}] Initialization failed: At least one expert agent ID must be provided.`
      );
    }
    logger$2.info(`Initializing KnowledgeWorkMoENetwork (ID: ${networkId})...`);
    const localExpertAgentsMap = /* @__PURE__ */ new Map();
    const localDescriptions = [];
    const localExpertAgentsForBaseConfig = [];
    for (const id of expertAgentIds) {
      const agent = agentRegistry[id];
      if (agent instanceof Agent) {
        localExpertAgentsMap.set(id, agent);
        localExpertAgentsForBaseConfig.push(agent);
        const description = agent?.config?.description ?? `${id} (Description unavailable)`;
        localDescriptions.push(`- ${id}: ${description}`);
        logger$2.info(`[${networkId}] Registered expert: ${id}`);
      } else {
        logger$2.warn(
          `[${networkId}] Specified expert agent ID "${id}" not found or invalid in registry. Skipping.`
          // Use parameter
        );
      }
    }
    if (localExpertAgentsMap.size === 0) {
      throw new Error(
        `[${networkId}] Initialization failed: No valid expert agents were found in the registry based on the provided IDs.`
        // Use parameter
      );
    }
    const fallbackAgent = agentRegistry[fallbackAgentId];
    if (!(fallbackAgent instanceof Agent)) {
      logger$2.error(
        `[${networkId}] CRITICAL CONFIGURATION ERROR: Specified fallback agent "${fallbackAgentId}" is not a valid Agent instance in the registry. Fallback mechanism WILL FAIL.`
        // Use parameters
      );
      throw new Error(
        `[${networkId}] Invalid fallback agent ID specified: "${fallbackAgentId}".`
        // Use parameters
      );
    } else if (!localExpertAgentsMap.has(fallbackAgentId)) {
      logger$2.info(
        `[${networkId}] Adding valid fallback agent "${fallbackAgentId}" to network's agent list.`
        // Use parameters
      );
      localExpertAgentsMap.set(fallbackAgentId, fallbackAgent);
      localExpertAgentsForBaseConfig.push(fallbackAgent);
      const description = fallbackAgent?.config?.description ?? `${fallbackAgentId} (Generalist Fallback)`;
      localDescriptions.push(`- ${fallbackAgentId}: ${description}`);
    }
    const expertDescriptions = localDescriptions.join("\n");
    logger$2.debug(
      `[${networkId}] Final expert descriptions for router:
${expertDescriptions}`
      // Use parameter
    );
    const routerInstructions = `
      You are an intelligent routing agent within a multi-agent system operating in a Mixture-of-Experts (MoE) configuration.
      Your SOLE TASK is to analyze the user's request and select the SINGLE most appropriate expert agent from the list below to handle the entire request in one step.
      Base your decision ONLY on the provided agent descriptions and the user's input.
      Do NOT attempt to chain agents, plan multiple steps, or decompose the task.

      Available Experts and their capabilities:
      ${expertDescriptions}

      User Request Analysis Steps:
      1. Understand the primary goal or task described in the user's request.
      2. Compare this goal to the capabilities listed for each expert agent.
      3. Identify the single expert whose capabilities most closely match the user's request.
      4. If no specific expert is a clear and strong match, you MUST select the designated fallback agent: '${fallbackAgentId}'. Do not invent capabilities or force a poor match.

      Your selection determines the *only* agent that will run for this turn. The network flow stops after the selected agent completes its task.
    `;
    const config = {
      name: `Knowledge Work MoE Network (${networkId})`,
      // Use parameter
      // description: // Removed as it's not part of AgentNetworkConfig
      //   "Routes tasks to the most appropriate specialized agent using rules or LLM routing.",
      agents: localExpertAgentsForBaseConfig,
      // Use local list
      model: createModelInstance(routerModelConfig),
      instructions: routerInstructions
      // memory: sharedMemory, // Memory might be handled differently or implicitly by the base class
      // hooks: {} // Add hooks if needed
    };
    super(config);
    this.agentRegistry = agentRegistry;
    this.fallbackAgentId = fallbackAgentId;
    this.networkId = networkId;
    this.expertAgentsMap = localExpertAgentsMap;
    logger$2.info(
      `[${this.networkId}] KnowledgeWorkMoENetwork initialized successfully with ${this.expertAgentsMap.size} agents (including fallback).`
    );
  }
  /**
   * Applies high-confidence, specific rule-based routing for common tasks.
   * Rules are ordered by likely specificity.
   *
   * @param userInput - The user's input string, trimmed and lowercased.
   * @returns The ID of the expert if a high-confidence rule matches, otherwise null.
   */
  _applyRuleBasedRouting(userInput) {
    const lowerInput = userInput.toLowerCase().trim();
    const logPrefix = `[${this.networkId}] Rule:`;
    if ((lowerInput.startsWith("debug") || lowerInput.includes("fix error in") || lowerInput.includes("troubleshoot")) && (lowerInput.includes("code") || lowerInput.includes("script") || lowerInput.includes("function"))) {
      if (this.expertAgentsMap.has("debuggerAgent")) {
        logger$2.info(`${logPrefix} Matched 'debug/fix code' -> debuggerAgent`);
        return "debuggerAgent";
      }
    }
    if (lowerInput.startsWith("document this code") || lowerInput.startsWith("add docstrings to") || lowerInput.startsWith("generate comments for") || lowerInput.startsWith("explain this code")) {
      if (this.expertAgentsMap.has("codeDocumenterAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'document/explain code' -> codeDocumenterAgent`
        );
        return "codeDocumenterAgent";
      }
    }
    if (lowerInput.includes("react component") || lowerInput.includes("css for") || lowerInput.includes("tailwind class") || lowerInput.includes("frontend code for")) {
      if (this.expertAgentsMap.has("uiUxCoderAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'ui/frontend code' -> uiUxCoderAgent`
        );
        return "uiUxCoderAgent";
      }
    }
    if (lowerInput.includes("system design for") || lowerInput.includes("component interaction")) {
      if (this.expertAgentsMap.has("architectAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'architecture/design' -> architectAgent`
        );
        return "architectAgent";
      }
    }
    if (lowerInput.startsWith("refactor") && lowerInput.includes("code")) {
      if (this.expertAgentsMap.has("coderAgent")) {
        logger$2.info(`${logPrefix} Matched 'refactor code' -> coderAgent`);
        return "coderAgent";
      }
    }
    if (lowerInput.startsWith("generate javascript") || lowerInput.startsWith("write code for") || lowerInput.startsWith("create a script")) {
      if (this.expertAgentsMap.has("coderAgent")) {
        logger$2.info(`${logPrefix} Matched 'write code/script' -> coderAgent`);
        return "coderAgent";
      }
    }
    if (lowerInput.includes("research") || lowerInput.includes("find information on") || lowerInput.includes("look up")) {
      if (this.expertAgentsMap.has("researchAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'research/find info' -> researchAgent`
        );
        return "researchAgent";
      }
    }
    if (lowerInput.includes("analyze data") || lowerInput.includes("interpret results") || lowerInput.includes("data insights")) {
      if (this.expertAgentsMap.has("analystAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'analyze/interpret data' -> analystAgent`
        );
        return "analystAgent";
      }
    }
    if (lowerInput.includes("market research for") || lowerInput.includes("competitor analysis") || lowerInput.includes("target audience")) {
      if (this.expertAgentsMap.has("marketResearchAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'market research' -> marketResearchAgent`
        );
        return "marketResearchAgent";
      }
    }
    if (lowerInput.includes("marketing copy for") || lowerInput.includes("write ad copy") || lowerInput.includes("product description") || lowerInput.includes("landing page text")) {
      if (this.expertAgentsMap.has("copywriterAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'copywriting/marketing content' -> copywriterAgent`
        );
        return "copywriterAgent";
      }
    }
    if (lowerInput.includes("social media post") || lowerInput.includes("tweet about") || lowerInput.includes("linkedin update") || lowerInput.includes("instagram caption")) {
      if (this.expertAgentsMap.has("socialMediaAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'social media content' -> socialMediaAgent`
        );
        return "socialMediaAgent";
      }
    }
    if (lowerInput.includes("seo strategy") || lowerInput.includes("keyword research for") || lowerInput.includes("meta description")) {
      if (this.expertAgentsMap.has("seoAgent")) {
        logger$2.info(`${logPrefix} Matched 'seo/keywords' -> seoAgent`);
        return "seoAgent";
      }
    }
    if (lowerInput.includes("manage file") || lowerInput.includes("vector database") || lowerInput.includes("save this data") || lowerInput.includes("organize data")) {
      if (this.expertAgentsMap.has("dataManagerAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'data/file/vector management' -> dataManagerAgent`
        );
        return "dataManagerAgent";
      }
    }
    if (lowerInput.startsWith("write") || lowerInput.startsWith("summarize") || lowerInput.startsWith("draft") || lowerInput.startsWith("explain")) {
      if (this.expertAgentsMap.has("writerAgent")) {
        logger$2.info(
          `${logPrefix} Matched 'write/summarize/draft/explain' -> writerAgent`
        );
        return "writerAgent";
      }
    }
    logger$2.debug(`[${this.networkId}] No high-confidence rule matched input.`);
    return null;
  }
  /**
   * Executes the MoE network logic, overriding the base class method.
   * It first attempts rule-based routing, then falls back to LLM-based routing
   * provided by the base AgentNetwork, and finally uses a designated fallback agent
   * if primary methods fail.
   *
   * @param input - The user input, which can be a string or a structured object.
   * @param options - Optional execution parameters, potentially including a threadId
   *                  or other contextual information.
   * @returns A promise that resolves to the output generated by the selected expert
   *          agent or the fallback agent.
   * @throws {Error} If both the primary execution path (rule-based or LLM-routed)
   *                 and the fallback agent execution fail, or if the fallback agent
   *                 is configured incorrectly.
   */
  async execute(input, options) {
    const inputString = typeof input === "string" ? input : JSON.stringify(input);
    logger$2.info(
      `[${this.networkId}] Executing MoE Network for input: "${inputString.substring(
        0,
        150
      )}..."`,
      { options }
    );
    const ruleBasedExpertId = this._applyRuleBasedRouting(inputString);
    if (ruleBasedExpertId) {
      const expertAgent = this.expertAgentsMap.get(ruleBasedExpertId);
      if (expertAgent) {
        logger$2.info(
          `[${this.networkId}] Rule matched. Bypassing LLM router. Executing expert: ${ruleBasedExpertId}`
        );
        try {
          const agentResourceId = ruleBasedExpertId;
          if (!agentResourceId || typeof agentResourceId !== "string") {
            logger$2.error(
              `[${this.networkId}] Invalid agent ID determined by rule-based routing: ${ruleBasedExpertId}. This should not happen.`
            );
            return this.executeFallback(
              input,
              options,
              `Agent ${ruleBasedExpertId} missing required resourceId.`
            );
          }
          const generateArgs = {
            ...options ?? {},
            // Spread original options
            resourceId: agentResourceId
            // Add required resourceId
          };
          if (typeof generateArgs.threadId !== "string") {
            generateArgs.threadId = `temp-thread-${Date.now()}`;
            logger$2.warn(
              `[${this.networkId}] Missing or invalid threadId in options for rule-based execution. Using temporary ID: ${generateArgs.threadId}`
            );
          }
          const result = await expertAgent.generate(inputString, generateArgs);
          logger$2.info(
            `[${this.networkId}] Rule-based execution for ${ruleBasedExpertId} completed successfully.`
          );
          return result;
        } catch (error) {
          logger$2.error(
            `[${this.networkId}] Rule-based expert "${ruleBasedExpertId}" failed during execution: ${error.message}`,
            { error, input, options }
          );
          return this.executeFallback(
            input,
            options,
            `Rule-based expert ${ruleBasedExpertId} failed: ${error.message}`
          );
        }
      } else {
        logger$2.error(
          `[${this.networkId}] Internal inconsistency: Rule matched expert "${ruleBasedExpertId}" but it's not in the network map. Proceeding to LLM router.`
        );
      }
    }
    logger$2.info(
      `[${this.networkId}] No applicable rule found or rule agent invalid. Using standard AgentNetwork LLM router.`
    );
    try {
      let messages;
      if (typeof input === "string") {
        messages = input;
      } else {
        messages = [{ role: "user", content: JSON.stringify(input) }];
        logger$2.debug(
          `[${this.networkId}] Converted structured input to user message for LLM router.`
        );
      }
      const baseGenerateArgs = {
        ...options ?? {},
        // Spread original options
        resourceId: this.networkId
        // Use the network's ID as the resourceId for routing
      };
      if (typeof baseGenerateArgs.threadId !== "string") {
        baseGenerateArgs.threadId = `temp-network-thread-${Date.now()}`;
        logger$2.warn(
          `[${this.networkId}] Missing or invalid threadId in options for LLM-routed execution. Using temporary ID: ${baseGenerateArgs.threadId}`
        );
      }
      const result = await super.generate(messages, baseGenerateArgs);
      logger$2.info(
        `[${this.networkId}] AgentNetwork LLM-routed execution completed successfully.`
      );
      return result;
    } catch (error) {
      logger$2.error(
        `[${this.networkId}] AgentNetwork LLM-routed execution failed: ${error.message}`,
        { error, input, options }
      );
      return this.executeFallback(
        input,
        options,
        `LLM-routed execution failed: ${error.message}`
      );
    }
  }
  /**
   * Executes the designated fallback agent when primary execution paths fail.
   * Internal helper method. Ensures fallback agent exists and handles its errors.
   *
   * @param originalInput - The original input to the network.
   * @param options - Original execution options potentially containing context like threadId.
   * @param failureReason - A string describing why the fallback is being triggered.
   * @returns {Promise<any>} The result from the fallback agent.
   * @throws {Error} If the fallback agent is unavailable or fails during its execution.
   */
  async executeFallback(originalInput, options, failureReason) {
    logger$2.warn(
      `[${this.networkId}] Triggering fallback agent "${this.fallbackAgentId}" due to: ${failureReason}`
    );
    const fallbackAgent = this.expertAgentsMap.get(this.fallbackAgentId);
    if (!fallbackAgent) {
      logger$2.error(
        `[${this.networkId}] CRITICAL FALLBACK FAILURE: Fallback agent "${this.fallbackAgentId}" is not available in this network instance. Cannot recover.`
      );
      throw new Error(
        `Execution failed (${failureReason}), and fallback agent "${this.fallbackAgentId}" is unavailable.`
      );
    }
    try {
      const fallbackInput = typeof originalInput === "string" ? originalInput : JSON.stringify(originalInput);
      const fallbackArgs = {
        ...options ?? {},
        // Spread original options
        resourceId: this.fallbackAgentId
        // Use the fallback agent's ID
      };
      if (typeof fallbackArgs.threadId !== "string") {
        fallbackArgs.threadId = `temp-fallback-thread-${Date.now()}`;
        logger$2.warn(
          `[${this.networkId}] Missing or invalid threadId in options for fallback execution. Using temporary ID: ${fallbackArgs.threadId}`
        );
      }
      const fallbackResult = await fallbackAgent.generate(
        fallbackInput,
        fallbackArgs
      );
      logger$2.info(
        `[${this.networkId}] Fallback agent "${this.fallbackAgentId}" execution completed successfully.`
      );
      return fallbackResult;
    } catch (fallbackError) {
      logger$2.error(
        `[${this.networkId}] CRITICAL FALLBACK FAILURE: Fallback agent "${this.fallbackAgentId}" also failed: ${fallbackError.message}`,
        { error: fallbackError, originalInput, options }
      );
      throw new Error(
        `Initial execution failed (${failureReason}), and fallback agent "${this.fallbackAgentId}" also failed: ${fallbackError.message}`
      );
    }
  }
  /** Returns the full agent registry (for debugging or dynamic access) */
  getAgentRegistry() {
    return this.agentRegistry;
  }
}

const baseNetworkConfig = {
  model: google("models/gemini-2.0-flash")
  // Note: shared hooks are applied in individual network configurations
  // memory is handled separately as it may not be part of AgentNetworkConfig
};
const deanInsightsHooks = {
  onError: async (error) => {
    console.error("Network error:", error);
    return {
      text: "The agent network encountered an error. Please try again or contact support.",
      error: error.message
    };
  },
  onGenerateResponse: async (response) => {
    const baseHook = createResponseHook({
      minResponseLength: 50,
      maxAttempts: 3,
      validateResponse: (res) => {
        if (res.object) {
          return Object.keys(res.object).length > 0;
        }
        return res.text ? res.text.length >= 50 : false;
      }
    });
    const validatedResponse = await baseHook(response);
    return {
      ...validatedResponse,
      metadata: {
        ...validatedResponse.metadata,
        // Assuming metadata exists
        network: "deanInsights",
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        agentCount: 5
      }
    };
  }
};
const dataFlowHooks = {
  onError: async (error) => {
    console.error("Network error:", error);
    return {
      text: "The agent network encountered an error. Please try again or contact support.",
      error: error.message
    };
  },
  onGenerateResponse: async (response) => {
    const baseHook = createResponseHook({
      minResponseLength: 50,
      maxAttempts: 3,
      validateResponse: (res) => {
        if (res.object) {
          return Object.keys(res.object).length > 0;
        }
        return res.text ? res.text.length >= 50 : false;
      }
    });
    const validatedResponse = await baseHook(response);
    return {
      ...validatedResponse,
      metadata: {
        ...validatedResponse.metadata,
        network: "dataFlow",
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        agentCount: 3
      }
    };
  }
};
const deanInsightsNetwork = new AgentNetwork({
  // id: "dean-insights", // ID is not part of AgentNetworkConfig, set via other means if necessary
  ...baseNetworkConfig,
  // Includes core config
  model: baseNetworkConfig.model,
  // Ensure model is explicitly provided and non-null
  name: "DeanInsights Network",
  agents: [
    researchAgent,
    analystAgent,
    writerAgent,
    rlTrainerAgent,
    dataManagerAgent
  ],
  // Apply hooks directly in the configuration
  hooks: {
    onError: deanInsightsHooks.onError,
    onResponse: deanInsightsHooks.onGenerateResponse
  },
  instructions: `
    You are a coordination system that routes queries to the appropriate specialized agents
    to deliver comprehensive and accurate insights.

    Your available agents are:

    1. Research Agent: Specializes in gathering and synthesizing information from various sources
    2. Analyst Agent: Specializes in analyzing data, identifying patterns, and extracting insights
    3. Writer Agent: Specializes in creating clear, engaging, and well-structured documentation
    4. RL Trainer Agent: Specializes in optimizing agent performance through reinforcement learning
    5. Data Manager Agent: Specializes in file operations and data organization

    For each user query:
    1. Start with the Research Agent to gather relevant information
    2. Route specific analytical tasks to the Analyst Agent
    3. Use the Data Manager Agent for any file operations needed
    4. Have the Writer Agent synthesize findings into a coherent response
    5. Periodically use the RL Trainer Agent to improve overall system performance

    Best practices:
    - Provide clear context when routing between agents
    - Avoid unnecessary agent switches that could lose context
    - Use the most specialized agent for each specific task
    - Ensure attribution of which agent contributed which information
    - When uncertain about a claim, use the Research Agent to verify it

    Note: Each agent has access to specific capabilities:
    - Research Agent: Web search (Exa), document search, knowledge base access
    - Analyst Agent: Data analysis with web search capabilities
    - Writer Agent: Content formatting with web search integration
    - RL Trainer Agent: Performance optimization with feedback tools
    - Data Manager Agent: File operations with knowledge base integration

    Coordinate these capabilities effectively to deliver comprehensive results.

    You should maintain a neutral, objective tone and prioritize accuracy and clarity.
  `
  // hooks: { ... } // Removed hooks from constructor - apply post-instantiation if needed
});
const dataFlowNetwork = new AgentNetwork({
  // id: "data-flow", // ID is not part of AgentNetworkConfig, set via other means if necessary
  ...baseNetworkConfig,
  // Includes core config
  model: baseNetworkConfig.model,
  // Ensure model is explicitly provided and non-null
  name: "DataFlow Network",
  agents: [dataManagerAgent, analystAgent, rlTrainerAgent],
  // Apply hooks directly in the configuration
  hooks: {
    onError: dataFlowHooks.onError,
    onResponse: dataFlowHooks.onGenerateResponse
  },
  instructions: `
    You are a data processing coordination system that orchestrates specialized agents
    to handle data operations, analysis, and optimization tasks.

    Your available agents are:

    1. Data Manager Agent: Specializes in file operations and data organization
    2. Analyst Agent: Specializes in analyzing data, identifying patterns, and extracting insights
    3. RL Trainer Agent: Specializes in optimizing agent performance through reinforcement learning

    For each user task:
    1. Start with the Data Manager Agent to handle file operations and data retrieval
    2. Route analytical tasks to the Analyst Agent to extract meaningful insights
    3. Use the RL Trainer Agent to continuously improve performance based on feedback

    Best practices:
    - Ensure data integrity across all operations
    - Validate inputs and outputs between agent handoffs
    - Log key metrics throughout the process
    - Apply proper error handling at each stage
    - Use the RL Trainer to identify optimization opportunities

    Note: Your agents have the following enhanced capabilities:
    - Data Manager: File operations with knowledge base integration
    - Analyst: Data analysis with web search capabilities
    - RL Trainer: Performance optimization with feedback tools

    Use these capabilities in combination for optimal results.

    Focus on producing accurate, engaging, and valuable content that effectively communicates complex information.
  `
  // hooks: { ... } // Removed hooks from constructor - apply post-instantiation if needed
});
const contentCreationNetwork = new AgentNetwork({
  // id: "content-creation", // ID is not part of AgentNetworkConfig, set via other means if necessary
  ...baseNetworkConfig,
  // Includes model and memory
  model: baseNetworkConfig.model,
  // Ensure model is explicitly provided and non-null
  name: "ContentCreation Network",
  agents: [researchAgent, writerAgent, rlTrainerAgent],
  instructions: `
    You are a content creation coordination system that orchestrates the process
    of researching topics and producing high-quality, well-structured content.

    Your available agents are:

    1. Research Agent: Specializes in gathering and synthesizing information from various sources
    2. Writer Agent: Specializes in creating clear, engaging, and well-structured documentation
    3. RL Trainer Agent: Specializes in optimizing content quality through reinforcement learning

    For each content request:
    1. Start with the Research Agent to gather comprehensive information on the topic
    2. Route to the Writer Agent to transform research into engaging, well-structured content
    3. Use the RL Trainer Agent to analyze feedback and improve content quality over time

    Best practices:
    - Ensure factual accuracy by thorough research
    - Maintain consistent tone and style throughout the content
    - Structure content for maximum readability and engagement
    - Incorporate user feedback to continuously improve content quality
    - Use appropriate formatting and organization for different content types

    Note: Your agents have these enhanced capabilities:
    - Research Agent: Web search (Exa), document search, knowledge base access
    - Writer Agent: Content formatting with web search integration
    - RL Trainer: Content quality optimization through feedback

    Leverage these tools for comprehensive content creation.

    Focus on producing accurate, engaging, and valuable content that effectively communicates complex information.
  `
  // hooks: { ... } // Removed hooks from constructor - apply post-instantiation if needed
});
const moeExpertIds = [
  "researchAgent",
  "analystAgent",
  "writerAgent",
  "coderAgent",
  "debuggerAgent",
  "architectAgent",
  "codeDocumenterAgent",
  "dataManagerAgent",
  "marketResearchAgent",
  "copywriterAgent",
  "socialMediaAgent",
  "seoAgent",
  "uiUxCoderAgent"
  // 'agenticAssistant' // Fallback agent is added automatically by the MoE class if valid & not listed.
];
const moeRouterConfig = DEFAULT_MODELS.GOOGLE_STANDARD;
const knowledgeWorkMoENetwork = new KnowledgeWorkMoENetwork(
  moeExpertIds,
  agents,
  // Pass the full agent registry
  moeRouterConfig,
  "knowledge-work-moe-v1"
  // Unique ID for this network instance
  // fallbackAgentId: 'agenticAssistant' // Default is usually fine
);
const networks = {
  // Use the unique IDs assigned during instantiation as keys
  "dean-insights": deanInsightsNetwork,
  "data-flow": dataFlowNetwork,
  "content-creation": contentCreationNetwork,
  "knowledge-work-moe-v1": knowledgeWorkMoENetwork
  // Add the MoE network using its ID
};

const embeddings = new GoogleGenerativeAIEmbeddings({
  apiKey: process.env.GOOGLE_GENERATIVE_AI_API_KEY
});
const researchStep = new Step({
  id: "research-step",
  description: "Researches the query and gathers relevant information",
  inputSchema: z.object({
    query: z.string().describe("The research query to investigate")
  }),
  execute: async ({ context, mastra }) => {
    if (mastra?.logger) {
      mastra.logger.info("Starting research step execution");
    }
    const triggerData = context?.getStepResult("trigger");
    if (!triggerData) {
      throw new Error("Trigger data not found");
    }
    const response = await researchAgent.generate(
      `Research the following topic in depth: ${triggerData.query}`,
      {
        memoryOptions: {
          lastMessages: 10
        }
      }
    );
    return {
      query: triggerData.query,
      findings: response.text,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const analysisStep = new Step({
  id: "analysis-step",
  description: "Analyzes the research findings and extracts insights",
  inputSchema: z.object({
    query: z.string(),
    findings: z.string(),
    timestamp: z.string()
  }),
  execute: async ({ context, mastra }) => {
    if (mastra?.logger) {
      mastra.logger.info("Starting analysis step execution");
    }
    const researchData = context?.getStepResult("research-step");
    if (!researchData) {
      throw new Error("Research data not found");
    }
    const response = await analystAgent.generate(
      `Analyze these research findings on "${researchData.query}" and extract key insights, patterns, and implications:

${researchData.findings}`,
      {
        memoryOptions: {
          lastMessages: 10
        }
      }
    );
    return {
      query: researchData.query,
      findings: researchData.findings,
      analysis: response.text,
      timestamp: researchData.timestamp
    };
  }
});
const documentationStep = new Step({
  id: "documentation-step",
  description: "Creates a well-formatted document based on research and analysis",
  inputSchema: z.object({
    query: z.string(),
    findings: z.string(),
    analysis: z.string(),
    timestamp: z.string()
  }),
  execute: async ({ context, mastra }) => {
    if (mastra?.logger) {
      mastra.logger.info("Starting documentation step execution");
    }
    const analysisData = context?.getStepResult("analysis-step");
    if (!analysisData) {
      throw new Error("Analysis data not found");
    }
    const response = await writerAgent.generate(
      `Create a comprehensive report based on this research query, findings, and analysis:

QUERY: ${analysisData.query}

FINDINGS: ${analysisData.findings}

ANALYSIS: ${analysisData.analysis}`,
      {
        memoryOptions: {
          lastMessages: 10
        }
      }
    );
    try {
      const pinecone = new Pinecone({
        apiKey: process.env.PINECONE_API_KEY
      });
      const indexName = process.env.PINECONE_INDEX || "Default";
      const pineconeIndex = pinecone.Index(indexName);
      const vectorStore = await PineconeStore.fromExistingIndex(embeddings, {
        pineconeIndex
      });
      await vectorStore.addDocuments([
        {
          pageContent: response.text,
          metadata: {
            query: analysisData.query,
            timestamp: analysisData.timestamp,
            type: "final_report"
          }
        }
      ]);
    } catch (error) {
      console.error("Error storing document in vector database:", error);
    }
    return {
      query: analysisData.query,
      document: response.text,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const feedbackStep = new Step({
  id: "feedback-step",
  description: "Collects feedback for reinforcement learning",
  inputSchema: z.object({
    query: z.string(),
    document: z.string(),
    timestamp: z.string(),
    feedback: z.object({
      accuracy: z.number().min(1).max(10).describe("Accuracy rating (1-10)"),
      completeness: z.number().min(1).max(10).describe("Completeness rating (1-10)"),
      clarity: z.number().min(1).max(10).describe("Clarity rating (1-10)"),
      comments: z.string().optional().describe("Additional feedback comments")
    }).optional()
  }),
  execute: async ({ context, mastra }) => {
    const documentData = context?.getStepResult("documentation-step");
    if (!documentData) {
      throw new Error("Document data not found");
    }
    if (mastra?.logger) {
      mastra.logger.info("Starting document feedback evaluation using AI SDK");
    }
    try {
      const result = await generateText({
        model: google("models/gemini-2.0-flash"),
        prompt: `
        You are an evaluator for research documents. Rate the following document on a scale of 1-10 for:
        1. Accuracy (factual correctness)
        2. Completeness (covers all aspects of the topic)
        3. Clarity (easy to understand)

        Also provide brief comments on what could be improved.

        QUERY: ${documentData.query}
        DOCUMENT: ${documentData.document}

        Return ONLY valid JSON with this structure:
        {
          "accuracy": 7,
          "completeness": 8,
          "clarity": 9,
          "comments": "Brief feedback comments here"
        }
      `
      });
      const feedbackText = result.text;
      let feedback;
      try {
        const jsonMatch = feedbackText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          feedback = JSON.parse(jsonMatch[0]);
        } else {
          feedback = {
            accuracy: 7,
            completeness: 7,
            clarity: 7,
            comments: "Unable to parse specific feedback"
          };
        }
      } catch (jsonError) {
        console.error("Error parsing feedback:", jsonError);
        feedback = {
          accuracy: 7,
          completeness: 7,
          clarity: 7,
          comments: "Error occurred during feedback generation"
        };
      }
      try {
        const feedbackThreadId = `feedback_${documentData.timestamp.replace(
          /[^a-zA-Z0-9]/g,
          ""
        )}`;
        const feedbackResourceId = `feedback_resource_${documentData.query.replace(/\s+/g, "_").toLowerCase()}`;
        await sharedMemory.createThread({
          resourceId: feedbackResourceId,
          threadId: feedbackThreadId,
          title: `Feedback for: ${documentData.query}`,
          metadata: {
            query: documentData.query,
            feedback,
            timestamp: (/* @__PURE__ */ new Date()).toISOString(),
            origin: "system"
          }
        });
      } catch (storageError) {
        console.error("Error storing feedback in memory:", storageError);
      }
      return {
        query: documentData.query,
        document: documentData.document,
        feedback,
        timestamp: documentData.timestamp
      };
    } catch (error) {
      console.error("Error in feedback step:", error);
      return {
        query: documentData.query,
        document: documentData.document,
        feedback: {
          accuracy: 5,
          completeness: 5,
          clarity: 5,
          comments: "Error occurred during feedback collection"
        },
        timestamp: documentData.timestamp
      };
    }
  }
});
const ragWorkflow = new Workflow({
  name: "rag-research-workflow",
  triggerSchema: z.object({
    query: z.string().describe("The research query to investigate")
  })
}).step(researchStep).then(analysisStep).then(documentationStep).then(feedbackStep);
ragWorkflow.commit();

const logger$1 = createLogger({
  name: "DeanMachinesAI-MastraCore",
  level: process.env.LOG_LEVEL === "debug" ? "debug" : "info"
});
logger$1.info("Initializing Mastra instance...");
const mastra = new Mastra({
  agents,
  // All registered agents
  networks,
  // All registered agent networks
  workflows: {
    ragWorkflow
  },
  // Workflows from workflows/index.ts
  logger: logger$1
  // Configured logger
  // Add other global configs as needed (storage, vectors, telemetry, etc.)
});
const agentCount = Object.keys(agents).length;
const networkCount = Object.keys(networks).length;
logger$1.info(`Mastra instance initialized successfully with ${agentCount} agents and ${networkCount} networks.`);
if (agentCount > 0) {
  logger$1.debug(`Registered Agent IDs: ${Object.keys(agents).join(", ")}`);
}
if (networkCount > 0) {
  logger$1.debug(`Registered Network IDs: ${Object.keys(networks).join(", ")}`);
}

// src/utils/filepath.ts
var getFilePath = (options) => {
  let filename = options.filename;
  const defaultDocument = options.defaultDocument || "index.html";
  if (filename.endsWith("/")) {
    filename = filename.concat(defaultDocument);
  } else if (!filename.match(/\.[a-zA-Z0-9_-]+$/)) {
    filename = filename.concat("/" + defaultDocument);
  }
  const path = getFilePathWithoutDefaultDocument({
    root: options.root,
    filename
  });
  return path;
};
var getFilePathWithoutDefaultDocument = (options) => {
  let root = options.root || "";
  let filename = options.filename;
  if (/(?:^|[\/\\])\.\.(?:$|[\/\\])/.test(filename)) {
    return;
  }
  filename = filename.replace(/^\.?[\/\\]/, "");
  filename = filename.replace(/\\/, "/");
  root = root.replace(/\/$/, "");
  let path = root ? root + "/" + filename : filename;
  path = path.replace(/^\.?\//, "");
  if (root[0] !== "/" && path[0] === "/") {
    return;
  }
  return path;
};

// src/utils/mime.ts
var getMimeType = (filename, mimes = baseMimes) => {
  const regexp = /\.([a-zA-Z0-9]+?)$/;
  const match = filename.match(regexp);
  if (!match) {
    return;
  }
  let mimeType = mimes[match[1]];
  if (mimeType && mimeType.startsWith("text")) {
    mimeType += "; charset=utf-8";
  }
  return mimeType;
};
var _baseMimes = {
  aac: "audio/aac",
  avi: "video/x-msvideo",
  avif: "image/avif",
  av1: "video/av1",
  bin: "application/octet-stream",
  bmp: "image/bmp",
  css: "text/css",
  csv: "text/csv",
  eot: "application/vnd.ms-fontobject",
  epub: "application/epub+zip",
  gif: "image/gif",
  gz: "application/gzip",
  htm: "text/html",
  html: "text/html",
  ico: "image/x-icon",
  ics: "text/calendar",
  jpeg: "image/jpeg",
  jpg: "image/jpeg",
  js: "text/javascript",
  json: "application/json",
  jsonld: "application/ld+json",
  map: "application/json",
  mid: "audio/x-midi",
  midi: "audio/x-midi",
  mjs: "text/javascript",
  mp3: "audio/mpeg",
  mp4: "video/mp4",
  mpeg: "video/mpeg",
  oga: "audio/ogg",
  ogv: "video/ogg",
  ogx: "application/ogg",
  opus: "audio/opus",
  otf: "font/otf",
  pdf: "application/pdf",
  png: "image/png",
  rtf: "application/rtf",
  svg: "image/svg+xml",
  tif: "image/tiff",
  tiff: "image/tiff",
  ts: "video/mp2t",
  ttf: "font/ttf",
  txt: "text/plain",
  wasm: "application/wasm",
  webm: "video/webm",
  weba: "audio/webm",
  webp: "image/webp",
  woff: "font/woff",
  woff2: "font/woff2",
  xhtml: "application/xhtml+xml",
  xml: "application/xml",
  zip: "application/zip",
  "3gp": "video/3gpp",
  "3g2": "video/3gpp2",
  gltf: "model/gltf+json",
  glb: "model/gltf-binary"
};
var baseMimes = _baseMimes;

// src/utils/html.ts
var HtmlEscapedCallbackPhase = {
  Stringify: 1};
var raw = (value, callbacks) => {
  const escapedString = new String(value);
  escapedString.isEscaped = true;
  escapedString.callbacks = callbacks;
  return escapedString;
};
var escapeRe = /[&<>'"]/;
var stringBufferToString = async (buffer, callbacks) => {
  let str = "";
  callbacks ||= [];
  const resolvedBuffer = await Promise.all(buffer);
  for (let i = resolvedBuffer.length - 1; ; i--) {
    str += resolvedBuffer[i];
    i--;
    if (i < 0) {
      break;
    }
    let r = resolvedBuffer[i];
    if (typeof r === "object") {
      callbacks.push(...r.callbacks || []);
    }
    const isEscaped = r.isEscaped;
    r = await (typeof r === "object" ? r.toString() : r);
    if (typeof r === "object") {
      callbacks.push(...r.callbacks || []);
    }
    if (r.isEscaped ?? isEscaped) {
      str += r;
    } else {
      const buf = [str];
      escapeToBuffer(r, buf);
      str = buf[0];
    }
  }
  return raw(str, callbacks);
};
var escapeToBuffer = (str, buffer) => {
  const match = str.search(escapeRe);
  if (match === -1) {
    buffer[0] += str;
    return;
  }
  let escape;
  let index;
  let lastIndex = 0;
  for (index = match; index < str.length; index++) {
    switch (str.charCodeAt(index)) {
      case 34:
        escape = "&quot;";
        break;
      case 39:
        escape = "&#39;";
        break;
      case 38:
        escape = "&amp;";
        break;
      case 60:
        escape = "&lt;";
        break;
      case 62:
        escape = "&gt;";
        break;
      default:
        continue;
    }
    buffer[0] += str.substring(lastIndex, index) + escape;
    lastIndex = index + 1;
  }
  buffer[0] += str.substring(lastIndex, index);
};
var resolveCallbackSync = (str) => {
  const callbacks = str.callbacks;
  if (!callbacks?.length) {
    return str;
  }
  const buffer = [str];
  const context = {};
  callbacks.forEach((c) => c({ phase: HtmlEscapedCallbackPhase.Stringify, buffer, context }));
  return buffer[0];
};
var resolveCallback = async (str, phase, preserveCallbacks, context, buffer) => {
  if (typeof str === "object" && !(str instanceof String)) {
    if (!(str instanceof Promise)) {
      str = str.toString();
    }
    if (str instanceof Promise) {
      str = await str;
    }
  }
  const callbacks = str.callbacks;
  if (!callbacks?.length) {
    return Promise.resolve(str);
  }
  if (buffer) {
    buffer[0] += str;
  } else {
    buffer = [str];
  }
  const resStr = Promise.all(callbacks.map((c) => c({ phase, buffer, context }))).then(
    (res) => Promise.all(
      res.filter(Boolean).map((str2) => resolveCallback(str2, phase, false, context, buffer))
    ).then(() => buffer[0])
  );
  {
    return resStr;
  }
};

// src/helper/html/index.ts
var html = (strings, ...values) => {
  const buffer = [""];
  for (let i = 0, len = strings.length - 1; i < len; i++) {
    buffer[0] += strings[i];
    const children = Array.isArray(values[i]) ? values[i].flat(Infinity) : [values[i]];
    for (let i2 = 0, len2 = children.length; i2 < len2; i2++) {
      const child = children[i2];
      if (typeof child === "string") {
        escapeToBuffer(child, buffer);
      } else if (typeof child === "number") {
        buffer[0] += child;
      } else if (typeof child === "boolean" || child === null || child === void 0) {
        continue;
      } else if (typeof child === "object" && child.isEscaped) {
        if (child.callbacks) {
          buffer.unshift("", child);
        } else {
          const tmp = child.toString();
          if (tmp instanceof Promise) {
            buffer.unshift("", tmp);
          } else {
            buffer[0] += tmp;
          }
        }
      } else if (child instanceof Promise) {
        buffer.unshift("", child);
      } else {
        escapeToBuffer(child.toString(), buffer);
      }
    }
  }
  buffer[0] += strings.at(-1);
  return buffer.length === 1 ? "callbacks" in buffer ? raw(resolveCallbackSync(raw(buffer[0], buffer.callbacks))) : raw(buffer[0]) : stringBufferToString(buffer, buffer.callbacks);
};

// src/compose.ts
var compose = (middleware, onError, onNotFound) => {
  return (context, next) => {
    let index = -1;
    return dispatch(0);
    async function dispatch(i) {
      if (i <= index) {
        throw new Error("next() called multiple times");
      }
      index = i;
      let res;
      let isError = false;
      let handler;
      if (middleware[i]) {
        handler = middleware[i][0][0];
        context.req.routeIndex = i;
      } else {
        handler = i === middleware.length && next || void 0;
      }
      if (handler) {
        try {
          res = await handler(context, () => dispatch(i + 1));
        } catch (err) {
          if (err instanceof Error && onError) {
            context.error = err;
            res = await onError(err, context);
            isError = true;
          } else {
            throw err;
          }
        }
      } else {
        if (context.finalized === false && onNotFound) {
          res = await onNotFound(context);
        }
      }
      if (res && (context.finalized === false || isError)) {
        context.res = res;
      }
      return context;
    }
  };
};

// src/utils/body.ts
var parseBody = async (request, options = /* @__PURE__ */ Object.create(null)) => {
  const { all = false, dot = false } = options;
  const headers = request instanceof HonoRequest ? request.raw.headers : request.headers;
  const contentType = headers.get("Content-Type");
  if (contentType?.startsWith("multipart/form-data") || contentType?.startsWith("application/x-www-form-urlencoded")) {
    return parseFormData(request, { all, dot });
  }
  return {};
};
async function parseFormData(request, options) {
  const formData = await request.formData();
  if (formData) {
    return convertFormDataToBodyData(formData, options);
  }
  return {};
}
function convertFormDataToBodyData(formData, options) {
  const form = /* @__PURE__ */ Object.create(null);
  formData.forEach((value, key) => {
    const shouldParseAllValues = options.all || key.endsWith("[]");
    if (!shouldParseAllValues) {
      form[key] = value;
    } else {
      handleParsingAllValues(form, key, value);
    }
  });
  if (options.dot) {
    Object.entries(form).forEach(([key, value]) => {
      const shouldParseDotValues = key.includes(".");
      if (shouldParseDotValues) {
        handleParsingNestedValues(form, key, value);
        delete form[key];
      }
    });
  }
  return form;
}
var handleParsingAllValues = (form, key, value) => {
  if (form[key] !== void 0) {
    if (Array.isArray(form[key])) {
      form[key].push(value);
    } else {
      form[key] = [form[key], value];
    }
  } else {
    form[key] = value;
  }
};
var handleParsingNestedValues = (form, key, value) => {
  let nestedForm = form;
  const keys = key.split(".");
  keys.forEach((key2, index) => {
    if (index === keys.length - 1) {
      nestedForm[key2] = value;
    } else {
      if (!nestedForm[key2] || typeof nestedForm[key2] !== "object" || Array.isArray(nestedForm[key2]) || nestedForm[key2] instanceof File) {
        nestedForm[key2] = /* @__PURE__ */ Object.create(null);
      }
      nestedForm = nestedForm[key2];
    }
  });
};

// src/utils/url.ts
var splitPath = (path) => {
  const paths = path.split("/");
  if (paths[0] === "") {
    paths.shift();
  }
  return paths;
};
var splitRoutingPath = (routePath) => {
  const { groups, path } = extractGroupsFromPath(routePath);
  const paths = splitPath(path);
  return replaceGroupMarks(paths, groups);
};
var extractGroupsFromPath = (path) => {
  const groups = [];
  path = path.replace(/\{[^}]+\}/g, (match, index) => {
    const mark = `@${index}`;
    groups.push([mark, match]);
    return mark;
  });
  return { groups, path };
};
var replaceGroupMarks = (paths, groups) => {
  for (let i = groups.length - 1; i >= 0; i--) {
    const [mark] = groups[i];
    for (let j = paths.length - 1; j >= 0; j--) {
      if (paths[j].includes(mark)) {
        paths[j] = paths[j].replace(mark, groups[i][1]);
        break;
      }
    }
  }
  return paths;
};
var patternCache = {};
var getPattern = (label, next) => {
  if (label === "*") {
    return "*";
  }
  const match = label.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
  if (match) {
    const cacheKey = `${label}#${next}`;
    if (!patternCache[cacheKey]) {
      if (match[2]) {
        patternCache[cacheKey] = next && next[0] !== ":" && next[0] !== "*" ? [cacheKey, match[1], new RegExp(`^${match[2]}(?=/${next})`)] : [label, match[1], new RegExp(`^${match[2]}$`)];
      } else {
        patternCache[cacheKey] = [label, match[1], true];
      }
    }
    return patternCache[cacheKey];
  }
  return null;
};
var tryDecode = (str, decoder) => {
  try {
    return decoder(str);
  } catch {
    return str.replace(/(?:%[0-9A-Fa-f]{2})+/g, (match) => {
      try {
        return decoder(match);
      } catch {
        return match;
      }
    });
  }
};
var tryDecodeURI = (str) => tryDecode(str, decodeURI);
var getPath = (request) => {
  const url = request.url;
  const start = url.indexOf("/", 8);
  let i = start;
  for (; i < url.length; i++) {
    const charCode = url.charCodeAt(i);
    if (charCode === 37) {
      const queryIndex = url.indexOf("?", i);
      const path = url.slice(start, queryIndex === -1 ? void 0 : queryIndex);
      return tryDecodeURI(path.includes("%25") ? path.replace(/%25/g, "%2525") : path);
    } else if (charCode === 63) {
      break;
    }
  }
  return url.slice(start, i);
};
var getPathNoStrict = (request) => {
  const result = getPath(request);
  return result.length > 1 && result.at(-1) === "/" ? result.slice(0, -1) : result;
};
var mergePath = (base, sub, ...rest) => {
  if (rest.length) {
    sub = mergePath(sub, ...rest);
  }
  return `${base?.[0] === "/" ? "" : "/"}${base}${sub === "/" ? "" : `${base?.at(-1) === "/" ? "" : "/"}${sub?.[0] === "/" ? sub.slice(1) : sub}`}`;
};
var checkOptionalParameter = (path) => {
  if (path.charCodeAt(path.length - 1) !== 63 || !path.includes(":")) {
    return null;
  }
  const segments = path.split("/");
  const results = [];
  let basePath = "";
  segments.forEach((segment) => {
    if (segment !== "" && !/\:/.test(segment)) {
      basePath += "/" + segment;
    } else if (/\:/.test(segment)) {
      if (/\?/.test(segment)) {
        if (results.length === 0 && basePath === "") {
          results.push("/");
        } else {
          results.push(basePath);
        }
        const optionalSegment = segment.replace("?", "");
        basePath += "/" + optionalSegment;
        results.push(basePath);
      } else {
        basePath += "/" + segment;
      }
    }
  });
  return results.filter((v, i, a) => a.indexOf(v) === i);
};
var _decodeURI = (value) => {
  if (!/[%+]/.test(value)) {
    return value;
  }
  if (value.indexOf("+") !== -1) {
    value = value.replace(/\+/g, " ");
  }
  return value.indexOf("%") !== -1 ? decodeURIComponent_(value) : value;
};
var _getQueryParam = (url, key, multiple) => {
  let encoded;
  if (!multiple && key && !/[%+]/.test(key)) {
    let keyIndex2 = url.indexOf(`?${key}`, 8);
    if (keyIndex2 === -1) {
      keyIndex2 = url.indexOf(`&${key}`, 8);
    }
    while (keyIndex2 !== -1) {
      const trailingKeyCode = url.charCodeAt(keyIndex2 + key.length + 1);
      if (trailingKeyCode === 61) {
        const valueIndex = keyIndex2 + key.length + 2;
        const endIndex = url.indexOf("&", valueIndex);
        return _decodeURI(url.slice(valueIndex, endIndex === -1 ? void 0 : endIndex));
      } else if (trailingKeyCode == 38 || isNaN(trailingKeyCode)) {
        return "";
      }
      keyIndex2 = url.indexOf(`&${key}`, keyIndex2 + 1);
    }
    encoded = /[%+]/.test(url);
    if (!encoded) {
      return void 0;
    }
  }
  const results = {};
  encoded ??= /[%+]/.test(url);
  let keyIndex = url.indexOf("?", 8);
  while (keyIndex !== -1) {
    const nextKeyIndex = url.indexOf("&", keyIndex + 1);
    let valueIndex = url.indexOf("=", keyIndex);
    if (valueIndex > nextKeyIndex && nextKeyIndex !== -1) {
      valueIndex = -1;
    }
    let name = url.slice(
      keyIndex + 1,
      valueIndex === -1 ? nextKeyIndex === -1 ? void 0 : nextKeyIndex : valueIndex
    );
    if (encoded) {
      name = _decodeURI(name);
    }
    keyIndex = nextKeyIndex;
    if (name === "") {
      continue;
    }
    let value;
    if (valueIndex === -1) {
      value = "";
    } else {
      value = url.slice(valueIndex + 1, nextKeyIndex === -1 ? void 0 : nextKeyIndex);
      if (encoded) {
        value = _decodeURI(value);
      }
    }
    if (multiple) {
      if (!(results[name] && Array.isArray(results[name]))) {
        results[name] = [];
      }
      results[name].push(value);
    } else {
      results[name] ??= value;
    }
  }
  return key ? results[key] : results;
};
var getQueryParam = _getQueryParam;
var getQueryParams = (url, key) => {
  return _getQueryParam(url, key, true);
};
var decodeURIComponent_ = decodeURIComponent;

// src/request.ts
var tryDecodeURIComponent = (str) => tryDecode(str, decodeURIComponent_);
var HonoRequest = class {
  raw;
  #validatedData;
  #matchResult;
  routeIndex = 0;
  path;
  bodyCache = {};
  constructor(request, path = "/", matchResult = [[]]) {
    this.raw = request;
    this.path = path;
    this.#matchResult = matchResult;
    this.#validatedData = {};
  }
  param(key) {
    return key ? this.#getDecodedParam(key) : this.#getAllDecodedParams();
  }
  #getDecodedParam(key) {
    const paramKey = this.#matchResult[0][this.routeIndex][1][key];
    const param = this.#getParamValue(paramKey);
    return param ? /\%/.test(param) ? tryDecodeURIComponent(param) : param : void 0;
  }
  #getAllDecodedParams() {
    const decoded = {};
    const keys = Object.keys(this.#matchResult[0][this.routeIndex][1]);
    for (const key of keys) {
      const value = this.#getParamValue(this.#matchResult[0][this.routeIndex][1][key]);
      if (value && typeof value === "string") {
        decoded[key] = /\%/.test(value) ? tryDecodeURIComponent(value) : value;
      }
    }
    return decoded;
  }
  #getParamValue(paramKey) {
    return this.#matchResult[1] ? this.#matchResult[1][paramKey] : paramKey;
  }
  query(key) {
    return getQueryParam(this.url, key);
  }
  queries(key) {
    return getQueryParams(this.url, key);
  }
  header(name) {
    if (name) {
      return this.raw.headers.get(name) ?? void 0;
    }
    const headerData = {};
    this.raw.headers.forEach((value, key) => {
      headerData[key] = value;
    });
    return headerData;
  }
  async parseBody(options) {
    return this.bodyCache.parsedBody ??= await parseBody(this, options);
  }
  #cachedBody = (key) => {
    const { bodyCache, raw } = this;
    const cachedBody = bodyCache[key];
    if (cachedBody) {
      return cachedBody;
    }
    const anyCachedKey = Object.keys(bodyCache)[0];
    if (anyCachedKey) {
      return bodyCache[anyCachedKey].then((body) => {
        if (anyCachedKey === "json") {
          body = JSON.stringify(body);
        }
        return new Response(body)[key]();
      });
    }
    return bodyCache[key] = raw[key]();
  };
  json() {
    return this.#cachedBody("json");
  }
  text() {
    return this.#cachedBody("text");
  }
  arrayBuffer() {
    return this.#cachedBody("arrayBuffer");
  }
  blob() {
    return this.#cachedBody("blob");
  }
  formData() {
    return this.#cachedBody("formData");
  }
  addValidatedData(target, data) {
    this.#validatedData[target] = data;
  }
  valid(target) {
    return this.#validatedData[target];
  }
  get url() {
    return this.raw.url;
  }
  get method() {
    return this.raw.method;
  }
  get matchedRoutes() {
    return this.#matchResult[0].map(([[, route]]) => route);
  }
  get routePath() {
    return this.#matchResult[0].map(([[, route]]) => route)[this.routeIndex].path;
  }
};

// src/context.ts
var TEXT_PLAIN = "text/plain; charset=UTF-8";
var setHeaders = (headers, map = {}) => {
  for (const key of Object.keys(map)) {
    headers.set(key, map[key]);
  }
  return headers;
};
var Context = class {
  #rawRequest;
  #req;
  env = {};
  #var;
  finalized = false;
  error;
  #status = 200;
  #executionCtx;
  #headers;
  #preparedHeaders;
  #res;
  #isFresh = true;
  #layout;
  #renderer;
  #notFoundHandler;
  #matchResult;
  #path;
  constructor(req, options) {
    this.#rawRequest = req;
    if (options) {
      this.#executionCtx = options.executionCtx;
      this.env = options.env;
      this.#notFoundHandler = options.notFoundHandler;
      this.#path = options.path;
      this.#matchResult = options.matchResult;
    }
  }
  get req() {
    this.#req ??= new HonoRequest(this.#rawRequest, this.#path, this.#matchResult);
    return this.#req;
  }
  get event() {
    if (this.#executionCtx && "respondWith" in this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no FetchEvent");
    }
  }
  get executionCtx() {
    if (this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no ExecutionContext");
    }
  }
  get res() {
    this.#isFresh = false;
    return this.#res ||= new Response("404 Not Found", { status: 404 });
  }
  set res(_res) {
    this.#isFresh = false;
    if (this.#res && _res) {
      try {
        for (const [k, v] of this.#res.headers.entries()) {
          if (k === "content-type") {
            continue;
          }
          if (k === "set-cookie") {
            const cookies = this.#res.headers.getSetCookie();
            _res.headers.delete("set-cookie");
            for (const cookie of cookies) {
              _res.headers.append("set-cookie", cookie);
            }
          } else {
            _res.headers.set(k, v);
          }
        }
      } catch (e) {
        if (e instanceof TypeError && e.message.includes("immutable")) {
          this.res = new Response(_res.body, {
            headers: _res.headers,
            status: _res.status
          });
          return;
        } else {
          throw e;
        }
      }
    }
    this.#res = _res;
    this.finalized = true;
  }
  render = (...args) => {
    this.#renderer ??= (content) => this.html(content);
    return this.#renderer(...args);
  };
  setLayout = (layout) => this.#layout = layout;
  getLayout = () => this.#layout;
  setRenderer = (renderer) => {
    this.#renderer = renderer;
  };
  header = (name, value, options) => {
    if (value === void 0) {
      if (this.#headers) {
        this.#headers.delete(name);
      } else if (this.#preparedHeaders) {
        delete this.#preparedHeaders[name.toLocaleLowerCase()];
      }
      if (this.finalized) {
        this.res.headers.delete(name);
      }
      return;
    }
    if (options?.append) {
      if (!this.#headers) {
        this.#isFresh = false;
        this.#headers = new Headers(this.#preparedHeaders);
        this.#preparedHeaders = {};
      }
      this.#headers.append(name, value);
    } else {
      if (this.#headers) {
        this.#headers.set(name, value);
      } else {
        this.#preparedHeaders ??= {};
        this.#preparedHeaders[name.toLowerCase()] = value;
      }
    }
    if (this.finalized) {
      if (options?.append) {
        this.res.headers.append(name, value);
      } else {
        this.res.headers.set(name, value);
      }
    }
  };
  status = (status) => {
    this.#isFresh = false;
    this.#status = status;
  };
  set = (key, value) => {
    this.#var ??= /* @__PURE__ */ new Map();
    this.#var.set(key, value);
  };
  get = (key) => {
    return this.#var ? this.#var.get(key) : void 0;
  };
  get var() {
    if (!this.#var) {
      return {};
    }
    return Object.fromEntries(this.#var);
  }
  #newResponse(data, arg, headers) {
    if (this.#isFresh && !headers && !arg && this.#status === 200) {
      return new Response(data, {
        headers: this.#preparedHeaders
      });
    }
    if (arg && typeof arg !== "number") {
      const header = new Headers(arg.headers);
      if (this.#headers) {
        this.#headers.forEach((v, k) => {
          if (k === "set-cookie") {
            header.append(k, v);
          } else {
            header.set(k, v);
          }
        });
      }
      const headers2 = setHeaders(header, this.#preparedHeaders);
      return new Response(data, {
        headers: headers2,
        status: arg.status ?? this.#status
      });
    }
    const status = typeof arg === "number" ? arg : this.#status;
    this.#preparedHeaders ??= {};
    this.#headers ??= new Headers();
    setHeaders(this.#headers, this.#preparedHeaders);
    if (this.#res) {
      this.#res.headers.forEach((v, k) => {
        if (k === "set-cookie") {
          this.#headers?.append(k, v);
        } else {
          this.#headers?.set(k, v);
        }
      });
      setHeaders(this.#headers, this.#preparedHeaders);
    }
    headers ??= {};
    for (const [k, v] of Object.entries(headers)) {
      if (typeof v === "string") {
        this.#headers.set(k, v);
      } else {
        this.#headers.delete(k);
        for (const v2 of v) {
          this.#headers.append(k, v2);
        }
      }
    }
    return new Response(data, {
      status,
      headers: this.#headers
    });
  }
  newResponse = (...args) => this.#newResponse(...args);
  body = (data, arg, headers) => {
    return typeof arg === "number" ? this.#newResponse(data, arg, headers) : this.#newResponse(data, arg);
  };
  text = (text, arg, headers) => {
    if (!this.#preparedHeaders) {
      if (this.#isFresh && !headers && !arg) {
        return new Response(text);
      }
      this.#preparedHeaders = {};
    }
    this.#preparedHeaders["content-type"] = TEXT_PLAIN;
    if (typeof arg === "number") {
      return this.#newResponse(text, arg, headers);
    }
    return this.#newResponse(text, arg);
  };
  json = (object, arg, headers) => {
    const body = JSON.stringify(object);
    this.#preparedHeaders ??= {};
    this.#preparedHeaders["content-type"] = "application/json";
    return typeof arg === "number" ? this.#newResponse(body, arg, headers) : this.#newResponse(body, arg);
  };
  html = (html, arg, headers) => {
    this.#preparedHeaders ??= {};
    this.#preparedHeaders["content-type"] = "text/html; charset=UTF-8";
    if (typeof html === "object") {
      return resolveCallback(html, HtmlEscapedCallbackPhase.Stringify, false, {}).then((html2) => {
        return typeof arg === "number" ? this.#newResponse(html2, arg, headers) : this.#newResponse(html2, arg);
      });
    }
    return typeof arg === "number" ? this.#newResponse(html, arg, headers) : this.#newResponse(html, arg);
  };
  redirect = (location, status) => {
    this.#headers ??= new Headers();
    this.#headers.set("Location", String(location));
    return this.newResponse(null, status ?? 302);
  };
  notFound = () => {
    this.#notFoundHandler ??= () => new Response();
    return this.#notFoundHandler(this);
  };
};

// src/router.ts
var METHOD_NAME_ALL = "ALL";
var METHOD_NAME_ALL_LOWERCASE = "all";
var METHODS = ["get", "post", "put", "delete", "options", "patch"];
var MESSAGE_MATCHER_IS_ALREADY_BUILT = "Can not add a route since the matcher is already built.";
var UnsupportedPathError = class extends Error {
};

// src/utils/constants.ts
var COMPOSED_HANDLER = "__COMPOSED_HANDLER";

// src/hono-base.ts
var notFoundHandler = (c) => {
  return c.text("404 Not Found", 404);
};
var errorHandler$1 = (err, c) => {
  if ("getResponse" in err) {
    return err.getResponse();
  }
  console.error(err);
  return c.text("Internal Server Error", 500);
};
var Hono$1 = class Hono {
  get;
  post;
  put;
  delete;
  options;
  patch;
  all;
  on;
  use;
  router;
  getPath;
  _basePath = "/";
  #path = "/";
  routes = [];
  constructor(options = {}) {
    const allMethods = [...METHODS, METHOD_NAME_ALL_LOWERCASE];
    allMethods.forEach((method) => {
      this[method] = (args1, ...args) => {
        if (typeof args1 === "string") {
          this.#path = args1;
        } else {
          this.#addRoute(method, this.#path, args1);
        }
        args.forEach((handler) => {
          this.#addRoute(method, this.#path, handler);
        });
        return this;
      };
    });
    this.on = (method, path, ...handlers) => {
      for (const p of [path].flat()) {
        this.#path = p;
        for (const m of [method].flat()) {
          handlers.map((handler) => {
            this.#addRoute(m.toUpperCase(), this.#path, handler);
          });
        }
      }
      return this;
    };
    this.use = (arg1, ...handlers) => {
      if (typeof arg1 === "string") {
        this.#path = arg1;
      } else {
        this.#path = "*";
        handlers.unshift(arg1);
      }
      handlers.forEach((handler) => {
        this.#addRoute(METHOD_NAME_ALL, this.#path, handler);
      });
      return this;
    };
    const { strict, ...optionsWithoutStrict } = options;
    Object.assign(this, optionsWithoutStrict);
    this.getPath = strict ?? true ? options.getPath ?? getPath : getPathNoStrict;
  }
  #clone() {
    const clone = new Hono$1({
      router: this.router,
      getPath: this.getPath
    });
    clone.routes = this.routes;
    return clone;
  }
  #notFoundHandler = notFoundHandler;
  errorHandler = errorHandler$1;
  route(path, app) {
    const subApp = this.basePath(path);
    app.routes.map((r) => {
      let handler;
      if (app.errorHandler === errorHandler$1) {
        handler = r.handler;
      } else {
        handler = async (c, next) => (await compose([], app.errorHandler)(c, () => r.handler(c, next))).res;
        handler[COMPOSED_HANDLER] = r.handler;
      }
      subApp.#addRoute(r.method, r.path, handler);
    });
    return this;
  }
  basePath(path) {
    const subApp = this.#clone();
    subApp._basePath = mergePath(this._basePath, path);
    return subApp;
  }
  onError = (handler) => {
    this.errorHandler = handler;
    return this;
  };
  notFound = (handler) => {
    this.#notFoundHandler = handler;
    return this;
  };
  mount(path, applicationHandler, options) {
    let replaceRequest;
    let optionHandler;
    if (options) {
      if (typeof options === "function") {
        optionHandler = options;
      } else {
        optionHandler = options.optionHandler;
        replaceRequest = options.replaceRequest;
      }
    }
    const getOptions = optionHandler ? (c) => {
      const options2 = optionHandler(c);
      return Array.isArray(options2) ? options2 : [options2];
    } : (c) => {
      let executionContext = void 0;
      try {
        executionContext = c.executionCtx;
      } catch {
      }
      return [c.env, executionContext];
    };
    replaceRequest ||= (() => {
      const mergedPath = mergePath(this._basePath, path);
      const pathPrefixLength = mergedPath === "/" ? 0 : mergedPath.length;
      return (request) => {
        const url = new URL(request.url);
        url.pathname = url.pathname.slice(pathPrefixLength) || "/";
        return new Request(url, request);
      };
    })();
    const handler = async (c, next) => {
      const res = await applicationHandler(replaceRequest(c.req.raw), ...getOptions(c));
      if (res) {
        return res;
      }
      await next();
    };
    this.#addRoute(METHOD_NAME_ALL, mergePath(path, "*"), handler);
    return this;
  }
  #addRoute(method, path, handler) {
    method = method.toUpperCase();
    path = mergePath(this._basePath, path);
    const r = { path, method, handler };
    this.router.add(method, path, [handler, r]);
    this.routes.push(r);
  }
  #handleError(err, c) {
    if (err instanceof Error) {
      return this.errorHandler(err, c);
    }
    throw err;
  }
  #dispatch(request, executionCtx, env, method) {
    if (method === "HEAD") {
      return (async () => new Response(null, await this.#dispatch(request, executionCtx, env, "GET")))();
    }
    const path = this.getPath(request, { env });
    const matchResult = this.router.match(method, path);
    const c = new Context(request, {
      path,
      matchResult,
      env,
      executionCtx,
      notFoundHandler: this.#notFoundHandler
    });
    if (matchResult[0].length === 1) {
      let res;
      try {
        res = matchResult[0][0][0][0](c, async () => {
          c.res = await this.#notFoundHandler(c);
        });
      } catch (err) {
        return this.#handleError(err, c);
      }
      return res instanceof Promise ? res.then(
        (resolved) => resolved || (c.finalized ? c.res : this.#notFoundHandler(c))
      ).catch((err) => this.#handleError(err, c)) : res ?? this.#notFoundHandler(c);
    }
    const composed = compose(matchResult[0], this.errorHandler, this.#notFoundHandler);
    return (async () => {
      try {
        const context = await composed(c);
        if (!context.finalized) {
          throw new Error(
            "Context is not finalized. Did you forget to return a Response object or `await next()`?"
          );
        }
        return context.res;
      } catch (err) {
        return this.#handleError(err, c);
      }
    })();
  }
  fetch = (request, ...rest) => {
    return this.#dispatch(request, rest[1], rest[0], request.method);
  };
  request = (input, requestInit, Env, executionCtx) => {
    if (input instanceof Request) {
      return this.fetch(requestInit ? new Request(input, requestInit) : input, Env, executionCtx);
    }
    input = input.toString();
    return this.fetch(
      new Request(
        /^https?:\/\//.test(input) ? input : `http://localhost${mergePath("/", input)}`,
        requestInit
      ),
      Env,
      executionCtx
    );
  };
  fire = () => {
    addEventListener("fetch", (event) => {
      event.respondWith(this.#dispatch(event.request, event, void 0, event.request.method));
    });
  };
};

// src/router/reg-exp-router/node.ts
var LABEL_REG_EXP_STR = "[^/]+";
var ONLY_WILDCARD_REG_EXP_STR = ".*";
var TAIL_WILDCARD_REG_EXP_STR = "(?:|/.*)";
var PATH_ERROR = Symbol();
var regExpMetaChars = new Set(".\\+*[^]$()");
function compareKey(a, b) {
  if (a.length === 1) {
    return b.length === 1 ? a < b ? -1 : 1 : -1;
  }
  if (b.length === 1) {
    return 1;
  }
  if (a === ONLY_WILDCARD_REG_EXP_STR || a === TAIL_WILDCARD_REG_EXP_STR) {
    return 1;
  } else if (b === ONLY_WILDCARD_REG_EXP_STR || b === TAIL_WILDCARD_REG_EXP_STR) {
    return -1;
  }
  if (a === LABEL_REG_EXP_STR) {
    return 1;
  } else if (b === LABEL_REG_EXP_STR) {
    return -1;
  }
  return a.length === b.length ? a < b ? -1 : 1 : b.length - a.length;
}
var Node$1 = class Node {
  #index;
  #varIndex;
  #children = /* @__PURE__ */ Object.create(null);
  insert(tokens, index, paramMap, context, pathErrorCheckOnly) {
    if (tokens.length === 0) {
      if (this.#index !== void 0) {
        throw PATH_ERROR;
      }
      if (pathErrorCheckOnly) {
        return;
      }
      this.#index = index;
      return;
    }
    const [token, ...restTokens] = tokens;
    const pattern = token === "*" ? restTokens.length === 0 ? ["", "", ONLY_WILDCARD_REG_EXP_STR] : ["", "", LABEL_REG_EXP_STR] : token === "/*" ? ["", "", TAIL_WILDCARD_REG_EXP_STR] : token.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
    let node;
    if (pattern) {
      const name = pattern[1];
      let regexpStr = pattern[2] || LABEL_REG_EXP_STR;
      if (name && pattern[2]) {
        regexpStr = regexpStr.replace(/^\((?!\?:)(?=[^)]+\)$)/, "(?:");
        if (/\((?!\?:)/.test(regexpStr)) {
          throw PATH_ERROR;
        }
      }
      node = this.#children[regexpStr];
      if (!node) {
        if (Object.keys(this.#children).some(
          (k) => k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR
        )) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[regexpStr] = new Node$1();
        if (name !== "") {
          node.#varIndex = context.varIndex++;
        }
      }
      if (!pathErrorCheckOnly && name !== "") {
        paramMap.push([name, node.#varIndex]);
      }
    } else {
      node = this.#children[token];
      if (!node) {
        if (Object.keys(this.#children).some(
          (k) => k.length > 1 && k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR
        )) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[token] = new Node$1();
      }
    }
    node.insert(restTokens, index, paramMap, context, pathErrorCheckOnly);
  }
  buildRegExpStr() {
    const childKeys = Object.keys(this.#children).sort(compareKey);
    const strList = childKeys.map((k) => {
      const c = this.#children[k];
      return (typeof c.#varIndex === "number" ? `(${k})@${c.#varIndex}` : regExpMetaChars.has(k) ? `\\${k}` : k) + c.buildRegExpStr();
    });
    if (typeof this.#index === "number") {
      strList.unshift(`#${this.#index}`);
    }
    if (strList.length === 0) {
      return "";
    }
    if (strList.length === 1) {
      return strList[0];
    }
    return "(?:" + strList.join("|") + ")";
  }
};

// src/router/reg-exp-router/trie.ts
var Trie = class {
  #context = { varIndex: 0 };
  #root = new Node$1();
  insert(path, index, pathErrorCheckOnly) {
    const paramAssoc = [];
    const groups = [];
    for (let i = 0; ; ) {
      let replaced = false;
      path = path.replace(/\{[^}]+\}/g, (m) => {
        const mark = `@\\${i}`;
        groups[i] = [mark, m];
        i++;
        replaced = true;
        return mark;
      });
      if (!replaced) {
        break;
      }
    }
    const tokens = path.match(/(?::[^\/]+)|(?:\/\*$)|./g) || [];
    for (let i = groups.length - 1; i >= 0; i--) {
      const [mark] = groups[i];
      for (let j = tokens.length - 1; j >= 0; j--) {
        if (tokens[j].indexOf(mark) !== -1) {
          tokens[j] = tokens[j].replace(mark, groups[i][1]);
          break;
        }
      }
    }
    this.#root.insert(tokens, index, paramAssoc, this.#context, pathErrorCheckOnly);
    return paramAssoc;
  }
  buildRegExp() {
    let regexp = this.#root.buildRegExpStr();
    if (regexp === "") {
      return [/^$/, [], []];
    }
    let captureIndex = 0;
    const indexReplacementMap = [];
    const paramReplacementMap = [];
    regexp = regexp.replace(/#(\d+)|@(\d+)|\.\*\$/g, (_, handlerIndex, paramIndex) => {
      if (handlerIndex !== void 0) {
        indexReplacementMap[++captureIndex] = Number(handlerIndex);
        return "$()";
      }
      if (paramIndex !== void 0) {
        paramReplacementMap[Number(paramIndex)] = ++captureIndex;
        return "";
      }
      return "";
    });
    return [new RegExp(`^${regexp}`), indexReplacementMap, paramReplacementMap];
  }
};

// src/router/reg-exp-router/router.ts
var emptyParam = [];
var nullMatcher = [/^$/, [], /* @__PURE__ */ Object.create(null)];
var wildcardRegExpCache = /* @__PURE__ */ Object.create(null);
function buildWildcardRegExp(path) {
  return wildcardRegExpCache[path] ??= new RegExp(
    path === "*" ? "" : `^${path.replace(
      /\/\*$|([.\\+*[^\]$()])/g,
      (_, metaChar) => metaChar ? `\\${metaChar}` : "(?:|/.*)"
    )}$`
  );
}
function clearWildcardRegExpCache() {
  wildcardRegExpCache = /* @__PURE__ */ Object.create(null);
}
function buildMatcherFromPreprocessedRoutes(routes) {
  const trie = new Trie();
  const handlerData = [];
  if (routes.length === 0) {
    return nullMatcher;
  }
  const routesWithStaticPathFlag = routes.map(
    (route) => [!/\*|\/:/.test(route[0]), ...route]
  ).sort(
    ([isStaticA, pathA], [isStaticB, pathB]) => isStaticA ? 1 : isStaticB ? -1 : pathA.length - pathB.length
  );
  const staticMap = /* @__PURE__ */ Object.create(null);
  for (let i = 0, j = -1, len = routesWithStaticPathFlag.length; i < len; i++) {
    const [pathErrorCheckOnly, path, handlers] = routesWithStaticPathFlag[i];
    if (pathErrorCheckOnly) {
      staticMap[path] = [handlers.map(([h]) => [h, /* @__PURE__ */ Object.create(null)]), emptyParam];
    } else {
      j++;
    }
    let paramAssoc;
    try {
      paramAssoc = trie.insert(path, j, pathErrorCheckOnly);
    } catch (e) {
      throw e === PATH_ERROR ? new UnsupportedPathError(path) : e;
    }
    if (pathErrorCheckOnly) {
      continue;
    }
    handlerData[j] = handlers.map(([h, paramCount]) => {
      const paramIndexMap = /* @__PURE__ */ Object.create(null);
      paramCount -= 1;
      for (; paramCount >= 0; paramCount--) {
        const [key, value] = paramAssoc[paramCount];
        paramIndexMap[key] = value;
      }
      return [h, paramIndexMap];
    });
  }
  const [regexp, indexReplacementMap, paramReplacementMap] = trie.buildRegExp();
  for (let i = 0, len = handlerData.length; i < len; i++) {
    for (let j = 0, len2 = handlerData[i].length; j < len2; j++) {
      const map = handlerData[i][j]?.[1];
      if (!map) {
        continue;
      }
      const keys = Object.keys(map);
      for (let k = 0, len3 = keys.length; k < len3; k++) {
        map[keys[k]] = paramReplacementMap[map[keys[k]]];
      }
    }
  }
  const handlerMap = [];
  for (const i in indexReplacementMap) {
    handlerMap[i] = handlerData[indexReplacementMap[i]];
  }
  return [regexp, handlerMap, staticMap];
}
function findMiddleware(middleware, path) {
  if (!middleware) {
    return void 0;
  }
  for (const k of Object.keys(middleware).sort((a, b) => b.length - a.length)) {
    if (buildWildcardRegExp(k).test(path)) {
      return [...middleware[k]];
    }
  }
  return void 0;
}
var RegExpRouter = class {
  name = "RegExpRouter";
  #middleware;
  #routes;
  constructor() {
    this.#middleware = { [METHOD_NAME_ALL]: /* @__PURE__ */ Object.create(null) };
    this.#routes = { [METHOD_NAME_ALL]: /* @__PURE__ */ Object.create(null) };
  }
  add(method, path, handler) {
    const middleware = this.#middleware;
    const routes = this.#routes;
    if (!middleware || !routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    if (!middleware[method]) {
      [middleware, routes].forEach((handlerMap) => {
        handlerMap[method] = /* @__PURE__ */ Object.create(null);
        Object.keys(handlerMap[METHOD_NAME_ALL]).forEach((p) => {
          handlerMap[method][p] = [...handlerMap[METHOD_NAME_ALL][p]];
        });
      });
    }
    if (path === "/*") {
      path = "*";
    }
    const paramCount = (path.match(/\/:/g) || []).length;
    if (/\*$/.test(path)) {
      const re = buildWildcardRegExp(path);
      if (method === METHOD_NAME_ALL) {
        Object.keys(middleware).forEach((m) => {
          middleware[m][path] ||= findMiddleware(middleware[m], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
        });
      } else {
        middleware[method][path] ||= findMiddleware(middleware[method], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
      }
      Object.keys(middleware).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(middleware[m]).forEach((p) => {
            re.test(p) && middleware[m][p].push([handler, paramCount]);
          });
        }
      });
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(routes[m]).forEach(
            (p) => re.test(p) && routes[m][p].push([handler, paramCount])
          );
        }
      });
      return;
    }
    const paths = checkOptionalParameter(path) || [path];
    for (let i = 0, len = paths.length; i < len; i++) {
      const path2 = paths[i];
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          routes[m][path2] ||= [
            ...findMiddleware(middleware[m], path2) || findMiddleware(middleware[METHOD_NAME_ALL], path2) || []
          ];
          routes[m][path2].push([handler, paramCount - len + i + 1]);
        }
      });
    }
  }
  match(method, path) {
    clearWildcardRegExpCache();
    const matchers = this.#buildAllMatchers();
    this.match = (method2, path2) => {
      const matcher = matchers[method2] || matchers[METHOD_NAME_ALL];
      const staticMatch = matcher[2][path2];
      if (staticMatch) {
        return staticMatch;
      }
      const match = path2.match(matcher[0]);
      if (!match) {
        return [[], emptyParam];
      }
      const index = match.indexOf("", 1);
      return [matcher[1][index], match];
    };
    return this.match(method, path);
  }
  #buildAllMatchers() {
    const matchers = /* @__PURE__ */ Object.create(null);
    Object.keys(this.#routes).concat(Object.keys(this.#middleware)).forEach((method) => {
      matchers[method] ||= this.#buildMatcher(method);
    });
    this.#middleware = this.#routes = void 0;
    return matchers;
  }
  #buildMatcher(method) {
    const routes = [];
    let hasOwnRoute = method === METHOD_NAME_ALL;
    [this.#middleware, this.#routes].forEach((r) => {
      const ownRoute = r[method] ? Object.keys(r[method]).map((path) => [path, r[method][path]]) : [];
      if (ownRoute.length !== 0) {
        hasOwnRoute ||= true;
        routes.push(...ownRoute);
      } else if (method !== METHOD_NAME_ALL) {
        routes.push(
          ...Object.keys(r[METHOD_NAME_ALL]).map((path) => [path, r[METHOD_NAME_ALL][path]])
        );
      }
    });
    if (!hasOwnRoute) {
      return null;
    } else {
      return buildMatcherFromPreprocessedRoutes(routes);
    }
  }
};

// src/router/smart-router/router.ts
var SmartRouter = class {
  name = "SmartRouter";
  #routers = [];
  #routes = [];
  constructor(init) {
    this.#routers = init.routers;
  }
  add(method, path, handler) {
    if (!this.#routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    this.#routes.push([method, path, handler]);
  }
  match(method, path) {
    if (!this.#routes) {
      throw new Error("Fatal error");
    }
    const routers = this.#routers;
    const routes = this.#routes;
    const len = routers.length;
    let i = 0;
    let res;
    for (; i < len; i++) {
      const router = routers[i];
      try {
        for (let i2 = 0, len2 = routes.length; i2 < len2; i2++) {
          router.add(...routes[i2]);
        }
        res = router.match(method, path);
      } catch (e) {
        if (e instanceof UnsupportedPathError) {
          continue;
        }
        throw e;
      }
      this.match = router.match.bind(router);
      this.#routers = [router];
      this.#routes = void 0;
      break;
    }
    if (i === len) {
      throw new Error("Fatal error");
    }
    this.name = `SmartRouter + ${this.activeRouter.name}`;
    return res;
  }
  get activeRouter() {
    if (this.#routes || this.#routers.length !== 1) {
      throw new Error("No active router has been determined yet.");
    }
    return this.#routers[0];
  }
};

// src/router/trie-router/node.ts
var emptyParams = /* @__PURE__ */ Object.create(null);
var Node = class {
  #methods;
  #children;
  #patterns;
  #order = 0;
  #params = emptyParams;
  constructor(method, handler, children) {
    this.#children = children || /* @__PURE__ */ Object.create(null);
    this.#methods = [];
    if (method && handler) {
      const m = /* @__PURE__ */ Object.create(null);
      m[method] = { handler, possibleKeys: [], score: 0 };
      this.#methods = [m];
    }
    this.#patterns = [];
  }
  insert(method, path, handler) {
    this.#order = ++this.#order;
    let curNode = this;
    const parts = splitRoutingPath(path);
    const possibleKeys = [];
    for (let i = 0, len = parts.length; i < len; i++) {
      const p = parts[i];
      const nextP = parts[i + 1];
      const pattern = getPattern(p, nextP);
      const key = Array.isArray(pattern) ? pattern[0] : p;
      if (Object.keys(curNode.#children).includes(key)) {
        curNode = curNode.#children[key];
        const pattern2 = getPattern(p, nextP);
        if (pattern2) {
          possibleKeys.push(pattern2[1]);
        }
        continue;
      }
      curNode.#children[key] = new Node();
      if (pattern) {
        curNode.#patterns.push(pattern);
        possibleKeys.push(pattern[1]);
      }
      curNode = curNode.#children[key];
    }
    const m = /* @__PURE__ */ Object.create(null);
    const handlerSet = {
      handler,
      possibleKeys: possibleKeys.filter((v, i, a) => a.indexOf(v) === i),
      score: this.#order
    };
    m[method] = handlerSet;
    curNode.#methods.push(m);
    return curNode;
  }
  #getHandlerSets(node, method, nodeParams, params) {
    const handlerSets = [];
    for (let i = 0, len = node.#methods.length; i < len; i++) {
      const m = node.#methods[i];
      const handlerSet = m[method] || m[METHOD_NAME_ALL];
      const processedSet = {};
      if (handlerSet !== void 0) {
        handlerSet.params = /* @__PURE__ */ Object.create(null);
        handlerSets.push(handlerSet);
        if (nodeParams !== emptyParams || params && params !== emptyParams) {
          for (let i2 = 0, len2 = handlerSet.possibleKeys.length; i2 < len2; i2++) {
            const key = handlerSet.possibleKeys[i2];
            const processed = processedSet[handlerSet.score];
            handlerSet.params[key] = params?.[key] && !processed ? params[key] : nodeParams[key] ?? params?.[key];
            processedSet[handlerSet.score] = true;
          }
        }
      }
    }
    return handlerSets;
  }
  search(method, path) {
    const handlerSets = [];
    this.#params = emptyParams;
    const curNode = this;
    let curNodes = [curNode];
    const parts = splitPath(path);
    const curNodesQueue = [];
    for (let i = 0, len = parts.length; i < len; i++) {
      const part = parts[i];
      const isLast = i === len - 1;
      const tempNodes = [];
      for (let j = 0, len2 = curNodes.length; j < len2; j++) {
        const node = curNodes[j];
        const nextNode = node.#children[part];
        if (nextNode) {
          nextNode.#params = node.#params;
          if (isLast) {
            if (nextNode.#children["*"]) {
              handlerSets.push(
                ...this.#getHandlerSets(nextNode.#children["*"], method, node.#params)
              );
            }
            handlerSets.push(...this.#getHandlerSets(nextNode, method, node.#params));
          } else {
            tempNodes.push(nextNode);
          }
        }
        for (let k = 0, len3 = node.#patterns.length; k < len3; k++) {
          const pattern = node.#patterns[k];
          const params = node.#params === emptyParams ? {} : { ...node.#params };
          if (pattern === "*") {
            const astNode = node.#children["*"];
            if (astNode) {
              handlerSets.push(...this.#getHandlerSets(astNode, method, node.#params));
              astNode.#params = params;
              tempNodes.push(astNode);
            }
            continue;
          }
          if (part === "") {
            continue;
          }
          const [key, name, matcher] = pattern;
          const child = node.#children[key];
          const restPathString = parts.slice(i).join("/");
          if (matcher instanceof RegExp) {
            const m = matcher.exec(restPathString);
            if (m) {
              params[name] = m[0];
              handlerSets.push(...this.#getHandlerSets(child, method, node.#params, params));
              if (Object.keys(child.#children).length) {
                child.#params = params;
                const componentCount = m[0].match(/\//)?.length ?? 0;
                const targetCurNodes = curNodesQueue[componentCount] ||= [];
                targetCurNodes.push(child);
              }
              continue;
            }
          }
          if (matcher === true || matcher.test(part)) {
            params[name] = part;
            if (isLast) {
              handlerSets.push(...this.#getHandlerSets(child, method, params, node.#params));
              if (child.#children["*"]) {
                handlerSets.push(
                  ...this.#getHandlerSets(child.#children["*"], method, params, node.#params)
                );
              }
            } else {
              child.#params = params;
              tempNodes.push(child);
            }
          }
        }
      }
      curNodes = tempNodes.concat(curNodesQueue.shift() ?? []);
    }
    if (handlerSets.length > 1) {
      handlerSets.sort((a, b) => {
        return a.score - b.score;
      });
    }
    return [handlerSets.map(({ handler, params }) => [handler, params])];
  }
};

// src/router/trie-router/router.ts
var TrieRouter = class {
  name = "TrieRouter";
  #node;
  constructor() {
    this.#node = new Node();
  }
  add(method, path, handler) {
    const results = checkOptionalParameter(path);
    if (results) {
      for (let i = 0, len = results.length; i < len; i++) {
        this.#node.insert(method, results[i], handler);
      }
      return;
    }
    this.#node.insert(method, path, handler);
  }
  match(method, path) {
    return this.#node.search(method, path);
  }
};

// src/hono.ts
var Hono = class extends Hono$1 {
  constructor(options = {}) {
    super(options);
    this.router = options.router ?? new SmartRouter({
      routers: [new RegExpRouter(), new TrieRouter()]
    });
  }
};

// src/http-exception.ts
var HTTPException = class extends Error {
  res;
  status;
  constructor(status = 500, options) {
    super(options?.message, { cause: options?.cause });
    this.res = options?.res;
    this.status = status;
  }
  getResponse() {
    if (this.res) {
      const newResponse = new Response(this.res.body, {
        status: this.status,
        headers: this.res.headers
      });
      return newResponse;
    }
    return new Response(this.message, {
      status: this.status
    });
  }
};

// src/middleware/body-limit/index.ts
var ERROR_MESSAGE = "Payload Too Large";
var BodyLimitError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "BodyLimitError";
  }
};
var bodyLimit = (options) => {
  const onError = options.onError || (() => {
    const res = new Response(ERROR_MESSAGE, {
      status: 413
    });
    throw new HTTPException(413, { res });
  });
  const maxSize = options.maxSize;
  return async function bodyLimit2(c, next) {
    if (!c.req.raw.body) {
      return next();
    }
    if (c.req.raw.headers.has("content-length")) {
      const contentLength = parseInt(c.req.raw.headers.get("content-length") || "0", 10);
      return contentLength > maxSize ? onError(c) : next();
    }
    let size = 0;
    const rawReader = c.req.raw.body.getReader();
    const reader = new ReadableStream({
      async start(controller) {
        try {
          for (; ; ) {
            const { done, value } = await rawReader.read();
            if (done) {
              break;
            }
            size += value.length;
            if (size > maxSize) {
              controller.error(new BodyLimitError(ERROR_MESSAGE));
              break;
            }
            controller.enqueue(value);
          }
        } finally {
          controller.close();
        }
      }
    });
    const requestInit = { body: reader, duplex: "half" };
    c.req.raw = new Request(c.req.raw, requestInit);
    await next();
    if (c.error instanceof BodyLimitError) {
      c.res = await onError(c);
    }
  };
};

// src/middleware/cors/index.ts
var cors = (options) => {
  const defaults = {
    origin: "*",
    allowMethods: ["GET", "HEAD", "PUT", "POST", "DELETE", "PATCH"],
    allowHeaders: [],
    exposeHeaders: []
  };
  const opts = {
    ...defaults,
    ...options
  };
  const findAllowOrigin = ((optsOrigin) => {
    if (typeof optsOrigin === "string") {
      if (optsOrigin === "*") {
        return () => optsOrigin;
      } else {
        return (origin) => optsOrigin === origin ? origin : null;
      }
    } else if (typeof optsOrigin === "function") {
      return optsOrigin;
    } else {
      return (origin) => optsOrigin.includes(origin) ? origin : null;
    }
  })(opts.origin);
  return async function cors2(c, next) {
    function set(key, value) {
      c.res.headers.set(key, value);
    }
    const allowOrigin = findAllowOrigin(c.req.header("origin") || "", c);
    if (allowOrigin) {
      set("Access-Control-Allow-Origin", allowOrigin);
    }
    if (opts.origin !== "*") {
      const existingVary = c.req.header("Vary");
      if (existingVary) {
        set("Vary", existingVary);
      } else {
        set("Vary", "Origin");
      }
    }
    if (opts.credentials) {
      set("Access-Control-Allow-Credentials", "true");
    }
    if (opts.exposeHeaders?.length) {
      set("Access-Control-Expose-Headers", opts.exposeHeaders.join(","));
    }
    if (c.req.method === "OPTIONS") {
      if (opts.maxAge != null) {
        set("Access-Control-Max-Age", opts.maxAge.toString());
      }
      if (opts.allowMethods?.length) {
        set("Access-Control-Allow-Methods", opts.allowMethods.join(","));
      }
      let headers = opts.allowHeaders;
      if (!headers?.length) {
        const requestHeaders = c.req.header("Access-Control-Request-Headers");
        if (requestHeaders) {
          headers = requestHeaders.split(/\s*,\s*/);
        }
      }
      if (headers?.length) {
        set("Access-Control-Allow-Headers", headers.join(","));
        c.res.headers.append("Vary", "Access-Control-Request-Headers");
      }
      c.res.headers.delete("Content-Length");
      c.res.headers.delete("Content-Type");
      return new Response(null, {
        headers: c.res.headers,
        status: 204,
        statusText: "No Content"
      });
    }
    await next();
  };
};

// src/utils/color.ts
function getColorEnabled() {
  const { process, Deno } = globalThis;
  const isNoColor = typeof Deno?.noColor === "boolean" ? Deno.noColor : process !== void 0 ? "NO_COLOR" in process?.env : false;
  return !isNoColor;
}

// src/middleware/logger/index.ts
var humanize = (times) => {
  const [delimiter, separator] = [",", "."];
  const orderTimes = times.map((v) => v.replace(/(\d)(?=(\d\d\d)+(?!\d))/g, "$1" + delimiter));
  return orderTimes.join(separator);
};
var time = (start) => {
  const delta = Date.now() - start;
  return humanize([delta < 1e3 ? delta + "ms" : Math.round(delta / 1e3) + "s"]);
};
var colorStatus = (status) => {
  const colorEnabled = getColorEnabled();
  if (colorEnabled) {
    switch (status / 100 | 0) {
      case 5:
        return `\x1B[31m${status}\x1B[0m`;
      case 4:
        return `\x1B[33m${status}\x1B[0m`;
      case 3:
        return `\x1B[36m${status}\x1B[0m`;
      case 2:
        return `\x1B[32m${status}\x1B[0m`;
    }
  }
  return `${status}`;
};
function log(fn, prefix, method, path, status = 0, elapsed) {
  const out = prefix === "<--" /* Incoming */ ? `${prefix} ${method} ${path}` : `${prefix} ${method} ${path} ${colorStatus(status)} ${elapsed}`;
  fn(out);
}
var logger = (fn = console.log) => {
  return async function logger2(c, next) {
    const { method, url } = c.req;
    const path = url.slice(url.indexOf("/", 8));
    log(fn, "<--" /* Incoming */, method, path);
    const start = Date.now();
    await next();
    log(fn, "-->" /* Outgoing */, method, path, c.res.status, time(start));
  };
};

// src/utils/stream.ts
var StreamingApi = class {
  writer;
  encoder;
  writable;
  abortSubscribers = [];
  responseReadable;
  aborted = false;
  closed = false;
  constructor(writable, _readable) {
    this.writable = writable;
    this.writer = writable.getWriter();
    this.encoder = new TextEncoder();
    const reader = _readable.getReader();
    this.abortSubscribers.push(async () => {
      await reader.cancel();
    });
    this.responseReadable = new ReadableStream({
      async pull(controller) {
        const { done, value } = await reader.read();
        done ? controller.close() : controller.enqueue(value);
      },
      cancel: () => {
        this.abort();
      }
    });
  }
  async write(input) {
    try {
      if (typeof input === "string") {
        input = this.encoder.encode(input);
      }
      await this.writer.write(input);
    } catch {
    }
    return this;
  }
  async writeln(input) {
    await this.write(input + "\n");
    return this;
  }
  sleep(ms) {
    return new Promise((res) => setTimeout(res, ms));
  }
  async close() {
    try {
      await this.writer.close();
    } catch {
    }
    this.closed = true;
  }
  async pipe(body) {
    this.writer.releaseLock();
    await body.pipeTo(this.writable, { preventClose: true });
    this.writer = this.writable.getWriter();
  }
  onAbort(listener) {
    this.abortSubscribers.push(listener);
  }
  abort() {
    if (!this.aborted) {
      this.aborted = true;
      this.abortSubscribers.forEach((subscriber) => subscriber());
    }
  }
};

// src/helper/streaming/utils.ts
var isOldBunVersion = () => {
  const version = typeof Bun !== "undefined" ? Bun.version : void 0;
  if (version === void 0) {
    return false;
  }
  const result = version.startsWith("1.1") || version.startsWith("1.0") || version.startsWith("0.");
  isOldBunVersion = () => result;
  return result;
};

// src/helper/streaming/stream.ts
var contextStash = /* @__PURE__ */ new WeakMap();
var stream = (c, cb, onError) => {
  const { readable, writable } = new TransformStream();
  const stream2 = new StreamingApi(writable, readable);
  if (isOldBunVersion()) {
    c.req.raw.signal.addEventListener("abort", () => {
      if (!stream2.closed) {
        stream2.abort();
      }
    });
  }
  contextStash.set(stream2.responseReadable, c);
  (async () => {
    try {
      await cb(stream2);
    } catch (e) {
      if (e === void 0) ; else if (e instanceof Error && onError) {
        await onError(e, stream2);
      } else {
        console.error(e);
      }
    } finally {
      stream2.close();
    }
  })();
  return c.newResponse(stream2.responseReadable);
};

// src/helper/streaming/text.ts
var streamText = (c, cb, onError) => {
  c.header("Content-Type", TEXT_PLAIN);
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Transfer-Encoding", "chunked");
  return stream(c, cb, onError);
};

// src/server/index.ts
var RequestError = class extends Error {
  static name = "RequestError";
  constructor(message, options) {
    super(message, options);
  }
};
var toRequestError = (e2) => {
  if (e2 instanceof RequestError) {
    return e2;
  }
  return new RequestError(e2.message, { cause: e2 });
};
var GlobalRequest = global.Request;
var Request$1 = class Request extends GlobalRequest {
  constructor(input, options) {
    if (typeof input === "object" && getRequestCache in input) {
      input = input[getRequestCache]();
    }
    if (typeof options?.body?.getReader !== "undefined") {
      options.duplex ??= "half";
    }
    super(input, options);
  }
};
var newRequestFromIncoming = (method, url, incoming, abortController) => {
  const headerRecord = [];
  const rawHeaders = incoming.rawHeaders;
  for (let i2 = 0; i2 < rawHeaders.length; i2 += 2) {
    const { [i2]: key, [i2 + 1]: value } = rawHeaders;
    if (key.charCodeAt(0) !== /*:*/
    58) {
      headerRecord.push([key, value]);
    }
  }
  const init = {
    method,
    headers: headerRecord,
    signal: abortController.signal
  };
  if (method === "TRACE") {
    init.method = "GET";
    const req = new Request$1(url, init);
    Object.defineProperty(req, "method", {
      get() {
        return "TRACE";
      }
    });
    return req;
  }
  if (!(method === "GET" || method === "HEAD")) {
    if ("rawBody" in incoming && incoming.rawBody instanceof Buffer) {
      init.body = new ReadableStream({
        start(controller) {
          controller.enqueue(incoming.rawBody);
          controller.close();
        }
      });
    } else {
      init.body = Readable.toWeb(incoming);
    }
  }
  return new Request$1(url, init);
};
var getRequestCache = Symbol("getRequestCache");
var requestCache = Symbol("requestCache");
var incomingKey = Symbol("incomingKey");
var urlKey = Symbol("urlKey");
var abortControllerKey = Symbol("abortControllerKey");
var getAbortController = Symbol("getAbortController");
var requestPrototype = {
  get method() {
    return this[incomingKey].method || "GET";
  },
  get url() {
    return this[urlKey];
  },
  [getAbortController]() {
    this[getRequestCache]();
    return this[abortControllerKey];
  },
  [getRequestCache]() {
    this[abortControllerKey] ||= new AbortController();
    return this[requestCache] ||= newRequestFromIncoming(
      this.method,
      this[urlKey],
      this[incomingKey],
      this[abortControllerKey]
    );
  }
};
[
  "body",
  "bodyUsed",
  "cache",
  "credentials",
  "destination",
  "headers",
  "integrity",
  "mode",
  "redirect",
  "referrer",
  "referrerPolicy",
  "signal",
  "keepalive"
].forEach((k) => {
  Object.defineProperty(requestPrototype, k, {
    get() {
      return this[getRequestCache]()[k];
    }
  });
});
["arrayBuffer", "blob", "clone", "formData", "json", "text"].forEach((k) => {
  Object.defineProperty(requestPrototype, k, {
    value: function() {
      return this[getRequestCache]()[k]();
    }
  });
});
Object.setPrototypeOf(requestPrototype, Request$1.prototype);
var newRequest = (incoming, defaultHostname) => {
  const req = Object.create(requestPrototype);
  req[incomingKey] = incoming;
  const host = (incoming instanceof Http2ServerRequest ? incoming.authority : incoming.headers.host) || defaultHostname;
  if (!host) {
    throw new RequestError("Missing host header");
  }
  const url = new URL(
    `${incoming instanceof Http2ServerRequest || incoming.socket && incoming.socket.encrypted ? "https" : "http"}://${host}${incoming.url}`
  );
  if (url.hostname.length !== host.length && url.hostname !== host.replace(/:\d+$/, "")) {
    throw new RequestError("Invalid host header");
  }
  req[urlKey] = url.href;
  return req;
};
function writeFromReadableStream(stream, writable) {
  if (stream.locked) {
    throw new TypeError("ReadableStream is locked.");
  } else if (writable.destroyed) {
    stream.cancel();
    return;
  }
  const reader = stream.getReader();
  writable.on("close", cancel);
  writable.on("error", cancel);
  reader.read().then(flow, cancel);
  return reader.closed.finally(() => {
    writable.off("close", cancel);
    writable.off("error", cancel);
  });
  function cancel(error) {
    reader.cancel(error).catch(() => {
    });
    if (error) {
      writable.destroy(error);
    }
  }
  function onDrain() {
    reader.read().then(flow, cancel);
  }
  function flow({ done, value }) {
    try {
      if (done) {
        writable.end();
      } else if (!writable.write(value)) {
        writable.once("drain", onDrain);
      } else {
        return reader.read().then(flow, cancel);
      }
    } catch (e2) {
      cancel(e2);
    }
  }
}
var buildOutgoingHttpHeaders = (headers) => {
  const res = {};
  if (!(headers instanceof Headers)) {
    headers = new Headers(headers ?? void 0);
  }
  const cookies = [];
  for (const [k, v] of headers) {
    if (k === "set-cookie") {
      cookies.push(v);
    } else {
      res[k] = v;
    }
  }
  if (cookies.length > 0) {
    res["set-cookie"] = cookies;
  }
  res["content-type"] ??= "text/plain; charset=UTF-8";
  return res;
};
var responseCache = Symbol("responseCache");
var getResponseCache = Symbol("getResponseCache");
var cacheKey = Symbol("cache");
var GlobalResponse = global.Response;
var Response2 = class _Response {
  #body;
  #init;
  [getResponseCache]() {
    delete this[cacheKey];
    return this[responseCache] ||= new GlobalResponse(this.#body, this.#init);
  }
  constructor(body, init) {
    this.#body = body;
    if (init instanceof _Response) {
      const cachedGlobalResponse = init[responseCache];
      if (cachedGlobalResponse) {
        this.#init = cachedGlobalResponse;
        this[getResponseCache]();
        return;
      } else {
        this.#init = init.#init;
      }
    } else {
      this.#init = init;
    }
    if (typeof body === "string" || typeof body?.getReader !== "undefined") {
      let headers = init?.headers || { "content-type": "text/plain; charset=UTF-8" };
      if (headers instanceof Headers) {
        headers = buildOutgoingHttpHeaders(headers);
      }
      this[cacheKey] = [init?.status || 200, body, headers];
    }
  }
};
[
  "body",
  "bodyUsed",
  "headers",
  "ok",
  "redirected",
  "status",
  "statusText",
  "trailers",
  "type",
  "url"
].forEach((k) => {
  Object.defineProperty(Response2.prototype, k, {
    get() {
      return this[getResponseCache]()[k];
    }
  });
});
["arrayBuffer", "blob", "clone", "formData", "json", "text"].forEach((k) => {
  Object.defineProperty(Response2.prototype, k, {
    value: function() {
      return this[getResponseCache]()[k]();
    }
  });
});
Object.setPrototypeOf(Response2, GlobalResponse);
Object.setPrototypeOf(Response2.prototype, GlobalResponse.prototype);
var stateKey = Reflect.ownKeys(new GlobalResponse()).find(
  (k) => typeof k === "symbol" && k.toString() === "Symbol(state)"
);
if (!stateKey) {
  console.warn("Failed to find Response internal state key");
}
function getInternalBody(response) {
  if (!stateKey) {
    return;
  }
  if (response instanceof Response2) {
    response = response[getResponseCache]();
  }
  const state = response[stateKey];
  return state && state.body || void 0;
}
var X_ALREADY_SENT = "x-hono-already-sent";
var webFetch = global.fetch;
if (typeof global.crypto === "undefined") {
  global.crypto = crypto;
}
global.fetch = (info, init) => {
  init = {
    // Disable compression handling so people can return the result of a fetch
    // directly in the loader without messing with the Content-Encoding header.
    compress: false,
    ...init
  };
  return webFetch(info, init);
};
var regBuffer = /^no$/i;
var regContentType = /^(application\/json\b|text\/(?!event-stream\b))/i;
var handleRequestError = () => new Response(null, {
  status: 400
});
var handleFetchError = (e2) => new Response(null, {
  status: e2 instanceof Error && (e2.name === "TimeoutError" || e2.constructor.name === "TimeoutError") ? 504 : 500
});
var handleResponseError = (e2, outgoing) => {
  const err = e2 instanceof Error ? e2 : new Error("unknown error", { cause: e2 });
  if (err.code === "ERR_STREAM_PREMATURE_CLOSE") {
    console.info("The user aborted a request.");
  } else {
    console.error(e2);
    if (!outgoing.headersSent) {
      outgoing.writeHead(500, { "Content-Type": "text/plain" });
    }
    outgoing.end(`Error: ${err.message}`);
    outgoing.destroy(err);
  }
};
var responseViaCache = (res, outgoing) => {
  const [status, body, header] = res[cacheKey];
  if (typeof body === "string") {
    header["Content-Length"] = Buffer.byteLength(body);
    outgoing.writeHead(status, header);
    outgoing.end(body);
  } else {
    outgoing.writeHead(status, header);
    return writeFromReadableStream(body, outgoing)?.catch(
      (e2) => handleResponseError(e2, outgoing)
    );
  }
};
var responseViaResponseObject = async (res, outgoing, options = {}) => {
  if (res instanceof Promise) {
    if (options.errorHandler) {
      try {
        res = await res;
      } catch (err) {
        const errRes = await options.errorHandler(err);
        if (!errRes) {
          return;
        }
        res = errRes;
      }
    } else {
      res = await res.catch(handleFetchError);
    }
  }
  if (cacheKey in res) {
    return responseViaCache(res, outgoing);
  }
  const resHeaderRecord = buildOutgoingHttpHeaders(res.headers);
  const internalBody = getInternalBody(res);
  if (internalBody) {
    const { length, source, stream } = internalBody;
    if (source instanceof Uint8Array && source.byteLength !== length) ; else {
      if (length) {
        resHeaderRecord["content-length"] = length;
      }
      outgoing.writeHead(res.status, resHeaderRecord);
      if (typeof source === "string" || source instanceof Uint8Array) {
        outgoing.end(source);
      } else if (source instanceof Blob) {
        outgoing.end(new Uint8Array(await source.arrayBuffer()));
      } else {
        await writeFromReadableStream(stream, outgoing);
      }
      return;
    }
  }
  if (res.body) {
    const {
      "transfer-encoding": transferEncoding,
      "content-encoding": contentEncoding,
      "content-length": contentLength,
      "x-accel-buffering": accelBuffering,
      "content-type": contentType
    } = resHeaderRecord;
    if (transferEncoding || contentEncoding || contentLength || // nginx buffering variant
    accelBuffering && regBuffer.test(accelBuffering) || !regContentType.test(contentType)) {
      outgoing.writeHead(res.status, resHeaderRecord);
      await writeFromReadableStream(res.body, outgoing);
    } else {
      const buffer = await res.arrayBuffer();
      resHeaderRecord["content-length"] = buffer.byteLength;
      outgoing.writeHead(res.status, resHeaderRecord);
      outgoing.end(new Uint8Array(buffer));
    }
  } else if (resHeaderRecord[X_ALREADY_SENT]) ; else {
    outgoing.writeHead(res.status, resHeaderRecord);
    outgoing.end();
  }
};
var getRequestListener = (fetchCallback, options = {}) => {
  if (options.overrideGlobalObjects !== false && global.Request !== Request$1) {
    Object.defineProperty(global, "Request", {
      value: Request$1
    });
    Object.defineProperty(global, "Response", {
      value: Response2
    });
  }
  return async (incoming, outgoing) => {
    let res, req;
    try {
      req = newRequest(incoming, options.hostname);
      outgoing.on("close", () => {
        const abortController = req[abortControllerKey];
        if (!abortController) {
          return;
        }
        if (incoming.errored) {
          req[abortControllerKey].abort(incoming.errored.toString());
        } else if (!outgoing.writableFinished) {
          req[abortControllerKey].abort("Client connection prematurely closed.");
        }
      });
      res = fetchCallback(req, { incoming, outgoing });
      if (cacheKey in res) {
        return responseViaCache(res, outgoing);
      }
    } catch (e2) {
      if (!res) {
        if (options.errorHandler) {
          res = await options.errorHandler(req ? e2 : toRequestError(e2));
          if (!res) {
            return;
          }
        } else if (!req) {
          res = handleRequestError();
        } else {
          res = handleFetchError(e2);
        }
      } else {
        return handleResponseError(e2, outgoing);
      }
    }
    try {
      return responseViaResponseObject(res, outgoing, options);
    } catch (e2) {
      return handleResponseError(e2, outgoing);
    }
  };
};
var createAdaptorServer = (options) => {
  const fetchCallback = options.fetch;
  const requestListener = getRequestListener(fetchCallback, {
    hostname: options.hostname,
    overrideGlobalObjects: options.overrideGlobalObjects
  });
  const createServer$1 = options.createServer || createServer;
  const server = createServer$1(options.serverOptions || {}, requestListener);
  return server;
};
var serve = (options, listeningListener) => {
  const server = createAdaptorServer(options);
  server.listen(options?.port, options.hostname, () => {
    const serverInfo = server.address();
    listeningListener && listeningListener(serverInfo);
  });
  return server;
};
var COMPRESSIBLE_CONTENT_TYPE_REGEX = /^\s*(?:text\/[^;\s]+|application\/(?:javascript|json|xml|xml-dtd|ecmascript|dart|postscript|rtf|tar|toml|vnd\.dart|vnd\.ms-fontobject|vnd\.ms-opentype|wasm|x-httpd-php|x-javascript|x-ns-proxy-autoconfig|x-sh|x-tar|x-virtualbox-hdd|x-virtualbox-ova|x-virtualbox-ovf|x-virtualbox-vbox|x-virtualbox-vdi|x-virtualbox-vhd|x-virtualbox-vmdk|x-www-form-urlencoded)|font\/(?:otf|ttf)|image\/(?:bmp|vnd\.adobe\.photoshop|vnd\.microsoft\.icon|vnd\.ms-dds|x-icon|x-ms-bmp)|message\/rfc822|model\/gltf-binary|x-shader\/x-fragment|x-shader\/x-vertex|[^;\s]+?\+(?:json|text|xml|yaml))(?:[;\s]|$)/i;
var ENCODINGS = {
  br: ".br",
  zstd: ".zst",
  gzip: ".gz"
};
var ENCODINGS_ORDERED_KEYS = Object.keys(ENCODINGS);
var createStreamBody = (stream) => {
  const body = new ReadableStream({
    start(controller) {
      stream.on("data", (chunk) => {
        controller.enqueue(chunk);
      });
      stream.on("end", () => {
        controller.close();
      });
    },
    cancel() {
      stream.destroy();
    }
  });
  return body;
};
var addCurrentDirPrefix = (path) => {
  return `./${path}`;
};
var getStats = (path) => {
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
  }
  return stats;
};
var serveStatic = (options = { root: "" }) => {
  return async (c2, next) => {
    if (c2.finalized) {
      return next();
    }
    let filename;
    try {
      filename = options.path ?? decodeURIComponent(c2.req.path);
    } catch {
      await options.onNotFound?.(c2.req.path, c2);
      return next();
    }
    let path = getFilePathWithoutDefaultDocument({
      filename: options.rewriteRequestPath ? options.rewriteRequestPath(filename) : filename,
      root: options.root
    });
    if (path) {
      path = addCurrentDirPrefix(path);
    } else {
      return next();
    }
    let stats = getStats(path);
    if (stats && stats.isDirectory()) {
      path = getFilePath({
        filename: options.rewriteRequestPath ? options.rewriteRequestPath(filename) : filename,
        root: options.root,
        defaultDocument: options.index ?? "index.html"
      });
      if (path) {
        path = addCurrentDirPrefix(path);
      } else {
        return next();
      }
      stats = getStats(path);
    }
    if (!stats) {
      await options.onNotFound?.(path, c2);
      return next();
    }
    await options.onFound?.(path, c2);
    const mimeType = getMimeType(path);
    c2.header("Content-Type", mimeType || "application/octet-stream");
    if (options.precompressed && (!mimeType || COMPRESSIBLE_CONTENT_TYPE_REGEX.test(mimeType))) {
      const acceptEncodingSet = new Set(
        c2.req.header("Accept-Encoding")?.split(",").map((encoding) => encoding.trim())
      );
      for (const encoding of ENCODINGS_ORDERED_KEYS) {
        if (!acceptEncodingSet.has(encoding)) {
          continue;
        }
        const precompressedStats = getStats(path + ENCODINGS[encoding]);
        if (precompressedStats) {
          c2.header("Content-Encoding", encoding);
          c2.header("Vary", "Accept-Encoding", { append: true });
          stats = precompressedStats;
          path = path + ENCODINGS[encoding];
          break;
        }
      }
    }
    const size = stats.size;
    if (c2.req.method == "HEAD" || c2.req.method == "OPTIONS") {
      c2.header("Content-Length", size.toString());
      c2.status(200);
      return c2.body(null);
    }
    const range = c2.req.header("range") || "";
    if (!range) {
      c2.header("Content-Length", size.toString());
      return c2.body(createStreamBody(createReadStream(path)), 200);
    }
    c2.header("Accept-Ranges", "bytes");
    c2.header("Date", stats.birthtime.toUTCString());
    const parts = range.replace(/bytes=/, "").split("-", 2);
    const start = parts[0] ? parseInt(parts[0], 10) : 0;
    let end = parts[1] ? parseInt(parts[1], 10) : stats.size - 1;
    if (size < end - start + 1) {
      end = size - 1;
    }
    const chunksize = end - start + 1;
    const stream = createReadStream(path, { start, end });
    c2.header("Content-Length", chunksize.toString());
    c2.header("Content-Range", `bytes ${start}-${end}/${stats.size}`);
    return c2.body(createStreamBody(stream), 206);
  };
};
var RENDER_TYPE = {
  STRING_ARRAY: "string_array",
  STRING: "string",
  JSON_STRING: "json_string",
  RAW: "raw"
};
var RENDER_TYPE_MAP = {
  configUrl: RENDER_TYPE.STRING,
  deepLinking: RENDER_TYPE.RAW,
  presets: RENDER_TYPE.STRING_ARRAY,
  plugins: RENDER_TYPE.STRING_ARRAY,
  spec: RENDER_TYPE.JSON_STRING,
  url: RENDER_TYPE.STRING,
  urls: RENDER_TYPE.JSON_STRING,
  layout: RENDER_TYPE.STRING,
  docExpansion: RENDER_TYPE.STRING,
  maxDisplayedTags: RENDER_TYPE.RAW,
  operationsSorter: RENDER_TYPE.RAW,
  requestInterceptor: RENDER_TYPE.RAW,
  responseInterceptor: RENDER_TYPE.RAW,
  persistAuthorization: RENDER_TYPE.RAW,
  defaultModelsExpandDepth: RENDER_TYPE.RAW,
  defaultModelExpandDepth: RENDER_TYPE.RAW,
  defaultModelRendering: RENDER_TYPE.STRING,
  displayRequestDuration: RENDER_TYPE.RAW,
  filter: RENDER_TYPE.RAW,
  showExtensions: RENDER_TYPE.RAW,
  showCommonExtensions: RENDER_TYPE.RAW,
  queryConfigEnabled: RENDER_TYPE.RAW,
  displayOperationId: RENDER_TYPE.RAW,
  tagsSorter: RENDER_TYPE.RAW,
  onComplete: RENDER_TYPE.RAW,
  syntaxHighlight: RENDER_TYPE.JSON_STRING,
  tryItOutEnabled: RENDER_TYPE.RAW,
  requestSnippetsEnabled: RENDER_TYPE.RAW,
  requestSnippets: RENDER_TYPE.JSON_STRING,
  oauth2RedirectUrl: RENDER_TYPE.STRING,
  showMutabledRequest: RENDER_TYPE.RAW,
  request: RENDER_TYPE.JSON_STRING,
  supportedSubmitMethods: RENDER_TYPE.JSON_STRING,
  validatorUrl: RENDER_TYPE.STRING,
  withCredentials: RENDER_TYPE.RAW,
  modelPropertyMacro: RENDER_TYPE.RAW,
  parameterMacro: RENDER_TYPE.RAW
};
var renderSwaggerUIOptions = (options) => {
  const optionsStrings = Object.entries(options).map(([k, v]) => {
    const key = k;
    if (!RENDER_TYPE_MAP[key] || v === void 0) {
      return "";
    }
    switch (RENDER_TYPE_MAP[key]) {
      case RENDER_TYPE.STRING:
        return `${key}: '${v}'`;
      case RENDER_TYPE.STRING_ARRAY:
        if (!Array.isArray(v)) {
          return "";
        }
        return `${key}: [${v.map((ve) => `${ve}`).join(",")}]`;
      case RENDER_TYPE.JSON_STRING:
        return `${key}: ${JSON.stringify(v)}`;
      case RENDER_TYPE.RAW:
        return `${key}: ${v}`;
      default:
        return "";
    }
  }).filter((item) => item !== "").join(",");
  return optionsStrings;
};
var remoteAssets = ({ version }) => {
  const url = `https://cdn.jsdelivr.net/npm/swagger-ui-dist${version !== void 0 ? `@${version}` : ""}`;
  return {
    css: [`${url}/swagger-ui.css`],
    js: [`${url}/swagger-ui-bundle.js`]
  };
};
var SwaggerUI = (options) => {
  const asset = remoteAssets({ version: options?.version });
  delete options.version;
  if (options.manuallySwaggerUIHtml) {
    return options.manuallySwaggerUIHtml(asset);
  }
  const optionsStrings = renderSwaggerUIOptions(options);
  return `
    <div>
      <div id="swagger-ui"></div>
      ${asset.css.map((url) => html`<link rel="stylesheet" href="${url}" />`)}
      ${asset.js.map((url) => html`<script src="${url}" crossorigin="anonymous"></script>`)}
      <script>
        window.onload = () => {
          window.ui = SwaggerUIBundle({
            dom_id: '#swagger-ui',${optionsStrings},
          })
        }
      </script>
    </div>
  `;
};
var middleware = (options) => async (c2) => {
  const title = options?.title ?? "SwaggerUI";
  return c2.html(
    /* html */
    `
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <meta name="description" content="SwaggerUI" />
          <title>${title}</title>
        </head>
        <body>
          ${SwaggerUI(options)}
        </body>
      </html>
    `
  );
};

// ../../node_modules/.pnpm/hono-openapi@0.4.6_hono@4.7.4_openapi-types@12.1.3_zod@3.24.2/node_modules/hono-openapi/utils.js
var e = Symbol("openapi");
var s2 = ["GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"];
var n = (e2) => e2.charAt(0).toUpperCase() + e2.slice(1);
var o = /* @__PURE__ */ new Map();
var a = (e2, t2) => {
  const s3 = `${e2}:${t2}`;
  if (o.has(s3)) return o.get(s3);
  let a2 = e2;
  if ("/" === t2) return `${a2}Index`;
  for (const e3 of t2.split("/")) 123 === e3.charCodeAt(0) ? a2 += `By${n(e3.slice(1, -1))}` : a2 += n(e3);
  return o.set(s3, a2), a2;
};
var r = /* @__PURE__ */ new Map();
function c(e2, t2, s3) {
  return e2 && t2 in e2 ? e2[t2] ?? s3 : s3;
}
function i(...e2) {
  return e2.reduce((e3, t2) => {
    if (!t2) return e3;
    let s3;
    return ("tags" in e3 && e3.tags || "tags" in t2 && t2.tags) && (s3 = [...c(e3, "tags", []), ...c(t2, "tags", [])]), { ...e3, ...t2, tags: s3, responses: { ...c(e3, "responses", {}), ...c(t2, "responses", {}) }, parameters: m(e3.parameters, t2.parameters) };
  }, {});
}
function p({ path: e2, method: t2, data: s3, schema: n2 }) {
  e2 = ((e3) => e3.split("/").map((e4) => {
    let t3 = e4;
    return t3.startsWith(":") && (t3 = t3.slice(1, t3.length), t3.endsWith("?") && (t3 = t3.slice(0, -1)), t3 = `{${t3}}`), t3;
  }).join("/"))(e2);
  const o2 = t2.toLowerCase();
  if ("all" === o2) if (r.has(e2)) {
    const t3 = r.get(e2) ?? {};
    r.set(e2, { ...t3, ...s3, parameters: m(t3.parameters, s3.parameters) });
  } else r.set(e2, s3);
  else {
    const t3 = function(e3) {
      const t4 = Array.from(r.keys());
      let s4 = {};
      for (const n3 of t4) e3.match(n3) && (s4 = i(s4, r.get(n3) ?? {}));
      return s4;
    }(e2);
    n2[e2] = { ...n2[e2] ? n2[e2] : {}, [o2]: { responses: {}, operationId: a(o2, e2), ...i(t3, n2[e2]?.[o2], s3) } };
  }
}
var l = (e2) => "$ref" in e2 ? e2.$ref : `${e2.in} ${e2.name}`;
function m(...e2) {
  const t2 = e2.flatMap((e3) => e3 ?? []).reduce((e3, t3) => (e3.set(l(t3), t3), e3), /* @__PURE__ */ new Map());
  return Array.from(t2.values());
}
function u(e2, { excludeStaticFile: t2 = true, exclude: s3 = [] }) {
  const n2 = {}, o2 = Array.isArray(s3) ? s3 : [s3];
  for (const [s4, a2] of Object.entries(e2)) if (!(o2.some((e3) => "string" == typeof e3 ? s4 === e3 : e3.test(s4)) || s4.includes("*") || t2 && s4.includes("."))) {
    for (const e3 of Object.keys(a2)) {
      const t3 = a2[e3];
      if (s4.includes("{")) {
        t3.parameters || (t3.parameters = []);
        const e4 = s4.split("/").filter((e5) => e5.startsWith("{") && !t3.parameters.find((t4) => "path" === t4.in && t4.name === e5.slice(1, e5.length - 1)));
        for (const s5 of e4) {
          const e5 = s5.slice(1, s5.length - 1), n3 = t3.parameters.findIndex((t4) => "param" === t4.in && t4.name === e5);
          -1 !== n3 ? t3.parameters[n3].in = "path" : t3.parameters.push({ schema: { type: "string" }, in: "path", name: e5, required: true });
        }
      }
      t3.responses || (t3.responses = { 200: {} });
    }
    n2[s4] = a2;
  }
  return n2;
}
function f(e2, t2) {
  const s3 = { version: "3.1.0", components: {} };
  let n2 = null;
  return async (o2) => (n2 || (n2 = await d(e2, t2, s3, o2)), o2.json(n2));
}
async function d(t2, { documentation: n2 = {}, excludeStaticFile: o2 = true, exclude: a2 = [], excludeMethods: r2 = ["OPTIONS"], excludeTags: c2 = [], defaultOptions: i2 } = { documentation: {}, excludeStaticFile: true, exclude: [], excludeMethods: ["OPTIONS"], excludeTags: [] }, { version: l2 = "3.1.0", components: m2 = {} } = { version: "3.1.0", components: {} }, f2) {
  const d2 = { version: l2, components: m2 }, h2 = {};
  for (const n3 of t2.routes) {
    if (!(e in n3.handler)) continue;
    if (r2.includes(n3.method)) continue;
    if (false === s2.includes(n3.method) && "ALL" !== n3.method) continue;
    const { resolver: t3, metadata: o3 = {} } = n3.handler[e], a3 = i2?.[n3.method], { docs: c3, components: l3 } = await t3({ ...d2, ...o3 }, a3);
    d2.components = { ...d2.components, ...l3 ?? {} }, p({ method: n3.method, path: n3.path, data: c3, schema: h2 });
  }
  for (const e2 in h2) for (const t3 in h2[e2]) {
    const s3 = h2[e2][t3]?.hide;
    s3 && ("boolean" == typeof s3 ? s3 : f2 && s3(f2)) && delete h2[e2][t3];
  }
  return { openapi: d2.version, ...{ ...n2, tags: n2.tags?.filter((e2) => !c2?.includes(e2?.name)), info: { title: "Hono Documentation", description: "Development documentation", version: "0.0.0", ...n2.info }, paths: { ...u(h2, { excludeStaticFile: o2, exclude: a2 }), ...n2.paths }, components: { ...n2.components, schemas: { ...d2.components, ...n2.components?.schemas } } } };
}
function h(s3) {
  const { validateResponse: n2, ...o2 } = s3;
  return Object.assign(async (e2, o3) => {
    if (await o3(), n2 && s3.responses) {
      const o4 = e2.res.status, a2 = e2.res.headers.get("content-type");
      if (o4 && a2) {
        const r2 = s3.responses[o4];
        if (r2 && "content" in r2 && r2.content) {
          const s4 = a2.split(";")[0], o5 = r2.content[s4];
          if (o5?.schema && "validator" in o5.schema) try {
            let t2;
            const n3 = e2.res.clone();
            if ("application/json" === s4 ? t2 = await n3.json() : "text/plain" === s4 && (t2 = await n3.text()), !t2) throw new Error("No data to validate!");
            await o5.schema.validator(t2);
          } catch (e3) {
            let s5 = { status: 500, message: "Response validation failed!" };
            throw "object" == typeof n2 && (s5 = { ...s5, ...n2 }), new HTTPException(s5.status, { message: s5.message, cause: e3 });
          }
        }
      }
    }
  }, { [e]: { resolver: (e2, t2) => x(e2, o2, t2) } });
}
async function x(e2, t2, s3 = {}) {
  let n2 = {};
  const o2 = { ...s3, ...t2, responses: { ...s3?.responses, ...t2.responses } };
  if (o2.responses) for (const t3 of Object.keys(o2.responses)) {
    const s4 = o2.responses[t3];
    if (s4 && "content" in s4) for (const t4 of Object.keys(s4.content ?? {})) {
      const o3 = s4.content?.[t4];
      if (o3 && (o3.schema && "builder" in o3.schema)) {
        const t5 = await o3.schema.builder(e2);
        o3.schema = t5.schema, t5.components && (n2 = { ...n2, ...t5.components });
      }
    }
  }
  return { docs: o2, components: n2 };
}

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/double-indexed-kv.js
var DoubleIndexedKV = class {
  constructor() {
    this.keyToValue = /* @__PURE__ */ new Map();
    this.valueToKey = /* @__PURE__ */ new Map();
  }
  set(key, value) {
    this.keyToValue.set(key, value);
    this.valueToKey.set(value, key);
  }
  getByKey(key) {
    return this.keyToValue.get(key);
  }
  getByValue(value) {
    return this.valueToKey.get(value);
  }
  clear() {
    this.keyToValue.clear();
    this.valueToKey.clear();
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/registry.js
var Registry = class {
  constructor(generateIdentifier) {
    this.generateIdentifier = generateIdentifier;
    this.kv = new DoubleIndexedKV();
  }
  register(value, identifier) {
    if (this.kv.getByValue(value)) {
      return;
    }
    if (!identifier) {
      identifier = this.generateIdentifier(value);
    }
    this.kv.set(identifier, value);
  }
  clear() {
    this.kv.clear();
  }
  getIdentifier(value) {
    return this.kv.getByValue(value);
  }
  getValue(identifier) {
    return this.kv.getByKey(identifier);
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/class-registry.js
var ClassRegistry = class extends Registry {
  constructor() {
    super((c2) => c2.name);
    this.classToAllowedProps = /* @__PURE__ */ new Map();
  }
  register(value, options) {
    if (typeof options === "object") {
      if (options.allowProps) {
        this.classToAllowedProps.set(value, options.allowProps);
      }
      super.register(value, options.identifier);
    } else {
      super.register(value, options);
    }
  }
  getAllowedProps(value) {
    return this.classToAllowedProps.get(value);
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/util.js
function valuesOfObj(record) {
  if ("values" in Object) {
    return Object.values(record);
  }
  const values = [];
  for (const key in record) {
    if (record.hasOwnProperty(key)) {
      values.push(record[key]);
    }
  }
  return values;
}
function find(record, predicate) {
  const values = valuesOfObj(record);
  if ("find" in values) {
    return values.find(predicate);
  }
  const valuesNotNever = values;
  for (let i2 = 0; i2 < valuesNotNever.length; i2++) {
    const value = valuesNotNever[i2];
    if (predicate(value)) {
      return value;
    }
  }
  return void 0;
}
function forEach(record, run) {
  Object.entries(record).forEach(([key, value]) => run(value, key));
}
function includes(arr, value) {
  return arr.indexOf(value) !== -1;
}
function findArr(record, predicate) {
  for (let i2 = 0; i2 < record.length; i2++) {
    const value = record[i2];
    if (predicate(value)) {
      return value;
    }
  }
  return void 0;
}

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/custom-transformer-registry.js
var CustomTransformerRegistry = class {
  constructor() {
    this.transfomers = {};
  }
  register(transformer) {
    this.transfomers[transformer.name] = transformer;
  }
  findApplicable(v) {
    return find(this.transfomers, (transformer) => transformer.isApplicable(v));
  }
  findByName(name) {
    return this.transfomers[name];
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/is.js
var getType = (payload) => Object.prototype.toString.call(payload).slice(8, -1);
var isUndefined = (payload) => typeof payload === "undefined";
var isNull = (payload) => payload === null;
var isPlainObject = (payload) => {
  if (typeof payload !== "object" || payload === null)
    return false;
  if (payload === Object.prototype)
    return false;
  if (Object.getPrototypeOf(payload) === null)
    return true;
  return Object.getPrototypeOf(payload) === Object.prototype;
};
var isEmptyObject = (payload) => isPlainObject(payload) && Object.keys(payload).length === 0;
var isArray = (payload) => Array.isArray(payload);
var isString = (payload) => typeof payload === "string";
var isNumber = (payload) => typeof payload === "number" && !isNaN(payload);
var isBoolean = (payload) => typeof payload === "boolean";
var isRegExp = (payload) => payload instanceof RegExp;
var isMap = (payload) => payload instanceof Map;
var isSet = (payload) => payload instanceof Set;
var isSymbol = (payload) => getType(payload) === "Symbol";
var isDate = (payload) => payload instanceof Date && !isNaN(payload.valueOf());
var isError = (payload) => payload instanceof Error;
var isNaNValue = (payload) => typeof payload === "number" && isNaN(payload);
var isPrimitive = (payload) => isBoolean(payload) || isNull(payload) || isUndefined(payload) || isNumber(payload) || isString(payload) || isSymbol(payload);
var isBigint = (payload) => typeof payload === "bigint";
var isInfinite = (payload) => payload === Infinity || payload === -Infinity;
var isTypedArray = (payload) => ArrayBuffer.isView(payload) && !(payload instanceof DataView);
var isURL = (payload) => payload instanceof URL;

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/pathstringifier.js
var escapeKey = (key) => key.replace(/\./g, "\\.");
var stringifyPath = (path) => path.map(String).map(escapeKey).join(".");
var parsePath = (string) => {
  const result = [];
  let segment = "";
  for (let i2 = 0; i2 < string.length; i2++) {
    let char = string.charAt(i2);
    const isEscapedDot = char === "\\" && string.charAt(i2 + 1) === ".";
    if (isEscapedDot) {
      segment += ".";
      i2++;
      continue;
    }
    const isEndOfSegment = char === ".";
    if (isEndOfSegment) {
      result.push(segment);
      segment = "";
      continue;
    }
    segment += char;
  }
  const lastSegment = segment;
  result.push(lastSegment);
  return result;
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/transformer.js
function simpleTransformation(isApplicable, annotation, transform, untransform) {
  return {
    isApplicable,
    annotation,
    transform,
    untransform
  };
}
var simpleRules = [
  simpleTransformation(isUndefined, "undefined", () => null, () => void 0),
  simpleTransformation(isBigint, "bigint", (v) => v.toString(), (v) => {
    if (typeof BigInt !== "undefined") {
      return BigInt(v);
    }
    console.error("Please add a BigInt polyfill.");
    return v;
  }),
  simpleTransformation(isDate, "Date", (v) => v.toISOString(), (v) => new Date(v)),
  simpleTransformation(isError, "Error", (v, superJson) => {
    const baseError = {
      name: v.name,
      message: v.message
    };
    superJson.allowedErrorProps.forEach((prop) => {
      baseError[prop] = v[prop];
    });
    return baseError;
  }, (v, superJson) => {
    const e2 = new Error(v.message);
    e2.name = v.name;
    e2.stack = v.stack;
    superJson.allowedErrorProps.forEach((prop) => {
      e2[prop] = v[prop];
    });
    return e2;
  }),
  simpleTransformation(isRegExp, "regexp", (v) => "" + v, (regex) => {
    const body = regex.slice(1, regex.lastIndexOf("/"));
    const flags = regex.slice(regex.lastIndexOf("/") + 1);
    return new RegExp(body, flags);
  }),
  simpleTransformation(
    isSet,
    "set",
    // (sets only exist in es6+)
    // eslint-disable-next-line es5/no-es6-methods
    (v) => [...v.values()],
    (v) => new Set(v)
  ),
  simpleTransformation(isMap, "map", (v) => [...v.entries()], (v) => new Map(v)),
  simpleTransformation((v) => isNaNValue(v) || isInfinite(v), "number", (v) => {
    if (isNaNValue(v)) {
      return "NaN";
    }
    if (v > 0) {
      return "Infinity";
    } else {
      return "-Infinity";
    }
  }, Number),
  simpleTransformation((v) => v === 0 && 1 / v === -Infinity, "number", () => {
    return "-0";
  }, Number),
  simpleTransformation(isURL, "URL", (v) => v.toString(), (v) => new URL(v))
];
function compositeTransformation(isApplicable, annotation, transform, untransform) {
  return {
    isApplicable,
    annotation,
    transform,
    untransform
  };
}
var symbolRule = compositeTransformation((s3, superJson) => {
  if (isSymbol(s3)) {
    const isRegistered = !!superJson.symbolRegistry.getIdentifier(s3);
    return isRegistered;
  }
  return false;
}, (s3, superJson) => {
  const identifier = superJson.symbolRegistry.getIdentifier(s3);
  return ["symbol", identifier];
}, (v) => v.description, (_, a2, superJson) => {
  const value = superJson.symbolRegistry.getValue(a2[1]);
  if (!value) {
    throw new Error("Trying to deserialize unknown symbol");
  }
  return value;
});
var constructorToName = [
  Int8Array,
  Uint8Array,
  Int16Array,
  Uint16Array,
  Int32Array,
  Uint32Array,
  Float32Array,
  Float64Array,
  Uint8ClampedArray
].reduce((obj, ctor) => {
  obj[ctor.name] = ctor;
  return obj;
}, {});
var typedArrayRule = compositeTransformation(isTypedArray, (v) => ["typed-array", v.constructor.name], (v) => [...v], (v, a2) => {
  const ctor = constructorToName[a2[1]];
  if (!ctor) {
    throw new Error("Trying to deserialize unknown typed array");
  }
  return new ctor(v);
});
function isInstanceOfRegisteredClass(potentialClass, superJson) {
  if (potentialClass?.constructor) {
    const isRegistered = !!superJson.classRegistry.getIdentifier(potentialClass.constructor);
    return isRegistered;
  }
  return false;
}
var classRule = compositeTransformation(isInstanceOfRegisteredClass, (clazz, superJson) => {
  const identifier = superJson.classRegistry.getIdentifier(clazz.constructor);
  return ["class", identifier];
}, (clazz, superJson) => {
  const allowedProps = superJson.classRegistry.getAllowedProps(clazz.constructor);
  if (!allowedProps) {
    return { ...clazz };
  }
  const result = {};
  allowedProps.forEach((prop) => {
    result[prop] = clazz[prop];
  });
  return result;
}, (v, a2, superJson) => {
  const clazz = superJson.classRegistry.getValue(a2[1]);
  if (!clazz) {
    throw new Error(`Trying to deserialize unknown class '${a2[1]}' - check https://github.com/blitz-js/superjson/issues/116#issuecomment-773996564`);
  }
  return Object.assign(Object.create(clazz.prototype), v);
});
var customRule = compositeTransformation((value, superJson) => {
  return !!superJson.customTransformerRegistry.findApplicable(value);
}, (value, superJson) => {
  const transformer = superJson.customTransformerRegistry.findApplicable(value);
  return ["custom", transformer.name];
}, (value, superJson) => {
  const transformer = superJson.customTransformerRegistry.findApplicable(value);
  return transformer.serialize(value);
}, (v, a2, superJson) => {
  const transformer = superJson.customTransformerRegistry.findByName(a2[1]);
  if (!transformer) {
    throw new Error("Trying to deserialize unknown custom value");
  }
  return transformer.deserialize(v);
});
var compositeRules = [classRule, symbolRule, customRule, typedArrayRule];
var transformValue = (value, superJson) => {
  const applicableCompositeRule = findArr(compositeRules, (rule) => rule.isApplicable(value, superJson));
  if (applicableCompositeRule) {
    return {
      value: applicableCompositeRule.transform(value, superJson),
      type: applicableCompositeRule.annotation(value, superJson)
    };
  }
  const applicableSimpleRule = findArr(simpleRules, (rule) => rule.isApplicable(value, superJson));
  if (applicableSimpleRule) {
    return {
      value: applicableSimpleRule.transform(value, superJson),
      type: applicableSimpleRule.annotation
    };
  }
  return void 0;
};
var simpleRulesByAnnotation = {};
simpleRules.forEach((rule) => {
  simpleRulesByAnnotation[rule.annotation] = rule;
});
var untransformValue = (json, type, superJson) => {
  if (isArray(type)) {
    switch (type[0]) {
      case "symbol":
        return symbolRule.untransform(json, type, superJson);
      case "class":
        return classRule.untransform(json, type, superJson);
      case "custom":
        return customRule.untransform(json, type, superJson);
      case "typed-array":
        return typedArrayRule.untransform(json, type, superJson);
      default:
        throw new Error("Unknown transformation: " + type);
    }
  } else {
    const transformation = simpleRulesByAnnotation[type];
    if (!transformation) {
      throw new Error("Unknown transformation: " + type);
    }
    return transformation.untransform(json, superJson);
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/accessDeep.js
var getNthKey = (value, n2) => {
  if (n2 > value.size)
    throw new Error("index out of bounds");
  const keys = value.keys();
  while (n2 > 0) {
    keys.next();
    n2--;
  }
  return keys.next().value;
};
function validatePath(path) {
  if (includes(path, "__proto__")) {
    throw new Error("__proto__ is not allowed as a property");
  }
  if (includes(path, "prototype")) {
    throw new Error("prototype is not allowed as a property");
  }
  if (includes(path, "constructor")) {
    throw new Error("constructor is not allowed as a property");
  }
}
var getDeep = (object, path) => {
  validatePath(path);
  for (let i2 = 0; i2 < path.length; i2++) {
    const key = path[i2];
    if (isSet(object)) {
      object = getNthKey(object, +key);
    } else if (isMap(object)) {
      const row = +key;
      const type = +path[++i2] === 0 ? "key" : "value";
      const keyOfRow = getNthKey(object, row);
      switch (type) {
        case "key":
          object = keyOfRow;
          break;
        case "value":
          object = object.get(keyOfRow);
          break;
      }
    } else {
      object = object[key];
    }
  }
  return object;
};
var setDeep = (object, path, mapper) => {
  validatePath(path);
  if (path.length === 0) {
    return mapper(object);
  }
  let parent = object;
  for (let i2 = 0; i2 < path.length - 1; i2++) {
    const key = path[i2];
    if (isArray(parent)) {
      const index = +key;
      parent = parent[index];
    } else if (isPlainObject(parent)) {
      parent = parent[key];
    } else if (isSet(parent)) {
      const row = +key;
      parent = getNthKey(parent, row);
    } else if (isMap(parent)) {
      const isEnd = i2 === path.length - 2;
      if (isEnd) {
        break;
      }
      const row = +key;
      const type = +path[++i2] === 0 ? "key" : "value";
      const keyOfRow = getNthKey(parent, row);
      switch (type) {
        case "key":
          parent = keyOfRow;
          break;
        case "value":
          parent = parent.get(keyOfRow);
          break;
      }
    }
  }
  const lastKey = path[path.length - 1];
  if (isArray(parent)) {
    parent[+lastKey] = mapper(parent[+lastKey]);
  } else if (isPlainObject(parent)) {
    parent[lastKey] = mapper(parent[lastKey]);
  }
  if (isSet(parent)) {
    const oldValue = getNthKey(parent, +lastKey);
    const newValue = mapper(oldValue);
    if (oldValue !== newValue) {
      parent.delete(oldValue);
      parent.add(newValue);
    }
  }
  if (isMap(parent)) {
    const row = +path[path.length - 2];
    const keyToRow = getNthKey(parent, row);
    const type = +lastKey === 0 ? "key" : "value";
    switch (type) {
      case "key": {
        const newKey = mapper(keyToRow);
        parent.set(newKey, parent.get(keyToRow));
        if (newKey !== keyToRow) {
          parent.delete(keyToRow);
        }
        break;
      }
      case "value": {
        parent.set(keyToRow, mapper(parent.get(keyToRow)));
        break;
      }
    }
  }
  return object;
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/plainer.js
function traverse(tree, walker2, origin = []) {
  if (!tree) {
    return;
  }
  if (!isArray(tree)) {
    forEach(tree, (subtree, key) => traverse(subtree, walker2, [...origin, ...parsePath(key)]));
    return;
  }
  const [nodeValue, children] = tree;
  if (children) {
    forEach(children, (child, key) => {
      traverse(child, walker2, [...origin, ...parsePath(key)]);
    });
  }
  walker2(nodeValue, origin);
}
function applyValueAnnotations(plain, annotations, superJson) {
  traverse(annotations, (type, path) => {
    plain = setDeep(plain, path, (v) => untransformValue(v, type, superJson));
  });
  return plain;
}
function applyReferentialEqualityAnnotations(plain, annotations) {
  function apply(identicalPaths, path) {
    const object = getDeep(plain, parsePath(path));
    identicalPaths.map(parsePath).forEach((identicalObjectPath) => {
      plain = setDeep(plain, identicalObjectPath, () => object);
    });
  }
  if (isArray(annotations)) {
    const [root, other] = annotations;
    root.forEach((identicalPath) => {
      plain = setDeep(plain, parsePath(identicalPath), () => plain);
    });
    if (other) {
      forEach(other, apply);
    }
  } else {
    forEach(annotations, apply);
  }
  return plain;
}
var isDeep = (object, superJson) => isPlainObject(object) || isArray(object) || isMap(object) || isSet(object) || isInstanceOfRegisteredClass(object, superJson);
function addIdentity(object, path, identities) {
  const existingSet = identities.get(object);
  if (existingSet) {
    existingSet.push(path);
  } else {
    identities.set(object, [path]);
  }
}
function generateReferentialEqualityAnnotations(identitites, dedupe) {
  const result = {};
  let rootEqualityPaths = void 0;
  identitites.forEach((paths) => {
    if (paths.length <= 1) {
      return;
    }
    if (!dedupe) {
      paths = paths.map((path) => path.map(String)).sort((a2, b) => a2.length - b.length);
    }
    const [representativePath, ...identicalPaths] = paths;
    if (representativePath.length === 0) {
      rootEqualityPaths = identicalPaths.map(stringifyPath);
    } else {
      result[stringifyPath(representativePath)] = identicalPaths.map(stringifyPath);
    }
  });
  if (rootEqualityPaths) {
    if (isEmptyObject(result)) {
      return [rootEqualityPaths];
    } else {
      return [rootEqualityPaths, result];
    }
  } else {
    return isEmptyObject(result) ? void 0 : result;
  }
}
var walker = (object, identities, superJson, dedupe, path = [], objectsInThisPath = [], seenObjects = /* @__PURE__ */ new Map()) => {
  const primitive = isPrimitive(object);
  if (!primitive) {
    addIdentity(object, path, identities);
    const seen = seenObjects.get(object);
    if (seen) {
      return dedupe ? {
        transformedValue: null
      } : seen;
    }
  }
  if (!isDeep(object, superJson)) {
    const transformed2 = transformValue(object, superJson);
    const result2 = transformed2 ? {
      transformedValue: transformed2.value,
      annotations: [transformed2.type]
    } : {
      transformedValue: object
    };
    if (!primitive) {
      seenObjects.set(object, result2);
    }
    return result2;
  }
  if (includes(objectsInThisPath, object)) {
    return {
      transformedValue: null
    };
  }
  const transformationResult = transformValue(object, superJson);
  const transformed = transformationResult?.value ?? object;
  const transformedValue = isArray(transformed) ? [] : {};
  const innerAnnotations = {};
  forEach(transformed, (value, index) => {
    if (index === "__proto__" || index === "constructor" || index === "prototype") {
      throw new Error(`Detected property ${index}. This is a prototype pollution risk, please remove it from your object.`);
    }
    const recursiveResult = walker(value, identities, superJson, dedupe, [...path, index], [...objectsInThisPath, object], seenObjects);
    transformedValue[index] = recursiveResult.transformedValue;
    if (isArray(recursiveResult.annotations)) {
      innerAnnotations[index] = recursiveResult.annotations;
    } else if (isPlainObject(recursiveResult.annotations)) {
      forEach(recursiveResult.annotations, (tree, key) => {
        innerAnnotations[escapeKey(index) + "." + key] = tree;
      });
    }
  });
  const result = isEmptyObject(innerAnnotations) ? {
    transformedValue,
    annotations: !!transformationResult ? [transformationResult.type] : void 0
  } : {
    transformedValue,
    annotations: !!transformationResult ? [transformationResult.type, innerAnnotations] : innerAnnotations
  };
  if (!primitive) {
    seenObjects.set(object, result);
  }
  return result;
};

// ../../node_modules/.pnpm/is-what@4.1.16/node_modules/is-what/dist/index.js
function getType2(payload) {
  return Object.prototype.toString.call(payload).slice(8, -1);
}
function isArray2(payload) {
  return getType2(payload) === "Array";
}
function isPlainObject2(payload) {
  if (getType2(payload) !== "Object")
    return false;
  const prototype = Object.getPrototypeOf(payload);
  return !!prototype && prototype.constructor === Object && prototype === Object.prototype;
}

// ../../node_modules/.pnpm/copy-anything@3.0.5/node_modules/copy-anything/dist/index.js
function assignProp(carry, key, newVal, originalObject, includeNonenumerable) {
  const propType = {}.propertyIsEnumerable.call(originalObject, key) ? "enumerable" : "nonenumerable";
  if (propType === "enumerable")
    carry[key] = newVal;
  if (includeNonenumerable && propType === "nonenumerable") {
    Object.defineProperty(carry, key, {
      value: newVal,
      enumerable: false,
      writable: true,
      configurable: true
    });
  }
}
function copy(target, options = {}) {
  if (isArray2(target)) {
    return target.map((item) => copy(item, options));
  }
  if (!isPlainObject2(target)) {
    return target;
  }
  const props = Object.getOwnPropertyNames(target);
  const symbols = Object.getOwnPropertySymbols(target);
  return [...props, ...symbols].reduce((carry, key) => {
    if (isArray2(options.props) && !options.props.includes(key)) {
      return carry;
    }
    const val = target[key];
    const newVal = copy(val, options);
    assignProp(carry, key, newVal, target, options.nonenumerable);
    return carry;
  }, {});
}

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/index.js
var SuperJSON = class {
  /**
   * @param dedupeReferentialEqualities  If true, SuperJSON will make sure only one instance of referentially equal objects are serialized and the rest are replaced with `null`.
   */
  constructor({ dedupe = false } = {}) {
    this.classRegistry = new ClassRegistry();
    this.symbolRegistry = new Registry((s3) => s3.description ?? "");
    this.customTransformerRegistry = new CustomTransformerRegistry();
    this.allowedErrorProps = [];
    this.dedupe = dedupe;
  }
  serialize(object) {
    const identities = /* @__PURE__ */ new Map();
    const output = walker(object, identities, this, this.dedupe);
    const res = {
      json: output.transformedValue
    };
    if (output.annotations) {
      res.meta = {
        ...res.meta,
        values: output.annotations
      };
    }
    const equalityAnnotations = generateReferentialEqualityAnnotations(identities, this.dedupe);
    if (equalityAnnotations) {
      res.meta = {
        ...res.meta,
        referentialEqualities: equalityAnnotations
      };
    }
    return res;
  }
  deserialize(payload) {
    const { json, meta } = payload;
    let result = copy(json);
    if (meta?.values) {
      result = applyValueAnnotations(result, meta.values, this);
    }
    if (meta?.referentialEqualities) {
      result = applyReferentialEqualityAnnotations(result, meta.referentialEqualities);
    }
    return result;
  }
  stringify(object) {
    return JSON.stringify(this.serialize(object));
  }
  parse(string) {
    return this.deserialize(JSON.parse(string));
  }
  registerClass(v, options) {
    this.classRegistry.register(v, options);
  }
  registerSymbol(v, identifier) {
    this.symbolRegistry.register(v, identifier);
  }
  registerCustom(transformer, name) {
    this.customTransformerRegistry.register({
      name,
      ...transformer
    });
  }
  allowErrorProps(...props) {
    this.allowedErrorProps.push(...props);
  }
};
SuperJSON.defaultInstance = new SuperJSON();
SuperJSON.serialize = SuperJSON.defaultInstance.serialize.bind(SuperJSON.defaultInstance);
SuperJSON.deserialize = SuperJSON.defaultInstance.deserialize.bind(SuperJSON.defaultInstance);
SuperJSON.stringify = SuperJSON.defaultInstance.stringify.bind(SuperJSON.defaultInstance);
SuperJSON.parse = SuperJSON.defaultInstance.parse.bind(SuperJSON.defaultInstance);
SuperJSON.registerClass = SuperJSON.defaultInstance.registerClass.bind(SuperJSON.defaultInstance);
SuperJSON.registerSymbol = SuperJSON.defaultInstance.registerSymbol.bind(SuperJSON.defaultInstance);
SuperJSON.registerCustom = SuperJSON.defaultInstance.registerCustom.bind(SuperJSON.defaultInstance);
SuperJSON.allowErrorProps = SuperJSON.defaultInstance.allowErrorProps.bind(SuperJSON.defaultInstance);
var stringify = SuperJSON.stringify;

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/Options.js
var ignoreOverride = Symbol("Let zodToJsonSchema decide on which parser to use");
var defaultOptions = {
  name: void 0,
  $refStrategy: "root",
  basePath: ["#"],
  effectStrategy: "input",
  pipeStrategy: "all",
  dateStrategy: "format:date-time",
  mapStrategy: "entries",
  removeAdditionalStrategy: "passthrough",
  allowedAdditionalProperties: true,
  rejectedAdditionalProperties: false,
  definitionPath: "definitions",
  target: "jsonSchema7",
  strictUnions: false,
  definitions: {},
  errorMessages: false,
  markdownDescription: false,
  patternStrategy: "escape",
  applyRegexFlags: false,
  emailStrategy: "format:email",
  base64Strategy: "contentEncoding:base64",
  nameStrategy: "ref"
};
var getDefaultOptions = (options) => typeof options === "string" ? {
  ...defaultOptions,
  name: options
} : {
  ...defaultOptions,
  ...options
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/Refs.js
var getRefs = (options) => {
  const _options = getDefaultOptions(options);
  const currentPath = _options.name !== void 0 ? [..._options.basePath, _options.definitionPath, _options.name] : _options.basePath;
  return {
    ..._options,
    currentPath,
    propertyPath: void 0,
    seen: new Map(Object.entries(_options.definitions).map(([name, def]) => [
      def._def,
      {
        def: def._def,
        path: [..._options.basePath, _options.definitionPath, name],
        // Resolution of references will be forced even though seen, so it's ok that the schema is undefined here for now.
        jsonSchema: void 0
      }
    ]))
  };
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/errorMessages.js
function addErrorMessage(res, key, errorMessage, refs) {
  if (!refs?.errorMessages)
    return;
  if (errorMessage) {
    res.errorMessage = {
      ...res.errorMessage,
      [key]: errorMessage
    };
  }
}
function setResponseValueAndErrors(res, key, value, errorMessage, refs) {
  res[key] = value;
  addErrorMessage(res, key, errorMessage, refs);
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/any.js
function parseAnyDef() {
  return {};
}
function parseArrayDef(def, refs) {
  const res = {
    type: "array"
  };
  if (def.type?._def && def.type?._def?.typeName !== ZodFirstPartyTypeKind.ZodAny) {
    res.items = parseDef(def.type._def, {
      ...refs,
      currentPath: [...refs.currentPath, "items"]
    });
  }
  if (def.minLength) {
    setResponseValueAndErrors(res, "minItems", def.minLength.value, def.minLength.message, refs);
  }
  if (def.maxLength) {
    setResponseValueAndErrors(res, "maxItems", def.maxLength.value, def.maxLength.message, refs);
  }
  if (def.exactLength) {
    setResponseValueAndErrors(res, "minItems", def.exactLength.value, def.exactLength.message, refs);
    setResponseValueAndErrors(res, "maxItems", def.exactLength.value, def.exactLength.message, refs);
  }
  return res;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/bigint.js
function parseBigintDef(def, refs) {
  const res = {
    type: "integer",
    format: "int64"
  };
  if (!def.checks)
    return res;
  for (const check of def.checks) {
    switch (check.kind) {
      case "min":
        if (refs.target === "jsonSchema7") {
          if (check.inclusive) {
            setResponseValueAndErrors(res, "minimum", check.value, check.message, refs);
          } else {
            setResponseValueAndErrors(res, "exclusiveMinimum", check.value, check.message, refs);
          }
        } else {
          if (!check.inclusive) {
            res.exclusiveMinimum = true;
          }
          setResponseValueAndErrors(res, "minimum", check.value, check.message, refs);
        }
        break;
      case "max":
        if (refs.target === "jsonSchema7") {
          if (check.inclusive) {
            setResponseValueAndErrors(res, "maximum", check.value, check.message, refs);
          } else {
            setResponseValueAndErrors(res, "exclusiveMaximum", check.value, check.message, refs);
          }
        } else {
          if (!check.inclusive) {
            res.exclusiveMaximum = true;
          }
          setResponseValueAndErrors(res, "maximum", check.value, check.message, refs);
        }
        break;
      case "multipleOf":
        setResponseValueAndErrors(res, "multipleOf", check.value, check.message, refs);
        break;
    }
  }
  return res;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/boolean.js
function parseBooleanDef() {
  return {
    type: "boolean"
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/branded.js
function parseBrandedDef(_def, refs) {
  return parseDef(_def.type._def, refs);
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/catch.js
var parseCatchDef = (def, refs) => {
  return parseDef(def.innerType._def, refs);
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/date.js
function parseDateDef(def, refs, overrideDateStrategy) {
  const strategy = overrideDateStrategy ?? refs.dateStrategy;
  if (Array.isArray(strategy)) {
    return {
      anyOf: strategy.map((item, i2) => parseDateDef(def, refs, item))
    };
  }
  switch (strategy) {
    case "string":
    case "format:date-time":
      return {
        type: "string",
        format: "date-time"
      };
    case "format:date":
      return {
        type: "string",
        format: "date"
      };
    case "integer":
      return integerDateParser(def, refs);
  }
}
var integerDateParser = (def, refs) => {
  const res = {
    type: "integer",
    format: "unix-time"
  };
  if (refs.target === "openApi3") {
    return res;
  }
  for (const check of def.checks) {
    switch (check.kind) {
      case "min":
        setResponseValueAndErrors(
          res,
          "minimum",
          check.value,
          // This is in milliseconds
          check.message,
          refs
        );
        break;
      case "max":
        setResponseValueAndErrors(
          res,
          "maximum",
          check.value,
          // This is in milliseconds
          check.message,
          refs
        );
        break;
    }
  }
  return res;
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/default.js
function parseDefaultDef(_def, refs) {
  return {
    ...parseDef(_def.innerType._def, refs),
    default: _def.defaultValue()
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/effects.js
function parseEffectsDef(_def, refs) {
  return refs.effectStrategy === "input" ? parseDef(_def.schema._def, refs) : {};
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/enum.js
function parseEnumDef(def) {
  return {
    type: "string",
    enum: Array.from(def.values)
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/intersection.js
var isJsonSchema7AllOfType = (type) => {
  if ("type" in type && type.type === "string")
    return false;
  return "allOf" in type;
};
function parseIntersectionDef(def, refs) {
  const allOf = [
    parseDef(def.left._def, {
      ...refs,
      currentPath: [...refs.currentPath, "allOf", "0"]
    }),
    parseDef(def.right._def, {
      ...refs,
      currentPath: [...refs.currentPath, "allOf", "1"]
    })
  ].filter((x2) => !!x2);
  let unevaluatedProperties = refs.target === "jsonSchema2019-09" ? { unevaluatedProperties: false } : void 0;
  const mergedAllOf = [];
  allOf.forEach((schema) => {
    if (isJsonSchema7AllOfType(schema)) {
      mergedAllOf.push(...schema.allOf);
      if (schema.unevaluatedProperties === void 0) {
        unevaluatedProperties = void 0;
      }
    } else {
      let nestedSchema = schema;
      if ("additionalProperties" in schema && schema.additionalProperties === false) {
        const { additionalProperties, ...rest } = schema;
        nestedSchema = rest;
      } else {
        unevaluatedProperties = void 0;
      }
      mergedAllOf.push(nestedSchema);
    }
  });
  return mergedAllOf.length ? {
    allOf: mergedAllOf,
    ...unevaluatedProperties
  } : void 0;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/literal.js
function parseLiteralDef(def, refs) {
  const parsedType = typeof def.value;
  if (parsedType !== "bigint" && parsedType !== "number" && parsedType !== "boolean" && parsedType !== "string") {
    return {
      type: Array.isArray(def.value) ? "array" : "object"
    };
  }
  if (refs.target === "openApi3") {
    return {
      type: parsedType === "bigint" ? "integer" : parsedType,
      enum: [def.value]
    };
  }
  return {
    type: parsedType === "bigint" ? "integer" : parsedType,
    const: def.value
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/string.js
var emojiRegex = void 0;
var zodPatterns = {
  /**
   * `c` was changed to `[cC]` to replicate /i flag
   */
  cuid: /^[cC][^\s-]{8,}$/,
  cuid2: /^[0-9a-z]+$/,
  ulid: /^[0-9A-HJKMNP-TV-Z]{26}$/,
  /**
   * `a-z` was added to replicate /i flag
   */
  email: /^(?!\.)(?!.*\.\.)([a-zA-Z0-9_'+\-\.]*)[a-zA-Z0-9_+-]@([a-zA-Z0-9][a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$/,
  /**
   * Constructed a valid Unicode RegExp
   *
   * Lazily instantiate since this type of regex isn't supported
   * in all envs (e.g. React Native).
   *
   * See:
   * https://github.com/colinhacks/zod/issues/2433
   * Fix in Zod:
   * https://github.com/colinhacks/zod/commit/9340fd51e48576a75adc919bff65dbc4a5d4c99b
   */
  emoji: () => {
    if (emojiRegex === void 0) {
      emojiRegex = RegExp("^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$", "u");
    }
    return emojiRegex;
  },
  /**
   * Unused
   */
  uuid: /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/,
  /**
   * Unused
   */
  ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/,
  ipv4Cidr: /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/(3[0-2]|[12]?[0-9])$/,
  /**
   * Unused
   */
  ipv6: /^(([a-f0-9]{1,4}:){7}|::([a-f0-9]{1,4}:){0,6}|([a-f0-9]{1,4}:){1}:([a-f0-9]{1,4}:){0,5}|([a-f0-9]{1,4}:){2}:([a-f0-9]{1,4}:){0,4}|([a-f0-9]{1,4}:){3}:([a-f0-9]{1,4}:){0,3}|([a-f0-9]{1,4}:){4}:([a-f0-9]{1,4}:){0,2}|([a-f0-9]{1,4}:){5}:([a-f0-9]{1,4}:){0,1})([a-f0-9]{1,4}|(((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2}))\.){3}((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2})))$/,
  ipv6Cidr: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/,
  base64: /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/,
  base64url: /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/,
  nanoid: /^[a-zA-Z0-9_-]{21}$/,
  jwt: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/
};
function parseStringDef(def, refs) {
  const res = {
    type: "string"
  };
  if (def.checks) {
    for (const check of def.checks) {
      switch (check.kind) {
        case "min":
          setResponseValueAndErrors(res, "minLength", typeof res.minLength === "number" ? Math.max(res.minLength, check.value) : check.value, check.message, refs);
          break;
        case "max":
          setResponseValueAndErrors(res, "maxLength", typeof res.maxLength === "number" ? Math.min(res.maxLength, check.value) : check.value, check.message, refs);
          break;
        case "email":
          switch (refs.emailStrategy) {
            case "format:email":
              addFormat(res, "email", check.message, refs);
              break;
            case "format:idn-email":
              addFormat(res, "idn-email", check.message, refs);
              break;
            case "pattern:zod":
              addPattern(res, zodPatterns.email, check.message, refs);
              break;
          }
          break;
        case "url":
          addFormat(res, "uri", check.message, refs);
          break;
        case "uuid":
          addFormat(res, "uuid", check.message, refs);
          break;
        case "regex":
          addPattern(res, check.regex, check.message, refs);
          break;
        case "cuid":
          addPattern(res, zodPatterns.cuid, check.message, refs);
          break;
        case "cuid2":
          addPattern(res, zodPatterns.cuid2, check.message, refs);
          break;
        case "startsWith":
          addPattern(res, RegExp(`^${escapeLiteralCheckValue(check.value, refs)}`), check.message, refs);
          break;
        case "endsWith":
          addPattern(res, RegExp(`${escapeLiteralCheckValue(check.value, refs)}$`), check.message, refs);
          break;
        case "datetime":
          addFormat(res, "date-time", check.message, refs);
          break;
        case "date":
          addFormat(res, "date", check.message, refs);
          break;
        case "time":
          addFormat(res, "time", check.message, refs);
          break;
        case "duration":
          addFormat(res, "duration", check.message, refs);
          break;
        case "length":
          setResponseValueAndErrors(res, "minLength", typeof res.minLength === "number" ? Math.max(res.minLength, check.value) : check.value, check.message, refs);
          setResponseValueAndErrors(res, "maxLength", typeof res.maxLength === "number" ? Math.min(res.maxLength, check.value) : check.value, check.message, refs);
          break;
        case "includes": {
          addPattern(res, RegExp(escapeLiteralCheckValue(check.value, refs)), check.message, refs);
          break;
        }
        case "ip": {
          if (check.version !== "v6") {
            addFormat(res, "ipv4", check.message, refs);
          }
          if (check.version !== "v4") {
            addFormat(res, "ipv6", check.message, refs);
          }
          break;
        }
        case "base64url":
          addPattern(res, zodPatterns.base64url, check.message, refs);
          break;
        case "jwt":
          addPattern(res, zodPatterns.jwt, check.message, refs);
          break;
        case "cidr": {
          if (check.version !== "v6") {
            addPattern(res, zodPatterns.ipv4Cidr, check.message, refs);
          }
          if (check.version !== "v4") {
            addPattern(res, zodPatterns.ipv6Cidr, check.message, refs);
          }
          break;
        }
        case "emoji":
          addPattern(res, zodPatterns.emoji(), check.message, refs);
          break;
        case "ulid": {
          addPattern(res, zodPatterns.ulid, check.message, refs);
          break;
        }
        case "base64": {
          switch (refs.base64Strategy) {
            case "format:binary": {
              addFormat(res, "binary", check.message, refs);
              break;
            }
            case "contentEncoding:base64": {
              setResponseValueAndErrors(res, "contentEncoding", "base64", check.message, refs);
              break;
            }
            case "pattern:zod": {
              addPattern(res, zodPatterns.base64, check.message, refs);
              break;
            }
          }
          break;
        }
        case "nanoid": {
          addPattern(res, zodPatterns.nanoid, check.message, refs);
        }
      }
    }
  }
  return res;
}
function escapeLiteralCheckValue(literal, refs) {
  return refs.patternStrategy === "escape" ? escapeNonAlphaNumeric(literal) : literal;
}
var ALPHA_NUMERIC = new Set("ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvxyz0123456789");
function escapeNonAlphaNumeric(source) {
  let result = "";
  for (let i2 = 0; i2 < source.length; i2++) {
    if (!ALPHA_NUMERIC.has(source[i2])) {
      result += "\\";
    }
    result += source[i2];
  }
  return result;
}
function addFormat(schema, value, message, refs) {
  if (schema.format || schema.anyOf?.some((x2) => x2.format)) {
    if (!schema.anyOf) {
      schema.anyOf = [];
    }
    if (schema.format) {
      schema.anyOf.push({
        format: schema.format,
        ...schema.errorMessage && refs.errorMessages && {
          errorMessage: { format: schema.errorMessage.format }
        }
      });
      delete schema.format;
      if (schema.errorMessage) {
        delete schema.errorMessage.format;
        if (Object.keys(schema.errorMessage).length === 0) {
          delete schema.errorMessage;
        }
      }
    }
    schema.anyOf.push({
      format: value,
      ...message && refs.errorMessages && { errorMessage: { format: message } }
    });
  } else {
    setResponseValueAndErrors(schema, "format", value, message, refs);
  }
}
function addPattern(schema, regex, message, refs) {
  if (schema.pattern || schema.allOf?.some((x2) => x2.pattern)) {
    if (!schema.allOf) {
      schema.allOf = [];
    }
    if (schema.pattern) {
      schema.allOf.push({
        pattern: schema.pattern,
        ...schema.errorMessage && refs.errorMessages && {
          errorMessage: { pattern: schema.errorMessage.pattern }
        }
      });
      delete schema.pattern;
      if (schema.errorMessage) {
        delete schema.errorMessage.pattern;
        if (Object.keys(schema.errorMessage).length === 0) {
          delete schema.errorMessage;
        }
      }
    }
    schema.allOf.push({
      pattern: stringifyRegExpWithFlags(regex, refs),
      ...message && refs.errorMessages && { errorMessage: { pattern: message } }
    });
  } else {
    setResponseValueAndErrors(schema, "pattern", stringifyRegExpWithFlags(regex, refs), message, refs);
  }
}
function stringifyRegExpWithFlags(regex, refs) {
  if (!refs.applyRegexFlags || !regex.flags) {
    return regex.source;
  }
  const flags = {
    i: regex.flags.includes("i"),
    m: regex.flags.includes("m"),
    s: regex.flags.includes("s")
    // `.` matches newlines
  };
  const source = flags.i ? regex.source.toLowerCase() : regex.source;
  let pattern = "";
  let isEscaped = false;
  let inCharGroup = false;
  let inCharRange = false;
  for (let i2 = 0; i2 < source.length; i2++) {
    if (isEscaped) {
      pattern += source[i2];
      isEscaped = false;
      continue;
    }
    if (flags.i) {
      if (inCharGroup) {
        if (source[i2].match(/[a-z]/)) {
          if (inCharRange) {
            pattern += source[i2];
            pattern += `${source[i2 - 2]}-${source[i2]}`.toUpperCase();
            inCharRange = false;
          } else if (source[i2 + 1] === "-" && source[i2 + 2]?.match(/[a-z]/)) {
            pattern += source[i2];
            inCharRange = true;
          } else {
            pattern += `${source[i2]}${source[i2].toUpperCase()}`;
          }
          continue;
        }
      } else if (source[i2].match(/[a-z]/)) {
        pattern += `[${source[i2]}${source[i2].toUpperCase()}]`;
        continue;
      }
    }
    if (flags.m) {
      if (source[i2] === "^") {
        pattern += `(^|(?<=[\r
]))`;
        continue;
      } else if (source[i2] === "$") {
        pattern += `($|(?=[\r
]))`;
        continue;
      }
    }
    if (flags.s && source[i2] === ".") {
      pattern += inCharGroup ? `${source[i2]}\r
` : `[${source[i2]}\r
]`;
      continue;
    }
    pattern += source[i2];
    if (source[i2] === "\\") {
      isEscaped = true;
    } else if (inCharGroup && source[i2] === "]") {
      inCharGroup = false;
    } else if (!inCharGroup && source[i2] === "[") {
      inCharGroup = true;
    }
  }
  return pattern;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/record.js
function parseRecordDef(def, refs) {
  if (refs.target === "openAi") {
    console.warn("Warning: OpenAI may not support records in schemas! Try an array of key-value pairs instead.");
  }
  if (refs.target === "openApi3" && def.keyType?._def.typeName === ZodFirstPartyTypeKind.ZodEnum) {
    return {
      type: "object",
      required: def.keyType._def.values,
      properties: def.keyType._def.values.reduce((acc, key) => ({
        ...acc,
        [key]: parseDef(def.valueType._def, {
          ...refs,
          currentPath: [...refs.currentPath, "properties", key]
        }) ?? {}
      }), {}),
      additionalProperties: refs.rejectedAdditionalProperties
    };
  }
  const schema = {
    type: "object",
    additionalProperties: parseDef(def.valueType._def, {
      ...refs,
      currentPath: [...refs.currentPath, "additionalProperties"]
    }) ?? refs.allowedAdditionalProperties
  };
  if (refs.target === "openApi3") {
    return schema;
  }
  if (def.keyType?._def.typeName === ZodFirstPartyTypeKind.ZodString && def.keyType._def.checks?.length) {
    const { type, ...keyType } = parseStringDef(def.keyType._def, refs);
    return {
      ...schema,
      propertyNames: keyType
    };
  } else if (def.keyType?._def.typeName === ZodFirstPartyTypeKind.ZodEnum) {
    return {
      ...schema,
      propertyNames: {
        enum: def.keyType._def.values
      }
    };
  } else if (def.keyType?._def.typeName === ZodFirstPartyTypeKind.ZodBranded && def.keyType._def.type._def.typeName === ZodFirstPartyTypeKind.ZodString && def.keyType._def.type._def.checks?.length) {
    const { type, ...keyType } = parseBrandedDef(def.keyType._def, refs);
    return {
      ...schema,
      propertyNames: keyType
    };
  }
  return schema;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/map.js
function parseMapDef(def, refs) {
  if (refs.mapStrategy === "record") {
    return parseRecordDef(def, refs);
  }
  const keys = parseDef(def.keyType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "items", "items", "0"]
  }) || {};
  const values = parseDef(def.valueType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "items", "items", "1"]
  }) || {};
  return {
    type: "array",
    maxItems: 125,
    items: {
      type: "array",
      items: [keys, values],
      minItems: 2,
      maxItems: 2
    }
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/nativeEnum.js
function parseNativeEnumDef(def) {
  const object = def.values;
  const actualKeys = Object.keys(def.values).filter((key) => {
    return typeof object[object[key]] !== "number";
  });
  const actualValues = actualKeys.map((key) => object[key]);
  const parsedTypes = Array.from(new Set(actualValues.map((values) => typeof values)));
  return {
    type: parsedTypes.length === 1 ? parsedTypes[0] === "string" ? "string" : "number" : ["string", "number"],
    enum: actualValues
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/never.js
function parseNeverDef() {
  return {
    not: {}
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/null.js
function parseNullDef(refs) {
  return refs.target === "openApi3" ? {
    enum: ["null"],
    nullable: true
  } : {
    type: "null"
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/union.js
var primitiveMappings = {
  ZodString: "string",
  ZodNumber: "number",
  ZodBigInt: "integer",
  ZodBoolean: "boolean",
  ZodNull: "null"
};
function parseUnionDef(def, refs) {
  if (refs.target === "openApi3")
    return asAnyOf(def, refs);
  const options = def.options instanceof Map ? Array.from(def.options.values()) : def.options;
  if (options.every((x2) => x2._def.typeName in primitiveMappings && (!x2._def.checks || !x2._def.checks.length))) {
    const types = options.reduce((types2, x2) => {
      const type = primitiveMappings[x2._def.typeName];
      return type && !types2.includes(type) ? [...types2, type] : types2;
    }, []);
    return {
      type: types.length > 1 ? types : types[0]
    };
  } else if (options.every((x2) => x2._def.typeName === "ZodLiteral" && !x2.description)) {
    const types = options.reduce((acc, x2) => {
      const type = typeof x2._def.value;
      switch (type) {
        case "string":
        case "number":
        case "boolean":
          return [...acc, type];
        case "bigint":
          return [...acc, "integer"];
        case "object":
          if (x2._def.value === null)
            return [...acc, "null"];
        case "symbol":
        case "undefined":
        case "function":
        default:
          return acc;
      }
    }, []);
    if (types.length === options.length) {
      const uniqueTypes = types.filter((x2, i2, a2) => a2.indexOf(x2) === i2);
      return {
        type: uniqueTypes.length > 1 ? uniqueTypes : uniqueTypes[0],
        enum: options.reduce((acc, x2) => {
          return acc.includes(x2._def.value) ? acc : [...acc, x2._def.value];
        }, [])
      };
    }
  } else if (options.every((x2) => x2._def.typeName === "ZodEnum")) {
    return {
      type: "string",
      enum: options.reduce((acc, x2) => [
        ...acc,
        ...x2._def.values.filter((x3) => !acc.includes(x3))
      ], [])
    };
  }
  return asAnyOf(def, refs);
}
var asAnyOf = (def, refs) => {
  const anyOf = (def.options instanceof Map ? Array.from(def.options.values()) : def.options).map((x2, i2) => parseDef(x2._def, {
    ...refs,
    currentPath: [...refs.currentPath, "anyOf", `${i2}`]
  })).filter((x2) => !!x2 && (!refs.strictUnions || typeof x2 === "object" && Object.keys(x2).length > 0));
  return anyOf.length ? { anyOf } : void 0;
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/nullable.js
function parseNullableDef(def, refs) {
  if (["ZodString", "ZodNumber", "ZodBigInt", "ZodBoolean", "ZodNull"].includes(def.innerType._def.typeName) && (!def.innerType._def.checks || !def.innerType._def.checks.length)) {
    if (refs.target === "openApi3") {
      return {
        type: primitiveMappings[def.innerType._def.typeName],
        nullable: true
      };
    }
    return {
      type: [
        primitiveMappings[def.innerType._def.typeName],
        "null"
      ]
    };
  }
  if (refs.target === "openApi3") {
    const base2 = parseDef(def.innerType._def, {
      ...refs,
      currentPath: [...refs.currentPath]
    });
    if (base2 && "$ref" in base2)
      return { allOf: [base2], nullable: true };
    return base2 && { ...base2, nullable: true };
  }
  const base = parseDef(def.innerType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "anyOf", "0"]
  });
  return base && { anyOf: [base, { type: "null" }] };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/number.js
function parseNumberDef(def, refs) {
  const res = {
    type: "number"
  };
  if (!def.checks)
    return res;
  for (const check of def.checks) {
    switch (check.kind) {
      case "int":
        res.type = "integer";
        addErrorMessage(res, "type", check.message, refs);
        break;
      case "min":
        if (refs.target === "jsonSchema7") {
          if (check.inclusive) {
            setResponseValueAndErrors(res, "minimum", check.value, check.message, refs);
          } else {
            setResponseValueAndErrors(res, "exclusiveMinimum", check.value, check.message, refs);
          }
        } else {
          if (!check.inclusive) {
            res.exclusiveMinimum = true;
          }
          setResponseValueAndErrors(res, "minimum", check.value, check.message, refs);
        }
        break;
      case "max":
        if (refs.target === "jsonSchema7") {
          if (check.inclusive) {
            setResponseValueAndErrors(res, "maximum", check.value, check.message, refs);
          } else {
            setResponseValueAndErrors(res, "exclusiveMaximum", check.value, check.message, refs);
          }
        } else {
          if (!check.inclusive) {
            res.exclusiveMaximum = true;
          }
          setResponseValueAndErrors(res, "maximum", check.value, check.message, refs);
        }
        break;
      case "multipleOf":
        setResponseValueAndErrors(res, "multipleOf", check.value, check.message, refs);
        break;
    }
  }
  return res;
}
function parseObjectDef(def, refs) {
  const forceOptionalIntoNullable = refs.target === "openAi";
  const result = {
    type: "object",
    properties: {}
  };
  const required = [];
  const shape = def.shape();
  for (const propName in shape) {
    let propDef = shape[propName];
    if (propDef === void 0 || propDef._def === void 0) {
      continue;
    }
    let propOptional = safeIsOptional(propDef);
    if (propOptional && forceOptionalIntoNullable) {
      if (propDef instanceof ZodOptional) {
        propDef = propDef._def.innerType;
      }
      if (!propDef.isNullable()) {
        propDef = propDef.nullable();
      }
      propOptional = false;
    }
    const parsedDef = parseDef(propDef._def, {
      ...refs,
      currentPath: [...refs.currentPath, "properties", propName],
      propertyPath: [...refs.currentPath, "properties", propName]
    });
    if (parsedDef === void 0) {
      continue;
    }
    result.properties[propName] = parsedDef;
    if (!propOptional) {
      required.push(propName);
    }
  }
  if (required.length) {
    result.required = required;
  }
  const additionalProperties = decideAdditionalProperties(def, refs);
  if (additionalProperties !== void 0) {
    result.additionalProperties = additionalProperties;
  }
  return result;
}
function decideAdditionalProperties(def, refs) {
  if (def.catchall._def.typeName !== "ZodNever") {
    return parseDef(def.catchall._def, {
      ...refs,
      currentPath: [...refs.currentPath, "additionalProperties"]
    });
  }
  switch (def.unknownKeys) {
    case "passthrough":
      return refs.allowedAdditionalProperties;
    case "strict":
      return refs.rejectedAdditionalProperties;
    case "strip":
      return refs.removeAdditionalStrategy === "strict" ? refs.allowedAdditionalProperties : refs.rejectedAdditionalProperties;
  }
}
function safeIsOptional(schema) {
  try {
    return schema.isOptional();
  } catch {
    return true;
  }
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/optional.js
var parseOptionalDef = (def, refs) => {
  if (refs.currentPath.toString() === refs.propertyPath?.toString()) {
    return parseDef(def.innerType._def, refs);
  }
  const innerSchema = parseDef(def.innerType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "anyOf", "1"]
  });
  return innerSchema ? {
    anyOf: [
      {
        not: {}
      },
      innerSchema
    ]
  } : {};
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/pipeline.js
var parsePipelineDef = (def, refs) => {
  if (refs.pipeStrategy === "input") {
    return parseDef(def.in._def, refs);
  } else if (refs.pipeStrategy === "output") {
    return parseDef(def.out._def, refs);
  }
  const a2 = parseDef(def.in._def, {
    ...refs,
    currentPath: [...refs.currentPath, "allOf", "0"]
  });
  const b = parseDef(def.out._def, {
    ...refs,
    currentPath: [...refs.currentPath, "allOf", a2 ? "1" : "0"]
  });
  return {
    allOf: [a2, b].filter((x2) => x2 !== void 0)
  };
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/promise.js
function parsePromiseDef(def, refs) {
  return parseDef(def.type._def, refs);
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/set.js
function parseSetDef(def, refs) {
  const items = parseDef(def.valueType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "items"]
  });
  const schema = {
    type: "array",
    uniqueItems: true,
    items
  };
  if (def.minSize) {
    setResponseValueAndErrors(schema, "minItems", def.minSize.value, def.minSize.message, refs);
  }
  if (def.maxSize) {
    setResponseValueAndErrors(schema, "maxItems", def.maxSize.value, def.maxSize.message, refs);
  }
  return schema;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/tuple.js
function parseTupleDef(def, refs) {
  if (def.rest) {
    return {
      type: "array",
      minItems: def.items.length,
      items: def.items.map((x2, i2) => parseDef(x2._def, {
        ...refs,
        currentPath: [...refs.currentPath, "items", `${i2}`]
      })).reduce((acc, x2) => x2 === void 0 ? acc : [...acc, x2], []),
      additionalItems: parseDef(def.rest._def, {
        ...refs,
        currentPath: [...refs.currentPath, "additionalItems"]
      })
    };
  } else {
    return {
      type: "array",
      minItems: def.items.length,
      maxItems: def.items.length,
      items: def.items.map((x2, i2) => parseDef(x2._def, {
        ...refs,
        currentPath: [...refs.currentPath, "items", `${i2}`]
      })).reduce((acc, x2) => x2 === void 0 ? acc : [...acc, x2], [])
    };
  }
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/undefined.js
function parseUndefinedDef() {
  return {
    not: {}
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/unknown.js
function parseUnknownDef() {
  return {};
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parsers/readonly.js
var parseReadonlyDef = (def, refs) => {
  return parseDef(def.innerType._def, refs);
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/selectParser.js
var selectParser = (def, typeName, refs) => {
  switch (typeName) {
    case ZodFirstPartyTypeKind.ZodString:
      return parseStringDef(def, refs);
    case ZodFirstPartyTypeKind.ZodNumber:
      return parseNumberDef(def, refs);
    case ZodFirstPartyTypeKind.ZodObject:
      return parseObjectDef(def, refs);
    case ZodFirstPartyTypeKind.ZodBigInt:
      return parseBigintDef(def, refs);
    case ZodFirstPartyTypeKind.ZodBoolean:
      return parseBooleanDef();
    case ZodFirstPartyTypeKind.ZodDate:
      return parseDateDef(def, refs);
    case ZodFirstPartyTypeKind.ZodUndefined:
      return parseUndefinedDef();
    case ZodFirstPartyTypeKind.ZodNull:
      return parseNullDef(refs);
    case ZodFirstPartyTypeKind.ZodArray:
      return parseArrayDef(def, refs);
    case ZodFirstPartyTypeKind.ZodUnion:
    case ZodFirstPartyTypeKind.ZodDiscriminatedUnion:
      return parseUnionDef(def, refs);
    case ZodFirstPartyTypeKind.ZodIntersection:
      return parseIntersectionDef(def, refs);
    case ZodFirstPartyTypeKind.ZodTuple:
      return parseTupleDef(def, refs);
    case ZodFirstPartyTypeKind.ZodRecord:
      return parseRecordDef(def, refs);
    case ZodFirstPartyTypeKind.ZodLiteral:
      return parseLiteralDef(def, refs);
    case ZodFirstPartyTypeKind.ZodEnum:
      return parseEnumDef(def);
    case ZodFirstPartyTypeKind.ZodNativeEnum:
      return parseNativeEnumDef(def);
    case ZodFirstPartyTypeKind.ZodNullable:
      return parseNullableDef(def, refs);
    case ZodFirstPartyTypeKind.ZodOptional:
      return parseOptionalDef(def, refs);
    case ZodFirstPartyTypeKind.ZodMap:
      return parseMapDef(def, refs);
    case ZodFirstPartyTypeKind.ZodSet:
      return parseSetDef(def, refs);
    case ZodFirstPartyTypeKind.ZodLazy:
      return () => def.getter()._def;
    case ZodFirstPartyTypeKind.ZodPromise:
      return parsePromiseDef(def, refs);
    case ZodFirstPartyTypeKind.ZodNaN:
    case ZodFirstPartyTypeKind.ZodNever:
      return parseNeverDef();
    case ZodFirstPartyTypeKind.ZodEffects:
      return parseEffectsDef(def, refs);
    case ZodFirstPartyTypeKind.ZodAny:
      return parseAnyDef();
    case ZodFirstPartyTypeKind.ZodUnknown:
      return parseUnknownDef();
    case ZodFirstPartyTypeKind.ZodDefault:
      return parseDefaultDef(def, refs);
    case ZodFirstPartyTypeKind.ZodBranded:
      return parseBrandedDef(def, refs);
    case ZodFirstPartyTypeKind.ZodReadonly:
      return parseReadonlyDef(def, refs);
    case ZodFirstPartyTypeKind.ZodCatch:
      return parseCatchDef(def, refs);
    case ZodFirstPartyTypeKind.ZodPipeline:
      return parsePipelineDef(def, refs);
    case ZodFirstPartyTypeKind.ZodFunction:
    case ZodFirstPartyTypeKind.ZodVoid:
    case ZodFirstPartyTypeKind.ZodSymbol:
      return void 0;
    default:
      return /* @__PURE__ */ ((_) => void 0)();
  }
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/parseDef.js
function parseDef(def, refs, forceResolution = false) {
  const seenItem = refs.seen.get(def);
  if (refs.override) {
    const overrideResult = refs.override?.(def, refs, seenItem, forceResolution);
    if (overrideResult !== ignoreOverride) {
      return overrideResult;
    }
  }
  if (seenItem && !forceResolution) {
    const seenSchema = get$ref(seenItem, refs);
    if (seenSchema !== void 0) {
      return seenSchema;
    }
  }
  const newItem = { def, path: refs.currentPath, jsonSchema: void 0 };
  refs.seen.set(def, newItem);
  const jsonSchemaOrGetter = selectParser(def, def.typeName, refs);
  const jsonSchema = typeof jsonSchemaOrGetter === "function" ? parseDef(jsonSchemaOrGetter(), refs) : jsonSchemaOrGetter;
  if (jsonSchema) {
    addMeta(def, refs, jsonSchema);
  }
  if (refs.postProcess) {
    const postProcessResult = refs.postProcess(jsonSchema, def, refs);
    newItem.jsonSchema = jsonSchema;
    return postProcessResult;
  }
  newItem.jsonSchema = jsonSchema;
  return jsonSchema;
}
var get$ref = (item, refs) => {
  switch (refs.$refStrategy) {
    case "root":
      return { $ref: item.path.join("/") };
    case "relative":
      return { $ref: getRelativePath(refs.currentPath, item.path) };
    case "none":
    case "seen": {
      if (item.path.length < refs.currentPath.length && item.path.every((value, index) => refs.currentPath[index] === value)) {
        console.warn(`Recursive reference detected at ${refs.currentPath.join("/")}! Defaulting to any`);
        return {};
      }
      return refs.$refStrategy === "seen" ? {} : void 0;
    }
  }
};
var getRelativePath = (pathA, pathB) => {
  let i2 = 0;
  for (; i2 < pathA.length && i2 < pathB.length; i2++) {
    if (pathA[i2] !== pathB[i2])
      break;
  }
  return [(pathA.length - i2).toString(), ...pathB.slice(i2)].join("/");
};
var addMeta = (def, refs, jsonSchema) => {
  if (def.description) {
    jsonSchema.description = def.description;
    if (refs.markdownDescription) {
      jsonSchema.markdownDescription = def.description;
    }
  }
  return jsonSchema;
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/zodToJsonSchema.js
var zodToJsonSchema = (schema, options) => {
  const refs = getRefs(options);
  const definitions = typeof options === "object" && options.definitions ? Object.entries(options.definitions).reduce((acc, [name2, schema2]) => ({
    ...acc,
    [name2]: parseDef(schema2._def, {
      ...refs,
      currentPath: [...refs.basePath, refs.definitionPath, name2]
    }, true) ?? {}
  }), {}) : void 0;
  const name = typeof options === "string" ? options : options?.nameStrategy === "title" ? void 0 : options?.name;
  const main = parseDef(schema._def, name === void 0 ? refs : {
    ...refs,
    currentPath: [...refs.basePath, refs.definitionPath, name]
  }, false) ?? {};
  const title = typeof options === "object" && options.name !== void 0 && options.nameStrategy === "title" ? options.name : void 0;
  if (title !== void 0) {
    main.title = title;
  }
  const combined = name === void 0 ? definitions ? {
    ...main,
    [refs.definitionPath]: definitions
  } : main : {
    $ref: [
      ...refs.$refStrategy === "relative" ? [] : refs.basePath,
      refs.definitionPath,
      name
    ].join("/"),
    [refs.definitionPath]: {
      ...definitions,
      [name]: main
    }
  };
  if (refs.target === "jsonSchema7") {
    combined.$schema = "http://json-schema.org/draft-07/schema#";
  } else if (refs.target === "jsonSchema2019-09" || refs.target === "openAi") {
    combined.$schema = "https://json-schema.org/draft/2019-09/schema#";
  }
  if (refs.target === "openAi" && ("anyOf" in combined || "oneOf" in combined || "allOf" in combined || "type" in combined && Array.isArray(combined.type))) {
    console.warn("Warning: OpenAI may not support schemas with unions as roots! Try wrapping it in an object property.");
  }
  return combined;
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.4_zod@3.24.2/node_modules/zod-to-json-schema/dist/esm/index.js
var esm_default = zodToJsonSchema;
function handleError(error, defaultMessage) {
  console.error(defaultMessage, error);
  const apiError = error;
  throw new HTTPException(apiError.status || 500, {
    message: apiError.message || defaultMessage
  });
}
function errorHandler(err, c2) {
  if (err instanceof HTTPException) {
    return c2.json({ error: err.message }, err.status);
  }
  console.error(err);
  return c2.json({ error: "Internal Server Error" }, 500);
}
function validateBody(body) {
  const errorResponse = Object.entries(body).reduce((acc, [key, value]) => {
    if (!value) {
      acc[key] = `${key} is required`;
    }
    return acc;
  }, {});
  if (Object.keys(errorResponse).length > 0) {
    throw new HTTPException(400, { message: JSON.stringify(errorResponse) });
  }
}

// src/server/handlers/agents.ts
async function getAgentsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agents = mastra.getAgents();
    const serializedAgents = Object.entries(agents).reduce((acc, [_id, _agent]) => {
      const agent = _agent;
      const serializedAgentTools = Object.entries(agent?.tools || {}).reduce((acc2, [key, tool]) => {
        const _tool = tool;
        acc2[key] = {
          ..._tool,
          inputSchema: _tool.inputSchema ? stringify(esm_default(_tool.inputSchema)) : void 0,
          outputSchema: _tool.outputSchema ? stringify(esm_default(_tool.outputSchema)) : void 0
        };
        return acc2;
      }, {});
      acc[_id] = {
        name: agent.name,
        instructions: agent.instructions,
        tools: serializedAgentTools,
        provider: agent.llm?.getProvider(),
        modelId: agent.llm?.getModelId()
      };
      return acc;
    }, {});
    return c2.json(serializedAgents);
  } catch (error) {
    return handleError(error, "Error getting agents");
  }
}
async function getAgentByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const serializedAgentTools = Object.entries(agent?.tools || {}).reduce((acc, [key, tool]) => {
      const _tool = tool;
      acc[key] = {
        ..._tool,
        inputSchema: _tool.inputSchema ? stringify(esm_default(_tool.inputSchema)) : void 0,
        outputSchema: _tool.outputSchema ? stringify(esm_default(_tool.outputSchema)) : void 0
      };
      return acc;
    }, {});
    return c2.json({
      name: agent.name,
      instructions: agent.instructions,
      tools: serializedAgentTools,
      provider: agent.llm?.getProvider(),
      modelId: agent.llm?.getModelId()
    });
  } catch (error) {
    return handleError(error, "Error getting agent");
  }
}
async function getEvalsByAgentIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const agent = mastra.getAgent(agentId);
    const evals = await mastra.storage?.getEvalsByAgentName?.(agent.name, "test") || [];
    return c2.json({
      id: agentId,
      name: agent.name,
      instructions: agent.instructions,
      evals
    });
  } catch (error) {
    return handleError(error, "Error getting test evals");
  }
}
async function getLiveEvalsByAgentIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const agent = mastra.getAgent(agentId);
    const evals = await mastra.storage?.getEvalsByAgentName?.(agent.name, "live") || [];
    return c2.json({
      id: agentId,
      name: agent.name,
      instructions: agent.instructions,
      evals
    });
  } catch (error) {
    return handleError(error, "Error getting live evals");
  }
}
async function generateHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const { messages, threadId, resourceid, resourceId, output, runId, ...rest } = await c2.req.json();
    validateBody({ messages });
    const finalResourceId = resourceId ?? resourceid;
    const result = await agent.generate(messages, { threadId, resourceId: finalResourceId, output, runId, ...rest });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error generating from agent");
  }
}
async function streamGenerateHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const { messages, threadId, resourceid, resourceId, output, runId, ...rest } = await c2.req.json();
    validateBody({ messages });
    const finalResourceId = resourceId ?? resourceid;
    const streamResult = await agent.stream(messages, {
      threadId,
      resourceId: finalResourceId,
      output,
      runId,
      ...rest
    });
    const streamResponse = output ? streamResult.toTextStreamResponse() : streamResult.toDataStreamResponse({
      sendUsage: true,
      sendReasoning: true,
      getErrorMessage: (error) => {
        return `An error occurred while processing your request. ${error instanceof Error ? error.message : JSON.stringify(error)}`;
      }
    });
    return streamResponse;
  } catch (error) {
    return handleError(error, "Error streaming from agent");
  }
}
async function setAgentInstructionsHandler(c2) {
  try {
    const isPlayground = c2.get("playground") === true;
    if (!isPlayground) {
      return c2.json({ error: "This API is only available in the playground environment" }, 403);
    }
    const agentId = c2.req.param("agentId");
    const { instructions } = await c2.req.json();
    if (!agentId || !instructions) {
      return c2.json({ error: "Missing required fields" }, 400);
    }
    const mastra = c2.get("mastra");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      return c2.json({ error: "Agent not found" }, 404);
    }
    agent.__updateInstructions(instructions);
    return c2.json(
      {
        instructions
      },
      200
    );
  } catch (error) {
    return handleError(error, "Error setting agent instructions");
  }
}

// src/server/handlers/client.ts
var clients = /* @__PURE__ */ new Set();
function handleClientsRefresh(c2) {
  const stream = new ReadableStream({
    start(controller) {
      clients.add(controller);
      controller.enqueue("data: connected\n\n");
      c2.req.raw.signal.addEventListener("abort", () => {
        clients.delete(controller);
      });
    }
  });
  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
function handleTriggerClientsRefresh(c2) {
  clients.forEach((controller) => {
    try {
      controller.enqueue("data: refresh\n\n");
    } catch {
      clients.delete(controller);
    }
  });
  return c2.json({ success: true, clients: clients.size });
}
async function getLogsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const transportId = c2.req.query("transportId");
    if (!transportId) {
      throw new HTTPException(400, { message: "transportId is required" });
    }
    const logs = await mastra.getLogs(transportId);
    return c2.json(logs);
  } catch (error) {
    return handleError(error, "Error getting logs");
  }
}
async function getLogsByRunIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runId = c2.req.param("runId");
    const transportId = c2.req.query("transportId");
    if (!transportId) {
      throw new HTTPException(400, { message: "transportId is required" });
    }
    const logs = await mastra.getLogsByRunId({ runId, transportId });
    return c2.json(logs);
  } catch (error) {
    return handleError(error, "Error getting logs by run ID");
  }
}
async function getLogTransports(c2) {
  try {
    const mastra = c2.get("mastra");
    const logger2 = mastra.getLogger();
    const transports = logger2.transports;
    return c2.json({
      transports: Object.keys(transports)
    });
  } catch (e2) {
    return handleError(e2, "Error getting log Transports ");
  }
}
function getMemoryFromContext(c2) {
  const mastra = c2.get("mastra");
  const agentId = c2.req.query("agentId");
  const agent = agentId ? mastra.getAgent(agentId) : null;
  if (agentId && !agent) {
    throw new HTTPException(404, { message: "Agent not found" });
  }
  const memory = agent?.getMemory?.() || mastra.memory;
  return memory;
}
async function getMemoryStatusHandler(c2) {
  try {
    const memory = getMemoryFromContext(c2);
    if (!memory) {
      return c2.json({ result: false });
    }
    return c2.json({ result: true });
  } catch (error) {
    return handleError(error, "Error getting memory status");
  }
}
async function getThreadsHandler(c2) {
  try {
    const { resourceid } = c2.req.query();
    const memory = getMemoryFromContext(c2);
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    if (!resourceid) {
      throw new HTTPException(400, { message: "Resource ID is required" });
    }
    const threads = await memory.getThreadsByResourceId({ resourceId: resourceid });
    return c2.json(threads);
  } catch (error) {
    return handleError(error, "Error getting threads");
  }
}
async function getThreadByIdHandler(c2) {
  try {
    const memory = getMemoryFromContext(c2);
    const threadId = c2.req.param("threadId");
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      throw new HTTPException(404, { message: "Thread not found" });
    }
    return c2.json(thread);
  } catch (error) {
    return handleError(error, "Error getting thread");
  }
}
async function saveMessagesHandler(c2) {
  try {
    const memory = getMemoryFromContext(c2);
    const { messages } = await c2.req.json();
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    validateBody({ messages });
    if (!Array.isArray(messages)) {
      throw new HTTPException(400, { message: "Messages should be an array" });
    }
    const processedMessages = messages.map((message) => ({
      ...message,
      id: memory.generateId(),
      createdAt: message.createdAt ? new Date(message.createdAt) : /* @__PURE__ */ new Date()
    }));
    const result = await memory.saveMessages({ messages: processedMessages, memoryConfig: {} });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error saving messages");
  }
}
async function createThreadHandler(c2) {
  try {
    const memory = getMemoryFromContext(c2);
    const { title, metadata, resourceid, threadId } = await c2.req.json();
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    validateBody({ resourceid });
    const result = await memory.createThread({ resourceId: resourceid, title, metadata, threadId });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error saving thread to memory");
  }
}
async function updateThreadHandler(c2) {
  try {
    const memory = getMemoryFromContext(c2);
    const threadId = c2.req.param("threadId");
    const { title, metadata, resourceid } = await c2.req.json();
    const updatedAt = /* @__PURE__ */ new Date();
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      throw new HTTPException(404, { message: "Thread not found" });
    }
    const updatedThread = {
      ...thread,
      title: title || thread.title,
      metadata: metadata || thread.metadata,
      resourceId: resourceid || thread.resourceId,
      createdAt: thread.createdAt,
      updatedAt
    };
    const result = await memory.saveThread({ thread: updatedThread });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error updating thread");
  }
}
async function deleteThreadHandler(c2) {
  try {
    const memory = getMemoryFromContext(c2);
    const threadId = c2.req.param("threadId");
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      throw new HTTPException(404, { message: "Thread not found" });
    }
    await memory.deleteThread(threadId);
    return c2.json({ result: "Thread deleted" });
  } catch (error) {
    return handleError(error, "Error deleting thread");
  }
}
async function getMessagesHandler(c2) {
  try {
    const memory = getMemoryFromContext(c2);
    const threadId = c2.req.param("threadId");
    if (!memory) {
      return c2.json({ error: "Memory is not initialized" }, 400);
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      return c2.json({ error: "Thread not found" }, 404);
    }
    const result = await memory.query({ threadId });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error getting messages");
  }
}
async function getNetworksHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const networks = mastra.getNetworks();
    const serializedNetworks = networks.map((network) => {
      const routingAgent = network.getRoutingAgent();
      const agents = network.getAgents();
      return {
        id: network.formatAgentId(routingAgent.name),
        name: routingAgent.name,
        instructions: routingAgent.instructions,
        agents: agents.map((agent) => ({
          name: agent.name,
          provider: agent.llm?.getProvider(),
          modelId: agent.llm?.getModelId()
        })),
        routingModel: {
          provider: routingAgent.llm?.getProvider(),
          modelId: routingAgent.llm?.getModelId()
        }
      };
    });
    return c2.json(serializedNetworks);
  } catch (error) {
    return handleError(error, "Error getting networks");
  }
}
async function getNetworkByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const networkId = c2.req.param("networkId");
    const networks = mastra.getNetworks();
    const network = networks.find((network2) => {
      const routingAgent2 = network2.getRoutingAgent();
      return network2.formatAgentId(routingAgent2.name) === networkId;
    });
    if (!network) {
      return c2.json({ error: "Network not found" }, 404);
    }
    const routingAgent = network.getRoutingAgent();
    const agents = network.getAgents();
    const serializedNetwork = {
      id: network.formatAgentId(routingAgent.name),
      name: routingAgent.name,
      instructions: routingAgent.instructions,
      agents: agents.map((agent) => ({
        name: agent.name,
        provider: agent.llm?.getProvider(),
        modelId: agent.llm?.getModelId()
      })),
      routingModel: {
        provider: routingAgent.llm?.getProvider(),
        modelId: routingAgent.llm?.getModelId()
      }
    };
    return c2.json(serializedNetwork);
  } catch (error) {
    return handleError(error, "Error getting network by ID");
  }
}
async function generateHandler2(c2) {
  try {
    const mastra = c2.get("mastra");
    const networkId = c2.req.param("networkId");
    const network = mastra.getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    const { messages, threadId, resourceid, resourceId, output, runId, ...rest } = await c2.req.json();
    validateBody({ messages });
    const finalResourceId = resourceId ?? resourceid;
    const result = await network.generate(messages, { threadId, resourceId: finalResourceId, output, runId, ...rest });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error generating from network");
  }
}
async function streamGenerateHandler2(c2) {
  try {
    const mastra = c2.get("mastra");
    const networkId = c2.req.param("networkId");
    const network = mastra.getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    const { messages, threadId, resourceid, resourceId, output, runId, ...rest } = await c2.req.json();
    validateBody({ messages });
    const finalResourceId = resourceId ?? resourceid;
    const streamResult = await network.stream(messages, {
      threadId,
      resourceId: finalResourceId,
      output,
      runId,
      ...rest
    });
    const streamResponse = output ? streamResult.toTextStreamResponse() : streamResult.toDataStreamResponse({
      sendUsage: true,
      sendReasoning: true,
      getErrorMessage: (error) => {
        return `An error occurred while processing your request. ${error instanceof Error ? error.message : JSON.stringify(error)}`;
      }
    });
    return streamResponse;
  } catch (error) {
    return handleError(error, "Error streaming from network");
  }
}
async function generateSystemPromptHandler(c2) {
  try {
    const agentId = c2.req.param("agentId");
    const isPlayground = c2.get("playground") === true;
    if (!isPlayground) {
      return c2.json({ error: "This API is only available in the playground environment" }, 403);
    }
    const { instructions, comment } = await c2.req.json();
    if (!instructions) {
      return c2.json({ error: "Missing instructions in request body" }, 400);
    }
    const mastra = c2.get("mastra");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      return c2.json({ error: "Agent not found" }, 404);
    }
    let evalSummary = "";
    try {
      const testEvals = await mastra.storage?.getEvalsByAgentName?.(agent.name, "test") || [];
      const liveEvals = await mastra.storage?.getEvalsByAgentName?.(agent.name, "live") || [];
      const evalsMapped = [...testEvals, ...liveEvals].filter(
        ({ instructions: evalInstructions }) => evalInstructions === instructions
      );
      evalSummary = evalsMapped.map(
        ({ input, output, result: result2 }) => `
          Input: ${input}

          Output: ${output}

          Result: ${JSON.stringify(result2)}

        `
      ).join("");
    } catch (error) {
      mastra.getLogger().error(`Error fetching evals`, { error });
    }
    const ENHANCE_SYSTEM_PROMPT_INSTRUCTIONS = `
            You are an expert system prompt engineer, specialized in analyzing and enhancing instructions to create clear, effective, and comprehensive system prompts. Your goal is to help users transform their basic instructions into well-structured system prompts that will guide AI behavior effectively.
            Follow these steps to analyze and enhance the instructions:
            1. ANALYSIS PHASE
            - Identify the core purpose and goals
            - Extract key constraints and requirements
            - Recognize domain-specific terminology and concepts
            - Note any implicit assumptions that should be made explicit
            2. PROMPT STRUCTURE
            Create a system prompt with these components:
            a) ROLE DEFINITION
                - Clear statement of the AI's role and purpose
                - Key responsibilities and scope
                - Primary stakeholders and users
            b) CORE CAPABILITIES
                - Main functions and abilities
                - Specific domain knowledge required
                - Tools and resources available
            c) BEHAVIORAL GUIDELINES
                - Communication style and tone
                - Decision-making framework
                - Error handling approach
                - Ethical considerations
            d) CONSTRAINTS & BOUNDARIES
                - Explicit limitations
                - Out-of-scope activities
                - Security and privacy considerations
            e) SUCCESS CRITERIA
                - Quality standards
                - Expected outcomes
                - Performance metrics
            3. QUALITY CHECKS
            Ensure the prompt is:
            - Clear and unambiguous
            - Comprehensive yet concise
            - Properly scoped
            - Technically accurate
            - Ethically sound
            4. OUTPUT FORMAT
            Return a structured response with:
            - Enhanced system prompt
            - Analysis of key components
            - Identified goals and constraints
            - Core domain concepts
            Remember: A good system prompt should be specific enough to guide behavior but flexible enough to handle edge cases. 
            Focus on creating prompts that are clear, actionable, and aligned with the intended use case.
        `;
    const systemPromptAgent = new Agent({
      name: "system-prompt-enhancer",
      instructions: ENHANCE_SYSTEM_PROMPT_INSTRUCTIONS,
      model: agent.llm?.getModel()
    });
    const result = await systemPromptAgent.generate(
      `
            We need to improve the system prompt. 
            Current: ${instructions}
            ${comment ? `User feedback: ${comment}` : ""}
            ${evalSummary ? `
Evaluation Results:
${evalSummary}` : ""}
        `,
      {
        output: z.object({
          new_prompt: z.string(),
          explanation: z.string()
        })
      }
    );
    return c2.json(result?.object || {});
  } catch (error) {
    return handleError(error, "Error generating system prompt");
  }
}

// src/server/handlers/root.ts
async function rootHandler(c2) {
  return c2.text("Hello to the Mastra API!");
}
async function getTelemetryHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const telemetry = mastra.getTelemetry();
    const storage = mastra.getStorage();
    const { name, scope, page, perPage } = c2.req.query();
    const attribute = c2.req.queries("attribute");
    if (!telemetry) {
      throw new HTTPException(400, { message: "Telemetry is not initialized" });
    }
    if (!storage) {
      throw new HTTPException(400, { message: "Storage is not initialized" });
    }
    const attributes = attribute ? Object.fromEntries(
      (Array.isArray(attribute) ? attribute : [attribute]).map((attr) => {
        const [key, value] = attr.split(":");
        return [key, value];
      })
    ) : void 0;
    const traces = await storage.getTraces({
      name,
      scope,
      page: Number(page ?? 0),
      perPage: Number(perPage ?? 100),
      attributes
    });
    return c2.json({ traces });
  } catch (error) {
    return handleError(error, "Error saving messages");
  }
}
async function getToolsHandler(c2) {
  try {
    const tools = c2.get("tools");
    if (!tools) {
      return c2.json({});
    }
    const serializedTools = Object.entries(tools).reduce(
      (acc, [id, _tool]) => {
        const tool = _tool;
        acc[id] = {
          ...tool,
          inputSchema: tool.inputSchema ? stringify(esm_default(tool.inputSchema)) : void 0,
          outputSchema: tool.outputSchema ? stringify(esm_default(tool.outputSchema)) : void 0
        };
        return acc;
      },
      {}
    );
    return c2.json(serializedTools);
  } catch (error) {
    return handleError(error, "Error getting tools");
  }
}
async function getToolByIdHandler(c2) {
  try {
    const tools = c2.get("tools");
    const toolId = c2.req.param("toolId");
    const tool = Object.values(tools || {}).find((tool2) => tool2.id === toolId);
    if (!tool) {
      throw new HTTPException(404, { message: "Tool not found" });
    }
    const serializedTool = {
      ...tool,
      inputSchema: tool.inputSchema ? stringify(esm_default(tool.inputSchema)) : void 0,
      outputSchema: tool.outputSchema ? stringify(esm_default(tool.outputSchema)) : void 0
    };
    return c2.json(serializedTool);
  } catch (error) {
    return handleError(error, "Error getting tool");
  }
}
function executeToolHandler(tools) {
  return async (c2) => {
    try {
      const toolId = decodeURIComponent(c2.req.param("toolId"));
      const tool = Object.values(tools || {}).find((tool2) => tool2.id === toolId);
      if (!tool) {
        return c2.json({ error: "Tool not found" }, 404);
      }
      if (!tool?.execute) {
        return c2.json({ error: "Tool is not executable" }, 400);
      }
      const { data } = await c2.req.json();
      const mastra = c2.get("mastra");
      if (isVercelTool(tool)) {
        const result2 = await tool.execute(data);
        return c2.json(result2);
      }
      const result = await tool.execute({
        context: data,
        mastra,
        runId: mastra.runId
      });
      return c2.json(result);
    } catch (error) {
      return handleError(error, "Error executing tool");
    }
  };
}
async function executeAgentToolHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const toolId = c2.req.param("toolId");
    const agent = mastra.getAgent(agentId);
    const tool = Object.values(agent?.tools || {}).find((tool2) => tool2.id === toolId);
    if (!tool) {
      throw new HTTPException(404, { message: "Tool not found" });
    }
    if (!tool?.execute) {
      return c2.json({ error: "Tool is not executable" }, 400);
    }
    const { data } = await c2.req.json();
    if (isVercelTool(tool)) {
      const result2 = await tool.execute(data);
      return c2.json(result2);
    }
    const result = await tool.execute({
      context: data,
      mastra,
      runId: agentId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error executing tool");
  }
}
var getVector = (c2, vectorName) => {
  const vector = c2.get("mastra").getVector(vectorName);
  if (!vector) {
    throw new HTTPException(404, { message: `Vector store ${vectorName} not found` });
  }
  return vector;
};
async function upsertVectors(c2) {
  try {
    const vectorName = c2.req.param("vectorName");
    const { indexName, vectors, metadata, ids } = await c2.req.json();
    if (!indexName || !vectors || !Array.isArray(vectors)) {
      throw new HTTPException(400, { message: "Invalid request body. indexName and vectors array are required." });
    }
    const vector = getVector(c2, vectorName);
    const result = await vector.upsert({ indexName, vectors, metadata, ids });
    return c2.json({ ids: result });
  } catch (error) {
    return handleError(error, "Error upserting vectors");
  }
}
async function createIndex(c2) {
  try {
    const vectorName = c2.req.param("vectorName");
    const { indexName, dimension, metric } = await c2.req.json();
    if (!indexName || typeof dimension !== "number" || dimension <= 0) {
      throw new HTTPException(400, {
        message: "Invalid request body. indexName and positive dimension number are required."
      });
    }
    if (metric && !["cosine", "euclidean", "dotproduct"].includes(metric)) {
      throw new HTTPException(400, { message: "Invalid metric. Must be one of: cosine, euclidean, dotproduct" });
    }
    const vector = getVector(c2, vectorName);
    await vector.createIndex({ indexName, dimension, metric });
    return c2.json({ success: true });
  } catch (error) {
    return handleError(error, "Error creating index");
  }
}
async function queryVectors(c2) {
  try {
    const vectorName = c2.req.param("vectorName");
    const { indexName, queryVector, topK = 10, filter, includeVector = false } = await c2.req.json();
    if (!indexName || !queryVector || !Array.isArray(queryVector)) {
      throw new HTTPException(400, { message: "Invalid request body. indexName and queryVector array are required." });
    }
    const vector = getVector(c2, vectorName);
    const results = await vector.query({ indexName, queryVector, topK, filter, includeVector });
    return c2.json({ results });
  } catch (error) {
    return handleError(error, "Error querying vectors");
  }
}
async function listIndexes(c2) {
  try {
    const vectorName = c2.req.param("vectorName");
    const vector = getVector(c2, vectorName);
    const indexes = await vector.listIndexes();
    return c2.json({ indexes: indexes.filter(Boolean) });
  } catch (error) {
    return handleError(error, "Error listing indexes");
  }
}
async function describeIndex(c2) {
  try {
    const vectorName = c2.req.param("vectorName");
    const indexName = c2.req.param("indexName");
    if (!indexName) {
      throw new HTTPException(400, { message: "Index name is required" });
    }
    const vector = getVector(c2, vectorName);
    const stats = await vector.describeIndex(indexName);
    return c2.json({
      dimension: stats.dimension,
      count: stats.count,
      metric: stats.metric?.toLowerCase()
    });
  } catch (error) {
    return handleError(error, "Error describing index");
  }
}
async function deleteIndex(c2) {
  try {
    const vectorName = c2.req.param("vectorName");
    const indexName = c2.req.param("indexName");
    if (!indexName) {
      throw new HTTPException(400, { message: "Index name is required" });
    }
    const vector = getVector(c2, vectorName);
    await vector.deleteIndex(indexName);
    return c2.json({ success: true });
  } catch (error) {
    return handleError(error, "Error deleting index");
  }
}
async function getSpeakersHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    if (!agent.voice) {
      throw new HTTPException(400, { message: "Agent does not have voice capabilities" });
    }
    const speakers = await agent.getSpeakers();
    return c2.json(speakers);
  } catch (error) {
    return handleError(error, "Error getting speakers");
  }
}
async function speakHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    if (!agent.voice) {
      throw new HTTPException(400, { message: "Agent does not have voice capabilities" });
    }
    const { input, options } = await c2.req.json();
    await validateBody({ input });
    const audioStream = await agent.voice.speak(input, options);
    c2.header("Content-Type", `audio/${options?.filetype ?? "mp3"}`);
    c2.header("Transfer-Encoding", "chunked");
    return c2.body(audioStream);
  } catch (error) {
    return handleError(error, "Error generating speech");
  }
}
async function listenHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const agent = mastra.getAgent(agentId);
    const logger2 = mastra.getLogger();
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    if (!agent.voice) {
      throw new HTTPException(400, { message: "Agent does not have voice capabilities" });
    }
    const formData = await c2.req.formData();
    const audioFile = formData.get("audio");
    const options = formData.get("options");
    if (!audioFile || !(audioFile instanceof File)) {
      throw new HTTPException(400, { message: "Audio file is required" });
    }
    const audioData = await audioFile.arrayBuffer();
    const audioStream = new Readable();
    audioStream.push(Buffer.from(audioData));
    audioStream.push(null);
    let parsedOptions;
    try {
      parsedOptions = options ? JSON.parse(options) : {};
    } catch (error) {
      if (error instanceof SyntaxError) {
        logger2.error("Invalid JSON in options:", error);
      }
      parsedOptions = {};
    }
    const transcription = await agent.voice.listen(audioStream, parsedOptions);
    return c2.json({ text: transcription });
  } catch (error) {
    return handleError(error, "Error transcribing speech");
  }
}
async function getWorkflowsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflows = mastra.getWorkflows({ serialized: false });
    const _workflows = Object.entries(workflows).reduce((acc, [key, workflow]) => {
      acc[key] = {
        stepGraph: workflow.stepGraph,
        stepSubscriberGraph: workflow.stepSubscriberGraph,
        serializedStepGraph: workflow.serializedStepGraph,
        serializedStepSubscriberGraph: workflow.serializedStepSubscriberGraph,
        name: workflow.name,
        triggerSchema: workflow.triggerSchema ? stringify(esm_default(workflow.triggerSchema)) : void 0,
        steps: Object.entries(workflow.steps).reduce((acc2, [key2, step]) => {
          const _step = step;
          acc2[key2] = {
            ..._step,
            inputSchema: _step.inputSchema ? stringify(esm_default(_step.inputSchema)) : void 0,
            outputSchema: _step.outputSchema ? stringify(esm_default(_step.outputSchema)) : void 0
          };
          return acc2;
        }, {})
      };
      return acc;
    }, {});
    return c2.json(_workflows);
  } catch (error) {
    return handleError(error, "Error getting workflows");
  }
}
async function getWorkflowByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const workflow = mastra.getWorkflow(workflowId);
    const triggerSchema = workflow?.triggerSchema;
    const stepGraph = workflow.stepGraph;
    const stepSubscriberGraph = workflow.stepSubscriberGraph;
    const serializedStepGraph = workflow.serializedStepGraph;
    const serializedStepSubscriberGraph = workflow.serializedStepSubscriberGraph;
    const serializedSteps = Object.entries(workflow.steps).reduce((acc, [key, step]) => {
      const _step = step;
      acc[key] = {
        ..._step,
        inputSchema: _step.inputSchema ? stringify(esm_default(_step.inputSchema)) : void 0,
        outputSchema: _step.outputSchema ? stringify(esm_default(_step.outputSchema)) : void 0
      };
      return acc;
    }, {});
    return c2.json({
      name: workflow.name,
      triggerSchema: triggerSchema ? stringify(esm_default(triggerSchema)) : void 0,
      steps: serializedSteps,
      stepGraph,
      stepSubscriberGraph,
      serializedStepGraph,
      serializedStepSubscriberGraph
    });
  } catch (error) {
    return handleError(error, "Error getting workflow");
  }
}
async function startAsyncWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const workflow = mastra.getWorkflow(workflowId);
    const body = await c2.req.json();
    const runId = c2.req.query("runId");
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to start run" });
    }
    const run = workflow.getRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const result = await run.start({
      triggerData: body
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error executing workflow");
  }
}
async function createRunHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const workflow = mastra.getWorkflow(workflowId);
    const prevRunId = c2.req.query("runId");
    const { runId } = workflow.createRun({ runId: prevRunId });
    return c2.json({ runId });
  } catch (e2) {
    return handleError(e2, "Error creating run");
  }
}
async function startWorkflowRunHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const workflow = mastra.getWorkflow(workflowId);
    const body = await c2.req.json();
    const runId = c2.req.query("runId");
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to start run" });
    }
    const run = workflow.getRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    run.start({
      triggerData: body
    });
    return c2.json({ message: "Workflow run started" });
  } catch (e2) {
    return handleError(e2, "Error starting workflow run");
  }
}
async function watchWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const logger2 = mastra.getLogger();
    const workflowId = c2.req.param("workflowId");
    const workflow = mastra.getWorkflow(workflowId);
    const runId = c2.req.query("runId");
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to watch workflow" });
    }
    const run = workflow.getRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    return streamText(
      c2,
      async (stream) => {
        return new Promise((_resolve, _reject) => {
          let unwatch = run.watch(({ activePaths, context, runId: runId2, timestamp, suspendedSteps }) => {
            void stream.write(JSON.stringify({ activePaths, context, runId: runId2, timestamp, suspendedSteps }) + "");
          });
          stream.onAbort(() => {
            unwatch?.();
          });
        });
      },
      async (err, stream) => {
        logger2.error("Error in watch stream: " + err?.message);
        stream.abort();
        await stream.close();
      }
    );
  } catch (error) {
    return handleError(error, "Error watching workflow");
  }
}
async function resumeAsyncWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const workflow = mastra.getWorkflow(workflowId);
    const runId = c2.req.query("runId");
    const { stepId, context } = await c2.req.json();
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to resume workflow" });
    }
    const run = workflow.getRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const result = await run.resume({
      stepId,
      context
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error resuming workflow step");
  }
}
async function resumeWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const workflow = mastra.getWorkflow(workflowId);
    const runId = c2.req.query("runId");
    const { stepId, context } = await c2.req.json();
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to resume workflow" });
    }
    const run = workflow.getRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    run.resume({
      stepId,
      context
    });
    return c2.json({ message: "Workflow run resumed" });
  } catch (error) {
    return handleError(error, "Error resuming workflow");
  }
}

// src/server/welcome.ts
var html2 = `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Welcome to Mastra</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/inter-ui/3.19.3/inter.min.css" />
    <style>
      body {
        margin: 0;
        padding: 0;
        background-color: #0d0d0d;
        color: #ffffff;
        font-family:
          'Inter',
          -apple-system,
          BlinkMacSystemFont,
          system-ui,
          sans-serif;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
      }

      main {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 2rem;
        text-align: center;
      }

      h1 {
        font-size: 4rem;
        font-weight: 600;
        margin: 0 0 1rem 0;
        background: linear-gradient(to right, #fff, #ccc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        line-height: 1.2;
      }

      .subtitle {
        color: #9ca3af;
        font-size: 1.25rem;
        max-width: 600px;
        margin: 0 auto 3rem auto;
        line-height: 1.6;
      }

      .docs-link {
        background-color: #1a1a1a;
        padding: 1rem 2rem;
        border-radius: 0.5rem;
        display: flex;
        align-items: center;
        gap: 1rem;
        font-family: monospace;
        font-size: 1rem;
        color: #ffffff;
        text-decoration: none;
        transition: background-color 0.2s;
      }

      .docs-link:hover {
        background-color: #252525;
      }

      .arrow-icon {
        transition: transform 0.2s;
      }

      .docs-link:hover .arrow-icon {
        transform: translateX(4px);
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Welcome to Mastra</h1>
      <p class="subtitle">
        From the team that brought you Gatsby: prototype and productionize AI features with a modern JS/TS stack.
      </p>

      <a href="https://mastra.ai/docs" class="docs-link">
        Browse the docs
        <svg
          class="arrow-icon"
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <path d="M5 12h14M12 5l7 7-7 7" />
        </svg>
      </a>
    </main>
  </body>
</html>
`;

// src/server/index.ts
async function createHonoServer(mastra, options = {}) {
  const app = new Hono();
  const mastraToolsPaths = process.env.MASTRA_TOOLS_PATH;
  const toolImports = mastraToolsPaths ? await Promise.all(
    mastraToolsPaths.split(",").map(async (toolPath) => {
      return import(pathToFileURL(toolPath).href);
    })
  ) : [];
  const tools = toolImports.reduce((acc, toolModule) => {
    Object.entries(toolModule).forEach(([key, tool]) => {
      acc[key] = tool;
    });
    return acc;
  }, {});
  app.use(
    "*",
    cors({
      origin: "*",
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowHeaders: ["Content-Type", "Authorization"],
      exposeHeaders: ["Content-Length", "X-Requested-With"],
      credentials: false,
      maxAge: 3600
    })
  );
  if (options.apiReqLogs) {
    app.use(logger());
  }
  app.onError(errorHandler);
  const serverMiddleware = mastra.getServerMiddleware?.();
  if (serverMiddleware && serverMiddleware.length > 0) {
    for (const m2 of serverMiddleware) {
      app.use(m2.path, m2.handler);
    }
  }
  app.use("*", async (c2, next) => {
    c2.set("mastra", mastra);
    c2.set("tools", tools);
    c2.set("playground", options.playground === true);
    await next();
  });
  const bodyLimitOptions = {
    maxSize: 4.5 * 1024 * 1024,
    // 4.5 MB,
    onError: (c2) => c2.json({ error: "Request body too large" }, 413)
  };
  app.get(
    "/api",
    h({
      description: "Get API status",
      tags: ["system"],
      responses: {
        200: {
          description: "Success"
        }
      }
    }),
    rootHandler
  );
  app.get(
    "/api/agents",
    h({
      description: "Get all available agents",
      tags: ["agents"],
      responses: {
        200: {
          description: "List of all agents"
        }
      }
    }),
    getAgentsHandler
  );
  app.get(
    "/api/networks",
    h({
      description: "Get all available networks",
      tags: ["networks"],
      responses: {
        200: {
          description: "List of all networks"
        }
      }
    }),
    getNetworksHandler
  );
  app.get(
    "/api/networks/:networkId",
    h({
      description: "Get network by ID",
      tags: ["networks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Network details"
        },
        404: {
          description: "Network not found"
        }
      }
    }),
    getNetworkByIdHandler
  );
  app.post(
    "/api/networks/:networkId/generate",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Generate a response from a network",
      tags: ["networks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: {
                  oneOf: [
                    { type: "string" },
                    {
                      type: "array",
                      items: { type: "object" }
                    }
                  ],
                  description: "Input for the network, can be a string or an array of CoreMessage objects"
                }
              },
              required: ["input"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Generated response"
        },
        404: {
          description: "Network not found"
        }
      }
    }),
    generateHandler2
  );
  app.post(
    "/api/networks/:networkId/stream",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Generate a response from a network",
      tags: ["networks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: {
                  oneOf: [
                    { type: "string" },
                    {
                      type: "array",
                      items: { type: "object" }
                    }
                  ],
                  description: "Input for the network, can be a string or an array of CoreMessage objects"
                }
              },
              required: ["input"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Generated response"
        },
        404: {
          description: "Network not found"
        }
      }
    }),
    streamGenerateHandler2
  );
  app.get(
    "/api/agents/:agentId",
    h({
      description: "Get agent by ID",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Agent details"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    getAgentByIdHandler
  );
  app.get(
    "/api/agents/:agentId/evals/ci",
    h({
      description: "Get CI evals by agent ID",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of evals"
        }
      }
    }),
    getEvalsByAgentIdHandler
  );
  app.get(
    "/api/agents/:agentId/evals/live",
    h({
      description: "Get live evals by agent ID",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of evals"
        }
      }
    }),
    getLiveEvalsByAgentIdHandler
  );
  app.post(
    "/api/agents/:agentId/generate",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Generate a response from an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                messages: {
                  type: "array",
                  items: { type: "object" }
                },
                threadId: { type: "string" },
                resourceId: { type: "string", description: "The resource ID for the conversation" },
                resourceid: {
                  type: "string",
                  description: "The resource ID for the conversation (deprecated, use resourceId instead)",
                  deprecated: true
                },
                runId: { type: "string" },
                output: { type: "object" }
              },
              required: ["messages"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Generated response"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    generateHandler
  );
  app.post(
    "/api/agents/:agentId/stream",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Stream a response from an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                messages: {
                  type: "array",
                  items: { type: "object" }
                },
                threadId: { type: "string" },
                resourceId: { type: "string", description: "The resource ID for the conversation" },
                resourceid: {
                  type: "string",
                  description: "The resource ID for the conversation (deprecated, use resourceId instead)",
                  deprecated: true
                },
                runId: { type: "string" },
                output: { type: "object" }
              },
              required: ["messages"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Streamed response"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    streamGenerateHandler
  );
  app.post(
    "/api/agents/:agentId/instructions",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Update an agent's instructions",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                instructions: {
                  type: "string",
                  description: "New instructions for the agent"
                }
              },
              required: ["instructions"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Instructions updated successfully"
        },
        403: {
          description: "Not allowed in non-playground environment"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    setAgentInstructionsHandler
  );
  app.post(
    "/api/agents/:agentId/instructions/enhance",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Generate an improved system prompt from instructions",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" },
          description: "ID of the agent whose model will be used for prompt generation"
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                instructions: {
                  type: "string",
                  description: "Instructions to generate a system prompt from"
                },
                comment: {
                  type: "string",
                  description: "Optional comment for the enhanced prompt"
                }
              },
              required: ["instructions"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Generated system prompt and analysis",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  explanation: {
                    type: "string",
                    description: "Detailed analysis of the instructions"
                  },
                  new_prompt: {
                    type: "string",
                    description: "The enhanced system prompt"
                  }
                }
              }
            }
          }
        },
        400: {
          description: "Missing or invalid request parameters"
        },
        404: {
          description: "Agent not found"
        },
        500: {
          description: "Internal server error or model response parsing error"
        }
      }
    }),
    generateSystemPromptHandler
  );
  app.get(
    "/api/agents/:agentId/speakers",
    async (c2, next) => {
      c2.header("Deprecation", "true");
      c2.header("Warning", '299 - "This endpoint is deprecated, use /api/agents/:agentId/voice/speakers instead"');
      c2.header("Link", '</api/agents/:agentId/voice/speakers>; rel="successor-version"');
      return next();
    },
    h({
      description: "[DEPRECATED] Use /api/agents/:agentId/voice/speakers instead. Get available speakers for an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of available speakers",
          content: {
            "application/json": {
              schema: {
                type: "array",
                items: {
                  type: "object",
                  description: "Speaker information depending on the voice provider",
                  properties: {
                    voiceId: { type: "string" }
                  },
                  additionalProperties: true
                }
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    getSpeakersHandler
  );
  app.get(
    "/api/agents/:agentId/voice/speakers",
    h({
      description: "Get available speakers for an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of available speakers",
          content: {
            "application/json": {
              schema: {
                type: "array",
                items: {
                  type: "object",
                  description: "Speaker information depending on the voice provider",
                  properties: {
                    voiceId: { type: "string" }
                  },
                  additionalProperties: true
                }
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    getSpeakersHandler
  );
  app.post(
    "/api/agents/:agentId/speak",
    bodyLimit(bodyLimitOptions),
    async (c2, next) => {
      c2.header("Deprecation", "true");
      c2.header("Warning", '299 - "This endpoint is deprecated, use /api/agents/:agentId/voice/speak instead"');
      c2.header("Link", '</api/agents/:agentId/voice/speak>; rel="successor-version"');
      return next();
    },
    h({
      description: "[DEPRECATED] Use /api/agents/:agentId/voice/speak instead. Convert text to speech using the agent's voice provider",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                text: {
                  type: "string",
                  description: "Text to convert to speech"
                },
                options: {
                  type: "object",
                  description: "Provider-specific options for speech generation",
                  properties: {
                    speaker: {
                      type: "string",
                      description: "Speaker ID to use for speech generation"
                    }
                  },
                  additionalProperties: true
                }
              },
              required: ["text"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Audio stream",
          content: {
            "audio/mpeg": {
              schema: {
                format: "binary",
                description: "Audio stream containing the generated speech"
              }
            },
            "audio/*": {
              schema: {
                format: "binary",
                description: "Audio stream depending on the provider"
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities or invalid request"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    speakHandler
  );
  app.post(
    "/api/agents/:agentId/voice/speak",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Convert text to speech using the agent's voice provider",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: {
                  type: "string",
                  description: "Text to convert to speech"
                },
                options: {
                  type: "object",
                  description: "Provider-specific options for speech generation",
                  properties: {
                    speaker: {
                      type: "string",
                      description: "Speaker ID to use for speech generation"
                    },
                    options: {
                      type: "object",
                      description: "Provider-specific options for speech generation",
                      additionalProperties: true
                    }
                  },
                  additionalProperties: true
                }
              },
              required: ["text"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Audio stream",
          content: {
            "audio/mpeg": {
              schema: {
                format: "binary",
                description: "Audio stream containing the generated speech"
              }
            },
            "audio/*": {
              schema: {
                format: "binary",
                description: "Audio stream depending on the provider"
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities or invalid request"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    speakHandler
  );
  app.post(
    "/api/agents/:agentId/listen",
    bodyLimit({
      ...bodyLimitOptions,
      maxSize: 10 * 1024 * 1024
      // 10 MB for audio files
    }),
    async (c2, next) => {
      c2.header("Deprecation", "true");
      c2.header("Warning", '299 - "This endpoint is deprecated, use /api/agents/:agentId/voice/listen instead"');
      c2.header("Link", '</api/agents/:agentId/voice/listen>; rel="successor-version"');
      return next();
    },
    h({
      description: "[DEPRECATED] Use /api/agents/:agentId/voice/listen instead. Convert speech to text using the agent's voice provider. Additional provider-specific options can be passed as query parameters.",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "audio/mpeg": {
            schema: {
              format: "binary",
              description: "Audio data stream to transcribe (supports various formats depending on provider like mp3, wav, webm, flac)"
            }
          }
        }
      },
      responses: {
        200: {
          description: "Transcription result",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  text: {
                    type: "string",
                    description: "Transcribed text"
                  }
                }
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities or invalid request"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    listenHandler
  );
  app.post(
    "/api/agents/:agentId/voice/listen",
    bodyLimit({
      ...bodyLimitOptions,
      maxSize: 10 * 1024 * 1024
      // 10 MB for audio files
    }),
    h({
      description: "Convert speech to text using the agent's voice provider. Additional provider-specific options can be passed as query parameters.",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "multipart/form-data": {
            schema: {
              type: "object",
              required: ["audio"],
              properties: {
                audio: {
                  type: "string",
                  format: "binary",
                  description: "Audio data stream to transcribe (supports various formats depending on provider like mp3, wav, webm, flac)"
                },
                options: {
                  type: "object",
                  description: "Provider-specific options for speech-to-text",
                  additionalProperties: true
                }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "Transcription result",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  text: {
                    type: "string",
                    description: "Transcribed text"
                  }
                }
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities or invalid request"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    listenHandler
  );
  app.post(
    "/api/agents/:agentId/tools/:toolId/execute",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Execute a tool through an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "toolId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                data: { type: "object" }
              },
              required: ["data"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Tool execution result"
        },
        404: {
          description: "Tool or agent not found"
        }
      }
    }),
    executeAgentToolHandler
  );
  app.get(
    "/api/memory/status",
    h({
      description: "Get memory status",
      tags: ["memory"],
      parameters: [
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Memory status"
        }
      }
    }),
    getMemoryStatusHandler
  );
  app.get(
    "/api/memory/threads",
    h({
      description: "Get all threads",
      tags: ["memory"],
      parameters: [
        {
          name: "resourceid",
          in: "query",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of all threads"
        }
      }
    }),
    getThreadsHandler
  );
  app.get(
    "/api/memory/threads/:threadId",
    h({
      description: "Get thread by ID",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Thread details"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    getThreadByIdHandler
  );
  app.get(
    "/api/memory/threads/:threadId/messages",
    h({
      description: "Get messages for a thread",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of messages"
        }
      }
    }),
    getMessagesHandler
  );
  app.post(
    "/api/memory/threads",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Create a new thread",
      tags: ["memory"],
      parameters: [
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                title: { type: "string" },
                metadata: { type: "object" },
                resourceid: { type: "string" },
                threadId: { type: "string" }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "Created thread"
        }
      }
    }),
    createThreadHandler
  );
  app.patch(
    "/api/memory/threads/:threadId",
    h({
      description: "Update a thread",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { type: "object" }
          }
        }
      },
      responses: {
        200: {
          description: "Updated thread"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    updateThreadHandler
  );
  app.delete(
    "/api/memory/threads/:threadId",
    h({
      description: "Delete a thread",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Thread deleted"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    deleteThreadHandler
  );
  app.post(
    "/api/memory/save-messages",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Save messages",
      tags: ["memory"],
      parameters: [
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                messages: {
                  type: "array",
                  items: { type: "object" }
                }
              },
              required: ["messages"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Messages saved"
        }
      }
    }),
    saveMessagesHandler
  );
  app.get(
    "/api/telemetry",
    h({
      description: "Get all traces",
      tags: ["telemetry"],
      responses: {
        200: {
          description: "List of all traces (paged)"
        }
      }
    }),
    getTelemetryHandler
  );
  app.get(
    "/api/workflows",
    h({
      description: "Get all workflows",
      tags: ["workflows"],
      responses: {
        200: {
          description: "List of all workflows"
        }
      }
    }),
    getWorkflowsHandler
  );
  app.get(
    "/api/workflows/:workflowId",
    h({
      description: "Get workflow by ID",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Workflow details"
        },
        404: {
          description: "Workflow not found"
        }
      }
    }),
    getWorkflowByIdHandler
  );
  app.post(
    "/api/workflows/:workflowId/resume",
    h({
      description: "Resume a suspended workflow step",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                stepId: { type: "string" },
                context: { type: "object" }
              }
            }
          }
        }
      }
    }),
    resumeWorkflowHandler
  );
  app.post(
    "/api/workflows/:workflowId/resumeAsync",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Resume a suspended workflow step",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                stepId: { type: "string" },
                context: { type: "object" }
              }
            }
          }
        }
      }
    }),
    resumeAsyncWorkflowHandler
  );
  app.post(
    "/api/workflows/:workflowId/createRun",
    h({
      description: "Create a new workflow run",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "New workflow run created"
        }
      }
    }),
    createRunHandler
  );
  app.post(
    "/api/workflows/:workflowId/startAsync",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Execute/Start a workflow",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: { type: "object" }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "Workflow execution result"
        },
        404: {
          description: "Workflow not found"
        }
      }
    }),
    startAsyncWorkflowHandler
  );
  app.post(
    "/api/workflows/:workflowId/start",
    h({
      description: "Create and start a new workflow run",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Workflow run started"
        },
        404: {
          description: "Workflow not found"
        }
      }
    }),
    startWorkflowRunHandler
  );
  app.get(
    "/api/workflows/:workflowId/watch",
    h({
      description: "Watch workflow transitions in real-time",
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      tags: ["workflows"],
      responses: {
        200: {
          description: "Workflow transitions in real-time"
        }
      }
    }),
    watchWorkflowHandler
  );
  app.get(
    "/api/logs",
    h({
      description: "Get all logs",
      tags: ["logs"],
      parameters: [
        {
          name: "transportId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of all logs"
        }
      }
    }),
    getLogsHandler
  );
  app.get(
    "/api/logs/transports",
    h({
      description: "List of all log transports",
      tags: ["logs"],
      responses: {
        200: {
          description: "List of all log transports"
        }
      }
    }),
    getLogTransports
  );
  app.get(
    "/api/logs/:runId",
    h({
      description: "Get logs by run ID",
      tags: ["logs"],
      parameters: [
        {
          name: "runId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "transportId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of logs for run ID"
        }
      }
    }),
    getLogsByRunIdHandler
  );
  app.get(
    "/api/tools",
    h({
      description: "Get all tools",
      tags: ["tools"],
      responses: {
        200: {
          description: "List of all tools"
        }
      }
    }),
    getToolsHandler
  );
  app.get(
    "/api/tools/:toolId",
    h({
      description: "Get tool by ID",
      tags: ["tools"],
      parameters: [
        {
          name: "toolId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Tool details"
        },
        404: {
          description: "Tool not found"
        }
      }
    }),
    getToolByIdHandler
  );
  app.post(
    "/api/tools/:toolId/execute",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Execute a tool",
      tags: ["tools"],
      parameters: [
        {
          name: "toolId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                data: { type: "object" }
              },
              required: ["data"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Tool execution result"
        },
        404: {
          description: "Tool not found"
        }
      }
    }),
    executeToolHandler(tools)
  );
  app.post(
    "/api/vector/:vectorName/upsert",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Upsert vectors into an index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                indexName: { type: "string" },
                vectors: {
                  type: "array",
                  items: {
                    type: "array",
                    items: { type: "number" }
                  }
                },
                metadata: {
                  type: "array",
                  items: { type: "object" }
                },
                ids: {
                  type: "array",
                  items: { type: "string" }
                }
              },
              required: ["indexName", "vectors"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Vectors upserted successfully"
        }
      }
    }),
    upsertVectors
  );
  app.post(
    "/api/vector/:vectorName/create-index",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Create a new vector index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                indexName: { type: "string" },
                dimension: { type: "number" },
                metric: {
                  type: "string",
                  enum: ["cosine", "euclidean", "dotproduct"]
                }
              },
              required: ["indexName", "dimension"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Index created successfully"
        }
      }
    }),
    createIndex
  );
  app.post(
    "/api/vector/:vectorName/query",
    bodyLimit(bodyLimitOptions),
    h({
      description: "Query vectors from an index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                indexName: { type: "string" },
                queryVector: {
                  type: "array",
                  items: { type: "number" }
                },
                topK: { type: "number" },
                filter: { type: "object" },
                includeVector: { type: "boolean" }
              },
              required: ["indexName", "queryVector"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Query results"
        }
      }
    }),
    queryVectors
  );
  app.get(
    "/api/vector/:vectorName/indexes",
    h({
      description: "List all indexes for a vector store",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of indexes"
        }
      }
    }),
    listIndexes
  );
  app.get(
    "/api/vector/:vectorName/indexes/:indexName",
    h({
      description: "Get details about a specific index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "indexName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Index details"
        }
      }
    }),
    describeIndex
  );
  app.delete(
    "/api/vector/:vectorName/indexes/:indexName",
    h({
      description: "Delete a specific index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "indexName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Index deleted successfully"
        }
      }
    }),
    deleteIndex
  );
  app.get(
    "/openapi.json",
    f(app, {
      documentation: {
        info: { title: "Mastra API", version: "1.0.0", description: "Mastra API" }
      }
    })
  );
  app.get("/swagger-ui", middleware({ url: "/openapi.json" }));
  if (options?.swaggerUI) {
    app.get("/swagger-ui", middleware({ url: "/openapi.json" }));
  }
  if (options?.playground) {
    app.get("/refresh-events", handleClientsRefresh);
    app.post("/__refresh", handleTriggerClientsRefresh);
    app.use("/assets/*", async (c2, next) => {
      const path = c2.req.path;
      if (path.endsWith(".js")) {
        c2.header("Content-Type", "application/javascript");
      } else if (path.endsWith(".css")) {
        c2.header("Content-Type", "text/css");
      }
      await next();
    });
    app.use(
      "/assets/*",
      serveStatic({
        root: "./playground/assets"
      })
    );
    app.use(
      "*",
      serveStatic({
        root: "./playground"
      })
    );
  }
  app.get("*", async (c2, next) => {
    if (c2.req.path.startsWith("/api/") || c2.req.path.startsWith("/swagger-ui") || c2.req.path.startsWith("/openapi.json")) {
      return await next();
    }
    if (options?.playground) {
      const indexHtml = await readFile(join(process.cwd(), "./playground/index.html"), "utf-8");
      return c2.newResponse(indexHtml, 200, { "Content-Type": "text/html" });
    }
    return c2.newResponse(html2, 200, { "Content-Type": "text/html" });
  });
  return app;
}
async function createNodeServer(mastra, options = {}) {
  const app = await createHonoServer(mastra, options);
  return serve(
    {
      fetch: app.fetch,
      port: Number(process.env.PORT) || 4111
    },
    () => {
      const logger2 = mastra.getLogger();
      logger2.info(`\u{1F984} Mastra API running on port ${process.env.PORT || 4111}/api`);
      logger2.info(`\u{1F4DA} Open API documentation available at http://localhost:${process.env.PORT || 4111}/openapi.json`);
      if (options?.swaggerUI) {
        logger2.info(`\u{1F9EA} Swagger UI available at http://localhost:${process.env.PORT || 4111}/swagger-ui`);
      }
      if (options?.playground) {
        logger2.info(`\u{1F468}\u200D\u{1F4BB} Playground available at http://localhost:${process.env.PORT || 4111}/`);
      }
    }
  );
}

// @ts-ignore
// @ts-ignore
// @ts-ignore
await createNodeServer(mastra, { playground: true, swaggerUI: true });

registerHook(AvailableHooks.ON_GENERATION, ({ input, output, metric, runId, agentName, instructions }) => {
  evaluate({
    agentName,
    input,
    metric,
    output,
    runId,
    globalRunId: runId,
    instructions,
  });
});

registerHook(AvailableHooks.ON_EVALUATION, async traceObject => {
  if (mastra.storage) {
    // Check for required fields
    const logger = mastra?.getLogger();
    const areFieldsValid = checkEvalStorageFields(traceObject, logger);
    if (!areFieldsValid) return;

    await mastra.storage.insert({
      tableName: TABLE_EVALS,
      record: {
        input: traceObject.input,
        output: traceObject.output,
        result: JSON.stringify(traceObject.result || {}),
        agent_name: traceObject.agentName,
        metric_name: traceObject.metricName,
        instructions: traceObject.instructions,
        test_info: null,
        global_run_id: traceObject.globalRunId,
        run_id: traceObject.runId,
        created_at: new Date().toISOString(),
      },
    });
  }
});

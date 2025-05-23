import process$1, { env } from 'process';
import { z, ZodType } from 'zod';
import { createTool } from '@mastra/core/tools';
import { createLogger } from '@mastra/core/logger';
import { google } from '@ai-sdk/google';
import { encodingForModel } from 'js-tiktoken';
import { createVectorQueryTool } from '@mastra/rag';
import { GoogleGenerativeAIEmbeddings, ChatGoogleGenerativeAI } from '@langchain/google-genai';
import { AsyncCaller } from '@langchain/core/utils/async_caller';
import { BraveSearchClient } from '@agentic/brave-search';
import { GoogleCustomSearchClient } from '@agentic/google-custom-search';
import { TavilyClient } from '@agentic/tavily';
import { aiFunction, AIFunctionsProvider, AIFunctionSet, asZodOrJsonSchema, sanitizeSearchParams, pruneEmpty, assert, getEnv, throttleKy, isZodSchema, asAgenticSchema, createAIFunction } from '@agentic/core';
import { createMastraTools } from '@agentic/mastra';
export { createMastraTools } from '@agentic/mastra';
import Exa from 'exa-js';
import * as fs from 'fs-extra';
import fs__default from 'fs-extra';
import path, { resolve, extname, dirname, join } from 'path';
import { Client } from 'langsmith';
import { v4 } from 'uuid';
import { LibSQLStore } from '@mastra/core/storage/libsql';
import { Memory } from '@mastra/memory';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-proto';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { SimpleSpanProcessor, ConsoleSpanExporter } from '@opentelemetry/sdk-trace-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { SemanticAttributes, SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import * as api from '@opentelemetry/api';
import { propagation, trace, metrics, context } from '@opentelemetry/api';
import { resourceFromAttributes, detectResources } from '@opentelemetry/resources';
import crypto, { randomUUID } from 'crypto';
import { vertex } from '@ai-sdk/google-vertex';
import { openai } from '@ai-sdk/openai';
import { anthropic } from '@ai-sdk/anthropic';
import { ollama } from 'ollama-ai-provider';
import { generateText, tool, jsonSchema } from 'ai';
import { LibSQLVector } from '@mastra/core/vector/libsql';
import fetch from 'node-fetch';
import mammoth from 'mammoth';
import Papa from 'papaparse';
import * as cheerio from 'cheerio';
import { FunctionTool } from 'llamaindex';
import { UpstashStore } from '@mastra/upstash';
import { Redis } from '@upstash/redis';
import { Index } from '@upstash/vector';
import { CompositePropagator } from '@opentelemetry/core';
import { B3Propagator } from '@opentelemetry/propagator-b3';
import { ParentBasedSampler, TraceIdRatioBasedSampler } from '@opentelemetry/sdk-trace-base';
import { XMLParser, XMLBuilder } from 'fast-xml-parser';
import YAML from 'yaml';
import Database from 'better-sqlite3';
import { zodToJsonSchema } from 'zod-to-json-schema';
import defaultKy from 'ky';
import pThrottle from 'p-throttle';
import { Sandbox } from '@e2b/code-interpreter';
import { Pinecone } from '@pinecone-database/pinecone';
import { PineconeStore } from '@langchain/pinecone';
import { Document } from 'langchain/document';
import { ChatOpenAI } from '@langchain/openai';
import { ChatAnthropic } from '@langchain/anthropic';
import { PromptTemplate } from '@langchain/core/prompts';
import { Langfuse } from 'langfuse';
import { Octokit } from 'octokit';
import { MCPConfiguration } from '@mastra/mcp';
import { GithubIntegration } from '@mastra/github';
import { PolygonClient } from '@agentic/polygon';
import { RedditClient } from '@agentic/reddit';
import puppeteer from 'puppeteer';
import { create, all } from 'mathjs';
import jsonld from 'jsonld';

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

const logger$a = createLogger({ name: "vector-query-tool", level: "info" });
const envSchema$2 = z.object({
  GOOGLE_AI_API_KEY: z.string().min(1, "Google AI API key is required"),
  PINECONE_INDEX: z.string().default("Default"),
  PINECONE_DIMENSION: z.coerce.number().default(2048),
  VECTOR_STORE_NAME: z.string().default("pinecone")
});
const validatedEnv$1 = (() => {
  try {
    return envSchema$2.parse(env);
  } catch (error) {
    logger$a.error("Environment validation failed:", { error });
    throw new Error(
      `Vector query tool configuration error: ${error instanceof Error ? error.message : String(error)}`
    );
  }
})();
function createMastraVectorQueryTool(config = {}) {
  try {
    const vectorStoreName = config.vectorStoreName || validatedEnv$1.VECTOR_STORE_NAME;
    const indexName = config.indexName || validatedEnv$1.PINECONE_INDEX;
    const embeddingProvider = config.embeddingProvider || "google";
    const tokenEncoding = config.tokenEncoding || "o200k_base";
    const dimensions = config.dimensions || validatedEnv$1.PINECONE_DIMENSION;
    const apiKey = config.apiKey || validatedEnv$1.GOOGLE_AI_API_KEY;
    const topK = config.topK || 5;
    logger$a.info(
      `Creating vector query tool for ${vectorStoreName}:${indexName}`
    );
    let embeddingModel;
    if (embeddingProvider === "tiktoken") {
      logger$a.info(`Using tiktoken embeddings with encoding: ${tokenEncoding}`);
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
            logger$a.error("Tiktoken embedding error:", { error });
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
      logger$a.info("Using Google embeddings");
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
    logger$a.info(`Vector query tool created: ${toolId}`);
    return tool;
  } catch (error) {
    logger$a.error("Failed to create vector query tool:", { error });
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

var FileEncoding = /* @__PURE__ */ ((FileEncoding2) => {
  FileEncoding2["UTF8"] = "utf8";
  FileEncoding2["ASCII"] = "ascii";
  FileEncoding2["UTF16LE"] = "utf16le";
  FileEncoding2["LATIN1"] = "latin1";
  FileEncoding2["BASE64"] = "base64";
  FileEncoding2["HEX"] = "hex";
  return FileEncoding2;
})(FileEncoding || {});
var FileWriteMode = /* @__PURE__ */ ((FileWriteMode2) => {
  FileWriteMode2["OVERWRITE"] = "overwrite";
  FileWriteMode2["APPEND"] = "append";
  FileWriteMode2["CREATE_NEW"] = "create-new";
  return FileWriteMode2;
})(FileWriteMode || {});
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
  execute: async ({ context, container }) => {
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
        container,
        // Pass the container
        context: {
          ...context,
          path: knowledgePath,
          // Provide the default value from writeToFileTool's schema
          maxSizeBytes: 100485760
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
        const contentStr = typeof content === "string" ? content : content.toString(context.encoding || "utf8");
        newContent = contentStr.replace(regex, function(match, ...args) {
          edits++;
          let result = context.replace;
          for (let i = 1; i < args.length - 1; i++) {
            result = result.replace(new RegExp("\\$" + i, "g"), args[i - 1] ?? "");
          }
          result = result.replace(/\$0/g, match);
          return result;
        });
      } else {
        const contentStr = typeof content === "string" ? content : content.toString(context.encoding || "utf8");
        newContent = contentStr.split(context.search).join(context.replace);
        edits = (contentStr.match(new RegExp(context.search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length;
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

const { SpanStatusCode } = api;
const OTelAttributeNames = {
  // General
  COMPONENT: "component",
  SERVICE_NAME: "service.name",
  SERVICE_VERSION: "service.version",
  ENVIRONMENT: "deployment.environment",
  USER_ID: "user.id",
  SESSION_ID: "session.id",
  TRACE_ID: "trace.id",
  // AI specific
  MODEL_NAME: "ai.model.name",
  MODEL_PROVIDER: "ai.model.provider",
  PROMPT_TOKENS: "ai.prompt.tokens",
  COMPLETION_TOKENS: "ai.completion.tokens",
  TOTAL_TOKENS: "ai.tokens.total",
  LATENCY_MS: "ai.latency.ms",
  // Mastra specific
  AGENT_ID: "mastra.agent.id",
  AGENT_TYPE: "mastra.agent.type",
  TOOL_ID: "mastra.tool.id",
  WORKFLOW_ID: "mastra.workflow.id",
  MEMORY_ID: "mastra.memory.id",
  THREAD_ID: "mastra.thread.id",
  // Error
  ERROR: "error",
  ERROR_MESSAGE: "error.message",
  ERROR_STACK: "error.stack"
};

const logger$9 = createLogger({ name: "signoz-service", level: "info" });
let sdk = null;
let tracer = null;
let meterProvider = null;
function initSigNoz(config = {}) {
  const isEnabled = env.MASTRA_TELEMETRY_ENABLED?.toLowerCase() === "false" ? false : config.enabled !== false;
  if (!isEnabled) {
    logger$9.info("SigNoz tracing is disabled via config or MASTRA_TELEMETRY_ENABLED=false.");
    return { tracer: null, meterProvider: null };
  }
  if (sdk) {
    logger$9.warn("SigNoz tracing already initialized.");
    return { tracer: getTracer(), meterProvider: getMeterProvider() };
  }
  try {
    const serviceName = env.MASTRA_SERVICE_NAME || config.serviceName || "deanmachines-ai-mastra";
    const tracesEndpoint = env.OTEL_EXPORTER_OTLP_ENDPOINT || config.export?.endpoint || "http://localhost:4318/";
    const metricsEndpoint = env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT || tracesEndpoint.replace("/v1/traces", "/v1/metrics");
    const headers = config.export?.headers || {};
    logger$9.info(`Initializing SigNoz telemetry for service: ${serviceName}`, {
      tracesEndpoint,
      metricsEndpoint,
      env: env.NODE_ENV || "development"
    });
    const resource = resourceFromAttributes({
      [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
      [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: env.NODE_ENV || "development",
      [SemanticResourceAttributes.SERVICE_VERSION]: env.npm_package_version,
      [SemanticResourceAttributes.HOST_NAME]: env.HOSTNAME || env.COMPUTERNAME,
      [SemanticResourceAttributes.OS_TYPE]: process.platform
    });
    logger$9.info(`Initializing SigNoz: traces\u2192${tracesEndpoint}, metrics\u2192${metricsEndpoint}`);
    sdk = new NodeSDK({
      resource,
      traceExporter: new OTLPTraceExporter({ url: tracesEndpoint, headers }),
      metricReader: new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({ url: metricsEndpoint, headers }),
        exportIntervalMillis: config.export?.metricsInterval ?? 6e4
      }),
      instrumentations: [getNodeAutoInstrumentations()],
      ...env.NODE_ENV !== "production" && {
        spanProcessor: new SimpleSpanProcessor(new ConsoleSpanExporter())
      }
    });
    sdk.start();
    logger$9.info("SigNoz NodeSDK started");
    tracer = api.trace.getTracer(`${serviceName}-tracer`);
    meterProvider = api.metrics.getMeterProvider();
    process.on("SIGTERM", () => {
      shutdownSigNoz().then(() => logger$9.info("SigNoz shutdown complete on SIGTERM.")).catch((err) => logger$9.error("Error shutting down SigNoz on SIGTERM:", err)).finally(() => process.exit(0));
    });
    process.on("SIGINT", () => {
      shutdownSigNoz().then(() => logger$9.info("SigNoz shutdown complete on SIGINT.")).catch((err) => logger$9.error("Error shutting down SigNoz on SIGINT:", err)).finally(() => process.exit(0));
    });
    return { tracer, meterProvider };
  } catch (error) {
    logger$9.error("Failed to initialize SigNoz NodeSDK", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : void 0
    });
    sdk = null;
    return { tracer: null, meterProvider: null };
  }
}
function getTracer() {
  if (!tracer) {
    throw new Error("SigNoz tracing has not been initialized successfully. Call initSigNoz first.");
  }
  return tracer;
}
function getMeterProvider() {
  if (!meterProvider) {
    throw new Error("SigNoz metrics has not been initialized successfully. Call initSigNoz first.");
  }
  return meterProvider;
}
function createAISpan(name, attributes = {}, options = {}) {
  try {
    const currentTracer = getTracer();
    return currentTracer.startSpan(name, {
      attributes: {
        "ai.operation": name,
        ...attributes
      },
      ...options
    });
  } catch (error) {
    logger$9.warn(`Failed to create span '${name}' - tracing likely not initialized.`, { error: error.message });
    return api.trace.wrapSpanContext(api.INVALID_SPAN_CONTEXT);
  }
}
function recordLlmMetrics(span, tokenInfo, latencyMs) {
  if (!span || !span.isRecording()) return;
  try {
    if (tokenInfo?.promptTokens !== void 0) {
      span.setAttribute(OTelAttributeNames.PROMPT_TOKENS, tokenInfo.promptTokens);
    }
    if (latencyMs !== void 0) {
      span.setAttribute(OTelAttributeNames.LATENCY_MS, latencyMs);
    }
  } catch (error) {
    logger$9.warn("Failed to record LLM metrics on span", { error: error.message });
  }
}
function recordMetrics(span, metrics) {
  if (!span || !span.isRecording()) return;
  try {
    const { status, errorMessage, latencyMs, tokens, ...extraAttributes } = metrics;
    if (tokens !== void 0) {
      span.setAttribute(OTelAttributeNames.TOTAL_TOKENS, tokens);
    }
    if (latencyMs !== void 0) {
      span.setAttribute(OTelAttributeNames.LATENCY_MS, latencyMs);
    }
    for (const [key, value] of Object.entries(extraAttributes)) {
      if (value !== void 0) {
        span.setAttribute(key, value);
      }
    }
    if (status === "error") {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: errorMessage || "Operation failed"
      });
      if (errorMessage) {
        span.recordException({ name: "OperationError", message: errorMessage });
      }
    } else {
      span.setStatus({
        code: SpanStatusCode.OK
      });
    }
  } catch (error) {
    logger$9.warn("Failed to record metrics on span", { error: error.message });
  }
}
function createHttpSpan(method, url, options = {}) {
  try {
    const currentTracer = getTracer();
    const { attributes = {}, ...spanOptions } = options;
    const parsedUrl = new URL(url);
    return currentTracer.startSpan(`HTTP ${method.toUpperCase()}`, {
      kind: api.SpanKind.CLIENT,
      attributes: {
        [SemanticAttributes.HTTP_METHOD]: method.toUpperCase(),
        [SemanticAttributes.HTTP_URL]: url,
        [SemanticAttributes.NET_PEER_NAME]: parsedUrl.hostname,
        [SemanticAttributes.NET_PEER_PORT]: parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80),
        ...attributes
      },
      ...spanOptions
    });
  } catch (error) {
    logger$9.warn(`Failed to create HTTP span for ${method} ${url}`, { error: error.message });
    return api.trace.wrapSpanContext(api.INVALID_SPAN_CONTEXT);
  }
}
async function shutdownSigNoz() {
  if (sdk) {
    try {
      logger$9.info("Shutting down SigNoz NodeSDK...");
      await sdk.shutdown();
      logger$9.info("SigNoz NodeSDK shutdown complete.");
      sdk = null;
      tracer = null;
      meterProvider = null;
    } catch (error) {
      logger$9.error("Error shutting down SigNoz NodeSDK", { error });
    }
  } else {
    logger$9.info("SigNoz NodeSDK not initialized or already shut down.");
  }
}
var signoz = {
  init: initSigNoz,
  getTracer,
  getMeterProvider,
  createSpan: createAISpan,
  createHttpSpan,
  recordLlmMetrics,
  recordMetrics,
  shutdown: shutdownSigNoz
};

const logger$8 = createLogger({ name: "thread-manager", level: "info" });
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
    logger$8.info("Creating thread", { resourceId: options.resourceId, metadata: options.metadata });
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
      logger$8.info("Thread created", { threadId, resourceId: options.resourceId });
      span.setStatus({ code: 1 });
      signoz.recordMetrics(span, { latencyMs: Date.now() - startTime, status: "success" });
      runId = await createLangSmithRun("thread.create", [options.resourceId]);
      await trackFeedback(runId, { score: 1, comment: "Thread created successfully" });
      return threadInfo;
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: Date.now() - startTime, status: "error", errorMessage: String(error) });
      if (runId) await trackFeedback(runId, { score: 0, comment: "Thread creation failed", value: error });
      logger$8.error("Failed to create thread", { error });
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
      logger$8.info("Get thread", { threadId, found: !!thread });
      span.setStatus({ code: 1 });
      return thread;
    } catch (error) {
      logger$8.error("Failed to get thread", { error });
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
      logger$8.info("Get threads by resource", { resourceId, count: threads.length });
      span.setStatus({ code: 1 });
      return threads;
    } catch (error) {
      logger$8.error("Failed to get threads by resource", { error });
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
        logger$8.info("No threads found for resource", { resourceId });
        span.setStatus({ code: 1 });
        return void 0;
      }
      const mostRecent = threads.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())[0];
      logger$8.info("Most recent thread", { resourceId, threadId: mostRecent.id });
      span.setStatus({ code: 1 });
      return mostRecent;
    } catch (error) {
      logger$8.error("Failed to get most recent thread", { error });
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
        logger$8.info("Found existing thread", { resourceId, threadId: existingThread.id });
        span.setStatus({ code: 1 });
        return existingThread;
      }
      logger$8.info("No existing thread, creating new", { resourceId });
      const newThread = await this.createThread({ resourceId, metadata });
      span.setStatus({ code: 1 });
      return newThread;
    } catch (error) {
      logger$8.error("Failed to get or create thread", { error });
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
        logger$8.info("Marked thread as read", { threadId, date });
      }
      span.setStatus({ code: 1 });
    } catch (error) {
      logger$8.error("Failed to mark thread as read", { error });
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
      logger$8.info("Get unread threads by resource", { resourceId, count: unread.length });
      span.setStatus({ code: 1 });
      return unread;
    } catch (error) {
      logger$8.error("Failed to get unread threads by resource", { error });
      span.setStatus({ code: 2, message: String(error) });
      return [];
    } finally {
      span.end();
    }
  }
}
const threadManager = new ThreadManager();

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
var FeedbackType = /* @__PURE__ */ ((FeedbackType2) => {
  FeedbackType2["EXPLICIT"] = "explicit";
  FeedbackType2["IMPLICIT"] = "implicit";
  FeedbackType2["SELF_CRITIQUE"] = "self_critique";
  return FeedbackType2;
})(FeedbackType || {});
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
function getUnreadFeedbackThreads(agentId) {
  return threadManager.getUnreadThreadsByResource(agentId);
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

var RewardType = /* @__PURE__ */ ((RewardType2) => {
  RewardType2["SCALAR"] = "scalar";
  RewardType2["VECTOR"] = "vector";
  RewardType2["BINARY"] = "binary";
  RewardType2["HUMAN"] = "human";
  return RewardType2;
})(RewardType || {});
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

const logger$7 = createLogger({ name: "document-tools", level: process.env.LOG_LEVEL === "debug" ? "debug" : "info" });
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
        logger$7.info(`Fetching HTML from URL: ${context.url}`);
        const response = await fetch(context.url);
        if (!response.ok) throw new Error(`Failed to fetch URL: ${response.statusText}`);
        html = await response.text();
      }
      if (!html) throw new Error("No HTML content provided or fetched.");
      logger$7.info("Extracting text from HTML using cheerio");
      const $ = cheerio.load(html);
      const text = $("body").text();
      recordMetrics(span, { status: "success" });
      return { text };
    } catch (error) {
      logger$7.error(`extractHtmlTextTool error: ${error instanceof Error ? error.message : String(error)}`);
      recordMetrics(span, { status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      throw error;
    } finally {
      span.end();
    }
  }
});

const logger$6 = createLogger({ name: "opentelemetry-tracing", level: "info" });
function logWithTraceContext(target, level, message, data) {
  const span = trace.getSpan(context.active());
  const traceFields = span ? { trace_id: span.spanContext().traceId, span_id: span.spanContext().spanId } : {};
  const fn = target[level] ?? target.info ?? console.log;
  fn.call(target, message, { ...data, ...traceFields });
}
function initOpenTelemetry(options) {
  const {
    serviceName = "deanmachines-ai",
    serviceVersion = "1.0.0",
    environment = "development",
    enabled = true,
    endpoint,
    metricsEnabled = true,
    metricsIntervalMs = 6e4,
    samplingRatio = 1
  } = options;
  if (!enabled) {
    logger$6.info("OpenTelemetry tracing is disabled");
    return null;
  }
  const detected = detectResources();
  const manual = resourceFromAttributes({
    [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
    [SemanticResourceAttributes.SERVICE_VERSION]: serviceVersion,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: environment
  });
  const resource = detected.merge(manual);
  const propagator = new CompositePropagator({
    propagators: [new B3Propagator()]
  });
  propagation.setGlobalPropagator(propagator);
  const sampler = new ParentBasedSampler({
    root: new TraceIdRatioBasedSampler(samplingRatio)
  });
  const traceExporter = new OTLPTraceExporter({
    url: endpoint || process$1.env.OTEL_EXPORTER_OTLP_ENDPOINT
  });
  const metricReader = metricsEnabled ? new PeriodicExportingMetricReader({
    exporter: new OTLPMetricExporter({
      url: (endpoint || process$1.env.OTEL_EXPORTER_OTLP_ENDPOINT || "").replace(
        "/v1/traces",
        "/v1/metrics"
      )
    }),
    exportIntervalMillis: metricsIntervalMs
  }) : void 0;
  const config = {
    resource,
    sampler,
    traceExporter,
    instrumentations: [
      getNodeAutoInstrumentations({
        "@opentelemetry/instrumentation-http": {
          ignoreIncomingRequestHook: (req) => req.url?.includes("/health") ?? false
        }
      })
    ],
    autoDetectResources: false,
    textMapPropagator: propagator,
    logRecordProcessors: [],
    metricReader,
    views: [],
    resourceDetectors: [],
    contextManager: void 0,
    logRecordProcessor: void 0,
    spanLimits: void 0,
    idGenerator: void 0
  };
  const sdk = new NodeSDK(config);
  try {
    sdk.start();
    logger$6.info("OpenTelemetry SDK initialized");
    trace.getTracer(serviceName);
    metrics.getMeter(serviceName + "-metrics");
  } catch (err) {
    logger$6.error("Error initializing OpenTelemetry SDK", { error: err.message });
  }
  process$1.on("SIGTERM", async () => {
    await sdk.shutdown();
    logger$6.info("OpenTelemetry SDK shut down");
    process$1.exit(0);
  });
  return sdk;
}

function traced(operation, fn) {
  const span = signoz.createSpan(operation);
  return fn().then((result) => {
    span.setStatus({ code: 1 });
    span.end();
    return result;
  }).catch((error) => {
    span.setStatus({ code: 2, message: error?.message || String(error) });
    logWithTraceContext(console, "error", `${operation} failed`, { error });
    span.end();
    throw error;
  });
}
try {
  new Redis({
    url: `https://${process.env.UPSTASH_REDIS_REST_URL}` || "file:.mastra/mastra.db",
    token: process.env.UPSTASH_REDIS_REST_TOKEN || "file:.mastra/mastra.db"
  });
  logWithTraceContext(console, "info", "Upstash Redis client initialized", { url: process.env.UPSTASH_REDIS_REST_URL });
} catch (error) {
  logWithTraceContext(console, "error", "Failed to initialize Upstash Redis client", { error });
}
let redisStore;
try {
  redisStore = new UpstashStore({
    url: `https://${process.env.UPSTASH_REDIS_REST_URL}` || "file:.mastra/mastra.db",
    token: process.env.UPSTASH_REDIS_REST_TOKEN || "file:.mastra/mastra.db"
  });
  new Memory({
    storage: redisStore,
    options: {
      lastMessages: 100
    }
  });
  logWithTraceContext(console, "info", "Upstash Redis memory initialized", { url: process.env.UPSTASH_REDIS_REST_URL });
} catch (error) {
  logWithTraceContext(console, "error", "Failed to initialize Upstash Redis memory", { error });
}
let upstashVector;
try {
  upstashVector = new Index({
    url: process.env.UPSTASH_VECTOR_REST_URL,
    token: process.env.UPSTASH_VECTOR_REST_TOKEN
  });
  logWithTraceContext(console, "info", "Upstash VectorDB initialized", { url: process.env.UPSTASH_VECTOR_REST_URL, index: process.env.UPSTASH_INDEX });
} catch (error) {
  logWithTraceContext(console, "error", "Failed to initialize Upstash VectorDB", { error });
}
async function vectorUpsert({ id, vector, metadata }) {
  if (!upstashVector) throw new Error("Upstash VectorDB not initialized");
  return traced("vector.upsert", () => upstashVector.upsert({ id, vector, metadata }));
}
async function vectorQuery({ query, topK = 5, filter, includeVectors = false, includeMetadata = true }) {
  if (!upstashVector) throw new Error("Upstash VectorDB not initialized");
  return traced("vector.query", () => upstashVector.query({
    vector: query,
    topK,
    filter,
    includeVectors,
    includeMetadata
  }));
}

function parseInput(input, format) {
  switch (format) {
    case "json":
      return JSON.parse(input);
    case "xml": {
      const parser = new XMLParser();
      return parser.parse(input);
    }
    case "yaml":
      return YAML.parse(input);
    case "txt":
    case "md":
      return input;
    // passthrough for plain text and markdown
    case "sqlite":
    case "db": {
      const db = new Database(input, { readonly: true });
      const rows = db.prepare("SELECT * FROM memory").all();
      db.close();
      return rows;
    }
    default:
      throw new Error(`Unsupported format: ${format}`);
  }
}
function stringifyOutput(obj, format) {
  switch (format) {
    case "json":
      return JSON.stringify(obj, null, 2);
    case "xml": {
      const builder = new XMLBuilder();
      return builder.build(obj);
    }
    case "yaml":
      return YAML.stringify(obj);
    case "txt":
    case "md":
      return typeof obj === "string" ? obj : String(obj);
    // passthrough
    default:
      throw new Error(`Unsupported format: ${format}`);
  }
}

const DEFAULT_KG_PATH = path.resolve(process.cwd(), "knowledge-graph.json");
async function createKnowledgeGraphFile(kg, filePath = DEFAULT_KG_PATH) {
  await fs__default.writeFile(filePath, stringifyOutput(kg, "json"), "utf-8");
  return filePath;
}
async function readKnowledgeGraphFile(filePath = DEFAULT_KG_PATH) {
  const raw = await fs__default.readFile(filePath, "utf-8");
  return parseInput(raw, "json");
}
function ensureKnowledgeGraphFile(filePath = DEFAULT_KG_PATH) {
  if (!fs__default.existsSync(filePath)) {
    fs__default.writeFileSync(filePath, stringifyOutput({ entities: [], relationships: [] }, "json"), "utf-8");
  }
}

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
function createMastraLlamaIndexTools(...aiFunctionLikeTools) {
  return createMastraTools(...aiFunctionLikeTools);
}
const llamaindex_query_vector_store = {
  id: "llamaindex_query_vector_store",
  description: "Query the LlamaIndex vector store for relevant documents given a query string.",
  inputSchema: z.object({
    query: z.string().describe("The query string to search for relevant documents."),
    topK: z.number().optional().default(5).describe("Number of top results to return.")
  }),
  outputSchema: z.object({
    results: z.array(z.object({
      id: z.string(),
      score: z.number(),
      text: z.string()
    })),
    tokenCount: z.number(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    let tokenCount = 0;
    try {
      const encoder = encodingForModel("o200k_base");
      if (!encoder) {
        throw new Error("Missing encoding/model");
      }
      tokenCount = encoder.encode(typeof context.query === "string" ? context.query : JSON.stringify(context.query)).length;
    } catch (err) {
      return { results: [], tokenCount: 0, success: false, error: "Tokenization failed: " + (err instanceof Error ? err.message : String(err)) };
    }
    try {
      const results = await vectorQuery({ query: context.query, topK: context.topK || 5 });
      const docs = Array.isArray(results) ? results : results?.matches || [];
      return { results: docs, tokenCount, success: true };
    } catch (error) {
      return { results: [], tokenCount, success: false, error: error instanceof Error ? error.message : String(error) };
    }
  },
  // Dummy properties to satisfy AIFunctionLike
  parseInput: (input) => input,
  spec: {
    name: "llamaindex_query_vector_store",
    description: "Query the LlamaIndex vector store for relevant documents given a query string.",
    parameters: zodToJsonSchema(z.object({
      query: z.string().describe("The query string to search for relevant documents."),
      topK: z.number().optional().default(5).describe("Number of top results to return.")
    })),
    // Always JSON Schema
    type: "function",
    strict: true
  }
};
const llamaindex_add_document = {
  id: "llamaindex_add_document",
  description: "Add a document to the LlamaIndex vector store.",
  inputSchema: z.object({
    id: z.string().describe("Unique document ID."),
    text: z.string().describe("Document text to index.")
  }),
  outputSchema: z.object({
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    let tokenCount = 0;
    try {
      const encoder = encodingForModel("o200k_base");
      tokenCount = encoder.encode(context.text).length;
    } catch (err) {
      return { success: false, tokenCount: 0, error: "Tokenization failed: " + (err instanceof Error ? err.message : String(err)) };
    }
    try {
      const vectorTool = createMastraVectorQueryTool({ embeddingProvider: "google" });
      const embeddingResult = await vectorTool.model.doEmbed({ values: [context.text] });
      const realVector = embeddingResult.embeddings[0].embedding;
      await vectorUpsert({ id: context.id, vector: realVector, metadata: { text: context.text } });
      return { success: true, tokenCount };
    } catch (error) {
      return { success: false, tokenCount, error: error instanceof Error ? error.message : String(error) };
    }
  },
  parseInput: (input) => input,
  spec: {
    name: "llamaindex_add_document",
    description: "Add a document to the LlamaIndex vector store.",
    parameters: zodToJsonSchema(z.object({
      id: z.string().describe("Unique document ID."),
      text: z.string().describe("Document text to index.")
    })),
    // Always JSON Schema
    type: "function",
    strict: true
  }
};
const llamaindex_delete_document = {
  id: "llamaindex_delete_document",
  description: "Delete a document from the LlamaIndex vector store.",
  inputSchema: z.object({
    id: z.string().describe("Unique document ID to delete.")
  }),
  outputSchema: z.object({
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    try {
      const kg = await readKnowledgeGraphFile();
      kg.entities = kg.entities.filter((e) => e.id !== context.id);
      kg.relationships = kg.relationships.filter((r) => r.source !== context.id && r.target !== context.id);
      await createKnowledgeGraphFile(kg);
      return { success: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
  },
  parseInput: (input) => input,
  spec: {
    name: "llamaindex_delete_document",
    description: "Delete a document from the LlamaIndex vector store.",
    parameters: zodToJsonSchema(z.object({
      id: z.string().describe("Unique document ID to delete.")
    })),
    // Always JSON Schema
    type: "function",
    strict: true
  }
};
const llamaindex_knowledge_graph_query = {
  id: "llamaindex_knowledge_graph_query",
  description: "Query the LlamaIndex knowledge graph for entities and relationships.",
  inputSchema: z.object({
    query: z.string().describe("The graph query (e.g., Cypher or natural language)."),
    topK: z.number().optional().default(5).describe("Number of top entities/relations to return.")
  }),
  outputSchema: z.object({
    entities: z.array(z.object({
      id: z.string(),
      label: z.string(),
      type: z.string()
    })),
    relationships: z.array(z.object({
      source: z.string(),
      target: z.string(),
      relation: z.string()
    })),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    ensureKnowledgeGraphFile();
    if (context.action === "create") {
      await createKnowledgeGraphFile({ entities: context.entities, relationships: context.relationships });
      return { success: true };
    } else if (context.action === "read") {
      const kg = await readKnowledgeGraphFile();
      return { ...kg, success: true };
    } else if (context.action === "add_entity") {
      const kg = await readKnowledgeGraphFile();
      kg.entities.push(context.entity);
      await createKnowledgeGraphFile(kg);
      return { success: true };
    } else if (context.action === "add_relationship") {
      const kg = await readKnowledgeGraphFile();
      kg.relationships.push(context.relationship);
      await createKnowledgeGraphFile(kg);
      return { success: true };
    } else {
      return { success: false, error: "Unknown knowledge graph action" };
    }
  },
  parseInput: (input) => input,
  spec: {
    name: "llamaindex_knowledge_graph_query",
    description: "Query the LlamaIndex knowledge graph for entities and relationships.",
    parameters: zodToJsonSchema(z.object({
      query: z.string().describe("The graph query (e.g., Cypher or natural language)."),
      topK: z.number().optional().default(5).describe("Number of top entities/relations to return.")
    })),
    // Always JSON Schema
    type: "function",
    strict: true
  }
};
const llamaindex_image_captioning = {
  id: "llamaindex_image_captioning",
  description: "Generate a caption for a given image using LlamaIndex's multimodal capabilities.",
  inputSchema: z.object({
    imageUrl: z.string().url().describe("URL of the image to caption.")
  }),
  outputSchema: z.object({
    caption: z.string(),
    success: z.boolean(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    return { caption: "", success: false, error: "Image captioning not implemented." };
  },
  parseInput: (input) => input,
  spec: {
    name: "llamaindex_image_captioning",
    description: "Generate a caption for a given image using LlamaIndex's multimodal capabilities.",
    parameters: zodToJsonSchema(z.object({
      imageUrl: z.string().url().describe("URL of the image to caption.")
    })),
    // Always JSON Schema
    type: "function",
    strict: true
  }
};
const llamaTools = [
  llamaindex_query_vector_store,
  llamaindex_add_document,
  llamaindex_delete_document,
  llamaindex_knowledge_graph_query,
  llamaindex_image_captioning
];
for (const tool of llamaTools) {
  tool.outputSchema = tool.outputSchema;
}
function makeAIFunctionLike(toolObj) {
  const fn = (input) => toolObj.execute({ context: input });
  fn.inputSchema = toolObj.inputSchema;
  fn.parseInput = toolObj.parseInput;
  fn.spec = toolObj.spec;
  fn.execute = toolObj.execute;
  fn.outputSchema = toolObj.outputSchema;
  return fn;
}
const llamaindexTools = createMastraLlamaIndexTools(
  ...llamaTools.map(makeAIFunctionLike)
);

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

function createAISDKTools(...aiFunctionLikeTools) {
  const fns = new AIFunctionSet(aiFunctionLikeTools);
  return Object.fromEntries(
    fns.map((fn) => [
      fn.spec.name,
      tool({
        description: fn.spec.description,
        parameters: isZodSchema(fn.inputSchema) ? fn.inputSchema : jsonSchema(asAgenticSchema(fn.inputSchema).jsonSchema),
        execute: fn.execute
      })
    ])
  );
}
function createMastraAISDKTools(...aiFunctionLikeTools) {
  return createMastraTools(...aiFunctionLikeTools);
}

const e2b = createAIFunction(
  {
    name: "execute_code",
    description: `
Execute code in a secure E2B sandbox. Supports Python and TypeScript.
- Specify the language ("python" or "typescript").
- Optionally install packages before execution.
- Optionally run shell commands before execution.
- Optionally write files before execution.
- Optionally set environment variables.
- Optionally retrieve output files after execution.
- Optionally set a timeout (ms) for code execution.
- Code can access the internet, filesystem, and install packages.
- Returns stdout, stderr, exit code, results, and output files.
    `.trim(),
    inputSchema: z.object({
      code: z.string().describe("Code to execute."),
      language: z.enum(["python", "typescript"]).default("python"),
      install: z.array(z.string()).optional().describe("Packages to install before running code."),
      files: z.record(z.string(), z.string()).optional().describe("Additional files to write before execution. Keys are file paths, values are file contents."),
      preCommands: z.array(z.string()).optional().describe("Shell commands to run before code execution (e.g., environment setup)."),
      outputFiles: z.array(z.string()).optional().describe("Files to retrieve after execution."),
      env: z.record(z.string(), z.string()).optional().describe("Environment variables for the execution."),
      timeout: z.number().int().optional().describe("Timeout in milliseconds for code execution.")
    })
  },
  async ({ code, language, install, files, preCommands, outputFiles, env, timeout }) => {
    const sandbox = await Sandbox.create({
      apiKey: getEnv("E2B_API_KEY")
    });
    try {
      if (files) {
        for (const [filePath, content] of Object.entries(files)) {
          await sandbox.files.write(filePath, content);
        }
      }
      if (preCommands && preCommands.length > 0) {
        for (const cmd of preCommands) {
          await sandbox.runCode(cmd, { envs: env });
        }
      }
      if (install && install.length > 0) {
        if (language === "python") {
          await sandbox.runCode(`pip install ${install.join(" ")}`, { envs: env });
        } else if (language === "typescript") {
          await sandbox.runCode(`npm install ${install.join(" ")}`, { envs: env });
        }
      }
      let exec;
      if (language === "python") {
        exec = await sandbox.runCode(code, {
          onStderr: (msg) => console.warn("[E2B stderr]", msg),
          onStdout: (msg) => console.log("[E2B stdout]", msg),
          envs: env,
          timeoutMs: timeout
        });
      } else if (language === "typescript") {
        await sandbox.files.write("/main.ts", code);
        await sandbox.runCode("npx tsc /main.ts", { envs: env, timeoutMs: timeout });
        exec = await sandbox.runCode("node /main.js", {
          onStderr: (msg) => console.warn("[E2B stderr]", msg),
          onStdout: (msg) => console.log("[E2B stdout]", msg),
          envs: env,
          timeoutMs: timeout
        });
      } else {
        throw new Error("Unsupported language");
      }
      if (exec.error) {
        throw new Error(exec.error.value || String(exec.error));
      }
      let retrievedFiles = {};
      if (outputFiles && outputFiles.length > 0) {
        for (const file of outputFiles) {
          try {
            retrievedFiles[file] = await sandbox.files.read(file);
          } catch {
            retrievedFiles[file] = null;
          }
        }
      }
      return {
        results: exec.results ? exec.results.map((r) => r.toJSON?.() ?? r) : [],
        stdout: exec.stdout ?? "",
        stderr: exec.stderr ?? "",
        exitCode: exec.exitCode ?? 0,
        outputFiles: retrievedFiles
      };
    } catch (err) {
      return {
        results: [],
        stdout: "",
        stderr: err?.message || String(err),
        exitCode: -1,
        error: true,
        outputFiles: {}
      };
    } finally {
      await sandbox.kill();
    }
  }
);
const E2BOutputSchema = z.object({
  results: z.array(z.any()),
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number(),
  outputFiles: z.record(z.string(), z.string().nullable()),
  error: z.boolean().optional()
});
function createE2BSandboxTool(config = {}) {
  return e2b;
}
function createMastraE2BTools(config = {}) {
  const e2bTool = createE2BSandboxTool(config);
  const mastraTools = createMastraTools(e2bTool);
  if (mastraTools.execute_code) {
    mastraTools.execute_code.outputSchema = E2BOutputSchema;
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
function createLLMChain(promptTemplate, config) {
  const llm = createLangChainModel(config);
  const prompt = PromptTemplate.fromTemplate(promptTemplate);
  return prompt.pipe(llm);
}

const logger$5 = createLogger({ name: "langfuse-service", level: "info" });
const envSchema$1 = z.object({
  LANGFUSE_PUBLIC_KEY: z.string().min(1, "Langfuse public key is required"),
  LANGFUSE_SECRET_KEY: z.string().min(1, "Langfuse secret key is required"),
  LANGFUSE_HOST: z.string().url().optional().default("https://cloud.langfuse.com")
});
function validateEnv() {
  try {
    return envSchema$1.parse(env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const missingKeys = error.errors.filter((e) => e.code === "invalid_type" && e.received === "undefined").map((e) => e.path.join("."));
      if (missingKeys.length > 0) {
        logger$5.error(
          `Missing required environment variables: ${missingKeys.join(", ")}`
        );
      }
    }
    logger$5.error("Langfuse environment validation failed:", { error });
    throw new Error(
      `Langfuse service configuration error: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
const validatedEnv = validateEnv();
function createLangfuseClient() {
  try {
    return new Langfuse({
      publicKey: validatedEnv.LANGFUSE_PUBLIC_KEY,
      secretKey: validatedEnv.LANGFUSE_SECRET_KEY,
      baseUrl: validatedEnv.LANGFUSE_HOST
    });
  } catch (error) {
    logger$5.error("Failed to create Langfuse client:", { error });
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
      logger$5.debug("Creating Langfuse trace", { name, ...options });
      return this.client.trace({ name, ...options });
    } catch (error) {
      logger$5.error("Error creating trace:", { error, name });
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
      logger$5.debug("Creating Langfuse span", { name, ...options });
      return this.client.span({ name, ...options });
    } catch (error) {
      logger$5.error("Error creating span:", { error, name });
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
      logger$5.debug("Logging Langfuse generation", { name, ...options });
      return this.client.generation({ name, ...options });
    } catch (error) {
      logger$5.error("Error logging generation:", { error, name });
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
      logger$5.debug("Creating Langfuse score", options);
      if (!options.traceId && !options.spanId && !options.generationId) {
        throw new Error("At least one of traceId, spanId, or generationId must be provided");
      }
      return this.client.score(options);
    } catch (error) {
      logger$5.error("Error creating score:", { error, name: options.name });
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
      logger$5.debug("Flushed Langfuse events");
    } catch (error) {
      logger$5.error("Error flushing Langfuse events:", { error });
      throw new Error(`Failed to flush Langfuse events: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}
const langfuse = new LangfuseService();

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

async function createMastraMcpTools(config) {
  const mcp = new MCPConfiguration({
    servers: config?.servers ?? {
      mastra: {
        command: "npx",
        args: ["-y", "@mastra/mcp-docs-server@latest"]
      },
      docker: {
        command: "docker",
        args: [
          "run",
          "-i",
          "--rm",
          "alpine/socat",
          "STDIO",
          "TCP:host.docker.internal:8811"
        ]
      },
      "@smithery/toolbox": {
        command: "npx",
        args: [
          "-y",
          "@smithery/cli@latest",
          "run",
          "@smithery/toolbox",
          "--key",
          "be98d3d0-f628-45e5-a532-cc4ade91164c"
        ]
      }
    },
    timeout: config?.timeout ?? 3e4
  });
  return await mcp.getTools();
}

const github = new GithubIntegration({
  config: {
    PERSONAL_ACCESS_TOKEN: process.env.GITHUB_PAT
  }
});

const logger$4 = createLogger({ name: "evals", level: "info" });
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
      logger$4.info("Faithfulness eval result", { score, explanation, response: context.response });
      return { score, explanation, success: true };
    } catch (error) {
      signoz.recordMetrics(span, { latencyMs: performance.now() - startTime, status: "error", errorMessage: error instanceof Error ? error.message : String(error) });
      span.end();
      logger$4.error("Faithfulness eval error", { error });
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
      logger$4.info("Bias eval result", { score, explanation, response: context.response });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      span.end();
      logger$4.error("Bias eval error", { error });
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
      logger$4.info("Toxicity eval result", { score, explanation, response: context.response });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      span.end();
      logger$4.error("Toxicity eval error", { error });
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
      logger$4.info("Hallucination eval result", { score, explanation, response: context.response });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      span.end();
      logger$4.error("Hallucination eval error", { error });
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
      logger$4.info("Summarization eval result", { score, explanation, summary: context.summary });
      span.end();
      return { score, explanation, success: true };
    } catch (error) {
      span.end();
      logger$4.error("Summarization eval error", { error });
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
var _cryptoTickers_dec, _cryptoPrice_dec, _cryptoAggregates_dec, _tickerPreviousClose_dec, _tickerAggregates_dec, _tickerNews_dec, _tickerDetails_dec, _a$1, _init$1;
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
}).partial();
const TickerNewsSchema = z.object({
  results: z.array(z.object({
    id: z.string(),
    publisher: z.object({
      name: z.string(),
      homepage_url: z.string().optional(),
      logo_url: z.string().optional(),
      favicon_url: z.string().optional()
    }),
    title: z.string(),
    author: z.string().optional(),
    published_utc: z.string(),
    article_url: z.string(),
    tickers: z.array(z.string()),
    description: z.string().optional(),
    keywords: z.array(z.string()).optional(),
    image_url: z.string().optional()
  })),
  status: z.string(),
  request_id: z.string(),
  count: z.number().optional()
});
const TickerAggregatesSchema = z.object({
  results: z.array(z.object({
    v: z.number(),
    // Volume
    vw: z.number(),
    // Volume weighted
    o: z.number(),
    // Open
    c: z.number(),
    // Close
    h: z.number(),
    // High
    l: z.number(),
    // Low
    t: z.number(),
    // Timestamp (ms)
    n: z.number()
    // Number of transactions
  })),
  ticker: z.string(),
  status: z.string(),
  queryCount: z.number(),
  resultsCount: z.number(),
  adjusted: z.boolean(),
  request_id: z.string(),
  count: z.number()
});
const PreviousCloseSchema = z.object({
  ticker: z.string(),
  status: z.string(),
  adjusted: z.boolean().optional(),
  queryCount: z.number().optional(),
  resultsCount: z.number().optional(),
  request_id: z.string().optional(),
  results: z.array(z.object({
    v: z.number(),
    // Volume
    vw: z.number(),
    // Volume weighted
    o: z.number(),
    // Open
    c: z.number(),
    // Close
    h: z.number(),
    // High
    l: z.number(),
    // Low
    t: z.number(),
    // Timestamp (ms)
    n: z.number()
    // Number of transactions
  }))
});
const CryptoAggregatesSchema = z.object({
  results: z.array(z.object({
    v: z.number(),
    // Volume
    vw: z.number(),
    // Volume weighted
    o: z.number(),
    // Open
    c: z.number(),
    // Close
    h: z.number(),
    // High
    l: z.number(),
    // Low
    t: z.number(),
    // Timestamp (ms)
    n: z.number()
    // Number of transactions
  })),
  ticker: z.string(),
  status: z.string(),
  queryCount: z.number(),
  resultsCount: z.number(),
  adjusted: z.boolean().optional(),
  request_id: z.string(),
  count: z.number()
});
const CryptoTickersSchema = z.object({
  results: z.array(z.object({
    ticker: z.string(),
    name: z.string().optional(),
    market: z.string().optional(),
    locale: z.string().optional(),
    active: z.boolean().optional(),
    currency_name: z.string().optional(),
    base_currency_symbol: z.string().optional(),
    base_currency_name: z.string().optional(),
    quote_currency_symbol: z.string().optional(),
    quote_currency_name: z.string().optional(),
    updated_utc: z.string().optional()
  })),
  status: z.string(),
  request_id: z.string(),
  count: z.number().optional()
});
class MastraPolygonClient extends (_a$1 = AIFunctionsProvider, _tickerDetails_dec = [aiFunction({
  name: "tickerDetails",
  description: "Get details for a given stock ticker symbol using Polygon.io.",
  inputSchema: z.object({
    ticker: z.string().describe("The stock ticker symbol (e.g., AAPL, MSFT)")
  })
})], _tickerNews_dec = [aiFunction({
  name: "tickerNews",
  description: "Get recent news articles for a given stock ticker symbol using Polygon.io.",
  inputSchema: z.object({
    ticker: z.string().describe("The stock ticker symbol (e.g., AAPL, MSFT)"),
    limit: z.number().int().min(1).max(50).default(10).optional()
  })
})], _tickerAggregates_dec = [aiFunction({
  name: "tickerAggregates",
  description: "Get daily OHLCV (open, high, low, close, volume) aggregates for a ticker and date range.",
  inputSchema: z.object({
    ticker: z.string().describe("The stock ticker symbol (e.g., AAPL, MSFT)"),
    from: z.string().describe("Start date (YYYY-MM-DD)"),
    to: z.string().describe("End date (YYYY-MM-DD)"),
    adjusted: z.boolean().optional().default(true),
    limit: z.number().int().min(1).max(5e3).optional()
  })
})], _tickerPreviousClose_dec = [aiFunction({
  name: "tickerPreviousClose",
  description: "Get the previous day's open, high, low, and close (OHLC) for a given stock ticker symbol using Polygon.io.",
  inputSchema: z.object({
    ticker: z.string().describe("The stock ticker symbol (e.g., AAPL, MSFT)")
  })
})], _cryptoAggregates_dec = [aiFunction({
  name: "cryptoAggregates",
  description: "Get daily OHLCV (open, high, low, close, volume) aggregates for a crypto pair and date range.",
  inputSchema: z.object({
    from: z.string().describe("Crypto symbol (e.g., BTC)"),
    to: z.string().describe("Quote currency (e.g., USD)"),
    start: z.string().describe("Start date (YYYY-MM-DD)"),
    end: z.string().describe("End date (YYYY-MM-DD)"),
    limit: z.number().int().min(1).max(5e3).optional()
  })
})], _cryptoPrice_dec = [aiFunction({
  name: "cryptoPrice",
  description: "Get the most recent daily closing price for a crypto pair (e.g., BTC-USD) using Polygon.io.",
  inputSchema: z.object({
    from: z.string().describe("Crypto symbol (e.g., BTC)"),
    to: z.string().describe("Quote currency (e.g., USD)")
  })
})], _cryptoTickers_dec = [aiFunction({
  name: "cryptoTickers",
  description: "List all supported crypto tickers from Polygon.io.",
  inputSchema: z.object({
    search: z.string().optional().describe("Search query for filtering tickers"),
    limit: z.number().int().min(1).max(1e3).optional()
  })
})], _a$1) {
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
  async tickerNews({ ticker, limit }) {
    try {
      const news = await this.client.tickerNews({ ticker, limit });
      return news;
    } catch (error) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching ticker news."
      };
    }
  }
  async tickerAggregates({
    ticker,
    from,
    to,
    adjusted = true,
    limit
  }) {
    try {
      const aggregates = await this.client.aggregates({
        ticker,
        multiplier: 1,
        timespan: "day",
        from,
        to,
        adjusted,
        limit
      });
      return aggregates;
    } catch (error) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching ticker aggregates."
      };
    }
  }
  async tickerPreviousClose({ ticker }) {
    try {
      const prevCloseData = await this.client.previousClose(ticker);
      return prevCloseData;
    } catch (error) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching ticker price."
      };
    }
  }
  async cryptoAggregates({
    from,
    to,
    start,
    end,
    limit
  }) {
    try {
      const ticker = `X:${from}${to}`;
      const aggregates = await this.client.aggregates({
        ticker,
        multiplier: 1,
        timespan: "day",
        from: start,
        to: end,
        limit
      });
      return aggregates;
    } catch (error) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching crypto aggregates."
      };
    }
  }
  async cryptoPrice({ from, to }) {
    try {
      const ticker = `X:${from}${to}`;
      const today = /* @__PURE__ */ new Date();
      const yesterday = new Date(today);
      yesterday.setDate(today.getDate() - 1);
      const toDateStr = today.toISOString().split("T")[0];
      const fromDateStr = yesterday.toISOString().split("T")[0];
      const aggregates = await this.client.aggregates({
        ticker,
        multiplier: 1,
        timespan: "day",
        from: fromDateStr,
        to: toDateStr,
        limit: 2
        // Get up to two bars (yesterday and today)
      });
      const latestBar = aggregates.results?.sort((a, b) => b.t - a.t)[0];
      if (latestBar) {
        return {
          symbol: `${from}-${to}`,
          price: latestBar.c,
          // Use the closing price
          volume: latestBar.v,
          timestamp: latestBar.t
        };
      } else {
        return {
          error: true,
          message: `No recent price data found for ${from}-${to}.`
        };
      }
    } catch (error) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching crypto price."
      };
    }
  }
  async cryptoTickers({ search, limit }) {
    try {
      const params = { market: "crypto" };
      if (search) params.search = search;
      if (limit) params.limit = limit;
      const result = await this.client.tickers(params);
      return result;
    } catch (error) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching crypto tickers."
      };
    }
  }
  // @aiFunction({
  //   name: "cryptoSnapshotAll",
  //   description: "Get snapshot data for all supported crypto tickers from Polygon.io.",
  //   inputSchema: z.object({}),
  // })
  // async cryptoSnapshotAll() {
  //   try {
  //     // TODO: Implement using direct API call if needed, client doesn't support this.
  //     // const result = await this.client.cryptoSnapshotAll();
  //     // return result;
  //     throw new Error("cryptoSnapshotAll is not implemented in the underlying client.");
  //   } catch (error: any) {
  //     return {
  //       error: true,
  //       message: error?.message || "Unknown error fetching crypto snapshot (all).",
  //     };
  //   }
  // }
  // @aiFunction({
  //   name: "cryptoSnapshotTicker",
  //   description: "Get snapshot data for a single crypto ticker from Polygon.io.",
  //   inputSchema: z.object({
  //     ticker: z.string().describe("The crypto ticker symbol (e.g., X:BTCUSD)"),
  //   }),
  // })
  // async cryptoSnapshotTicker({ ticker }: { ticker: string }) {
  //   try {
  //     // TODO: Implement using direct API call if needed, client doesn't support this.
  //     // const result = await this.client.cryptoSnapshotTicker({ ticker });
  //     // return result;
  //      throw new Error("cryptoSnapshotTicker is not implemented in the underlying client.");
  //   } catch (error: any) {
  //     return {
  //       error: true,
  //       message: error?.message || "Unknown error fetching crypto snapshot (ticker).",
  //     };
  //   }
  // }
}
_init$1 = __decoratorStart$1(_a$1);
__decorateElement$1(_init$1, 1, "tickerDetails", _tickerDetails_dec, MastraPolygonClient);
__decorateElement$1(_init$1, 1, "tickerNews", _tickerNews_dec, MastraPolygonClient);
__decorateElement$1(_init$1, 1, "tickerAggregates", _tickerAggregates_dec, MastraPolygonClient);
__decorateElement$1(_init$1, 1, "tickerPreviousClose", _tickerPreviousClose_dec, MastraPolygonClient);
__decorateElement$1(_init$1, 1, "cryptoAggregates", _cryptoAggregates_dec, MastraPolygonClient);
__decorateElement$1(_init$1, 1, "cryptoPrice", _cryptoPrice_dec, MastraPolygonClient);
__decorateElement$1(_init$1, 1, "cryptoTickers", _cryptoTickers_dec, MastraPolygonClient);
__decoratorMetadata$1(_init$1, MastraPolygonClient);
function createMastraPolygonTools(config = {}) {
  const apiKey = config.apiKey ?? getEnv("POLYGON_API_KEY");
  if (!apiKey) throw new Error("POLYGON_API_KEY is required in env or config");
  const polygonClient = new MastraPolygonClient({ apiKey });
  const mastraTools = createMastraTools(polygonClient);
  if (mastraTools.tickerDetails) {
    mastraTools.tickerDetails.outputSchema = TickerDetailsSchema;
  }
  if (mastraTools.tickerNews) {
    mastraTools.tickerNews.outputSchema = TickerNewsSchema;
  }
  if (mastraTools.tickerAggregates) {
    mastraTools.tickerAggregates.outputSchema = TickerAggregatesSchema;
  }
  if (mastraTools.cryptoTickers) {
    mastraTools.cryptoTickers.outputSchema = CryptoTickersSchema;
  }
  if (mastraTools.tickerPreviousClose) {
    mastraTools.tickerPreviousClose.outputSchema = PreviousCloseSchema;
  }
  if (mastraTools.cryptoAggregates) {
    mastraTools.cryptoAggregates.outputSchema = CryptoAggregatesSchema;
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

const logger$3 = createLogger({ name: "puppeteer", level: "debug" });
logger$3.info("Initializing Puppeteer tool for web navigation and screenshotting.");
const SCREENSHOT_DIR = path.resolve(process.cwd(), "puppeteer_screenshots");
function generateScreenshotFilename$1(url) {
  const timestamp = (/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-");
  const urlHash = crypto.createHash("md5").update(url).digest("hex").substring(0, 8);
  return `screenshot_${urlHash}_${timestamp}.png`;
}
const ClickActionSchema$1 = z.object({
  type: z.literal("click"),
  selector: z.string().describe("CSS selector for the element to click."),
  waitForNavigation: z.boolean().optional().default(false).describe("Wait for navigation to complete after the click.")
});
const TypeActionSchema$1 = z.object({
  type: z.literal("type"),
  selector: z.string().describe("CSS selector for the input field."),
  text: z.string().describe("Text to type into the field."),
  delay: z.number().optional().default(50).describe("Delay between keystrokes in milliseconds.")
});
const ScrapeActionSchema$1 = z.object({
  type: z.literal("scrape"),
  selector: z.string().describe("CSS selector for the element(s) to scrape."),
  attribute: z.string().optional().describe("Optional attribute to extract (e.g., 'href', 'src'). If omitted, extracts text content."),
  multiple: z.boolean().optional().default(false).describe("Whether to scrape multiple matching elements.")
});
const WaitForSelectorActionSchema$1 = z.object({
  type: z.literal("waitForSelector"),
  selector: z.string().describe("CSS selector to wait for."),
  timeout: z.number().optional().default(3e4).describe("Maximum time to wait in milliseconds.")
});
const ScrollActionSchema$1 = z.object({
  type: z.literal("scroll"),
  direction: z.enum(["down", "up", "bottom", "top"]).describe("Direction to scroll."),
  amount: z.number().optional().describe("Pixel amount to scroll (for 'down'/'up'). Defaults to window height/width."),
  selector: z.string().optional().describe("Optional selector to scroll within or to.")
  // Scroll within an element or scroll element into view
});
const HoverActionSchema$1 = z.object({
  type: z.literal("hover"),
  selector: z.string().describe("CSS selector for the element to hover over.")
});
const SelectActionSchema$1 = z.object({
  type: z.literal("select"),
  selector: z.string().describe("CSS selector for the <select> element."),
  value: z.string().describe("The value of the <option> to select.")
});
const WaitActionSchema$1 = z.object({
  type: z.literal("wait"),
  duration: z.number().int().min(1).describe("Duration to wait in milliseconds.")
});
const EvaluateActionSchema$1 = z.object({
  type: z.literal("evaluate"),
  script: z.string().describe("JavaScript code to execute in the page context. Use 'return' to output data.")
});
const ActionSchema$1 = z.discriminatedUnion("type", [
  ClickActionSchema$1,
  TypeActionSchema$1,
  ScrapeActionSchema$1,
  WaitForSelectorActionSchema$1,
  ScrollActionSchema$1,
  HoverActionSchema$1,
  SelectActionSchema$1,
  WaitActionSchema$1,
  EvaluateActionSchema$1
]);
const PuppeteerOutputSchema = z.object({
  url: z.string().url().describe("The final URL after navigation and actions."),
  pageTitle: z.string().optional().describe("The title of the web page after actions."),
  scrapedData: z.array(z.any()).optional().describe("Data scraped or returned by evaluate actions."),
  screenshotPath: z.string().optional().describe("Absolute path to the saved screenshot file, if taken."),
  success: z.boolean().describe("Whether the overall operation was successful."),
  error: z.string().optional().describe("Error message if the operation failed.")
});
const PuppeteerInputSchema = z.object({
  url: z.string().url().describe("The initial URL of the web page to navigate to."),
  screenshot: z.boolean().optional().default(false).describe("Whether to take a full-page screenshot at the end."),
  initialWaitForSelector: z.string().optional().describe("A CSS selector to wait for after initial navigation."),
  actions: z.array(ActionSchema$1).optional().describe("A sequence of actions to perform on the page.")
});
const puppeteerTool = createTool({
  id: "puppeteer_web_automator",
  description: "Navigates to a web page using Puppeteer, performs a sequence of actions (click, type, scrape, wait), optionally takes a screenshot, and returns page information and scraped data.",
  inputSchema: PuppeteerInputSchema,
  outputSchema: PuppeteerOutputSchema,
  execute: async (executionContext) => {
    const { context: input} = executionContext;
    const span = createAISpan("puppeteer_tool_execution", {
      "tool.id": "puppeteer_web_automator",
      "input.url": input.url,
      "input.actions_count": input.actions?.length ?? 0,
      "input.screenshot_requested": input.screenshot ?? false
    });
    let browser = null;
    const output = {
      url: input.url,
      success: false,
      scrapedData: []
    };
    const startTime = Date.now();
    try {
      logger$3.info(`Starting Puppeteer automation for URL: ${input.url}`);
      span.addEvent("Automation started", { url: input.url });
      if (input.screenshot) {
        await fs__default.ensureDir(SCREENSHOT_DIR);
        logger$3.debug(`Ensured screenshot directory exists: ${SCREENSHOT_DIR}`);
      }
      browser = await puppeteer.launch({
        headless: true,
        args: ["--no-sandbox", "--disable-setuid-sandbox"]
      });
      logger$3.debug("Puppeteer browser launched.");
      const page = await browser.newPage();
      logger$3.debug("New page created.");
      await page.setViewport({ width: 1280, height: 800 });
      logger$3.debug("Viewport set.");
      logger$3.info(`Navigating to ${input.url}...`);
      await page.goto(input.url, { waitUntil: "networkidle2", timeout: 6e4 });
      output.url = page.url();
      span.setAttribute("navigation.final_url", output.url);
      logger$3.info(`Navigation complete. Current URL: ${output.url}`);
      if (input.initialWaitForSelector) {
        logger$3.info(`Waiting for initial selector: ${input.initialWaitForSelector}`);
        await page.waitForSelector(input.initialWaitForSelector, { timeout: 3e4 });
        logger$3.debug(`Initial selector found: ${input.initialWaitForSelector}`);
      }
      if (input.actions && input.actions.length > 0) {
        logger$3.info(`Executing ${input.actions.length} actions...`);
        span.addEvent("Executing actions", { count: input.actions.length });
        for (const [index, action] of input.actions.entries()) {
          logger$3.debug(`Executing action ${index + 1}: ${action.type}`);
          try {
            switch (action.type) {
              case "click":
                logger$3.info(`Clicking element: ${action.selector}`);
                const clickPromise = page.click(action.selector);
                if (action.waitForNavigation) {
                  logger$3.debug("Waiting for navigation after click...");
                  await Promise.all([clickPromise, page.waitForNavigation({ waitUntil: "networkidle2", timeout: 6e4 })]);
                  output.url = page.url();
                  logger$3.info(`Navigation after click complete. New URL: ${output.url}`);
                } else {
                  await clickPromise;
                }
                logger$3.debug(`Clicked element: ${action.selector}`);
                break;
              case "type":
                logger$3.info(`Typing into element: ${action.selector}`);
                await page.type(action.selector, action.text, { delay: action.delay });
                logger$3.debug(`Typed text into: ${action.selector}`);
                break;
              case "scrape":
                logger$3.info(`Scraping element(s): ${action.selector}` + (action.attribute ? ` [Attribute: ${action.attribute}]` : " [Text Content]"));
                let scrapedItems = [];
                if (action.multiple) {
                  scrapedItems = await page.$$eval(
                    action.selector,
                    (elements, attr) => elements.map((el) => attr ? el.getAttribute(attr) : el.textContent?.trim() ?? null),
                    action.attribute
                  );
                } else {
                  const scrapedItem = await page.$eval(
                    action.selector,
                    (element, attr) => attr ? element.getAttribute(attr) : element.textContent?.trim() ?? null,
                    action.attribute
                  ).catch(() => null);
                  if (scrapedItem !== null) {
                    scrapedItems = [scrapedItem];
                  }
                }
                output.scrapedData = [...output.scrapedData ?? [], ...scrapedItems];
                logger$3.debug(`Scraped ${scrapedItems.length} items. Total scraped: ${output.scrapedData?.length}`);
                break;
              case "waitForSelector":
                logger$3.info(`Waiting for selector: ${action.selector} (Timeout: ${action.timeout}ms)`);
                await page.waitForSelector(action.selector, { timeout: action.timeout });
                logger$3.debug(`Selector found: ${action.selector}`);
                break;
              case "scroll":
                logger$3.info(`Scrolling ${action.direction}` + (action.selector ? ` within/to ${action.selector}` : " window"));
                await page.evaluate(async (options) => {
                  const element = options.selector ? document.querySelector(options.selector) : window;
                  if (!element) throw new Error(`Scroll target not found: ${options.selector}`);
                  const scrollAmount = options.amount ?? (options.direction === "down" || options.direction === "up" ? window.innerHeight : window.innerWidth);
                  const target = options.selector && element !== window ? element : document.scrollingElement || document.documentElement;
                  switch (options.direction) {
                    case "down":
                      target.scrollTop += scrollAmount;
                      break;
                    case "up":
                      target.scrollTop -= scrollAmount;
                      break;
                    case "bottom":
                      if (options.selector && element instanceof Element) {
                        element.scrollTop = element.scrollHeight;
                      } else {
                        target.scrollTop = target.scrollHeight;
                      }
                      break;
                    case "top":
                      if (options.selector && element instanceof Element) {
                        element.scrollTop = 0;
                      } else {
                        target.scrollTop = 0;
                      }
                      break;
                  }
                  await new Promise((resolve) => setTimeout(resolve, 100));
                }, action);
                logger$3.debug(`Scrolled ${action.direction}.`);
                break;
              case "hover":
                logger$3.info(`Hovering over element: ${action.selector}`);
                await page.hover(action.selector);
                logger$3.debug(`Hovered over: ${action.selector}`);
                break;
              case "select":
                logger$3.info(`Selecting option [value=${action.value}] in dropdown: ${action.selector}`);
                await page.select(action.selector, action.value);
                logger$3.debug(`Selected option in: ${action.selector}`);
                break;
              case "wait":
                logger$3.info(`Waiting for ${action.duration}ms`);
                await new Promise((resolve) => setTimeout(resolve, action.duration));
                logger$3.debug("Wait complete.");
                break;
              case "evaluate":
                logger$3.info(`Evaluating script...`);
                const result = await page.evaluate(action.script);
                if (result !== void 0) {
                  output.scrapedData = [...output.scrapedData ?? [], result];
                  logger$3.debug(`Script evaluated. Result added to scrapedData. Total scraped: ${output.scrapedData?.length}`);
                } else {
                  logger$3.debug(`Script evaluated. No return value.`);
                }
                break;
              default:
                logger$3.error("Unsupported action type encountered", { action });
                throw new Error(`Unsupported action type encountered: ${JSON.stringify(action)}`);
            }
          } catch (actionError) {
            const errorMsg = `Error during action ${index + 1} (${action.type}): ${actionError.message}`;
            logger$3.error(errorMsg, actionError);
            throw new Error(errorMsg);
          }
        }
        logger$3.info("All actions executed.");
        span.addEvent("Actions completed");
      }
      output.pageTitle = await page.title();
      logger$3.debug(`Final page title: ${output.pageTitle}`);
      if (input.screenshot) {
        const filename = generateScreenshotFilename$1(output.url);
        const screenshotPath = path.join(SCREENSHOT_DIR, filename);
        await page.screenshot({ path: screenshotPath, fullPage: true });
        output.screenshotPath = screenshotPath;
      }
      output.success = true;
      logger$3.info("Puppeteer automation completed successfully.");
      span.setAttribute("output.scraped_count", output.scrapedData?.length ?? 0);
      recordMetrics(span, {
        status: "success",
        latencyMs: Date.now() - startTime
        // 'output.scraped_count' is now a span attribute, not a metric
      });
    } catch (error) {
      logger$3.error(`Puppeteer tool error: ${error.message}`, error);
      output.error = error instanceof Error ? error.message : String(error);
      output.success = false;
      recordMetrics(span, {
        status: "error",
        errorMessage: output.error,
        latencyMs: Date.now() - startTime
      });
      span.recordException(error);
    } finally {
      if (browser) {
        await browser.close();
        logger$3.info("Browser closed.");
        span.addEvent("Browser closed");
      }
      span.end();
    }
    return output;
  }
});

const math = create(all);
const calculatorTool = createTool({
  id: "calculator",
  description: "Performs advanced mathematical calculations (arithmetic, algebra, functions, constants, etc.) and returns a human-readable answer.",
  inputSchema: z.object({
    expression: z.string().describe("Mathematical expression to evaluate. Supports arithmetic, functions, constants, parentheses, etc.")
  }),
  outputSchema: z.object({
    result: z.number().or(z.string()),
    answer: z.string().describe("A human-readable answer to present to the user."),
    steps: z.array(z.string()).optional(),
    error: z.string().optional()
  }),
  execute: async ({ context }) => {
    try {
      const { expression } = context;
      const result = math.evaluate(expression);
      let steps = [];
      try {
        const node = math.parse(expression);
        if (["OperatorNode", "ParenthesisNode", "FunctionNode"].includes(node.type)) {
          steps.push(`Parsed: ${node.toString()}`);
          steps.push(`LaTeX: ${node.toTex()}`);
          if (node.type === "OperatorNode" && Array.isArray(node.args) && node.args.length === 2) {
            steps.push(`Left: ${node.args[0].toString()}`);
            steps.push(`Right: ${node.args[1].toString()}`);
          }
        }
      } catch {
      }
      const answer = `The result of ${expression} is ${result}.`;
      return {
        result,
        answer,
        steps
      };
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Unknown error";
      return {
        result: NaN,
        answer: `Sorry, I couldn't calculate that expression. (${errorMsg})`,
        error: errorMsg
      };
    }
  }
});

const logger$2 = createLogger({ name: "llm-chain-tool", level: "info" });
function createAiSdkModel(config = {}) {
  switch (config.provider || "google") {
    case "openai": {
      const modelName = config.modelName || "gpt-4o";
      return openai.chat(modelName, {});
    }
    case "google": {
      const modelName = config.modelName || env.MODEL || "models/gemini-2.0-flash";
      return google(modelName, {});
    }
    case "anthropic": {
      const modelName = config.modelName || "claude-3-sonnet-20240229";
      return anthropic(modelName, {});
    }
    default:
      throw new Error(`Unsupported provider: ${config.provider}`);
  }
}
const llmChainInputSchema = z.object({
  promptTemplate: z.string().describe("The prompt template with {variables} to replace"),
  variables: z.record(z.string()).describe("Key-value pairs to substitute in the template"),
  provider: z.enum(["openai", "google", "anthropic"]).optional().describe("LLM provider to use"),
  modelName: z.string().optional().describe("Specific model name to use"),
  temperature: z.number().min(0).max(1).optional().describe("Creativity temperature (0-1)"),
  maxTokens: z.number().optional().describe("Maximum tokens in response"),
  useLangChain: z.boolean().optional().default(false).describe("Whether to use LangChain (true) or AI SDK (false)")
});
const llmChainTool = createAIFunction(
  {
    name: "llm-chain",
    description: "Runs an LLM chain with a prompt template and variables",
    inputSchema: llmChainInputSchema
  },
  async (context) => {
    const startTime = Date.now();
    const runId = await createLangSmithRun("llm-chain-tool", [
      "llm-chain",
      context.provider || "default"
    ]);
    try {
      const {
        promptTemplate,
        variables,
        provider = "google",
        modelName,
        temperature,
        maxTokens,
        useLangChain = false
      } = context;
      const llmConfig = {
        provider,
        modelName,
        temperature,
        maxTokens,
        enableTracing: true
      };
      let result;
      if (useLangChain) {
        const chain = createLLMChain(promptTemplate, llmConfig);
        const response = await chain.invoke(variables);
        result = String(response);
      } else {
        const model = createAiSdkModel(llmConfig);
        let prompt = promptTemplate;
        for (const [key, value] of Object.entries(variables)) {
          prompt = prompt.replace(new RegExp(`{${key}}`, "g"), String(value));
        }
        const messages = [{ role: "user", content: prompt }];
        let response;
        if (provider === "openai") {
          const openAIModel = model;
          response = await openAIModel.chat({ messages });
          result = response.content;
        } else if (provider === "anthropic") {
          const anthropicModel = model;
          response = await anthropicModel.messages({ messages });
          result = response.content;
        } else {
          const googleModel = model;
          response = await googleModel.generateContent({
            contents: [{ role: "user", text: prompt }]
          });
          result = response.text;
        }
      }
      const elapsedTimeMs = Date.now() - startTime;
      await trackFeedback(runId, {
        score: 1,
        comment: `Successfully executed LLM chain in ${elapsedTimeMs}ms`,
        key: "llm_chain_success"
      });
      return {
        result,
        success: true,
        metadata: {
          provider,
          model: modelName || (provider === "google" ? "gemini" : provider === "openai" ? "gpt-4o" : "claude"),
          elapsedTimeMs
        }
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("LLM chain execution error:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: errorMessage,
        key: "llm_chain_failure"
      });
      return {
        result: "",
        success: false,
        metadata: {
          provider: context.provider || "unknown",
          model: context.modelName || "unknown",
          elapsedTimeMs: Date.now() - startTime
        },
        error: errorMessage
      };
    }
  }
);
console.log("llmChainTool:", llmChainTool);
logger$2.info("Registered llmChainTool", { tool: llmChainTool });
const aiSdkPromptInputSchema = z.object({
  prompt: z.string().describe("The prompt to send to the model"),
  provider: z.enum(["openai", "google", "anthropic"]).optional().describe("LLM provider to use"),
  modelName: z.string().optional().describe("Specific model name to use"),
  temperature: z.number().min(0).max(1).optional().describe("Creativity temperature (0-1)"),
  maxTokens: z.number().optional().describe("Maximum tokens in response"),
  schema: z.record(z.any()).optional().describe("JSON schema for structured output"),
  systemPrompt: z.string().optional().describe("System prompt to use"),
  history: z.array(
    z.object({
      role: z.enum(["user", "assistant", "system"]),
      content: z.string()
    })
  ).optional().describe("Conversation history"),
  // Add threadId and resourceId to the input schema if they are needed by the execute logic
  threadId: z.string().optional().describe("Execution thread ID"),
  resourceId: z.string().optional().describe("Resource ID for observability")
});
const aiSdkPromptTool = createAIFunction(
  {
    name: "ai-sdk-prompt",
    description: "Runs a prompt through AI SDK with structured output support",
    inputSchema: aiSdkPromptInputSchema
  },
  async (context) => {
    const startTime = Date.now();
    const runId = await createLangSmithRun("ai-sdk-prompt-tool", [
      "ai-sdk",
      context.provider || "default"
    ]);
    const executionThreadId = context.threadId;
    const resourceId = context.resourceId;
    try {
      const {
        prompt,
        provider = "google",
        modelName,
        schema,
        systemPrompt,
        history = []
      } = context;
      const llmConfig = {
        provider,
        modelName};
      const model = createAiSdkModel(llmConfig);
      const messages = [];
      if (systemPrompt) {
        messages.push({ role: "system", content: systemPrompt });
      }
      if (history.length > 0) {
        messages.push(...history);
      }
      messages.push({ role: "user", content: prompt });
      let text;
      let structured = void 0;
      let response;
      if (provider === "openai") {
        const options = { messages };
        if (executionThreadId) {
          options.thread_id = executionThreadId;
        }
        if (resourceId) {
          options.metadata = {
            ...options.metadata || {},
            resourceId
          };
        }
        if (schema) {
          options.tools = [
            {
              type: "function",
              function: {
                name: "output_formatter",
                description: "Format output according to schema",
                parameters: schema
              }
            }
          ];
          options.tool_choice = {
            type: "function",
            function: { name: "output_formatter" }
          };
        }
        const openAIModel = model;
        response = await openAIModel.chat(options);
        if (schema && response.tool_calls?.length > 0) {
          try {
            structured = JSON.parse(response.tool_calls[0].function.arguments);
            text = JSON.stringify(structured, null, 2);
          } catch (e) {
            console.warn("Failed to parse OpenAI tool call response:", e);
            text = response.content || "";
          }
        } else {
          text = response.content || "";
        }
      } else if (provider === "anthropic") {
        const options = { messages };
        if (executionThreadId) {
          options.threadId = executionThreadId;
        }
        if (resourceId) {
          options.metadata = {
            ...options.metadata || {},
            resourceId
          };
        }
        if (schema) {
          options.tools = [
            {
              name: "output_formatter",
              description: "Format output according to schema",
              parameters: schema
            }
          ];
          options.tool_choice = {
            type: "function",
            function: { name: "output_formatter" }
          };
          const anthropicModel = model;
          response = await anthropicModel.messages(options);
          if (response.tool_calls && response.tool_calls.length > 0) {
            try {
              structured = JSON.parse(
                response.tool_calls[0].function.arguments
              );
              text = JSON.stringify(structured, null, 2);
            } catch (e) {
              console.warn("Failed to parse Claude tool call response:", e);
              text = response.content || "";
            }
          } else {
            text = response.content || "";
          }
        } else {
          const anthropicModel = model;
          response = await anthropicModel.messages(options);
          text = response.content || "";
        }
      } else {
        const options = {
          contents: messages.map((m) => ({
            role: m.role,
            parts: [{ text: m.content }]
          }))
        };
        if (executionThreadId) {
          options.threadId = executionThreadId;
        }
        if (resourceId) {
          options.metadata = {
            ...options.metadata || {},
            resourceId
          };
        }
        if (schema) {
          options.tools = [
            {
              functionDeclarations: [
                {
                  name: "output_formatter",
                  description: "Format output according to schema",
                  parameters: schema
                }
              ]
            }
          ];
          options.toolConfig = {
            functionCallingConfig: {
              mode: "AUTO",
              allowedFunctionNames: ["output_formatter"]
            }
          };
        }
        const googleModel = model;
        response = await googleModel.generateContent(options);
        if (schema && response.candidates && response.candidates[0]?.content?.parts?.length > 0) {
          const functionCallPart = response.candidates[0].content.parts.find(
            (part) => part.functionCall
          );
          if (functionCallPart?.functionCall) {
            try {
              structured = JSON.parse(functionCallPart.functionCall.args);
              text = JSON.stringify(structured, null, 2);
            } catch (e) {
              console.warn("Failed to parse Google function call response:", e);
              text = response.text || "";
            }
          } else {
            text = response.text || "";
          }
        } else if (response.candidates?.[0]?.content?.parts?.[0]?.text) {
          text = response.candidates[0].content.parts[0].text;
        } else {
          text = response.text || "";
        }
      }
      const elapsedTimeMs = Date.now() - startTime;
      await trackFeedback(runId, {
        score: 1,
        comment: `Successfully executed AI SDK prompt in ${elapsedTimeMs}ms`,
        key: "ai_sdk_success"
      });
      return {
        text,
        structured,
        success: true,
        metadata: {
          provider,
          model: modelName || (provider === "google" ? "gemini" : provider === "openai" ? "gpt-4o" : "claude"),
          elapsedTimeMs
        }
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      console.error("AI SDK prompt execution error:", error);
      await trackFeedback(runId, {
        score: 0,
        comment: errorMessage,
        key: "ai_sdk_failure"
      });
      return {
        text: "",
        success: false,
        metadata: {
          provider: context.provider || "unknown",
          model: context.modelName || "unknown",
          elapsedTimeMs: Date.now() - startTime
        },
        error: errorMessage
      };
    }
  }
);
const LLMChainOutputSchema = z.object({
  result: z.string().describe("The final string output from the LLM chain."),
  success: z.boolean().describe("Indicates if the chain execution was successful."),
  metadata: z.object({
    provider: z.string(),
    model: z.string(),
    elapsedTimeMs: z.number()
  }).passthrough().describe("Execution metadata."),
  error: z.string().optional().describe("Error message if execution failed.")
}).describe("Schema for the output of the llm-chain tool");
const AiSdkPromptOutputSchema = z.object({
  text: z.string().describe("The primary text output from the AI SDK call."),
  structured: z.unknown().optional().describe("Parsed structured output object if a schema was provided."),
  success: z.boolean().describe("Indicates if the AI SDK call was successful."),
  metadata: z.object({
    provider: z.string(),
    model: z.string(),
    elapsedTimeMs: z.number(),
    usage: z.object({
      promptTokens: z.number().int().optional(),
      completionTokens: z.number().int().optional(),
      totalTokens: z.number().int().optional()
    }).optional(),
    finishReason: z.string().optional(),
    rawResponse: z.any().optional()
  }).passthrough().describe("Execution metadata."),
  error: z.string().optional().describe("Error message if execution failed.")
}).describe("Schema for the output of the ai-sdk-prompt tool");
function createMastraLLMChainTools() {
  const mastraTools = createMastraTools(llmChainTool, aiSdkPromptTool);
  if (mastraTools["llm-chain"]) {
    mastraTools["llm-chain"].outputSchema = LLMChainOutputSchema;
  }
  if (mastraTools["ai-sdk-prompt"]) {
    mastraTools["ai-sdk-prompt"].outputSchema = AiSdkPromptOutputSchema;
  }
  return mastraTools;
}

const logger$1 = createLogger({ name: "puppeteerScrape", level: "debug" });
function generateScreenshotFilename(url) {
  const timestamp = (/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-");
  const urlHash = crypto.createHash("md5").update(url).digest("hex").substring(0, 8);
  return `screenshot_${urlHash}_${timestamp}.png`;
}
const ClickActionSchema = z.object({
  type: z.literal("click"),
  selector: z.string(),
  waitForNavigation: z.boolean().optional().default(false)
});
const TypeActionSchema = z.object({
  type: z.literal("type"),
  selector: z.string(),
  text: z.string(),
  delay: z.number().optional().default(50)
});
const ScrapeActionSchema = z.object({
  type: z.literal("scrape"),
  selector: z.string(),
  attribute: z.string().optional(),
  multiple: z.boolean().optional().default(false)
});
const WaitForSelectorActionSchema = z.object({
  type: z.literal("waitForSelector"),
  selector: z.string(),
  timeout: z.number().optional().default(3e4)
});
const ScrollActionSchema = z.object({
  type: z.literal("scroll"),
  direction: z.enum(["down", "up", "bottom", "top"]),
  amount: z.number().optional(),
  selector: z.string().optional()
});
const HoverActionSchema = z.object({
  type: z.literal("hover"),
  selector: z.string()
});
const SelectActionSchema = z.object({
  type: z.literal("select"),
  selector: z.string(),
  value: z.string()
});
const WaitActionSchema = z.object({
  type: z.literal("wait"),
  duration: z.number().int().min(1)
});
const EvaluateActionSchema = z.object({
  type: z.literal("evaluate"),
  script: z.string()
});
const ActionSchema = z.discriminatedUnion("type", [
  ClickActionSchema,
  TypeActionSchema,
  ScrapeActionSchema,
  WaitForSelectorActionSchema,
  ScrollActionSchema,
  HoverActionSchema,
  SelectActionSchema,
  WaitActionSchema,
  EvaluateActionSchema
]);
const PuppeteerScrapeOutputSchema = z.object({
  url: z.string().url(),
  pageTitle: z.string().optional(),
  scrapedData: z.array(z.any()).optional(),
  screenshotPath: z.string().optional(),
  success: z.boolean(),
  error: z.string().optional()
});
const PuppeteerScrapeInputSchema = z.object({
  url: z.string().url(),
  screenshot: z.boolean().optional().default(false),
  initialWaitForSelector: z.string().optional(),
  actions: z.array(ActionSchema).optional()
});
const puppeteerScrapeTool = createTool({
  id: "puppeteer_scrape",
  description: "Navigates to a web page using Puppeteer, performs actions (click, type, scrape, wait), and returns scraped data (no file writing).",
  inputSchema: PuppeteerScrapeInputSchema,
  outputSchema: PuppeteerScrapeOutputSchema,
  execute: async ({ context }) => {
    let browser = null;
    const output = {
      url: context.url,
      success: false,
      scrapedData: []
    };
    try {
      browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      await page.goto(context.url, { waitUntil: "networkidle2", timeout: 6e4 });
      output.url = page.url();
      output.pageTitle = await page.title();
      if (context.initialWaitForSelector) {
        await page.waitForSelector(context.initialWaitForSelector, { timeout: 3e4 });
      }
      if (context.actions && context.actions.length > 0) {
        for (const action of context.actions) {
          switch (action.type) {
            case "click":
              const clickPromise = page.click(action.selector);
              if (action.waitForNavigation) {
                await Promise.all([clickPromise, page.waitForNavigation({ waitUntil: "networkidle2", timeout: 6e4 })]);
                output.url = page.url();
              } else {
                await clickPromise;
              }
              break;
            case "type":
              await page.type(action.selector, action.text, { delay: action.delay });
              break;
            case "scrape":
              let scrapedItems = [];
              if (action.multiple) {
                scrapedItems = await page.$$eval(
                  action.selector,
                  (elements, attr) => elements.map((el) => attr ? el.getAttribute(attr) : el.textContent?.trim() ?? null),
                  action.attribute
                );
              } else {
                const scrapedItem = await page.$eval(
                  action.selector,
                  (element, attr) => attr ? element.getAttribute(attr) : element.textContent?.trim() ?? null,
                  action.attribute
                ).catch(() => null);
                if (scrapedItem !== null) scrapedItems = [scrapedItem];
              }
              output.scrapedData = [...output.scrapedData ?? [], ...scrapedItems];
              break;
            case "waitForSelector":
              await page.waitForSelector(action.selector, { timeout: action.timeout });
              break;
            case "scroll":
              await page.evaluate(async (options) => {
                const { direction, amount, selector } = options;
                let target = selector ? document.querySelector(selector) : window;
                if (!target) return;
                if (direction === "down" || direction === "up") {
                  const scrollAmount = amount || window.innerHeight;
                  if (direction === "down") {
                    target.scrollBy ? target.scrollBy(0, scrollAmount) : window.scrollBy(0, scrollAmount);
                  } else {
                    target.scrollBy ? target.scrollBy(0, -scrollAmount) : window.scrollBy(0, -scrollAmount);
                  }
                } else if (direction === "bottom") {
                  target.scrollTo ? target.scrollTo(0, document.body.scrollHeight) : window.scrollTo(0, document.body.scrollHeight);
                } else if (direction === "top") {
                  target.scrollTo ? target.scrollTo(0, 0) : window.scrollTo(0, 0);
                }
              }, action);
              break;
            case "hover":
              await page.hover(action.selector);
              break;
            case "select":
              await page.select(action.selector, action.value);
              break;
            case "wait":
              await new Promise((resolve) => setTimeout(resolve, action.duration));
              break;
            case "evaluate":
              const evalResult = await page.evaluate(action.script);
              output.scrapedData = [...output.scrapedData ?? [], evalResult];
              break;
          }
        }
      }
      if (context.screenshot) {
        const SCREENSHOT_DIR = path.resolve(process.cwd(), "puppeteer_screenshots");
        await page.screenshot({ path: path.join(SCREENSHOT_DIR, generateScreenshotFilename(context.url)), fullPage: true });
        output.screenshotPath = path.join(SCREENSHOT_DIR, generateScreenshotFilename(context.url));
      }
      output.success = true;
    } catch (error) {
      output.error = error instanceof Error ? error.message : String(error);
      output.success = false;
      logger$1.error(`puppeteerScrapeTool error: ${output.error}`);
    } finally {
      if (browser) await browser.close();
    }
    return output;
  }
});

const KG_PATH = path.join(__dirname, "knowledge-graph.json");
const AgentSchema = z.object({
  id: z.string(),
  label: z.string(),
  agentType: z.string(),
  skills: z.array(z.string())
});
const AgentListSchema = z.array(AgentSchema);
const RelationshipSchema = z.object({
  source: z.string(),
  target: z.string(),
  type: z.string(),
  since: z.string().optional(),
  weight: z.number().optional()
});
const RelationshipListSchema = z.array(RelationshipSchema);
async function loadKnowledgeGraph() {
  const raw = await fs__default.readFile(KG_PATH, "utf-8");
  const doc = JSON.parse(raw);
  const expanded = await jsonld.expand(doc);
  return { doc, expanded };
}
function listAgents(doc) {
  return doc.entities.map((agent) => ({
    id: agent.id,
    label: agent.label,
    agentType: agent.agentType,
    skills: agent.skills
  }));
}
function findAgentsWithSkill(doc, skill) {
  return doc.entities.filter((agent) => agent.skills && agent.skills.includes(skill));
}
function getCollaborators(doc, agentId) {
  const agent = doc.entities.find((a) => a.id === agentId);
  if (!agent || !agent.collaborates_with) return [];
  return agent.collaborates_with.map(
    (id) => doc.entities.find((a) => a.id === id)
  );
}
function listRelationships(doc, type) {
  if (!doc.relationships) return [];
  return type ? doc.relationships.filter((rel) => rel.type === type) : doc.relationships;
}
const listAgentsTool = createTool({
  id: "listAgents",
  description: "List all agents in the knowledge graph",
  inputSchema: z.object({}),
  outputSchema: AgentListSchema,
  execute: async () => {
    const { doc } = await loadKnowledgeGraph();
    return listAgents(doc);
  }
});
const findAgentsWithSkillTool = createTool({
  id: "findAgentsWithSkill",
  description: "Find agents with a specific skill",
  inputSchema: z.object({ skill: z.string() }),
  outputSchema: AgentListSchema,
  execute: async ({ skill }) => {
    const { doc } = await loadKnowledgeGraph();
    return findAgentsWithSkill(doc, skill);
  }
});
const getCollaboratorsTool = createTool({
  id: "getCollaborators",
  description: "Get collaborators for a given agent",
  inputSchema: z.object({ agentId: z.string() }),
  outputSchema: AgentListSchema,
  execute: async ({ agentId }) => {
    const { doc } = await loadKnowledgeGraph();
    return getCollaborators(doc, agentId);
  }
});
const listRelationshipsTool = createTool({
  id: "listRelationships",
  description: "List relationships in the knowledge graph, optionally filtered by type",
  inputSchema: z.object({ type: z.string().optional() }),
  outputSchema: RelationshipListSchema,
  execute: async ({ type }) => {
    const { doc } = await loadKnowledgeGraph();
    return listRelationships(doc, type);
  }
});

const logger = createLogger({
  name: "tool-initialization",
  level: "info"
});
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
        logger.error(`Missing required environment variables: ${missingKeys.join(", ")}`);
      }
    }
    logger.error("Environment validation failed:", {
      error
    });
    throw new Error(`Failed to validate environment configuration: ${error instanceof Error ? error.message : String(error)}`);
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
      logger.error("GitHub client or git.getRef method not available.");
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
      return {
        ref: mainRef?.data?.ref
      };
    } catch (error) {
      if (error.status === 404) {
        logger.warn(`Main branch ref not found for ${context.context.owner}/${context.context.repo}`);
        return {
          ref: void 0
        };
      }
      logger.error(`Error fetching main branch ref for ${context.context.owner}/${context.context.repo}:`, error);
      throw error;
    }
  }
});
function ensureToolOutputSchema(tool) {
  if (tool.outputSchema && tool.outputSchema instanceof ZodType) {
    return tool;
  }
  logger.warn(`Tool "${tool.id}" missing valid output schema, defaulting to empty object.`);
  return {
    ...tool,
    outputSchema: z.object({}).describe("Default empty output")
  };
}
const searchTools = {
  brave: config.BRAVE_API_KEY ? createBraveSearchTool({
    apiKey: config.BRAVE_API_KEY
  }) : void 0,
  google: config.GOOGLE_CSE_KEY && config.GOOGLE_CSE_ID ? createGoogleSearchTool({
    apiKey: config.GOOGLE_CSE_KEY,
    searchEngineId: config.GOOGLE_CSE_ID
  }) : void 0,
  tavily: config.TAVILY_API_KEY ? createTavilySearchTool({
    apiKey: config.TAVILY_API_KEY
  }) : void 0,
  exa: config.EXA_API_KEY ? (() => {
    const exaTool = createMastraExaSearchTools({
      apiKey: config.EXA_API_KEY
    })["exa_search"];
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
const additionalTools = [analyzeContentTool, formatContentTool, searchDocumentsTool, embedDocumentTool];
const extraTools = [];
try {
  const e2bToolsObject = createMastraE2BTools();
  const e2bToolsArray = Object.values(e2bToolsObject);
  extraTools.push(...e2bToolsArray.map((tool) => tool));
  logger.info(`Added ${e2bToolsArray.length} E2B tools.`);
} catch (error) {
  logger.error("Failed to initialize E2B tools:", {
    error
  });
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
    logger.info(`Added ${llamaIndexTools.length} LlamaIndex tools.`);
  } else {
    logger.warn("createLlamaIndexTools did not return an array.");
  }
} catch (error) {
  logger.error("Failed to initialize LlamaIndex tools:", {
    error
  });
}
try {
  const mcpToolsObject = await createMastraMcpTools();
  const mcpToolsArray = Object.values(mcpToolsObject);
  extraTools.push(...mcpToolsArray.map((tool) => tool));
  logger.info(`Added ${mcpToolsArray.length} MCP tools.`);
} catch (error) {
  logger.error("Failed to initialize MCP tools:", {
    error
  });
}
try {
  const arxivToolsObject = createMastraArxivTools();
  const arxivToolsArray = Object.values(arxivToolsObject);
  extraTools.push(...arxivToolsArray.map((tool) => tool));
  logger.info(`Added ${arxivToolsArray.length} Arxiv tools.`);
} catch (error) {
  logger.error("Failed to initialize Arxiv tools:", {
    error
  });
}
try {
  const aisdkToolsObject = createMastraAISDKTools();
  const aisdkToolsArray = Object.values(aisdkToolsObject);
  extraTools.push(...aisdkToolsArray.map((tool) => tool));
  logger.info(`Added ${aisdkToolsArray.length} AI SDK tools (via Mastra helper).`);
} catch (error) {
  logger.error("Failed to initialize AI SDK tools:", {
    error
  });
}
try {
  const wikiToolsObject = createMastraWikipediaTools();
  const wikiToolsArray = Object.values(wikiToolsObject);
  extraTools.push(...wikiToolsArray.map((tool) => tool));
  logger.info(`Added ${wikiToolsArray.length} Wikipedia tools.`);
} catch (error) {
  logger.error("Failed to initialize Wikipedia tools:", {
    error
  });
}
try {
  if (createGraphRagTool && typeof createGraphRagTool === "object" && "id" in createGraphRagTool) {
    extraTools.push(ensureToolOutputSchema(createGraphRagTool));
  } else {
    logger.warn("createGraphRagTool is not a valid Tool object.");
  }
  if (graphRagQueryTool && typeof graphRagQueryTool === "object" && "id" in graphRagQueryTool) {
    extraTools.push(ensureToolOutputSchema(graphRagQueryTool));
  } else {
    logger.warn("graphRagQueryTool is not a valid Tool object.");
  }
  if (createGraphRagTool && typeof createGraphRagTool === "object" && "id" in createGraphRagTool) {
    const baseTool = createGraphRagTool;
    const graphRagAliasTool = {
      ...baseTool,
      id: "graph-rag"
    };
    extraTools.push(ensureToolOutputSchema(graphRagAliasTool));
    logger.info("Added GraphRag tools and 'graph-rag' alias.");
  } else {
    logger.warn("Could not create 'graph-rag' alias: createGraphRagTool is not valid.");
  }
} catch (error) {
  logger.error("Failed to initialize GraphRag tools:", {
    error
  });
}
try {
  const polygonToolsObject = createMastraPolygonTools({
    apiKey: config.POLYGON_API_KEY
  });
  const polygonToolsArray = Object.values(polygonToolsObject);
  extraTools.push(...polygonToolsArray.map((tool) => tool));
  logger.info(`Added ${polygonToolsArray.length} Polygon tools.`);
} catch (error) {
  logger.error("Failed to initialize Polygon tools:", {
    error
  });
}
try {
  const redditToolsObject = createMastraRedditTools();
  const redditToolsArray = Object.values(redditToolsObject);
  extraTools.push(...redditToolsArray.map((tool) => tool));
  logger.info(`Added ${redditToolsArray.length} Reddit tools.`);
} catch (error) {
  logger.error("Failed to initialize Reddit tools:", {
    error
  });
}
try {
  const githubToolsObject = createMastraGitHubTools();
  const githubToolsArray = Object.values(githubToolsObject);
  extraTools.push(...githubToolsArray.map((tool) => tool));
  logger.info(`Added ${githubToolsArray.length} GitHub tools (via Mastra helper).`);
} catch (error) {
  logger.error("Failed to initialize GitHub tools:", {
    error
  });
}
extraTools.push(ensureToolOutputSchema(getMainBranchRef));
extraTools.push(...tracingTools);
extraTools.push(ensureToolOutputSchema(puppeteerTool));
const optionalTools = Object.values(searchTools).filter((tool) => tool !== void 0);
const allTools = Object.freeze([...coreTools, ...optionalTools, ...additionalTools, ...extraTools]);
const allToolsMap = new Map(allTools.map((tool) => [tool.id, tool]));
const toolGroups = {
  search: optionalTools,
  vector: [vectorQueryTool, googleVectorQueryTool, filteredQueryTool],
  file: [readFileTool, writeToFileTool],
  memory: [vectorQueryTool],
  rl: [collectFeedbackTool, analyzeFeedbackTool, applyRLInsightsTool, calculateRewardTool, defineRewardFunctionTool, optimizePolicyTool],
  content: additionalTools.filter((t) => ["analyzeContentTool", "formatContentTool"].includes(t.id)),
  document: additionalTools.filter((t) => ["searchDocumentsTool", "embedDocumentTool"].includes(t.id)),
  github: [getMainBranchRef, ...extraTools.filter((t) => t.id.startsWith("github_"))],
  // Group custom and provider tools
  extra: extraTools
  // Contains all tools added above
};
logger.info(`Initialized ${allTools.length} tools successfully.`);
logger.info(`Search tools available: ${toolGroups.search.map((t) => t.id).join(", ") || "none"}`);
logger.info(`GraphRag tools included: ${extraTools.some((t) => t.id.startsWith("graphRag") || t.id === "createGraphRagTool" || t.id === "graph-rag")}`);
logger.info(`LLMChain tools included: ${extraTools.some((t) => t.id.startsWith("llm-chain_"))}`);
logger.info(`E2B tools included: ${extraTools.some((t) => t.id.startsWith("e2b_"))}`);
logger.info(`Arxiv tools included: ${extraTools.some((t) => t.id.startsWith("arxiv_"))}`);
logger.info(`AI SDK tools included: ${extraTools.some((t) => t.id.startsWith("ai-sdk_"))}`);
console.log("All available tool IDs:", Array.from(allToolsMap.keys()));

export { AgentListSchema, AgentSchema, AiSdkPromptOutputSchema, ArXivClient, ArxivDownloadPdfOutputSchema, ArxivPdfUrlOutputSchema, ArxivSearchEntrySchema, ArxivSearchOutputSchema, E2BOutputSchema, createExaSearchProvider as ExaSearchOutputSchema, ExaSearchProvider, FeedbackType, FileEncoding, FileWriteMode, GitHubBranchSchema, GitHubBranchesListSchema, GitHubClient, GitHubCodeSearchItemSchema, GitHubCodeSearchResultsSchema, GitHubCommitSchema, GitHubCommitsListSchema, GitHubIssueSchema, GitHubIssuesListSchema, GitHubPullSchema, GitHubPullsListSchema, GitHubReleaseSchema, GitHubReleasesListSchema, GitHubRepoSchema, GitHubReposListSchema, GitHubUserSchema, LLMChainOutputSchema, MastraRedditClient, OTelAttributeNames, RelationshipListSchema, RelationshipSchema, RewardType, SpanStatusCode, SubredditPostSchema, SubredditPostsSchema, TickerDetailsSchema, WikipediaClient, WikipediaPageResultSchema, WikipediaSearchSchema, WikipediaSummarySchema, WikipediaThumbnailSchema, aiSdkPromptTool, allTools, allToolsMap, analyzeContentTool, analyzeFeedbackTool, applyRLInsightsTool, arxiv, calculateRewardTool, calculatorTool as calculator, collectFeedbackTool, createAISDKTools, createAISpan, createArxivClient, createBraveSearchTool, createE2BSandboxTool, createExaSearchProvider, createFileTool, createGitHubClient, createGoogleSearchTool, createGraphRagTool, createHttpSpan, createLlamaIndexTools, createMastraAISDKTools, createMastraArxivTools, createMastraE2BTools, createMastraExaSearchTools, createMastraGitHubTools, createMastraLLMChainTools, createMastraLlamaIndexTools, createMastraMcpTools, createMastraRedditTools, createMastraVectorQueryTool, createMastraWikipediaTools, createTavilySearchTool, createWikipediaClient, csvReaderTool, allToolsMap as default, defineRewardFunctionTool, deleteFileTool, docxReaderTool, e2b, editFileTool, embedDocumentTool, extractHtmlTextTool, filteredQueryTool, findAgentsWithSkillTool, formatContentTool, getCollaboratorsTool, getMainBranchRef, getMeterProvider, getTracer, getUnreadFeedbackThreads, googleVectorQueryTool, graphRagQueryTool, toolGroups as groups, initOpenTelemetryTool, initSigNoz, jsonReaderTool, listAgentsTool, listFilesTool, listRelationshipsTool, llamaindexTools, llmChainTool, optimizePolicyTool, puppeteerScrapeTool, readFileTool, readKnowledgeFileTool, recordLlmMetrics, recordLlmMetricsTool, recordMetrics, searchDocumentsTool, shutdownSigNoz, shutdownTracingTool, startAISpanTool, toolGroups, allToolsMap as toolMap, tracingTools, vectorQueryTool, wikipedia, writeKnowledgeFileTool, writeToFileTool };

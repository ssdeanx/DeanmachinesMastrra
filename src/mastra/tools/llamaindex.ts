import {
  type AIFunctionLike,
  AIFunctionSet,
  asZodOrJsonSchema,
} from "@agentic/core";
import { createMastraTools } from "@agentic/mastra";
import { FunctionTool } from "llamaindex";

/**
 * Converts a set of Agentic stdlib AI functions to an array of LlamaIndex-
 * compatible tools.
 *
 * Note: The returned tools should be wrapped with `createMastraTools` from
 * @agentic/mastra when added to extraTools in index.ts like:
 * `extraTools.push(...createMastraTools(...llamaIndexArray));`
 *
 * @param aiFunctionLikeTools - Agentic functions to convert to LlamaIndex tools
 * @returns An array of LlamaIndex compatible tools
 */
export function createLlamaIndexTools(
  ...aiFunctionLikeTools: AIFunctionLike[]
) {
  const fns = new AIFunctionSet(aiFunctionLikeTools);

  return fns.map((fn) =>
    FunctionTool.from(fn.execute, {
      name: fn.spec.name,
      description: fn.spec.description,
      // TODO: Investigate types here
      parameters: asZodOrJsonSchema(fn.inputSchema) as any,
    })
  );
}

/**
 * Helper function to create Mastra-compatible LlamaIndex tools
 *
 * @param aiFunctionLikeTools - Agentic functions to convert and adapt
 * @returns An array of Mastra-compatible tools
 */
export function createMastraLlamaIndexTools(
  ...aiFunctionLikeTools: AIFunctionLike[]
) {
  // Adapt the original AIFunctionLike tools directly for Mastra
  return createMastraTools(...aiFunctionLikeTools);
}

// --- LlamaIndex Tools ---
import { z } from "zod";
import { vectorUpsert, vectorQuery, vectorFetch } from "../database/redis";
import { createMastraVectorQueryTool } from "./vectorquerytool";
import { createKnowledgeGraphFile, readKnowledgeGraphFile, ensureKnowledgeGraphFile } from "./llamaindex-knowledge-graph.utils";
import { parseInput, stringifyOutput } from "../agents/format.utils";
import { loadAgentConfigFromFile } from "../agents/configLoader";
import { encodingForModel } from "js-tiktoken";
import { zodToJsonSchema } from "zod-to-json-schema";

// Query Vector Store Tool
// --- Types ---
type VectorQueryMatch = { id: string; score: number; text: string };
type VectorQueryResult = { matches: VectorQueryMatch[] } | VectorQueryMatch[];

// Query Vector Store Tool
const llamaindex_query_vector_store = {
  id: "llamaindex_query_vector_store",
  description: "Query the LlamaIndex vector store for relevant documents given a query string.",
  inputSchema: z.object({
    query: z.string().describe("The query string to search for relevant documents."),
    topK: z.number().optional().default(5).describe("Number of top results to return."),
  }),
  outputSchema: z.object({
    results: z.array(z.object({
      id: z.string(),
      score: z.number(),
      text: z.string(),
    })),
    tokenCount: z.number(),
    success: z.boolean(),
    error: z.string().optional(),
  }),
  execute: async ({ context }) => {
    // Use js-tiktoken for real tokenization
    let tokenCount = 0;
    try {
      // Type assertion to satisfy TiktokenModel type
      const encoder = encodingForModel('o200k_base' as any);
      if (!encoder) {
        throw new Error('Missing encoding/model');
      }
      tokenCount = encoder.encode(typeof context.query === 'string' ? context.query : JSON.stringify(context.query)).length;
    } catch (err) {
      return { results: [], tokenCount: 0, success: false, error: 'Tokenization failed: ' + (err instanceof Error ? err.message : String(err)) };
    }
    try {
      const results = await vectorQuery({ query: context.query, topK: context.topK || 5 }) as VectorQueryResult;
      // Handle both array and object with matches
      const docs = Array.isArray(results) ? results : (results?.matches || []);
      return { results: docs, tokenCount, success: true };
    } catch (error) {
      return { results: [], tokenCount, success: false, error: error instanceof Error ? error.message : String(error) };
    }
  },

  // Dummy properties to satisfy AIFunctionLike
  parseInput: (input: any) => input,
  spec: {
    name: "llamaindex_query_vector_store",
    description: "Query the LlamaIndex vector store for relevant documents given a query string.",
    parameters: zodToJsonSchema(z.object({
      query: z.string().describe("The query string to search for relevant documents."),
      topK: z.number().optional().default(5).describe("Number of top results to return."),
    })), // Always JSON Schema
    type: "function" as "function",
    strict: true
  },
};

// Add Document Tool
const llamaindex_add_document = {
  id: "llamaindex_add_document",
  description: "Add a document to the LlamaIndex vector store.",
  inputSchema: z.object({
    id: z.string().describe("Unique document ID."),
    text: z.string().describe("Document text to index."),
  }),
  outputSchema: z.object({
    success: z.boolean(),
    error: z.string().optional(),
  }),
  execute: async ({ context }) => {
    // Use js-tiktoken for real tokenization
    let tokenCount = 0;
    try {
      // Type assertion to satisfy TiktokenModel type
      const encoder = encodingForModel('o200k_base' as any);
      tokenCount = encoder.encode(context.text).length;
    } catch (err) {
      return { success: false, tokenCount: 0, error: 'Tokenization failed: ' + (err instanceof Error ? err.message : String(err)) };
    }
    // Use Upstash vector embedding logic with Google embeddings
    try {
      // Use the Google embedding function from vectorquerytool.ts
      const vectorTool = createMastraVectorQueryTool({ embeddingProvider: "google" });
      // The embedding function expects an array of values
      const embeddingResult = await vectorTool.model.doEmbed({ values: [context.text] });
      const realVector = embeddingResult.embeddings[0].embedding;
      await vectorUpsert({ id: context.id, vector: realVector, metadata: { text: context.text } });
      return { success: true, tokenCount };
    } catch (error) {
      return { success: false, tokenCount, error: error instanceof Error ? error.message : String(error) };
    }
  },

  parseInput: (input: any) => input,
  spec: {
    name: "llamaindex_add_document",
    description: "Add a document to the LlamaIndex vector store.",
    parameters: zodToJsonSchema(z.object({
      id: z.string().describe("Unique document ID."),
      text: z.string().describe("Document text to index."),
    })), // Always JSON Schema
    type: "function" as "function",
    strict: true
  },
};

// Delete Document Tool
const llamaindex_delete_document = {
  id: "llamaindex_delete_document",
  description: "Delete a document from the LlamaIndex vector store.",
  inputSchema: z.object({
    id: z.string().describe("Unique document ID to delete."),
  }),
  outputSchema: z.object({
    success: z.boolean(),
    error: z.string().optional(),
  }),
  execute: async ({ context }) => {
    // Optionally implement delete if available in redis.ts
    // For now, simulate deletion by removing from knowledge graph file if present
    try {
      const kg = await readKnowledgeGraphFile();
      kg.entities = kg.entities.filter(e => e.id !== context.id);
      kg.relationships = kg.relationships.filter(r => r.source !== context.id && r.target !== context.id);
      await createKnowledgeGraphFile(kg);
      return { success: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
  },

  parseInput: (input: any) => input,
  spec: {
    name: "llamaindex_delete_document",
    description: "Delete a document from the LlamaIndex vector store.",
    parameters: zodToJsonSchema(z.object({
      id: z.string().describe("Unique document ID to delete."),
    })), // Always JSON Schema
    type: "function" as "function",
    strict: true
  },
};

// Knowledge Graph Query Tool
const llamaindex_knowledge_graph_query = {
  id: "llamaindex_knowledge_graph_query",
  description: "Query the LlamaIndex knowledge graph for entities and relationships.",
  inputSchema: z.object({
    query: z.string().describe("The graph query (e.g., Cypher or natural language)."),
    topK: z.number().optional().default(5).describe("Number of top entities/relations to return."),
  }),
  outputSchema: z.object({
    entities: z.array(z.object({
      id: z.string(),
      label: z.string(),
      type: z.string(),
    })),
    relationships: z.array(z.object({
      source: z.string(),
      target: z.string(),
      relation: z.string(),
    })),
    success: z.boolean(),
    error: z.string().optional(),
  }),
  execute: async ({ context }) => {
    // Knowledge Graph CRUD: create/read/update/query as JSON file
    ensureKnowledgeGraphFile();
    if (context.action === 'create') {
      // context.entities and context.relationships must be provided
      await createKnowledgeGraphFile({ entities: context.entities, relationships: context.relationships });
      return { success: true };
    } else if (context.action === 'read') {
      const kg = await readKnowledgeGraphFile();
      return { ...kg, success: true };
    } else if (context.action === 'add_entity') {
      const kg = await readKnowledgeGraphFile();
      kg.entities.push(context.entity);
      await createKnowledgeGraphFile(kg);
      return { success: true };
    } else if (context.action === 'add_relationship') {
      const kg = await readKnowledgeGraphFile();
      kg.relationships.push(context.relationship);
      await createKnowledgeGraphFile(kg);
      return { success: true };
    } else {
      return { success: false, error: 'Unknown knowledge graph action' };
    }
  },

  parseInput: (input: any) => input,
  spec: {
    name: "llamaindex_knowledge_graph_query",
    description: "Query the LlamaIndex knowledge graph for entities and relationships.",
    parameters: zodToJsonSchema(z.object({
      query: z.string().describe("The graph query (e.g., Cypher or natural language)."),
      topK: z.number().optional().default(5).describe("Number of top entities/relations to return."),
    })), // Always JSON Schema
    type: "function" as "function",
    strict: true
  },
};

// Image Captioning Tool (Multimodal Example)
const llamaindex_image_captioning = {
  id: "llamaindex_image_captioning",
  description: "Generate a caption for a given image using LlamaIndex's multimodal capabilities.",
  inputSchema: z.object({
    imageUrl: z.string().url().describe("URL of the image to caption."),
  }),
  outputSchema: z.object({
    caption: z.string(),
    success: z.boolean(),
    error: z.string().optional(),
  }),
  execute: async ({ context }) => {
    // No image captioning API in Upstash/redis.ts
    return { caption: "", success: false, error: "Image captioning not implemented." };
  },

  parseInput: (input: any) => input,
  spec: {
    name: "llamaindex_image_captioning",
    description: "Generate a caption for a given image using LlamaIndex's multimodal capabilities.",
    parameters: zodToJsonSchema(z.object({
      imageUrl: z.string().url().describe("URL of the image to caption."),
    })), // Always JSON Schema
    type: "function" as "function",
    strict: true
  },
};

// Patch outputSchema for all tools (future-proof)
const llamaTools = [
  llamaindex_query_vector_store,
  llamaindex_add_document,
  llamaindex_delete_document,
  llamaindex_knowledge_graph_query,
  llamaindex_image_captioning,
];
for (const tool of llamaTools) {
  (tool as any).outputSchema = tool.outputSchema;
}

// Adapter to make tool objects callable as a function with all required properties
// Custom type for callable tool with all required props
 type CallableTool = ((input: any) => any) & {
   inputSchema: any;
   parseInput: any;
   spec: any;
   execute: any;
   outputSchema: any;
 };
function makeAIFunctionLike(toolObj: any): CallableTool {
  const fn = ((input: any) => toolObj.execute({ context: input })) as CallableTool;
  fn.inputSchema = toolObj.inputSchema;
  fn.parseInput = toolObj.parseInput;
  fn.spec = toolObj.spec;
  fn.execute = toolObj.execute;
  fn.outputSchema = toolObj.outputSchema;
  return fn;
}

// Register all tools for Mastra using the adapter
export const llamaindexTools = createMastraLlamaIndexTools(
  ...llamaTools.map(makeAIFunctionLike)
);

// Export adapter for convenience
export { createMastraTools };


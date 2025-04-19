PS C:\Users\dm\Documents\Backup\DeanmachinesMastrra> mastra dev
INFO [2025-04-19 15:04:14.147 -0400] (BUNDLER - Dev): Starting watcher...
INFO [2025-04-19 15:04:15.243 -0400] (BUNDLER - Dev): Bundling finished, starting server...
INFO [2025-04-19 15:04:15.259 -0400] (Mastra CLI): [Mastra Dev] - Starting server...
llamaindex was already imported. This breaks constructor checks and will lead to issues!
INFO [2025-04-19 15:04:23.878 -0400] (vector-query-tool): Creating vector query tool for pinecone:Default
Initializing embeddings with model: models/gemini-embedding-exp-03-07
LangSmith tracing configured successfully
INFO [2025-04-19 15:04:24.067 -0400] (tool-initialization): Added 1 E2B tools.
INFO [2025-04-19 15:04:23.881 -0400] (vector-query-tool): Using tiktoken embeddings with encoding: o200k_base
INFO [2025-04-19 15:04:23.881 -0400] (vector-query-tool): Vector query tool created: vector-query
INFO [2025-04-19 15:04:23.882 -0400] (vector-query-tool): Creating vector query tool for pinecone:Default
INFO [2025-04-19 15:04:23.882 -0400] (vector-query-tool): Using Google embeddings  
INFO [2025-04-19 15:04:23.883 -0400] (vector-query-tool): Vector query tool created: google-vector-query
INFO [2025-04-19 15:04:23.883 -0400] (vector-query-tool): Creating vector query tool for pinecone:Default
INFO [2025-04-19 15:04:23.883 -0400] (vector-query-tool): Using tiktoken embeddings with encoding: o200k_base
INFO [2025-04-19 15:04:23.883 -0400] (vector-query-tool): Vector query tool created: filtered-vector-query
INFO [2025-04-19 15:04:24.067 -0400] (tool-initialization): Added 0 LlamaIndex tools.
INFO [2025-04-19 15:04:24.436 -0400] (LLM - MastraMCPClient): Successfully connected to MCP server
2025-04-19T19:04:33.380Z [Runner] Using saved configuration
2025-04-19T19:04:33.380Z [Runner] Connecting to server: {"id":"@smithery/toolbox","connectionTypes":["ws"]}
2025-04-19T19:04:33.382Z [Runner] Connecting to WebSocket endpoint: https://server.smithery.ai/@smithery/toolbox
2025-04-19T19:04:33.554Z [Runner] WebSocket connection initiated
2025-04-19T19:04:33.555Z [Runner] WebSocket connection established
INFO [2025-04-19 15:04:33.902 -0400] (LLM - MastraMCPClient): Successfully connected to MCP server
INFO [2025-04-19 15:04:34.168 -0400] (LLM - MastraMCPClient): [MCP SERVER LOG]
    data: {
      "message": "Started Mastra Docs MCP Server"
    }
INFO [2025-04-19 15:04:34.172 -0400] (LLM - MastraMCPClient): Successfully connected to MCP server
INFO [2025-04-19 15:04:34.176 -0400] (tool-initialization): Added 85 MCP tools.    
INFO [2025-04-19 15:04:34.305 -0400] (opentelemetry-tracing): OpenTelemetry metrics enabled
INFO [2025-04-19 15:04:34.320 -0400] (signoz-service): Initializing SigNoz tracing for service: agent-initialization
    endpoint: "http://localhost:4318/v1/traces"
INFO [2025-04-19 15:04:34.324 -0400] (agent-initialization): Creating agent: research-agent with 23 tools
INFO [2025-04-19 15:04:34.345 -0400] (coder-agent): Initializing coder agent
INFO [2025-04-19 15:04:34.348 -0400] (copywriter-agent): Initializing copywriter agent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): Initializing KnowledgeWorkMoENetwork (ID: knowledge-work-moe-v1)...
INFO [2025-04-19 15:04:34.377 -0400] (DeanMachinesAI-MastraCore): Initializing Mastra instance...
INFO [2025-04-19 15:04:34.178 -0400] (tool-initialization): Added 3 Arxiv tools.
INFO [2025-04-19 15:04:34.179 -0400] (tool-initialization): Added 0 AI SDK tools (via Mastra helper).
INFO [2025-04-19 15:04:34.180 -0400] (tool-initialization): Added 2 Wikipedia tools.
INFO [2025-04-19 15:04:34.180 -0400] (tool-initialization): Added GraphRag tools and 'graph-rag' alias.
INFO [2025-04-19 15:04:34.181 -0400] (tool-initialization): Added 7 Polygon tools. 
INFO [2025-04-19 15:04:34.182 -0400] (tool-initialization): Added 1 Reddit tools.  
INFO [2025-04-19 15:04:34.187 -0400] (tool-initialization): Added 10 GitHub tools (via Mastra helper).
INFO [2025-04-19 15:04:34.187 -0400] (tool-initialization): Initialized 160 tools successfully.
INFO [2025-04-19 15:04:34.187 -0400] (tool-initialization): Search tools available: brave-search, google-search, tavily-search, exa_search
INFO [2025-04-19 15:04:34.187 -0400] (tool-initialization): GraphRag tools included: true
INFO [2025-04-19 15:04:34.188 -0400] (tool-initialization): LLMChain tools included: false
INFO [2025-04-19 15:04:34.188 -0400] (tool-initialization): E2B tools included: false
INFO [2025-04-19 15:04:34.188 -0400] (tool-initialization): Arxiv tools included: true
INFO [2025-04-19 15:04:34.188 -0400] (tool-initialization): AI SDK tools included: false
INFO [2025-04-19 15:04:34.320 -0400] (opentelemetry-tracing): OpenTelemetry SDK initialized successfully
INFO [2025-04-19 15:04:34.321 -0400] (signoz-service): SigNoz tracing initialized successfully
INFO [2025-04-19 15:04:34.334 -0400] (agent-initialization): Creating agent: analyst-agent with 30 tools
INFO [2025-04-19 15:04:34.336 -0400] (agent-initialization): Creating agent: writer-agent with 21 tools
INFO [2025-04-19 15:04:34.339 -0400] (agent-initialization): Creating agent: rl-trainer-agent with 10 tools
INFO [2025-04-19 15:04:34.341 -0400] (agent-initialization): Creating agent: data-manager-agent with 8 tools
INFO [2025-04-19 15:04:34.343 -0400] (agent-initialization): Creating agent: agentic-assistant with 4 tools
INFO [2025-04-19 15:04:34.346 -0400] (agent-initialization): Creating agent: coder-agent with 4 tools
INFO [2025-04-19 15:04:34.348 -0400] (agent-initialization): Creating agent: copywriter-agent with 4 tools
INFO [2025-04-19 15:04:34.354 -0400] (agent-initialization): Creating agent: architect-agent with 7 tools
INFO [2025-04-19 15:04:34.357 -0400] (agent-initialization): Creating agent: debugger-agent with 5 tools
INFO [2025-04-19 15:04:34.360 -0400] (agent-initialization): Creating agent: ui-ux-coder-agent with 6 tools
INFO [2025-04-19 15:04:34.362 -0400] (agent-initialization): Creating agent: code-documenter with 6 tools
INFO [2025-04-19 15:04:34.363 -0400] (agent-initialization): Creating agent: market-research-agent with 8 tools
INFO [2025-04-19 15:04:34.365 -0400] (agent-initialization): Creating agent: social-media-agent with 6 tools
INFO [2025-04-19 15:04:34.367 -0400] (agent-initialization): Creating agent: seo-agent with 6 tools
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: researchAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: analystAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: writerAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: coderAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: debuggerAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: architectAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: codeDocumenterAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: dataManagerAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: marketResearchAgent
INFO [2025-04-19 15:04:34.374 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: copywriterAgent
INFO [2025-04-19 15:04:34.375 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: socialMediaAgent
INFO [2025-04-19 15:04:34.375 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: seoAgent
INFO [2025-04-19 15:04:34.375 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] Registered expert: uiUxCoderAgent
INFO [2025-04-19 15:04:34.376 -0400] (KnowledgeWorkMoENetwork): [knowledge-work-moe-v1] KnowledgeWorkMoENetwork initialized successfully with 13 agents (including fallback).
INFO [2025-04-19 15:04:34.383 -0400] (DeanMachinesAI-MastraCore): Mastra instance initialized successfully with 15 agents and 4 networks.
INFO [2025-04-19 15:04:35.720 -0400] (vector-query-tool): Creating vector query tool for pinecone:Default
Initializing embeddings with model: models/gemini-embedding-exp-03-07
LangSmith tracing configured successfully
llmChainTool: [Function: llm-chain] {
  inputSchema: ZodObject {
    spa: [Function: bound safeParseAsync] AsyncFunction,
    _def: {
      shape: [Function: shape],
      unknownKeys: 'strip',
      catchall: [ZodNever],
      typeName: 'ZodObject'
    },
    parse: [Function: bound parse],
    safeParse: [Function: bound safeParse],
    parseAsync: [Function: bound parseAsync] AsyncFunction,
    safeParseAsync: [Function: bound safeParseAsync] AsyncFunction,
    refine: [Function: bound refine],
    refinement: [Function: bound refinement],
    superRefine: [Function: bound superRefine],
    optional: [Function: bound optional],
    nullable: [Function: bound nullable],
    nullish: [Function: bound nullish],
    array: [Function: bound array],
    promise: [Function: bound promise],
    or: [Function: bound or],
    and: [Function: bound and],
    transform: [Function: bound transform],
    brand: [Function: bound brand],
    default: [Function: bound default],
    catch: [Function: bound catch],
    describe: [Function: bound describe],
    pipe: [Function: bound pipe],
    readonly: [Function: bound readonly],
    isNullable: [Function: bound isNullable],
    isOptional: [Function: bound isOptional],
    '~standard': { version: 1, vendor: 'zod', validate: [Function: validate] },    
    _cached: null,
    nonstrict: [Function: passthrough],
    augment: [Function: extend]
  },
  parseInput: [Function: parseInput],
  execute: [AsyncFunction (anonymous)],
  tags: undefined,
  spec: {
    name: 'llm-chain',
    description: 'Runs an LLM chain with a prompt template and variables',
    parameters: {
      type: 'object',
      properties: [Object],
      required: [Array],
      additionalProperties: false
    },
    type: 'function',
    strict: true
  }
}
INFO [2025-04-19 15:04:35.837 -0400] (llm-chain-tool): Registered llmChainTool
INFO [2025-04-19 15:04:35.840 -0400] (tool-initialization): Added 1 E2B tools.     
INFO [2025-04-19 15:04:35.848 -0400] (DeanMachinesAI-MastraCore): ≡ƒªä Mastra API running on port 4111/api
INFO [2025-04-19 15:04:35.721 -0400] (vector-query-tool): Using tiktoken embeddings with encoding: o200k_base
INFO [2025-04-19 15:04:35.721 -0400] (vector-query-tool): Vector query tool created: vector-query
INFO [2025-04-19 15:04:35.721 -0400] (vector-query-tool): Creating vector query tool for pinecone:Default
INFO [2025-04-19 15:04:35.721 -0400] (vector-query-tool): Using Google embeddings  
INFO [2025-04-19 15:04:35.722 -0400] (vector-query-tool): Vector query tool created: google-vector-query
INFO [2025-04-19 15:04:35.722 -0400] (vector-query-tool): Creating vector query tool for pinecone:Default
INFO [2025-04-19 15:04:35.722 -0400] (vector-query-tool): Using tiktoken embeddings with encoding: o200k_base
INFO [2025-04-19 15:04:35.723 -0400] (vector-query-tool): Vector query tool created: filtered-vector-query
INFO [2025-04-19 15:04:35.840 -0400] (tool-initialization): Added 0 LlamaIndex tools.
ERROR [2025-04-19 15:04:35.840 -0400] (tool-initialization): Failed to initialize MCP tools:
    error: {}
INFO [2025-04-19 15:04:35.841 -0400] (tool-initialization): Added 3 Arxiv tools.   
INFO [2025-04-19 15:04:35.841 -0400] (tool-initialization): Added 0 AI SDK tools (via Mastra helper).
INFO [2025-04-19 15:04:35.842 -0400] (tool-initialization): Added 2 Wikipedia tools.
INFO [2025-04-19 15:04:35.842 -0400] (tool-initialization): Added GraphRag tools and 'graph-rag' alias.
INFO [2025-04-19 15:04:35.842 -0400] (tool-initialization): Added 7 Polygon tools. 
INFO [2025-04-19 15:04:35.843 -0400] (tool-initialization): Added 1 Reddit tools.  
INFO [2025-04-19 15:04:35.844 -0400] (tool-initialization): Added 10 GitHub tools (via Mastra helper).
INFO [2025-04-19 15:04:35.844 -0400] (tool-initialization): Initialized 75 tools successfully.
INFO [2025-04-19 15:04:35.844 -0400] (tool-initialization): Search tools available: brave-search, google-search, tavily-search, exa_search
INFO [2025-04-19 15:04:35.844 -0400] (tool-initialization): GraphRag tools included: true
INFO [2025-04-19 15:04:35.844 -0400] (tool-initialization): LLMChain tools included: false
INFO [2025-04-19 15:04:35.844 -0400] (tool-initialization): E2B tools included: false
INFO [2025-04-19 15:04:35.844 -0400] (tool-initialization): Arxiv tools included: true
INFO [2025-04-19 15:04:35.844 -0400] (tool-initialization): AI SDK tools included: false
INFO [2025-04-19 15:04:35.848 -0400] (DeanMachinesAI-MastraCore): ≡ƒôÜ Open API documentation available at http://localhost:4111/openapi.json
INFO [2025-04-19 15:04:35.848 -0400] (DeanMachinesAI-MastraCore): ≡ƒº¬ Swagger UI available at http://localhost:4111/swagger-ui
INFO [2025-04-19 15:04:35.848 -0400] (DeanMachinesAI-MastraCore): ≡ƒæ¿ΓÇì≡ƒÆ╗ Playground available at http://localhost:4111/

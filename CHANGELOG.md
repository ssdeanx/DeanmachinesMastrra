# Changelog

All notable changes to the DeanMachines Mastra Backend will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.0.17] - 2025-04-21

### Added

- **src/mastra/database/index.ts**: Exported `defaultMemoryConfig` to centralize memory defaults (semanticRecall, workingMemory, threads) across storage adapters.
- **src/mastra/database/redis.ts**: Imported `defaultMemoryConfig` and UpstashVectorIndex; initialized `redisMemory` with vector support and full memory features.
- **src/mastra/database/index.ts** & **src/mastra/database/redis.ts**: Imported and re‑exported the `threadManager` singleton for consistent thread-based context management.
- **src/mastra/agents/base.agent.ts**: Attached `threadManager` to each Agent instance via `(agent as any).threadManager` to enable conversation threading.
- **src/mastra/agents/advanced.base.agent.ts**: Injected `threadManager` into advanced agents before return, allowing advanced workflows to use threaded memory.

### Changed

- **src/mastra/tools/rlReward.ts**: Added Zod input/output validation in `execute` using `.safeParse()`, destructured inputs for clarity, and improved error reporting.
- **src/mastra/tools/rlFeedback.ts**: Refactored `execute` to use destructured, Zod-validated `input`; standardized feedback structure and removed raw `context` usage.
- **src/mastra/database/redis.ts**: Moved UpstashVectorIndex initialization above memory instantiation to fix TDZ; configured `redisMemory` using `defaultMemoryConfig` for semantic recall and threads.
- **src/mastra/database/index.ts**: Increased `lastMessages` default from 50 to 100; exported the config for reuse by Redis memory layer.

### Fixed

- **src/mastra/database/redis.ts**: Resolved "block-scoped variable 'upstashVector' used before its declaration" by reordering initialization.
- **src/mastra/database/index.ts**: Synchronized default `lastMessages` value (100) and added export on `defaultMemoryConfig` to fix import errors.

---

## [v0.0.16] - [Agent Core & Config Loader Enhancements] - 2025-04-20

### Added

- **src/mastra/agents/advanced.base.agent.ts**
  - Major refactor of the core agent base class for extensibility, modularity, and robust error handling.
  - Added lifecycle hooks (`onInit`, `onBeforeRun`, `onAfterRun`, `onError`, `onTeardown`) to allow middleware, tracing, and custom agent logic at every stage.
  - Integrated SigNoz and OpenTelemetry tracing at agent initialization and tool execution boundaries for deep observability.
  - Improved type safety for agent config, runtime options, and tool registration.
  - Provided detailed inline documentation, JSDoc, and developer comments for onboarding and future extension.
  - Enhanced agent teardown and error recovery to prevent resource leaks and provide clear error messages.

- **src/mastra/agents/format.utils.ts**
  - Developed and exported `parseInput` and related utilities to support seamless parsing of agent configs/prompts from multiple formats:
    - Supported formats: JSON (`.json`), YAML (`.yaml`, `.yml`), XML (`.xml`), TXT (`.txt`), Markdown (`.md`).
    - Centralized format detection logic based on file extension and content heuristics.
    - Added robust error handling and reporting for malformed or unsupported files.
    - Utilities are fully extensible for future formats (add new parser, register in format map).
    - All utility functions are documented for clarity and future extension.

- **src/mastra/agents/configLoader.ts**
  - Implemented a robust async loader utility for agent config and prompt files.
  - Automatically detects and parses file format using `format.utils.ts`.
  - Handles both full agent configs (structured objects) and simple prompt/instruction files (free text or markdown).
  - Provides clear, actionable error messages for missing, invalid, or unsupported config fields.
  - Designed for integration into agent initialization routines and example loaders.
  - Comprehensive JSDoc and usage examples included.

- **Example Prompts & Configs (src/mastra/agents/loaders/):**
  - Added new example prompt/config files to demonstrate and test multi-format loader support:
    - `prompt.json`: Example agent prompt/config in JSON format. Demonstrates structured prompt with fields for instructions, context, and parameters.
    - `prompt.txt`: Plaintext agent prompt. Demonstrates support for raw text instructions.
    - `prompt.md`: Markdown agent prompt. Demonstrates support for rich formatting, headings, and code blocks in instructions.
    - (If present) `prompt.yaml`/`prompt.yml`: YAML-formatted agent prompt/config, showing alternative structured config.
    - (If present) `prompt.xml`: XML-formatted agent prompt/config, for extensibility demonstration.
  - These files are used in the loader example and serve as templates for future agent prompt/config creation.

- **src/mastra/agents/loaders/example.loader.ts**
  - Provided a comprehensive script demonstrating how to load and initialize agents from all supported prompt/config formats.
  - Detects file format, parses config, and initializes agent with memory (including SQLite integration if configured).
  - Serves as a reference implementation and testing harness for loader utilities.

### Changed

- Refactored agent initialization and config loading to use the new utilities and base class for improved reliability and developer experience.
- Enhanced error handling and logging throughout the agent configuration and loading process.
- Updated internal documentation and code comments to reflect new architecture and usage patterns.
- README updated with detailed instructions and code snippets for using the new loader and example prompts.

### Fixed

- Addressed previous pain points with config file parsing, format detection, and error reporting.
- Improved maintainability and extensibility for future agent and config loader development.

### Developer Notes

- To add a new prompt/config, create a file in `src/mastra/agents/loaders/` with the appropriate extension (`.json`, `.yaml`, `.xml`, `.txt`, `.md`).
- The loader utilities will automatically detect the format and parse the file.
- See `example.loader.ts` for a full workflow and integration pattern.
- All new patterns are documented in the codebase and README for onboarding and future maintenance.

---

- Integrates with format.utils.ts for seamless multi-format support.
- Handles both full agent configs and simple prompt/instruction files.
- Provides clear error messages and validation for missing or invalid config fields.
- Added comprehensive documentation and usage examples.

### Changed

- Refactored agent initialization and config loading to use the new utilities and base class for improved reliability and developer experience.
- Enhanced error handling and logging throughout the agent configuration and loading process.
- Updated internal documentation and code comments to reflect new architecture and usage patterns.

### Fixed

- Addressed previous pain points with config file parsing, format detection, and error reporting.
- Improved maintainability and extensibility for future agent and config loader development.

### Notes

- These changes lay the foundation for flexible, robust agent configuration and extensible agent base classes.
- All new patterns are documented in the codebase and README for onboarding and future maintenance.

---

## [v0.0.15] - 2025-04-20

### Added

- **Puppeteer Tool (`puppeteerTool.ts`)** Needs fixed causes stream to crash.
Trace
Trace Id
Started Total Duration

stream
b1052f4e30ebab490748d50db729b901 4/20/2025, 9:51:12 AM 15.861ms

stream
8642fc5243ae5610e419a4431b792779 4/20/2025, 9:49:01 AM 1924.593ms

__registerMastra
9337ac666c23e33bd1f6b85d98daf44a 4/20/2025, 9:48:45 AM 0.007ms

__registerMastra
e85fb9fff96413107517aac82da2e943 4/20/2025, 9:48:45 AM 0.005ms

__registerMastra
e39c38bd34ca5e5cbc47a2d6a32cd057 4/20/2025, 9:48:45 AM 0.005ms

__registerMastra
1fc4f91de6d279050eca05ef2f5d598e 4/20/2025, 9:48:45 AM 0.051ms

__registerPrimitives
93250cfc44aaf1d882d180aa4fe39b13 4/20/2025, 9:48:45 AM 0.096ms

__registerMastra
2744379f4f8e815785ebaddaa4830add 4/20/2025, 9:48:45 AM 0.391ms

__registerPrimitives
629c2ccf8f2b4bc80f8867c4ef9ef0de 4/20/2025, 9:48:45 AM 0.168ms

- Implemented a new Mastra tool (`puppeteer_web_automator`) for advanced browser automation using Puppeteer.
- Supports navigating to URLs, executing a sequence of actions (click, type, scrape, wait, scroll, hover, select, evaluate), taking screenshots, and extracting data.
- Includes robust action schemas defined with Zod for type safety and validation.
- Provides detailed logging for each step of the automation process.
- **Knowledge Base Integration (`puppeteerTool.ts`)**
  - Integrated `writeKnowledgeFileTool` (from `readwrite.ts`) into `puppeteerTool`.
  - Added input options (`saveKnowledgeFilename`, `saveFormat`, `saveMode`, `saveEncoding`) to allow users to optionally save scraped data directly to the knowledge base.
  - Handles formatting scraped data into JSON or basic CSV before saving.
  - Includes error handling and status reporting for the save operation in the tool's output.
- **Observability (`puppeteerTool.ts`)**
  - Integrated SigNoz tracing (`createAISpan`, `recordMetrics`) into `puppeteerTool`.
  - Creates a span for each tool execution, recording input parameters, key events (navigation, actions, saving), latency, final status (success/error), and exceptions.
  - Provides detailed observability into the tool's performance and behavior.
- **Tool Registration (`index.ts`)**
  - Imported and registered `puppeteerTool` in the main tool barrel file (`src/mastra/tools/index.ts`).
  - Added `puppeteerTool` to `allTools`, `allToolsMap`, and `toolGroups` for unified tool discovery and registration.

---

## [v0.0.14] - 2025-04-19

### Added

- **Agent Usage Standardization**
  - All agents (researchAgent, analystAgent, writerAgent, copywriterAgent, etc.) now use the `.generate()` method as the standard command for invoking agent logic within workflows and other orchestration code.
  - This change ensures consistency and type safety across all workflow steps and agent integrations.

#### Example Usage

The following code snippet demonstrates the new standard for invoking agents:

```typescript
// Correct usage for all agents in workflow steps:
const { text } = await researchAgent.generate(queryInput);
const { text } = await analystAgent.generate(researchResult);
const { text } = await writerAgent.generate(analysisResult);
const { text } = await copywriterAgent.generate(writingResult);
```

- All previous usages of `.run`, `.call`, `.chat`, or direct function invocation have been replaced with `.generate()` for clarity and compatibility with the Mastra agent API.

### Changed

- Updated all workflow steps in `multiagentWorkflow.ts` and related files to use `.generate()` for agent execution.
- Improved documentation and inline comments to clarify the `.generate()` pattern for future maintainers.

### Notes

- The `.generate()` method is now the **only supported way** to invoke agent logic in this codebase.
- This standardization prevents confusion and runtime errors related to agent invocation.
- Please update any custom agents or tools to implement a `.generate()` method if they do not already.

---

## [v0.0.13] - 2025-04-19

### Added

- **mcptool.ts**
  - Added `createMastraMcpTools` helper for robust async MCP tool loading, supporting multiple MCP servers (`mastra`, `sequentialthinking`, and a custom `socat` TCP relay).
  - Ensured only Mastra-native helpers and types are used (no `@agentic/mastra`).
  - Ready for direct use in agent and tool registry initialization.
  - Added `@smithery/toolbox` MCP server configuration. Smithery Toolbox MCP tools are now auto-discovered and available to agents.
  - Docker-based socat relay MCP server is now included and confirmed working.
  - Both Smithery.ai MCP tools and the custom Docker server are connected and operational, as verified by successful tool initialization logs.
  - Improved error handling and logging for MCP tool initialization.

- **index.ts (tool barrel)**
  - Integrated async MCP tool initialization using `createMastraMcpTools` in the extra tools section.
  - MCP tools are now loaded and available to agents via `allTools`, `allToolsMap`, and `toolGroups`.
  - Added `export * from "./mcptool";` for unified exports.
  - Provided clear comments and error handling for async tool loading.
  - MCP tools from Smithery.ai and Docker are now included in the unified tool registry and available to all agents.

### Changed

- **Polygon Tools**
  - Cleaned up and finalized Polygon tool schemas and registration.
  - Ensured all Polygon endpoints and schemas are patched and exported for agent use.

- **General**
  - Improved documentation and inline comments for MCP and Polygon tool integration.
  - Clarified async initialization pattern for tool registry to support MCP and other async tools.
  - Confirmed robust async initialization and registration of all MCP tools, including Smithery Toolbox and Docker relay, with successful connection and tool loading logs.

### Fixed

- Removed all references to `@agentic/mastra` in MCP tool loading to prevent cross-package errors.
- Ensured MCP tools are loaded asynchronously and safely, with robust error logging.
- Confirmed all tools (including MCP, Polygon, Reddit, etc.) are discoverable and usable by agents.
- Ensured all MCP servers (Smithery Toolbox and Docker) are reachable and tools are loaded without errors.
- Improved error logging for MCP initialization failures.

### Notes

- MCP tools now follow the Mastra pattern: async loading, explicit Zod schemas, and unified exports.
- Smithery.ai MCP tools and Docker-based MCP server are now fully integrated and operational in the Mastra tool registry.
- Initialization logs confirm all MCP tools are connected and available for agent use.
- All changes linted and type-checked after edits.
- Next steps: Continue to document new tool patterns and agent integration in this changelog for future maintainers.

---

## [v0.0.12] - 2025-04-19

### Added

- **arxiv.ts**
  - Implemented `arxiv_download_pdf` tool: Downloads a PDF for a given arXiv ID and saves it to disk using `fs-extra` and `ky`. Ensures directory creation and robust file writing.
  - All arXiv tools now have explicit Zod output schemas (`ArxivSearchOutputSchema`, `ArxivPdfUrlOutputSchema`, `ArxivDownloadPdfOutputSchema`).
  - Patched all arXiv tool output schemas in `createMastraArxivTools` for Mastra compatibility.
  - Improved `extractId` utility for robust arXiv ID parsing.
  - Cleaned up namespace and type exports for clarity.

- **polygon.ts**
  - Productionized MastraPolygonClient: Now requires and validates `POLYGON_API_KEY` from environment or config.
  - Added robust error handling for API failures.
  - Explicitly patched `tickerDetails` output schema for Mastra compatibility.
  - Exported `TickerDetailsSchema` for downstream use and type safety.

- **reddit.ts**
  - Expanded `SubredditPostSchema` to include all relevant Reddit post fields.
  - Added error handling to Reddit tool methods.
  - Patched `getSubredditPosts` output schema for Mastra compatibility.
  - Exported `SubredditPostSchema` for downstream use and type safety.

- **index.ts (tool barrel)**
  - Ensured all tools (`arxiv`, `polygon`, `reddit`, etc.) are exported using `export * from ...` for unified tool registration.
  - Added `POLYGON_API_KEY` to `envSchema` for environment validation.
  - Exported all relevant schemas (`TickerDetailsSchema`, `SubredditPostSchema`, etc.) for agent and workflow configs.
  - Confirmed all tools are discoverable via `allTools`, `allToolsMap`, and `toolGroups`.

- **Agent Integration**
  - Updated agent creation logic to resolve tools from `allToolsMap` using tool IDs.
  - Added robust error logging and throwing for missing tools in agent configs.
  - Ensured all tools (including new/updated ones) are available to agents via the barrel file.

### Changed

- **General**
  - Standardized tool registration and output schema patching across all Mastra tools.
  - Improved documentation and inline comments for tool and agent registration patterns.
  - Cleaned up and clarified environment variable requirements in `envSchema`.

### Fixed

- Ensured all tools have explicit output schemas and are patched at registration, preventing runtime errors in Mastra workflows.
- Fixed tool discovery and registration issues for new tools (arxiv, polygon, reddit) by updating the barrel file and tool initialization logic.

### Notes

- All new and updated tools follow the Mastra pattern: explicit Zod schemas, output schema patching, and unified exports.
- Agents now reliably resolve and use all registered tools, with clear error messages if a tool is missing.
- Next steps: Continue to lint and type-check after every file edit, and document any new tool or agent patterns in this changelog for future maintainers.

---

## [v0.0.11] - 2025-04-19 12:00 UTC

### Added

- **fileLogger.ts**  
  • Switched to `fs‑extra` (`ensureDirSync`/`ensureFileSync`) so `logs/mastra.log` is created automatically.  
  • Retains full JSON‑line format and log levels.

- **upstashLog.ts**  
  • Exposed `createUpstashLogger()` factory and `upstashLogger` default instance.  
  • Normalizes the Redis REST URL with `https://` to satisfy `new URL()`.  
  • Re‑exports `UpstashTransport` for advanced use.

- **consoleLogger.ts**  
  • Simple in‑process console transport with `debug`/`info`/`warn`/`error` and timestamped prefixes.

- **tracing.ts & signoz.ts**  
  • `initializeDefaultTracing()` auto‑instruments Node + graceful shutdown.  
  • `initSigNoz()` configures OTLP exporter, tracer + meter, periodic metric reader.

- **base.agent.ts**  
  • Imported and wired:
  - `consoleLogger`, `upstashLogger`, `fileLogger` under a unified `logger` API.  
  - OpenTelemetry via `initializeDefaultTracing()`.  
  - SigNoz tracer + meter via `initSigNoz()`.  
  • Created spans around agent lifecycle (`agent.create`, `agent.debug/info/warn/error`).  
  • Recorded metrics (`agent.creation.count`, `agent.creation.latency_ms`).  
  • **Voice integration is stubbed**—the `createGoogleVoice()` import and `voice` prop in the `Agent` constructor are commented out because real‑time streaming (connect, listen, speaker events) is not yet implemented.  

- **voice/googlevoice.ts & voice/index.ts**  
  • Exposed `createGoogleVoice()` and barrel‑exported from `index.ts`.  
  • Configured `CompositeVoice` with tool injection and global instructions.  
  • Did **not** hook into BaseAgent because real‑time support is pending.

### Fixed

- Avoid “File path does not exist” by auto‑creating directories/files in `fileLogger.ts`.  
- Prevent `ERR_INVALID_URL` in Upstash by prefixing missing `https://`.

### Notes

- Voice support is **half‑complete**. All voice factory code is in place, but in `base.agent.ts` it remains commented out.  
- **Next steps**:
  1. Wire a real‑time STT/TTS provider (e.g. Google streaming API).  
  2. Hook up `voice.connect()`, `voice.on("listen")`, `voice.on("speaker")`.  
  3. Pass the active `voice` instance into the `Agent` constructor.  
  4. Un‑comment the `voice` lines and verify end‑to‑end audio streaming.

## [v0.0.10] - 2025-04-16

### Added

- Full, type-safe support for OpenAI, Anthropic, and Ollama providers in provider.utils.ts and model.utils.ts, matching Google/Vertex patterns.
- Standard/default model configs for OpenAI (gpt-4o), Anthropic (claude-3.5-sonnet-2024-04-08), and Ollama (gemma3:4b) in config.types.ts.
- Provider/model instantiation logic now robustly uses options and environment variables for overrides.
- All lint/type errors checked and resolved after changes.
- New `createModelInstance` function added for streamlined model creation.

### Changed

- Refactored model.utils.ts and provider.utils.ts to ensure options are always read and passed to model instantiation for all providers.
- Updated config.types.ts to include future-proofed, extensible model/provider patterns for all major LLMs.

### Notes

- All providers (Google, Vertex, OpenAI, Anthropic, Ollama) are now fully modular, type-safe, and ready for agent config integration.
- Please continue to lint and type-check after every file edit as per project policy.

- Date: 2025-04-16
- Time: 18:00 UTC

## [v0.0.9] - 2025-04-16

### Added

- Comprehensive evals toolset in `tools/evals.ts` with SigNoz tracing: includes completeness, answer relevancy, content similarity, context precision, context position, tone consistency, keyword coverage, textual difference, faithfulness, and token count metrics.
- All eval tools output normalized scores, explanations, and are ready for agent/workflow integration.
- LlamaIndex tool output schema and type safety improvements.

### Changed

- Integrated SigNoz tracing into all eval tools and reinforced tracing in agent and tool workflows.
- Updated RL Trainer agent config and tool registration for robust RL workflows.
- Updated tool barrel (`tools/index.ts`) to ensure all schemas and tools are exported only once and are available for agent configs.

### Fixed

- Removed all duplicate schema/tool exports in `wikibase.ts`, `wikidata-client.ts`, `github.ts`, `llamaindex.ts`, and `evals.ts`.
- Fixed throttle type mismatches and replaced unsupported string methods for broader TypeScript compatibility.
- Lint and type errors resolved across all affected files.

## [v0.0.8] - 2025-04-14

### Fixed

- Vertex AI authentication and model instantiation now use GOOGLE_APPLICATION_CREDENTIALS for robust, cross-platform support (Windows included).
- provider.utils.ts updated to prefer GOOGLE_APPLICATION_CREDENTIALS and only fallback to inline credentials if necessary.
- Cleaned up .env recommendations: removed GOOGLE_CLIENT_EMAIL and GOOGLE_PRIVATE_KEY when using GOOGLE_APPLICATION_CREDENTIALS.
- Confirmed model.utils.ts and config.types.ts are compatible with new Vertex AI credential handling.
- All lint/type errors checked and resolved after changes.

### Changed

- Updated documentation and .env guidance for Vertex AI best practices.
- README and internal comments clarified for provider setup and troubleshooting.

- Date: 2025-04-16
- Time: 16:00 UTC

## [v0.0.7] - 2025-04-15  

- Integrated UpstashVector as a modular vector store alongside LibSQL for hybrid memory and RAG workflows.  
- Refactored workflowFactory.ts for type safety, tracing, error handling, and modular dynamic workflow creation.  
- Added and re-exported Upstash vector helpers in database/index.ts for best-practice access.  
- Implemented tracing wrappers for memory operations in database/index.ts using SigNoz.  
- Improved type safety and error handling in workflowFactory.ts and related workflow logic.  
- Ensured all lint/type errors are fixed after every file edit.  
- Updated README and documentation to reflect new memory, RAG, and workflow patterns.  
- Added csv-reader, docx-reader, tools  

- Date: 2025-04-15  
- Time: 15:00 UTC

## [v0.0.6] - 2025-04-15

### Added

- Comprehensive evals toolset in `tools/evals.ts` with SigNoz tracing: includes completeness, answer relevancy, content similarity, context precision, context position, tone consistency, keyword coverage, textual difference, faithfulness, and token count metrics.
- All eval tools output normalized scores, explanations, and are ready for agent/workflow integration.
- LlamaIndex tool output schema and type safety improvements.

### Changed

- Integrated SigNoz tracing into all eval tools and reinforced tracing in agent and tool workflows.
- Updated RL Trainer agent config and tool registration for robust RL workflows.
- Updated tool barrel (`tools/index.ts`) to ensure all schemas and tools are exported only once and are available for agent configs.

### Fixed

- Removed all duplicate schema/tool exports in `wikibase.ts`, `wikidata-client.ts`, `github.ts`, `llamaindex.ts`, and `evals.ts`.
- Fixed throttle type mismatches and replaced unsupported string methods for broader TypeScript compatibility.
- Lint and type errors resolved across all affected files.

## [v0.0.5] - 2025-04-15

### Added

- Full support for OpenAI and Anthropic providers in model and provider utilities, with strict Zod validation and type safety.
- Updated provider config schemas/types for all major LLM providers (Google, Vertex, OpenAI, Anthropic).
- Improved model instantiation logic to match @ai-sdk best practices for provider instance creation and environment variable usage.
- Expanded README with detailed architecture, agent, tool, memory, and observability documentation for AI assistants and contributors.
- Documented Windows OS context and workspace structure for onboarding and reproducibility.

### Changed

- Refactored model.utils.ts and provider.utils.ts for robust provider option handling and error-free instantiation.
- Updated config.types.ts and index.ts to export correct types and provider utilities for downstream use.
- README.md now includes explicit instructions for tool registration, agent config, tracing, and best practices for AI assistants.

### Fixed

- All lint and type errors related to provider/model instantiation and type mismatches.
- Ensured all tool schemas are patched and validated at registration.

### Version

- v0.9.1
- Date: 2025-04-15

## [v0.0.4] - 2025-04-15

### Added

- Productionized all eval tools in `src/mastra/tools/evals.ts` with Vertex AI LLM integration, robust prompts, JSON parsing, latency/model/tokens in output, and fallback heuristics.
- All eval tools are now imported and registered in the main tool barrel file (`src/mastra/tools/index.ts`), with output schemas patched for type safety.
- Moved `getMainBranchRef` from coreTools to extraTools for better separation of core and extra tools.
- Ensured all tools are discoverable via `allTools`, `allToolsMap`, and `toolGroups`.

### Changed

- Refactored tool registry to use `ensureToolOutputSchema` for all eval tools.
- Updated tool registry organization for clarity and maintainability.

### Version

- v0.9.0
- Date: 2025-04-15

## [v0.0.3] - 2025-04-14

### Added

- Comprehensive evals toolset in `tools/evals.ts` with SigNoz tracing: includes completeness, answer relevancy, content similarity, context precision, context position, tone consistency, keyword coverage, textual difference, faithfulness, and token count metrics.
- All eval tools output normalized scores, explanations, and are ready for agent/workflow integration.
- LlamaIndex tool output schema and type safety improvements.

### Changed

- Integrated SigNoz tracing into all eval tools and reinforced tracing in agent and tool workflows.
- Updated RL Trainer agent config and tool registration for robust RL workflows.
- Updated tool barrel (`tools/index.ts`) to ensure all schemas and tools are exported only once and are available for agent configs.

### Fixed

- Removed all duplicate schema/tool exports in `wikibase.ts`, `wikidata-client.ts`, `github.ts`, `llamaindex.ts`, and `evals.ts`.
- Fixed throttle type mismatches and replaced unsupported string methods for broader TypeScript compatibility.
- Lint and type errors resolved across all affected files.

## [v0.0.2] - 2025-04-14

### Added

- Comprehensive response schema for Architecture Agent
- Enhanced code documentation throughout agent configuration files
- Improved type safety with additional Zod schema definitions

### Changed

- Refactored agent configuration files to remove redundant `getToolsFromIds` function
- Centralized tool resolution in the Agent Factory
- Standardized agent configuration patterns across all agent types

### Fixed

- Removed duplicate code that was causing maintenance issues
- Improved code consistency across agent configuration files

### Security

- Updated dependencies to address potential vulnerabilities

## [v0.0.1] - 2025-04-01

### Added

- Initial release of DeanMachines Mastra Backend
- Support for multiple specialized AI agents
- Integration with various external tools and services
- Memory management for persistent agent context
- Workflow orchestration capabilities

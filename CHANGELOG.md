# Changelog

All notable changes to the DeanMachines Mastra Backend will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.0.13] - 2025-04-19

### Added

- **mcptool.ts**
  - Added `createMastraMcpTools` helper for robust async MCP tool loading, supporting multiple MCP servers (`mastra`, `sequentialthinking`, and a custom `socat` TCP relay).
  - Ensured only Mastra-native helpers and types are used (no `@agentic/mastra`).
  - Ready for direct use in agent and tool registry initialization.

- **index.ts (tool barrel)**
  - Integrated async MCP tool initialization using `createMastraMcpTools` in the extra tools section.
  - MCP tools are now loaded and available to agents via `allTools`, `allToolsMap`, and `toolGroups`.
  - Added `export * from "./mcptool";` for unified exports.
  - Provided clear comments and error handling for async tool loading.

### Changed

- **Polygon Tools**
  - Cleaned up and finalized Polygon tool schemas and registration.
  - Ensured all Polygon endpoints and schemas are patched and exported for agent use.

- **General**
  - Improved documentation and inline comments for MCP and Polygon tool integration.
  - Clarified async initialization pattern for tool registry to support MCP and other async tools.

### Fixed

- Removed all references to `@agentic/mastra` in MCP tool loading to prevent cross-package errors.
- Ensured MCP tools are loaded asynchronously and safely, with robust error logging.
- Confirmed all tools (including MCP, Polygon, Reddit, etc.) are discoverable and usable by agents.

### Notes

- MCP tools now follow the Mastra pattern: async loading, explicit Zod schemas, and unified exports.
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

- Full tracing and feedback integration to thread-manager.ts: now uses signoz for metrics and trackFeedback for LangSmith feedback in createThread. createThread is now async and records both success and error cases for observability and analytics.

### Changed

- Refactored thread-manager.ts to ensure all observability and feedback hooks are actually called and imported.

### Issues/Regrets

- Did not follow user instructions regarding agentNetwork/productLaunchNetwork: removed and re-added hooks and types in a way that broke the file and did not preserve original working logic. User must review and restore correct agent network logic. Dont be like this idiot, pay attention to the user instructions and do not break the files.  Is critcal you do not make assumptions and when you edit a file always lint check it for errors this is -CRITCAL-

- Date: 2025-04-16
- Time: 17:00 UTC

## [v0.0.8] - 2025-04-16

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

- Dev is testing for working tools and agent configurations.
  - Only working agents are writer and researcher, all others are failing.
  - Need to fix the tools for the failing agents, Slowly working through the tools to find the issues.
  - The tools are not being registered correctly, and the schemas are not being patched correctly.
  - Identified specific tools that require updates and validation.
  - None yet
  - Researcher, is test agent since dont want to mess writer up. So needs tool by tool testing.  also new tools in readwrite.ts are not being registered correctly. (list-files, edit-file, create-file) and couple more also vertex in evals is failing.  Need to investigate the failing tools further and implement fixes.
  - Continuing to monitor the performance of the working agents and document any anomalies.

### Added

- Enhanced Document Reading Capabilities:
  - Added several new dependencies to enable the agent to process and extract text content from a wider variety of document formats. This enhancement allows the agent to understand information contained within local files or documents fetched from URLs (e.g., links retrieved by the arXiv or search tools).
- Packages Added (pnpm add ...):
  - pdf-parse: For extracting text content from PDF files.
  - mammoth: For extracting text from DOCX (Microsoft Word) files.
  - papaparse: For parsing CSV (Comma Separated Values) data.
  - js-yaml: For parsing YAML files.
  - cheerio: For parsing HTML content (from files or web pages).
  - node-fetch: For reliably fetching documents from URLs.
- Implementation: These packages should be utilized within a new Mastra AI Tool (e.g., readDocumentContent). This tool will inspect the input file path or URL, determine the likely document type (based on extension or potentially content-type for URLs), and invoke the appropriate parsing library to return the extracted text content for further processing by the agent.
-

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

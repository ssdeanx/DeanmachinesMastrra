/**
 * Research Agent Configuration
 *
 * This module defines the configuration for the Research Agent, which specializes in
 * gathering, synthesizing, and analyzing information from various sources.
 */

import { z, type ZodTypeAny } from "zod";
import type { Tool } from "@mastra/core/tools";
import type { RestOptions } from "./rest.options";
import {
  BaseAgentConfig,
  DEFAULT_MODELS,
  defaultResponseValidation,
} from "./config.types";

/**
 * Configuration for retrieving relevant tools for the agent
 *
 * @param toolIds - Array of tool identifiers to include
 * @param allTools - Map of all available tools
 * @returns Record of tools mapped by their IDs
 * @throws {Error} When required tools are missing
 */
export function getToolsFromIds(
  toolIds: string[],
  allTools: ReadonlyMap<
    string,
    Tool<ZodTypeAny | undefined, ZodTypeAny | undefined>
  >
): Record<string, Tool<ZodTypeAny | undefined, ZodTypeAny | undefined>> {
  const tools: Record<
    string,
    Tool<ZodTypeAny | undefined, ZodTypeAny | undefined>
  > = {};
  const missingTools: string[] = [];

  for (const id of toolIds) {
    const tool = allTools.get(id);
    if (tool) {
      tools[id] = tool;
    } else {
      missingTools.push(id);
    }
  }

  if (missingTools.length > 0) {
    throw new Error(`Missing required tools: ${missingTools.join(", ")}`);
  }

  return tools;
}

/**
 * Configuration for the Research Agent.
 *
 * @remarks
 * The Research Agent focuses on information gathering and synthesis
 * using web searches, document analysis, and file operations.
 *
 * @property {string[]} toolIds - The list of tool IDs required by the agent.
 */
export const researchAgentConfig: BaseAgentConfig = {
  id: "research-agent",
  name: "Research Agent",
  description:
    "Specialized in finding, gathering, and synthesizing information from various sources.",
  modelConfig: DEFAULT_MODELS.GOOGLE_MAIN,
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
    "read-file", // Corrected ID
    "write-file", // Corrected ID
    "tavily-search", // Specific search tool
    "brave-search", // Specific search tool
    "vector-query", // Specific vector tool
    "google-vector-query", // Specific vector tool
    "filtered-vector-query", // Specific vector tool
    "search-documents", // Specific document tool
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
    "wikipedia_get_page_summary",
    "context-precision-eval",
    "execute_code",

  ],
  restOptions: {
    timeout: 30000,
    stream: true,
    responseType: 'json', // parse agent output as JSON
    maxRetries: 2,
    instructions: `You are a research assistant. For each query, perform thorough web and document research, identify credible sources, and synthesize key findings. Respond strictly in JSON format following the researchResponseSchema: an object with "topic", "insights", and "confidence" fields. Do not include any additional text.`,
    headers: { 'X-Agent-Type': 'research' },
  } as RestOptions,

};

/**
 * Schema for structured research agent responses
 */
// Adaptable findings schema
const findingSchema = z.object({
  topic: z.string().describe("Specific topic or area of research").optional(),
  insights: z.string().describe("Key insights discovered").optional(),
  confidence: z.number().min(0).max(1).describe("Confidence level in this finding (0-1)").optional(),
}).passthrough(); // Allow extra fields

// Adaptable sources schema
const sourceSchema = z.object({
  title: z.string().describe("Source title").optional(),
  url: z.string().optional().describe("Source URL if applicable"),
  type: z.string().describe("Source type (article, paper, document, etc.)").optional(),
  relevance: z.number().min(0).max(1).optional().describe("Relevance score (0-1)"),
}).passthrough(); // Allow extra fields

// Main adaptable response schema
export const researchResponseSchema = z.object({
  summary: z.string().describe("Concise summary of the research findings").optional(),
  findings: z.array(findingSchema).describe("Detailed findings from the research").optional(),
  sources: z.array(sourceSchema).describe("Sources used in the research").optional(),
  gaps: z.array(z.string()).optional().describe("Identified information gaps"),
  recommendations: z.array(z.string()).optional().describe("Recommendations based on findings"),
  nextSteps: z.array(z.string()).optional().describe("Suggested next research steps"),
}).passthrough(); // Allow extra top-level fields


/**
 * Type for structured responses from the Research agent
 */
export type ResearchResponse = z.infer<typeof researchResponseSchema>;

/**
 * Type for the Research Agent configuration
 */
export type ResearchAgentConfig = typeof researchAgentConfig;

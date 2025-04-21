import fs from "fs-extra";
import path from "path";
import jsonld from "jsonld";
import { z } from "zod";
import { createTool } from "@mastra/core/tools";

const KG_PATH = path.join(__dirname, "knowledge-graph.json");

// Zod Schemas
export const AgentSchema = z.object({
  id: z.string(),
  label: z.string(),
  agentType: z.string(),
  skills: z.array(z.string()),
});
export const AgentListSchema = z.array(AgentSchema);
export const RelationshipSchema = z.object({
  source: z.string(),
  target: z.string(),
  type: z.string(),
  since: z.string().optional(),
  weight: z.number().optional(),
});
export const RelationshipListSchema = z.array(RelationshipSchema);

async function loadKnowledgeGraph() {
  const raw = await fs.readFile(KG_PATH, "utf-8");
  const doc = JSON.parse(raw);
  // Expand JSON-LD for easier querying
  const expanded = await jsonld.expand(doc);
  return { doc, expanded };
}

function listAgents(doc: any) {
  return doc.entities.map((agent: any) => ({
    id: agent.id,
    label: agent.label,
    agentType: agent.agentType,
    skills: agent.skills,
  }));
}

function findAgentsWithSkill(doc: any, skill: string) {
  return doc.entities.filter((agent: any) => agent.skills && agent.skills.includes(skill));
}

function getCollaborators(doc: any, agentId: string) {
  const agent = doc.entities.find((a: any) => a.id === agentId);
  if (!agent || !agent.collaborates_with) return [];
  return agent.collaborates_with.map((id: string) =>
    doc.entities.find((a: any) => a.id === id)
  );
}

function listRelationships(doc: any, type?: string) {
  if (!doc.relationships) return [];
  return type
    ? doc.relationships.filter((rel: any) => rel.type === type)
    : doc.relationships;
}

// Tool Wrappers
export const listAgentsTool = createTool({
  id: "listAgents",
  description: "List all agents in the knowledge graph",
  inputSchema: z.object({}),
  outputSchema: AgentListSchema,
  execute: async () => {
    const { doc } = await loadKnowledgeGraph();
    return listAgents(doc);
  }
});

export const findAgentsWithSkillTool = createTool({
  id: "findAgentsWithSkill",
  description: "Find agents with a specific skill",
  inputSchema: z.object({ skill: z.string() }),
  outputSchema: AgentListSchema,
  execute: async ({ skill }) => {
    const { doc } = await loadKnowledgeGraph();
    return findAgentsWithSkill(doc, skill);
  }
});

export const getCollaboratorsTool = createTool({
  id: "getCollaborators",
  description: "Get collaborators for a given agent",
  inputSchema: z.object({ agentId: z.string() }),
  outputSchema: AgentListSchema,
  execute: async ({ agentId }) => {
    const { doc } = await loadKnowledgeGraph();
    return getCollaborators(doc, agentId);
  }
});

export const listRelationshipsTool = createTool({
  id: "listRelationships",
  description: "List relationships in the knowledge graph, optionally filtered by type",
  inputSchema: z.object({ type: z.string().optional() }),
  outputSchema: RelationshipListSchema,
  execute: async ({ type }) => {
    const { doc } = await loadKnowledgeGraph();
    return listRelationships(doc, type);
  }
});

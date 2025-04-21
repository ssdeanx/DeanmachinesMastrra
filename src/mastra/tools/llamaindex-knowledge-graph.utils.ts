import fs from 'fs-extra';
import path from 'path';
import { parseInput, stringifyOutput, SupportedFormat } from '../agents/format.utils';

export type KnowledgeGraph = {
  entities: Array<{ id: string; type: string; label: string; properties?: Record<string, any> }>;
  relationships: Array<{ id: string; source: string; target: string; type: string; properties?: Record<string, any> }>;
};

const DEFAULT_KG_PATH = path.resolve(process.cwd(), 'knowledge-graph.json');

export async function createKnowledgeGraphFile(kg: KnowledgeGraph, filePath: string = DEFAULT_KG_PATH) {
  await fs.writeFile(filePath, stringifyOutput(kg, 'json'), 'utf-8');
  return filePath;
}

export async function readKnowledgeGraphFile(filePath: string = DEFAULT_KG_PATH): Promise<KnowledgeGraph> {
  const raw = await fs.readFile(filePath, 'utf-8');
  return parseInput(raw, 'json') as KnowledgeGraph;
}

export function ensureKnowledgeGraphFile(filePath: string = DEFAULT_KG_PATH) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, stringifyOutput({ entities: [], relationships: [] }, 'json'), 'utf-8');
  }
}

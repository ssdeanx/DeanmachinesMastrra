// Example loader for all supported prompt formats in src/mastra/agents/loaders
// Usage: Run this file with ts-node or import its functions in your agent setup

import { parseInput, SupportedFormat } from '../format.utils';
import { createAdvancedAgent } from '../advanced.base.agent';

// Helper to determine format from file extension
function getFormatFromExtension(filename: string): SupportedFormat {
  if (filename.endsWith('.json')) return 'json';
  if (filename.endsWith('.yaml') || filename.endsWith('.yml')) return 'yaml';
  if (filename.endsWith('.xml')) return 'xml';
  if (filename.endsWith('.txt')) return 'txt';
  if (filename.endsWith('.md')) return 'md';
  throw new Error('Unsupported file extension: ' + filename);
}

// Example usage for each loader file
const promptFiles = [
  './src/mastra/agents/loaders/prompt.json',
  './src/mastra/agents/loaders/prompt.txt',
  './src/mastra/agents/loaders/prompt.md',
];

const config: any = {
  id: 'example-agent',
  name: 'ExampleAgent',
  toolIds: ['search', 'summarize'],
  modelConfig: { provider: 'openai', model: 'gpt-4' },
};

function loadAgentWithPromptFile(promptFile: string) {
  const format = getFormatFromExtension(promptFile);
  const prompt = parseInput(promptFile, format);
  // If JSON, treat as config; otherwise use as instructions
  if (format === 'json' && typeof prompt === 'object') {
    return createAdvancedAgent(prompt);
  } else {
    return createAdvancedAgent({ ...config, instructions: prompt });
  }
}

// Example: Load all agents from all prompt files
declare const require: any;
if (require.main === module) {
  for (const file of promptFiles) {
    try {
      const agent = loadAgentWithPromptFile(file);
      console.log(`Loaded agent from ${file}:`, agent);
    } catch (err) {
      console.error(`Failed to load agent from ${file}:`, err);
    }
  }
}

export { loadAgentWithPromptFile, getFormatFromExtension };

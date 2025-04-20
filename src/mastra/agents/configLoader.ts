import { parseInput, SupportedFormat } from './format.utils';
import fs from 'fs-extra';

/**
 * Loads an agent config from a file (JSON, YAML, or XML) and returns the parsed config object.
 * @param filePath Path to the config file
 * @param format Format of the config file: 'json', 'yaml', or 'xml'
 */
export function loadAgentConfigFromFile(filePath: string, format: SupportedFormat): any {
  const raw = fs.readFileSync(filePath, 'utf-8');
  return parseInput(raw, format);
}

/**
 * Async version for future use
 */
export async function loadAgentConfigFromFileAsync(filePath: string, format: SupportedFormat): Promise<any> {
  const raw = await fs.readFile(filePath, 'utf-8');
  return parseInput(raw, format);
}


/**
 * Example usage:
 *
 * const config = loadAgentConfigFromFile('./agents/myAgent.yaml', 'yaml');
 * const agent = createAdvancedAgent(config, ...);
 */

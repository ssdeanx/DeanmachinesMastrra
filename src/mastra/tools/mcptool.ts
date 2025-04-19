import { MCPConfiguration } from "@mastra/mcp";
import { Tool } from "@mastra/core/tools";

/**
 * Helper to create Mastra-compatible MCP tools for use with agents.
 * This will connect to the default MCP docs server and a custom socat TCP relay (or your custom config)
 * and expose all available MCP tools as a plain object.
 */
export async function createMastraMcpTools(config?: {
  servers?: Record<string, any>;
  timeout?: number;
}): Promise<Record<string, Tool<any, any>>> {
  const mcp = new MCPConfiguration({
    servers: config?.servers ?? {
      mastra: {
        command: "npx",
        args: ["-y", "@mastra/mcp-docs-server@latest"],
      },
      docker: {
        command: "docker",
        args: [
          "run", "-i", "--rm", "alpine/socat",
          "STDIO", "TCP:host.docker.internal:8811"
        ],
      },
    },
    timeout: config?.timeout ?? 30000,
  });

  // This returns a plain object of Mastra Tool definitions, ready for agent use
  return await mcp.getTools();
}
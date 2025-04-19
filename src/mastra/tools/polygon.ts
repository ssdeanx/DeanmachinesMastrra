import { PolygonClient } from '@agentic/polygon';
import { aiFunction, AIFunctionsProvider, getEnv } from "@agentic/core";
import { createMastraTools } from "@agentic/mastra";
import { z } from "zod";

/**
 * Output schema for Polygon ticker details.
 */
export const TickerDetailsSchema = z.object({
  ticker: z.string(),
  name: z.string(),
  market: z.string(),
  locale: z.string(),
  primary_exchange: z.string().optional(),
  type: z.string().optional(),
  active: z.boolean().optional(),
  currency_name: z.string().optional(),
  cik: z.string().optional(),
  composite_figi: z.string().optional(),
  share_class_figi: z.string().optional(),
  last_updated_utc: z.string().optional(),
  // Add more fields as needed based on Polygon API response
}).partial();

/**
 * Mastra-compatible Polygon client with error handling.
 */
export class MastraPolygonClient extends AIFunctionsProvider {
  private readonly client: PolygonClient;

  /**
   * @param apiKey Polygon.io API key (required)
   */
  constructor({ apiKey }: { apiKey: string }) {
    super();
    if (!apiKey) throw new Error("Polygon API key is required");
    this.client = new PolygonClient({ apiKey });
  }

  /**
   * Get details for a given stock ticker symbol using Polygon.io.
   * @param ticker The stock ticker symbol (e.g., AAPL, MSFT)
   */
  @aiFunction({
    name: "tickerDetails",
    description: "Get details for a given stock ticker symbol using Polygon.io.",
    inputSchema: z.object({
      ticker: z.string().describe("The stock ticker symbol (e.g., AAPL, MSFT)")
    }),
  })
  async tickerDetails({ ticker }: { ticker: string }) {
    try {
      const details = await this.client.tickerDetails({ ticker });
      // Optionally validate/massage the response here
      return details;
    } catch (error: any) {
      return {
        error: true,
        message: error?.message || "Unknown error fetching ticker details.",
      };
    }
  }
}

/**
 * Helper to create Mastra-compatible Polygon tools.
 * @param config.apiKey Polygon.io API key (optional if set in env as POLYGON_API_KEY)
 */
export function createMastraPolygonTools(config: { apiKey?: string } = {}) {
  const apiKey = config.apiKey ?? getEnv("POLYGON_API_KEY");
  if (!apiKey) throw new Error("POLYGON_API_KEY is required in env or config");
  const polygonClient = new MastraPolygonClient({ apiKey });
  const mastraTools = createMastraTools(polygonClient);
  if (mastraTools.tickerDetails) {
    (mastraTools.tickerDetails as any).outputSchema = TickerDetailsSchema;
  }
  return mastraTools;
}

export { createMastraTools };
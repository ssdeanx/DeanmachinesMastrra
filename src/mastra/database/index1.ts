/**
 * Database configuration for memory persistence using Upstash Redis.
 *
 * This module sets up the Upstash Redis adapter for Mastra memory persistence,
 * allowing agent conversations and context to be stored reliably.
 */

import { UpstashStore } from "@mastra/upstash";
import { Memory } from "@mastra/memory";
import type { MastraStorage, MastraVector } from "@mastra/core";
import { createLogger } from "@mastra/core/logger";
import { Index as UpstashVectorIndex } from "@upstash/vector";

const logger = createLogger({ name: "Memory", level: "debug" });

logger.info("Initializing Memory with Upstash Redis storage");

// Define the memory configuration type
export interface MemoryConfig {
  lastMessages: number;
  semanticRecall: {
    topK: number;
    messageRange: {
      before: number;
      after: number;
    };
  };
  workingMemory: {
    enabled: boolean;
    type: "text-stream";
  };
  threads: {
    generateTitle: boolean;
  };
}

// Default memory configuration that works well for most agents
const defaultMemoryConfig: MemoryConfig = {
  lastMessages: 200,
  semanticRecall: {
    topK: 8,
    messageRange: {
      before: 4,
      after: 2,
    },
  },
  workingMemory: {
    enabled: true,
    type: "text-stream",
  },
  threads: {
    generateTitle: true,
  },
};

/**
 * Creates a new Memory instance with Upstash Redis storage and vector capabilities.
 * @param options Memory configuration options
 * @returns Configured Memory instance
 */
export function createMemory(
  options: Partial<MemoryConfig> = defaultMemoryConfig
): Memory {
  // Initialize Upstash Redis storage
  const storage = new UpstashStore({
    url: `https://${process.env.UPSTASH_REDIS_REST_URL}` || "file:.mastra/mastra.db",
    token: process.env.UPSTASH_REDIS_REST_TOKEN! || "default-token",
  });

  // Initialize Upstash Vector store for semantic search
  const vector = new UpstashVectorIndex({
    url: process.env.UPSTASH_VECTOR_REST_URL! || "file:.mastra/mastra.db",
    token: process.env.UPSTASH_VECTOR_REST_TOKEN! || "default-token",
  }) as unknown as MastraVector;

  return new Memory({
    storage: storage as MastraStorage,
    vector,
    options,
  });
}

// Export shared memory instance
export const sharedMemory = createMemory();

// Re-export Memory type for convenience
export type { Memory };

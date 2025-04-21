/**
 * Runtime and REST options for advanced agent operations
 *
 * Best-practice options for AI agent REST/runtime configuration.
 */
export interface RestOptions {
  abortSignal?: AbortSignal;
  headers?: Record<string, string>;
  timeout?: number;
  maxRetries?: number;
  experimental_output?: unknown;
  instructions?: string;
  toolsets?: unknown;
  stream?: boolean;
  onProgress?: (chunk: any) => void;
  queryParams?: Record<string, string | number>;
  responseType?: 'json' | 'text' | 'blob';
}

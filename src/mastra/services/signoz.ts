/**
 * SigNoz Integration Service for Mastra
 *
 * This module provides OpenTelemetry instrumentation for the DeanMachines AI platform
 * specifically configured to work with SigNoz as the observability backend.
 */
import { env } from 'process';
import { createLogger } from '@mastra/core/logger';
import * as api from '@opentelemetry/api';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import {
  BatchSpanProcessor,
  SimpleSpanProcessor,
  ConsoleSpanExporter,
  SpanProcessor
} from '@opentelemetry/sdk-trace-base';
import {
  OTLPMetricExporter,
} from '@opentelemetry/exporter-metrics-otlp-proto';
import { PeriodicExportingMetricReader, MeterProvider } from '@opentelemetry/sdk-metrics';
import { getNodeAutoInstrumentations as getInstrumentation } from '@opentelemetry/auto-instrumentations-node';

// Import types from the types module
import { 
  OtelConfig, 
  TokenInfo, 
  OTelAttributeNames,
  SpanStatusCode
} from './types';

// Configure logger for SigNoz service
const logger = createLogger({ name: 'signoz-service', level: 'info' });

// Global SDK tracers and providers
let tracerProvider: NodeTracerProvider | null = null;
let tracer: api.Tracer | null = null;

/**
 * Initialize OpenTelemetry tracing for SigNoz
 *
 * @param config - Mastra telemetry configuration
 * @returns The configured tracer and meter for creating spans and metrics, or null if disabled
 */
export function initSigNoz(config: OtelConfig): { tracer: api.Tracer | null; meter: MeterProvider | null } {
  // Skip if explicitly disabled
  if (config.enabled === false) {
    logger.info('SigNoz tracing is disabled');
    return { tracer: null, meter: null };
  }
  
  // Use existing tracer if already initialized
  if (tracer) {
    return { tracer, meter: null };
  }

  try {
    // Get configuration values with fallbacks
    const serviceName = config.serviceName || 'deanmachines-ai';
    const endpoint = config.export?.endpoint || 
                    env.OTEL_EXPORTER_OTLP_ENDPOINT || 
                    'http://localhost:4318/v1/traces';
    const headers = config.export?.headers || {};
    
    logger.info(`Initializing SigNoz tracing for service: ${serviceName}`, { endpoint });

    // Create resource with required attributes for SigNoz using resourceFromAttributes (SDK 2.0)
    const resource = resourceFromAttributes({
      [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
      [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: env.NODE_ENV || 'development',
    });

    // Configure OTLP exporter for SigNoz
    const otlpExporter = new OTLPTraceExporter({
      url: endpoint,
      headers,
    });
    
    // Create array of span processors for SDK v2.0
    const processors: SpanProcessor[] = [];
    
    // Add BatchSpanProcessor for better performance
    processors.push(new BatchSpanProcessor(otlpExporter));
    
    // For development, add console exporter
    if (env.NODE_ENV !== 'production') {
      processors.push(new SimpleSpanProcessor(new ConsoleSpanExporter()));
      logger.debug('Added console span exporter for debugging');
    }

    // Initialize tracer provider with the resource and processors (SDK v2.0 pattern)
    tracerProvider = new NodeTracerProvider({
      resource,
      spanProcessors: processors
    });

    // Register the provider
    tracerProvider.register();

    // Create a global tracer instance
    tracer = api.trace.getTracer('deanmachines-tracer');
    
    logger.info('SigNoz tracing initialized successfully');

    // ─── METRICS SETUP ───────────────────────────────────────────────
    const metricExporter = new OTLPMetricExporter({
      url: env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT || endpoint.replace('/v1/traces', '/v1/metrics'),
      headers,
    });

    // Create a periodic reader for metrics export
    const metricReader = new PeriodicExportingMetricReader({
      exporter: metricExporter,
      exportIntervalMillis: config.export?.metricsInterval ?? 60000,
    });

    const meterProvider = new MeterProvider({
      resource,
      views: [], // add any custom views here
      readers: [metricReader],
    });
    if (env.NODE_ENV !== 'production') {
      logger.debug('SigNoz metrics exporter configured');
    }

    return { tracer, meter: meterProvider };
    
  } catch (error) {
    logger.error('Failed to initialize SigNoz tracing', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    return { tracer: null, meter: null };
  }
}

/**
 * Get the current tracer instance
 *
 * @returns The global tracer instance
 */
export function getTracer(): api.Tracer {
  if (!tracer) {
    throw new Error('SigNoz tracing has not been initialized. Call initSigNoz first.');
  }
  return tracer;
}

/**
 * Create a new span for monitoring AI operations
 * 
 * @param name - Name of the operation
 * @param attributes - Additional attributes to include
 * @returns The created span
 */
export function createAISpan(
  name: string, 
  attributes: Record<string, string | number | boolean> = {}
): api.Span {
  if (!tracer) {
    logger.warn('Creating span without initialized SigNoz tracing');
    // In SDK 2.0, create a non-recording span differently
    return api.trace.getTracer('no-op').startSpan(name);
  }
  
  return tracer.startSpan(name, { 
    attributes: {
      'ai.operation': name,
      ...attributes
    }
  });
}

/**
 * Record LLM usage information on a span
 * 
 * @param span - The span to record metrics on
 * @param tokenInfo - Token usage information
 * @param latencyMs - Latency in milliseconds
 */
export function recordLlmMetrics(
  span: api.Span,
  tokenInfo?: TokenInfo,
  latencyMs?: number
): void {
  if (!span) return;
  
  if (tokenInfo?.promptTokens !== undefined) {
    span.setAttribute(OTelAttributeNames.PROMPT_TOKENS, tokenInfo.promptTokens);
  }
  
  if (tokenInfo?.completionTokens !== undefined) {
    span.setAttribute(OTelAttributeNames.COMPLETION_TOKENS, tokenInfo.completionTokens);
  }
  
  if (tokenInfo?.totalTokens !== undefined) {
    span.setAttribute(OTelAttributeNames.TOTAL_TOKENS, tokenInfo.totalTokens);
  }
  
  if (latencyMs !== undefined) {
    span.setAttribute(OTelAttributeNames.LATENCY_MS, latencyMs);
  }
}

/**
 * Record completion of an AI operation with metrics
 * 
 * @param span - The active span
 * @param metrics - Performance metrics to record
 */
export function recordMetrics(
  span: api.Span,
  metrics: {
    tokens?: number;
    latencyMs?: number;
    status?: 'success' | 'error';
    errorMessage?: string;
  }
): void {
  if (!span) return;
  
  if (metrics.tokens !== undefined) {
    span.setAttribute(OTelAttributeNames.TOTAL_TOKENS, metrics.tokens);
  }
  
  if (metrics.latencyMs !== undefined) {
    span.setAttribute(OTelAttributeNames.LATENCY_MS, metrics.latencyMs);
  }
  
  if (metrics.status === 'error' && metrics.errorMessage) {
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: metrics.errorMessage
    });
  } else {
    span.setStatus({
      code: SpanStatusCode.OK
    });
  }
}

/**
 * Gracefully shut down SigNoz tracing
 */
export async function shutdownSigNoz(): Promise<void> {
  if (tracerProvider) {
    try {
      logger.info('Shutting down SigNoz tracing');
      await tracerProvider.shutdown();
      logger.info('SigNoz tracing shutdown complete');
    } catch (error) {
      logger.error('Error shutting down SigNoz tracing', { error });
    }
  }
}

/**
 * Create a span for tracing an HTTP request
 * 
 * @param method - HTTP method
 * @param url - Request URL
 * @param attributes - Additional attributes
 * @returns The created span
 */
export function createHttpSpan(
  method: string,
  url: string,
  attributes: Record<string, string | number | boolean> = {}
): api.Span {
  if (!tracer) {
    return api.trace.getTracer('no-op').startSpan(`HTTP ${method}`);
  }
  
  try {
    const urlObj = new URL(url);
    return tracer.startSpan(`HTTP ${method}`, {
      attributes: {
        'http.method': method,
        'http.url': url,
        'http.host': urlObj.host,
        'http.scheme': urlObj.protocol.replace(':', ''),
        'http.target': urlObj.pathname,
        ...attributes
      }
    });
  } catch (error) {
    // If URL parsing fails, fall back to simpler attributes
    return tracer.startSpan(`HTTP ${method}`, {
      attributes: {
        'http.method': method,
        'http.url': url,
        ...attributes
      }
    });
  }
}

// Export a simplified interface
export default {
  init: initSigNoz,
  getTracer,
  createSpan: createAISpan,
  createHttpSpan,
  recordLlmMetrics,
  recordMetrics,
  shutdown: async () => {
    if (tracerProvider) await tracerProvider.shutdown();
    // also shutdown metric reader if needed
  }
};
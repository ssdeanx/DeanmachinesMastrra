/**
 * Telemetry and Observability Services
 *
 * This module exports all telemetry and observability services used by the DeanMachines AI Platform.
 * These services are responsible for logging, tracing, and monitoring LLM operations.
 */

// Export OpenTelemetry types and functions
export * from './types';

// Export LangChain integration
export * from './langchain';

// Export Langfuse service for LLM tracing
export { langfuse, LangfuseService } from './langfuse';

// Export LangSmith services for evaluations and tracing
export { 
  configureLangSmithTracing, 
  createLangSmithRun, 
  trackFeedback 
} from './langsmith';

// Export SigNoz for OpenTelemetry integration
export { default as signoz } from './signoz';
export { 
  initSigNoz, 
  getTracer as getSigNozTracer, // Renamed export to avoid conflict 
  createAISpan, 
  createHttpSpan,
  recordMetrics,
  recordLlmMetrics,
  shutdownSigNoz 
} from './signoz';



/**
 * Initialize all observability services
 * @param config - Configuration options
 * @returns Object containing initialized services
 */
import * as api from "@opentelemetry/api";
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { configureLangSmithTracing } from "./langsmith"; // Assuming configureLangSmithTracing returns something specific
import { initializeDefaultTracing } from "./tracing"; // Assuming getOpenTelemetrySdk returns something specific
import { initSigNoz } from "./signoz"; // Assuming initSigNoz is void or returns something else
// Assuming the getTracer imported from './signoz' is the intended one for use within initObservability
import { getTracer as getSigNozTracer } from './signoz'; 
import { langfuse as langfuseService } from './langfuse'; // Assuming langfuse is the service instance


/**
 * Initialize all observability services
 * @param config - Configuration options
 * @returns Object containing initialized services
 */
export function initObservability(config: {
  langfuseEnabled?: boolean;
  langsmithEnabled?: boolean;
  signozEnabled?: boolean;
  otelEnabled?: boolean;
  serviceName?: string;
  environment?: string;
  export?: { // Add the optional export property
    endpoint?: string;
    headers?: Record<string, string>;
  };
}) {
  const services: {
    langfuse: typeof langfuseService | null;
    langsmith: ReturnType<typeof configureLangSmithTracing> | null; // Use ReturnType or the actual type
    signoz: api.Tracer | null; // Assuming getTracer returns Tracer | null
  } = {
    langfuse: null,
    langsmith: null,
    signoz: null,
  };
  const serviceName = process.env.MASTRA_SERVICE_NAME || config.serviceName || 'deanmachines-ai-mastra';
  const tracesEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || config.export?.endpoint || 'http://localhost:4318/';
  const metricsEndpoint = process.env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT || tracesEndpoint.replace('/v1/traces', '/v1/metrics');
  const headers = config.export?.headers || {};
  // Get service name and environment from config or environment variables

  const environment = config.environment || process.env.NODE_ENV || 'development';
  // Log the environment to ensure it's read (useful for debugging setup)
  console.log(`Configuring observability for environment: ${environment}`);

  // Initialize OpenTelemetry if enabled (most general, initialize first)
  if (config.otelEnabled !== false) {
    // Assuming initializeDefaultTracing sets up the global provider and returns the SDK
    initializeDefaultTracing(); 
  }

  // Initialize Langfuse if enabled
  if (config.langfuseEnabled !== false) {
    // Assuming langfuse is directly usable after import or needs initialization
    services.langfuse = langfuseService; 
  }

  // Initialize LangSmith if enabled
  if (config.langsmithEnabled !== false) {
    services.langsmith = configureLangSmithTracing({
      projectName: serviceName,
      // Ensure 'enabled' is explicitly passed if the function expects it
      // enabled: true // This might be redundant if the function enables by default
    });
  }

  // Initialize SigNoz if enabled
  if (config.signozEnabled !== false) {
    initSigNoz({
      serviceName,
      // Pass the export config down to initSigNoz, adding the required 'type'
      export: config.export ? { ...config.export, type: "otlp" } : undefined
      // Ensure 'enabled' is explicitly passed if the function expects it
      // enabled: true // This might be redundant if the function enables by default
    });
    // Use the imported getTracer from signoz.ts
    services.signoz = getSigNozTracer();
  }

  return services;
}

/**
 * Get the current tracer instance
 * 
 * @param name - Name of the tracer (defaults to service name)
 * @param version - Version of the tracer (defaults to service version)
 */
export function getTracer(name?: string, version?: string): api.Tracer {
  // Accessing _resource is using an internal property, consider alternatives if possible
  const serviceName = name || process.env.OTEL_SERVICE_NAME || 'default-tracer';
  const serviceVersion = version || process.env.npm_package_version || '1.0.0';
  
  return api.trace.getTracer(serviceName, serviceVersion);
}
export {
  initOpenTelemetry,
  initializeDefaultTracing,
  getTracer as getOtelTracer, // Renamed export to avoid conflict
} from './tracing';
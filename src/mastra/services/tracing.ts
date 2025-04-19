/**
 * OpenTelemetry Tracing Service for Mastra
 * 
 * This module provides OpenTelemetry initialization and tracing functionality
 * for the DeanMachines AI platform. It sets up auto-instrumentation and provides
 * utilities to interact with the OpenTelemetry API.
 */
import process from 'process';
import { NodeSDK /*, NodeSDKConfiguration */ } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { createLogger } from '@mastra/core/logger';
import { OTelInitOptions } from './types';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-proto';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';

// Configure logger for the tracing service
const logger = createLogger({ name: 'opentelemetry-tracing', level: 'info' });

/**
 * Initialize OpenTelemetry SDK with auto-instrumentation for SigNoz
 * 
 * @param options - Configuration options for the OpenTelemetry SDK
 * @returns The configured SDK instance
 */
export function initOpenTelemetry({
  serviceName = 'deanmachines-ai',
  serviceVersion = '1.0.0',
  environment = 'development',
  enabled = true,
  endpoint,
  metricsEnabled = true,
  metricsIntervalMs = 60000,
}: OTelInitOptions & { metricsEnabled?: boolean; metricsIntervalMs?: number }): NodeSDK | null {
  if (!enabled) {
    logger.info('OpenTelemetry tracing is disabled');
    return null;
  }

  // prepare common SDK config
  const exporterUrl = endpoint ||
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT ||
    'http://localhost:4317/v1/traces';

  const traceExporter = new OTLPTraceExporter({ url: exporterUrl });
  const resource = resourceFromAttributes({
    [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
    [SemanticResourceAttributes.SERVICE_VERSION]: serviceVersion,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: environment,
  });

  const sdkConfig: Partial<import('@opentelemetry/sdk-node').NodeSDKConfiguration> = {
    resource,
    traceExporter,
    instrumentations: [getNodeAutoInstrumentations()],
  };

  if (metricsEnabled) {
    const metricExporter = new OTLPMetricExporter({
      url: exporterUrl.replace('/v1/traces', '/v1/metrics'),
    });
    const metricReader = new PeriodicExportingMetricReader({
      exporter: metricExporter,
      exportIntervalMillis: metricsIntervalMs,
    });
    sdkConfig.metricReader = metricReader;
    logger.info('OpenTelemetry metrics enabled');
  }

  const sdk = new NodeSDK(sdkConfig);

  try {
    sdk.start();
    logger.info('OpenTelemetry SDK initialized successfully');
  } catch (initError) {
    logger.error('Error initializing OpenTelemetry SDK', {
      error: initError instanceof Error ? initError.message : String(initError),
    });
  }

  process.on('SIGTERM', async () => {
    try {
      await sdk.shutdown();
      logger.info('OpenTelemetry SDK shut down successfully');
    } catch (shutdownError) {
      logger.error('Error shutting down OpenTelemetry SDK', {
        error: shutdownError instanceof Error ? shutdownError.message : String(shutdownError),
      });
    } finally {
      process.exit(0);
    }
  });

  return sdk;
}

// Export SDK instance for external use
let sdkInstance: NodeSDK | null = null;

/**
 * Get the current SDK instance
 * 
 * @returns The SDK instance or null if not initialized
 */
export function getOpenTelemetrySdk(): NodeSDK | null {
  return sdkInstance;
}

/**
 * Initialize OpenTelemetry with default configuration
 * 
 * @returns The SDK instance
 */
export function initializeDefaultTracing(): NodeSDK | null {
  if (!sdkInstance) {
    sdkInstance = initOpenTelemetry({
      serviceName: process.env.OTEL_SERVICE_NAME || 'deanmachines-ai',
      environment: process.env.NODE_ENV || 'development',
      enabled: process.env.ENABLE_OPENTELEMETRY !== 'false',
    });
  }
  return sdkInstance;
}

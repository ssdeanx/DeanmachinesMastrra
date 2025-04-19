import { UpstashTransport } from "@mastra/loggers/upstash";

const logger = createLogger({
  name: "Mastra",
  transports: {
    upstash: new UpstashTransport({
      listName: "production-logs",
      upstashUrl: process.env.UPSTASH_REDIS_REST_URL!,
      upstashToken: process.env.UPSTASH_REDIS_REST_TOKEN!,
    }),
  },
  level: "info",
});
 
function createLogger({ name, transports, level }: { name: string; transports: { upstash: UpstashTransport }; level: string }) {
    return {
        info: (log: Record<string, any>) => {
            // Add logger name and level to the log entry
            const entry = { ...log, logger: name, level: "info", timestamp: new Date().toISOString() };
            // Push log entry to buffer and flush
            transports.upstash.logBuffer.push(entry);
            transports.upstash._flush();
        },
        warn: (log: Record<string, any>) => {
            const entry = { ...log, logger: name, level: "warn", timestamp: new Date().toISOString() };
            transports.upstash.logBuffer.push(entry);
            transports.upstash._flush();
        },
        error: (log: Record<string, any>) => {
            const entry = { ...log, logger: name, level: "error", timestamp: new Date().toISOString() };
            transports.upstash.logBuffer.push(entry);
            transports.upstash._flush();
        },
        debugger: (log: Record<string, any>) => {
            const entry = { ...log, logger: name, level: "debug", timestamp: new Date().toISOString() };
            transports.upstash.logBuffer.push(entry);
            transports.upstash._flush();
        },
        // You can add more log levels (warn, error, etc.) as needed
    };
}
// Export the logger instance for external use
// This allows you to use the logger directly if needed
export const upstashLogger = logger;
// Export the logger instance for external use
// This allows you to use the logger directly if needed
export default upstashLogger;
// Export the UpstashTransport for external use
// This allows you to use the UpstashTransport directly if needed
export { UpstashTransport };
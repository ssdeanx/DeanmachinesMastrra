import { FileTransport } from "@mastra/loggers/file";
 
const fileLogger = createLogger({
  name: "Mastra",
  transports: { file: new FileTransport({ path: "test-dir/mastra.log" }) },
  level: "info",
});
function createLogger({ name, transports, level }: { name: string; transports: { file: FileTransport }; level: string }) {
    return {
        warn: (message: string, meta?: Record<string, any>) => {
            const entry = {
                message,
                ...meta,
                logger: name,
                level: "warn",
                timestamp: new Date().toISOString(),
            };
            transports.file.write(JSON.stringify(entry) + "\n");
        },
        info: (message: string, meta?: Record<string, any>) => {
            const entry = {
                message,
                ...meta,
                logger: name,
                level: "info",
                timestamp: new Date().toISOString(),
            };
            transports.file.write(JSON.stringify(entry) + "\n");
        },
        error: (message: string, meta?: Record<string, any>) => {
            const entry = {
                message,
                ...meta,
                logger: name,
                level: "error",
                timestamp: new Date().toISOString(),
            };
            transports.file.write(JSON.stringify(entry) + "\n");
        },
        debug: (message: string, meta?: Record<string, any>) => {
            const entry = {
                message,
                ...meta,
                logger: name,
                level: "debug",
                timestamp: new Date().toISOString(),
            };
            transports.file.write(JSON.stringify(entry) + "\n");
        },
        // You can add more log levels (info, error, etc.) as needed
    };
}

export const fileLoggerInstance = fileLogger;
export default fileLoggerInstance;
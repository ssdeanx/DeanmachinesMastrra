import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import puppeteer, { Browser, Page } from 'puppeteer';
import fs from 'fs-extra';
import path from 'path';
import crypto from 'crypto';
import { createLogger } from "@mastra/core/logger";
import { writeKnowledgeFileTool, FileWriteMode, FileEncoding } from "./readwrite";
import { createAISpan, recordMetrics } from "../services/signoz";
import { Span } from '@opentelemetry/api'; // Import Span type

const logger = createLogger({ name: "puppeteer", level: "debug" });

logger.info("Initializing Puppeteer tool for web navigation and screenshotting.");

// Define a directory for screenshots (consider making this configurable)
const SCREENSHOT_DIR = path.resolve(process.cwd(), 'puppeteer_screenshots');

/**
 * Generates a unique filename for screenshots.
 */
function generateScreenshotFilename(url: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const urlHash = crypto.createHash('md5').update(url).digest('hex').substring(0, 8);
    return `screenshot_${urlHash}_${timestamp}.png`;
}

// --- Action Schemas ---
const ClickActionSchema = z.object({
    type: z.literal("click"),
    selector: z.string().describe("CSS selector for the element to click."),
    waitForNavigation: z.boolean().optional().default(false).describe("Wait for navigation to complete after the click."),
});

const TypeActionSchema = z.object({
    type: z.literal("type"),
    selector: z.string().describe("CSS selector for the input field."),
    text: z.string().describe("Text to type into the field."),
    delay: z.number().optional().default(50).describe("Delay between keystrokes in milliseconds."),
});

const ScrapeActionSchema = z.object({
    type: z.literal("scrape"),
    selector: z.string().describe("CSS selector for the element(s) to scrape."),
    attribute: z.string().optional().describe("Optional attribute to extract (e.g., 'href', 'src'). If omitted, extracts text content."),
    multiple: z.boolean().optional().default(false).describe("Whether to scrape multiple matching elements."),
});

const WaitForSelectorActionSchema = z.object({
    type: z.literal("waitForSelector"),
    selector: z.string().describe("CSS selector to wait for."),
    timeout: z.number().optional().default(30000).describe("Maximum time to wait in milliseconds."),
});

const ScrollActionSchema = z.object({
    type: z.literal("scroll"),
    direction: z.enum(["down", "up", "bottom", "top"]).describe("Direction to scroll."),
    amount: z.number().optional().describe("Pixel amount to scroll (for 'down'/'up'). Defaults to window height/width."),
    selector: z.string().optional().describe("Optional selector to scroll within or to."), // Scroll within an element or scroll element into view
});

const HoverActionSchema = z.object({
    type: z.literal("hover"),
    selector: z.string().describe("CSS selector for the element to hover over."),
});

const SelectActionSchema = z.object({
    type: z.literal("select"),
    selector: z.string().describe("CSS selector for the <select> element."),
    value: z.string().describe("The value of the <option> to select."),
});

const WaitActionSchema = z.object({
    type: z.literal("wait"),
    duration: z.number().int().min(1).describe("Duration to wait in milliseconds."),
});

const EvaluateActionSchema = z.object({
    type: z.literal("evaluate"),
    script: z.string().describe("JavaScript code to execute in the page context. Use 'return' to output data."),
});

// Union of all possible action types
const ActionSchema = z.discriminatedUnion("type", [
    ClickActionSchema,
    TypeActionSchema,
    ScrapeActionSchema,
    WaitForSelectorActionSchema,
    ScrollActionSchema,
    HoverActionSchema,
    SelectActionSchema,
    WaitActionSchema,
    EvaluateActionSchema,
]);
// --- End Action Schemas ---

// Define the output schema separately
const PuppeteerOutputSchema = z.object({
    url: z.string().url().describe("The final URL after navigation and actions."),
    pageTitle: z.string().optional().describe("The title of the web page after actions."),
    scrapedData: z.array(z.any()).optional().describe("Data scraped or returned by evaluate actions."),
    screenshotPath: z.string().optional().describe("Absolute path to the saved screenshot file, if taken."),
    // --- Updated fields for knowledge save status ---
    knowledgeSavePath: z.string().optional().describe("Full path where scraped data was saved in the knowledge base, if requested."), // Renamed
    saveSuccess: z.boolean().optional().describe("Indicates if saving scraped data to knowledge base was successful."),
    saveError: z.string().optional().describe("Error message if saving scraped data to knowledge base failed."),
    // --- End updated fields ---
    success: z.boolean().describe("Whether the overall operation was successful."),
    error: z.string().optional().describe("Error message if the operation failed."),
});

// Define the input schema
const PuppeteerInputSchema = z.object({
    url: z.string().url().describe("The initial URL of the web page to navigate to."),
    screenshot: z.boolean().optional().default(false).describe("Whether to take a full-page screenshot at the end."),
    initialWaitForSelector: z.string().optional().describe("A CSS selector to wait for after initial navigation."),
    actions: z.array(ActionSchema).optional().describe("A sequence of actions to perform on the page."),
    // --- Fields for saving to knowledge base ---
    saveKnowledgeFilename: z.string().optional().describe("Optional filename (e.g., 'scraped_results.json') to save scraped data within the knowledge base."),
    saveFormat: z.enum(["json", "csv"]).optional().default("json").describe("Format to save the scraped data (default: json)."),
    saveMode: z.nativeEnum(FileWriteMode).optional().default(FileWriteMode.OVERWRITE).describe("Write mode for saving data (overwrite, append, create-new)."),
    saveEncoding: z.nativeEnum(FileEncoding).optional().default(FileEncoding.UTF8).describe("Encoding for saving data."),
    // --- End fields ---
});

// Infer the output type from the schema
export const puppeteerTool = createTool<typeof PuppeteerInputSchema, typeof PuppeteerOutputSchema>({
    id: "puppeteer_web_automator",
    description: "Navigates to a web page using Puppeteer, performs a sequence of actions (click, type, scrape, wait), optionally takes a screenshot, and returns page information and scraped data.",
    inputSchema: PuppeteerInputSchema,
    outputSchema: PuppeteerOutputSchema,
    execute: async (executionContext) => {
        const { context: input, container } = executionContext;
        // Start SigNoz Span for the tool execution
        const span: Span = createAISpan('puppeteer_tool_execution', {
            'tool.id': 'puppeteer_web_automator',
            'input.url': input.url,
            'input.actions_count': input.actions?.length ?? 0,
            'input.screenshot_requested': input.screenshot ?? false,
            'input.save_requested': !!input.saveKnowledgeFilename,
        });

        let browser: Browser | null = null;
        const output: z.infer<typeof PuppeteerOutputSchema> = {
            url: input.url,
            success: false,
            scrapedData: [],
        };

        const startTime = Date.now(); // For latency calculation

        try {
            logger.info(`Starting Puppeteer automation for URL: ${input.url}`);
            span.addEvent('Automation started', { url: input.url }); // Add event to span

            if (input.screenshot) {
                await fs.ensureDir(SCREENSHOT_DIR);
                logger.debug(`Ensured screenshot directory exists: ${SCREENSHOT_DIR}`);
            }

            browser = await puppeteer.launch({
                headless: true,
                args: ['--no-sandbox', '--disable-setuid-sandbox']
            });
            logger.debug("Puppeteer browser launched.");
            const page: Page = await browser.newPage();
            logger.debug("New page created.");

            await page.setViewport({ width: 1280, height: 800 });
            logger.debug("Viewport set.");

            logger.info(`Navigating to ${input.url}...`);
            await page.goto(input.url, { waitUntil: 'networkidle2', timeout: 60000 });
            output.url = page.url();
            span.setAttribute('navigation.final_url', output.url); // Record final URL after nav
            logger.info(`Navigation complete. Current URL: ${output.url}`);

            if (input.initialWaitForSelector) {
                logger.info(`Waiting for initial selector: ${input.initialWaitForSelector}`);
                await page.waitForSelector(input.initialWaitForSelector, { timeout: 30000 });
                logger.debug(`Initial selector found: ${input.initialWaitForSelector}`);
            }

            // --- Execute Actions ---
            if (input.actions && input.actions.length > 0) {
                logger.info(`Executing ${input.actions.length} actions...`);
                span.addEvent('Executing actions', { count: input.actions.length });
                for (const [index, action] of input.actions.entries()) {
                    logger.debug(`Executing action ${index + 1}: ${action.type}`);
                    try {
                        switch (action.type) {
                            case "click":
                                logger.info(`Clicking element: ${action.selector}`);
                                const clickPromise = page.click(action.selector);
                                if (action.waitForNavigation) {
                                    logger.debug("Waiting for navigation after click...");
                                    await Promise.all([clickPromise, page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 })]);
                                    output.url = page.url();
                                    logger.info(`Navigation after click complete. New URL: ${output.url}`);
                                } else {
                                    await clickPromise;
                                }
                                logger.debug(`Clicked element: ${action.selector}`);
                                break;

                            case "type":
                                logger.info(`Typing into element: ${action.selector}`);
                                await page.type(action.selector, action.text, { delay: action.delay });
                                logger.debug(`Typed text into: ${action.selector}`);
                                break;

                            case "scrape":
                                logger.info(`Scraping element(s): ${action.selector}` + (action.attribute ? ` [Attribute: ${action.attribute}]` : ' [Text Content]'));
                                let scrapedItems: (string | null)[] = [];
                                if (action.multiple) {
                                    scrapedItems = await page.$$eval(action.selector, (elements, attr) =>
                                        elements.map(el => attr ? el.getAttribute(attr) : el.textContent?.trim() ?? null),
                                        action.attribute
                                    );
                                } else {
                                    const scrapedItem = await page.$eval(action.selector, (element, attr) =>
                                        attr ? element.getAttribute(attr) : element.textContent?.trim() ?? null,
                                        action.attribute
                                    ).catch(() => null); // Handle case where element is not found
                                    if (scrapedItem !== null) {
                                        scrapedItems = [scrapedItem];
                                    }
                                }
                                output.scrapedData = [...(output.scrapedData ?? []), ...scrapedItems];
                                logger.debug(`Scraped ${scrapedItems.length} items. Total scraped: ${output.scrapedData?.length}`);
                                break;

                            case "waitForSelector":
                                logger.info(`Waiting for selector: ${action.selector} (Timeout: ${action.timeout}ms)`);
                                await page.waitForSelector(action.selector, { timeout: action.timeout });
                                logger.debug(`Selector found: ${action.selector}`);
                                break;

                            case "scroll":
                                logger.info(`Scrolling ${action.direction}` + (action.selector ? ` within/to ${action.selector}` : ' window'));
                                await page.evaluate(async (options) => {
                                    const element = options.selector ? document.querySelector(options.selector) : window;
                                    if (!element) throw new Error(`Scroll target not found: ${options.selector}`);

                                    const scrollAmount = options.amount ?? (options.direction === 'down' || options.direction === 'up' ? window.innerHeight : window.innerWidth);
                                    const target = options.selector && element !== window ? element : document.scrollingElement || document.documentElement;

                                    switch (options.direction) {
                                        case 'down':
                                            (target as Element).scrollTop += scrollAmount;
                                            break;
                                        case 'up':
                                            (target as Element).scrollTop -= scrollAmount;
                                            break;
                                        case 'bottom':
                                            if (options.selector && element instanceof Element) {
                                                element.scrollTop = element.scrollHeight;
                                            } else {
                                                (target as Element).scrollTop = (target as Element).scrollHeight;
                                            }
                                            break;
                                        case 'top':
                                            if (options.selector && element instanceof Element) {
                                                element.scrollTop = 0;
                                            } else {
                                                (target as Element).scrollTop = 0;
                                            }
                                            break;
                                    }
                                    await new Promise(resolve => setTimeout(resolve, 100));
                                }, action);
                                logger.debug(`Scrolled ${action.direction}.`);
                                break;

                            case "hover":
                                logger.info(`Hovering over element: ${action.selector}`);
                                await page.hover(action.selector);
                                logger.debug(`Hovered over: ${action.selector}`);
                                break;

                            case "select":
                                logger.info(`Selecting option [value=${action.value}] in dropdown: ${action.selector}`);
                                await page.select(action.selector, action.value);
                                logger.debug(`Selected option in: ${action.selector}`);
                                break;

                            case "wait":
                                logger.info(`Waiting for ${action.duration}ms`);
                                await new Promise(resolve => setTimeout(resolve, action.duration));
                                logger.debug("Wait complete.");
                                break;

                            case "evaluate":
                                logger.info(`Evaluating script...`);
                                const result = await page.evaluate(action.script);
                                if (result !== undefined) {
                                    output.scrapedData = [...(output.scrapedData ?? []), result];
                                    logger.debug(`Script evaluated. Result added to scrapedData. Total scraped: ${output.scrapedData?.length}`);
                                } else {
                                    logger.debug(`Script evaluated. No return value.`);
                                }
                                break;

                            default:
                                const _exhaustiveCheck: never = action;
                                logger.error("Unsupported action type encountered", { action: _exhaustiveCheck });
                                throw new Error(`Unsupported action type encountered: ${JSON.stringify(_exhaustiveCheck)}`);
                        }
                    } catch (actionError: any) {
                        const errorMsg = `Error during action ${index + 1} (${(action as any).type}): ${actionError.message}`;
                        logger.error(errorMsg, actionError);
                        throw new Error(errorMsg);
                    }
                }
                logger.info("All actions executed.");
                span.addEvent('Actions completed');
            }
            // --- End Execute Actions ---

            output.pageTitle = await page.title();
            logger.debug(`Final page title: ${output.pageTitle}`);

            if (input.screenshot) {
                const filename = generateScreenshotFilename(output.url);
                const screenshotPath = path.join(SCREENSHOT_DIR, filename);
                await page.screenshot({ path: screenshotPath, fullPage: true });
                output.screenshotPath = screenshotPath;
            }

            if (input.saveKnowledgeFilename && output.scrapedData && output.scrapedData.length > 0) {
                span.addEvent('Saving scraped data', { filename: input.saveKnowledgeFilename, count: output.scrapedData.length });
                let contentToSave = "";

                try {
                    if (input.saveFormat === "json") {
                        contentToSave = JSON.stringify(output.scrapedData, null, 2);
                    } else if (input.saveFormat === "csv") {
                        if (output.scrapedData.every(item => typeof item === 'object' && item !== null)) {
                            const headers = Object.keys(output.scrapedData[0] as object).join(',');
                            const rows = output.scrapedData.map(item =>
                                Object.values(item as object).map(val => JSON.stringify(val)).join(',')
                            );
                            contentToSave = `${headers}\n${rows.join('\n')}`;
                        } else {
                            throw new Error("CSV format requires scraped data to be an array of objects.");
                        }
                    } else {
                        throw new Error(`Unsupported save format: ${input.saveFormat}`);
                    }

                    if (!writeKnowledgeFileTool?.execute) {
                        throw new Error("writeKnowledgeFileTool.execute is not defined or tool not imported correctly.");
                    }

                    const writeResult = await writeKnowledgeFileTool.execute({
                        context: {
                            path: input.saveKnowledgeFilename,
                            content: contentToSave,
                            mode: input.saveMode,
                            encoding: input.saveEncoding,
                            createDirectory: true,
                        },
                        container: container
                    });

                    if (writeResult.success) {
                        span.setAttribute('output.save_path', writeResult.metadata.path);
                        span.addEvent('Save successful');
                        output.knowledgeSavePath = writeResult.metadata.path;
                        output.saveSuccess = true;
                        logger.info(`Successfully saved scraped data to knowledge base: ${output.knowledgeSavePath}`);
                    } else {
                        span.addEvent('Save failed', { error: output.saveError });
                        output.saveSuccess = false;
                        output.saveError = writeResult.error || "Unknown error saving to knowledge base.";
                        logger.error(`Failed to save scraped data to knowledge base: ${output.saveError}`);
                    }
                } catch (saveError: any) {
                    output.saveSuccess = false;
                    output.saveError = saveError instanceof Error ? saveError.message : String(saveError);
                    logger.error(`Error preparing or saving scraped data to knowledge base: ${output.saveError}`);
                }
            } else if (input.saveKnowledgeFilename) {
                logger.warn(`Knowledge base filename provided (${input.saveKnowledgeFilename}), but no scraped data to save.`);
            }

            output.success = true;
            logger.info("Puppeteer automation completed successfully.");
            span.setAttribute('output.scraped_count', output.scrapedData?.length ?? 0); // Add custom attribute to span
            recordMetrics(span, {
                status: 'success',
                latencyMs: Date.now() - startTime,
                // 'output.scraped_count' is now a span attribute, not a metric
            });

        } catch (error: any) {
            logger.error(`Puppeteer tool error: ${error.message}`, error);
            output.error = error instanceof Error ? error.message : String(error);
            output.success = false;
            recordMetrics(span, {
                status: 'error',
                errorMessage: output.error,
                latencyMs: Date.now() - startTime,
            });
            span.recordException(error);

        } finally {
            if (browser) {
                await browser.close();
                logger.info("Browser closed.");
                span.addEvent('Browser closed');
            }
            span.end();
        }

        return output;
    },
});
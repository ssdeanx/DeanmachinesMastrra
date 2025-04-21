import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import puppeteer, { Browser, Page } from 'puppeteer';
import path from 'path';
import crypto from 'crypto';
import { createLogger } from "@mastra/core/logger";

const logger = createLogger({ name: "puppeteerScrape", level: "debug" });

// Generates a unique filename for screenshots (optional, can be used if screenshotting is desired)
function generateScreenshotFilename(url: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const urlHash = crypto.createHash('md5').update(url).digest('hex').substring(0, 8);
    return `screenshot_${urlHash}_${timestamp}.png`;
}

// Action Schemas (copied from puppeteerTool)
const ClickActionSchema = z.object({
    type: z.literal("click"),
    selector: z.string(),
    waitForNavigation: z.boolean().optional().default(false),
});
const TypeActionSchema = z.object({
    type: z.literal("type"),
    selector: z.string(),
    text: z.string(),
    delay: z.number().optional().default(50),
});
const ScrapeActionSchema = z.object({
    type: z.literal("scrape"),
    selector: z.string(),
    attribute: z.string().optional(),
    multiple: z.boolean().optional().default(false),
});
const WaitForSelectorActionSchema = z.object({
    type: z.literal("waitForSelector"),
    selector: z.string(),
    timeout: z.number().optional().default(30000),
});
const ScrollActionSchema = z.object({
    type: z.literal("scroll"),
    direction: z.enum(["down", "up", "bottom", "top"]),
    amount: z.number().optional(),
    selector: z.string().optional(),
});
const HoverActionSchema = z.object({
    type: z.literal("hover"),
    selector: z.string(),
});
const SelectActionSchema = z.object({
    type: z.literal("select"),
    selector: z.string(),
    value: z.string(),
});
const WaitActionSchema = z.object({
    type: z.literal("wait"),
    duration: z.number().int().min(1),
});
const EvaluateActionSchema = z.object({
    type: z.literal("evaluate"),
    script: z.string(),
});
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

const PuppeteerScrapeOutputSchema = z.object({
    url: z.string().url(),
    pageTitle: z.string().optional(),
    scrapedData: z.array(z.any()).optional(),
    screenshotPath: z.string().optional(),
    success: z.boolean(),
    error: z.string().optional(),
});

const PuppeteerScrapeInputSchema = z.object({
    url: z.string().url(),
    screenshot: z.boolean().optional().default(false),
    initialWaitForSelector: z.string().optional(),
    actions: z.array(ActionSchema).optional(),
});

export const puppeteerScrapeTool = createTool({
    id: "puppeteer_scrape",
    description: "Navigates to a web page using Puppeteer, performs actions (click, type, scrape, wait), and returns scraped data (no file writing).",
    inputSchema: PuppeteerScrapeInputSchema,
    outputSchema: PuppeteerScrapeOutputSchema,
    execute: async ({ context }) => {
        let browser: Browser | null = null;
        const output: z.infer<typeof PuppeteerScrapeOutputSchema> = {
            url: context.url,
            success: false,
            scrapedData: [],
        };
        try {
            browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
            const page: Page = await browser.newPage();
            await page.setViewport({ width: 1280, height: 800 });
            await page.goto(context.url, { waitUntil: 'networkidle2', timeout: 60000 });
            output.url = page.url();
            output.pageTitle = await page.title();
            if (context.initialWaitForSelector) {
                await page.waitForSelector(context.initialWaitForSelector, { timeout: 30000 });
            }
            if (context.actions && context.actions.length > 0) {
                for (const action of context.actions) {
                    switch (action.type) {
                        case "click":
                            const clickPromise = page.click(action.selector);
                            if (action.waitForNavigation) {
                                await Promise.all([clickPromise, page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 })]);
                                output.url = page.url();
                            } else {
                                await clickPromise;
                            }
                            break;
                        case "type":
                            await page.type(action.selector, action.text, { delay: action.delay });
                            break;
                        case "scrape":
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
                                ).catch(() => null);
                                if (scrapedItem !== null) scrapedItems = [scrapedItem];
                            }
                            output.scrapedData = [...(output.scrapedData ?? []), ...scrapedItems];
                            break;
                        case "waitForSelector":
                            await page.waitForSelector(action.selector, { timeout: action.timeout });
                            break;
                        case "scroll":
                            await page.evaluate(async (options) => {
                                const { direction, amount, selector } = options;
                                let target = selector ? document.querySelector(selector) : window;
                                if (!target) return;
                                if (direction === "down" || direction === "up") {
                                    const scrollAmount = amount || window.innerHeight;
                                    if (direction === "down") {
                                        (target as any).scrollBy ? (target as any).scrollBy(0, scrollAmount) : window.scrollBy(0, scrollAmount);
                                    } else {
                                        (target as any).scrollBy ? (target as any).scrollBy(0, -scrollAmount) : window.scrollBy(0, -scrollAmount);
                                    }
                                } else if (direction === "bottom") {
                                    (target as any).scrollTo ? (target as any).scrollTo(0, document.body.scrollHeight) : window.scrollTo(0, document.body.scrollHeight);
                                } else if (direction === "top") {
                                    (target as any).scrollTo ? (target as any).scrollTo(0, 0) : window.scrollTo(0, 0);
                                }
                            }, action);
                            break;
                        case "hover":
                            await page.hover(action.selector);
                            break;
                        case "select":
                            await page.select(action.selector, action.value);
                            break;
                        case "wait":
                            await new Promise(resolve => setTimeout(resolve, action.duration));
                            break;
                        case "evaluate":
                            const evalResult = await page.evaluate(action.script);
                            output.scrapedData = [...(output.scrapedData ?? []), evalResult];
                            break;
                        default:
                            break;
                    }
                }
            }
            if (context.screenshot) {
                const SCREENSHOT_DIR = path.resolve(process.cwd(), 'puppeteer_screenshots');
                await page.screenshot({ path: path.join(SCREENSHOT_DIR, generateScreenshotFilename(context.url)), fullPage: true });
                output.screenshotPath = path.join(SCREENSHOT_DIR, generateScreenshotFilename(context.url));
            }
            output.success = true;
        } catch (error: any) {
            output.error = error instanceof Error ? error.message : String(error);
            output.success = false;
            logger.error(`puppeteerScrapeTool error: ${output.error}`);
        } finally {
            if (browser) await browser.close();
        }
        return output;
    }
});

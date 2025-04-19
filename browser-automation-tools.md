# Category: Browser Automation (Advanced Web Interaction)

**Overview:** This document details tools for controlling web browsers programmatically within Mastra AI agents. It covers two primary approaches:
1.  **Local Browser Libraries:** Using **Puppeteer** (by Google) or **Playwright** (by Microsoft) to control locally installed browsers (Chrome, Firefox, WebKit).
2.  **Browser-as-a-Service (BaaS):** Using the **Hyperbrowser SDK** (hyperbrowser.ai) to control scalable cloud browser instances via API.

**Critical Considerations:** Browser automation is powerful but introduces significant challenges:

*   **Resource Intensity (Local):** Puppeteer/Playwright consume substantial CPU/RAM. Limit concurrency (see Resource Management below).
*   **Environment Complexity (Local):** Requires Node.js libraries (`puppeteer`/`playwright`) AND browser binaries (`npx playwright install`) installed where the agent runs. Docker is strongly recommended.
*   **Environment Complexity (Hyperbrowser):** Requires the Hyperbrowser SDK (`npm install @hyperbrowser/sdk` - **verify package name**) and secure API key management.
*   **Brittleness:** Scripts depend heavily on website structure (selectors, layout). Site updates frequently break automation. Use stable selectors (`data-testid`, IDs) and expect maintenance.
*   **Anti-Bot Measures:** Websites actively block bots (CAPTCHAs, fingerprinting, JS challenges). While mitigation techniques exist (see below), success isn't guaranteed and may violate Terms of Service. Hyperbrowser specializes in this area.
*   **Security Risks:**
    *   Browsing arbitrary sites carries inherent risks. Use sandboxing (default).
    *   **Form submission (`FillFormAndSubmit`) and script execution (`ExecuteScript`) tools are EXTREMELY HIGH RISK.** Implement with **strict URL allowlists**, never execute arbitrary code, handle credentials securely, and use only when absolutely necessary on trusted sites.

---

## Section 1: Tools using Puppeteer / Playwright

**Prerequisites:**
*   `npm install playwright` or `npm install puppeteer`.
*   Browser binaries installed via `npx playwright install` (or Puppeteer's setup) in the execution environment.

### Tool: `pptr_playwright_NavigateAndScrape`

*   **Purpose:** Navigates a browser, waits for conditions, and extracts structured data via CSS selectors. Essential for dynamic/JS-heavy sites.
*   **Suggested Libraries:** `playwright` or `puppeteer`.
*   **How to Use (Implementation Sketch - Playwright Example):**
    ```typescript
    import { Tool } from '@mastra/core';
    import { z } from 'zod';
    import playwright, { TimeoutError } from 'playwright'; // Import specific errors if needed

    const schema = z.object({ /* ... (Same as previous draft) ... */ });

    export const navigateAndScrapeTool = new Tool({
      name: 'pptr_playwright_NavigateAndScrape',
      description: 'Uses Playwright/Puppeteer to navigate and scrape data.',
      schema: schema,
      execute: async ({ input }) => {
        let browser: playwright.Browser | null = null; // etc...
        const results: Record<string, string | null> = {};
        try {
          // --- Launch & Setup ---
          browser = await playwright.chromium.launch({ headless: true /* Configurable */ });
          const context = await browser.newContext({ userAgent: '...' });
          const page = await context.newPage();

          // --- Actions ---
          await page.goto(input.url, { waitUntil: input.waitUntilEvent, timeout: input.timeoutMs });
          if (input.waitForSelector) {
            await page.waitForSelector(input.waitForSelector, { timeout: input.timeoutMs });
          }
          for (const key in input.scrapeSelectors) { /* ... (Scraping logic with try/catch per selector) ... */ }

          // --- Success Return ---
          return { success: true, data: results };

        } catch (error: any) {
          // --- Error Handling ---
          let errorType = 'GenericBrowserError';
          if (error instanceof TimeoutError) errorType = 'TimeoutError';
          else if (error.message?.includes('net::ERR_NAME_NOT_RESOLVED')) errorType = 'NavigationError';
          // Add more specific error checks if needed
          console.error(`[${errorType}] ${input.url}: ${error.message}`);
          return { success: false, error: `Failed: ${errorType} - ${error.message}`, data: results }; // Return partial data if useful
        } finally {
          // --- CRITICAL Cleanup ---
          /* ... (Close page, context, browser) ... */
        }
      },
    });
    ```
*   **When & Why:** Scraping SPAs, JS-rendered content, when simple HTTP fetch fails.
*   **What Used For:** "Get product price/rating from URL", "Extract headlines from dynamic feed", "Scrape metrics from internal dashboard".

---

### Tool: `pptr_playwright_TakeScreenshot`

*   **Purpose:** Captures a screenshot (full page or element).
*   **Suggested Libraries:** `playwright` or `puppeteer`.
*   **How to Use (Implementation Sketch - Playwright Example):**
    ```typescript
    // ... (Imports and Schema as previous draft) ...
    export const takeScreenshotTool = new Tool({
      name: 'pptr_playwright_TakeScreenshot',
      description: 'Uses Playwright/Puppeteer to take a screenshot.',
      schema: schema,
      execute: async ({ input }) => {
        let browser: playwright.Browser | null = null; // etc...
        try {
          // --- Launch & Setup ---
          browser = await playwright.chromium.launch({ headless: true }); // etc...
          const page = await context.newPage();

          // --- Actions ---
          await page.goto(input.url, { waitUntil: 'networkidle', timeout: input.timeoutMs });
          let screenshotBuffer: Buffer;
          if (input.elementSelector) { /* ... (Element screenshot logic) ... */ }
          else { /* ... (Page screenshot logic) ... */ }

          // --- Success Return ---
          return { success: true, imageDataBase64: screenshotBuffer.toString('base64'), format: input.outputFormat };

        } catch (error: any) {
          // --- Error Handling ---
          /* ... (Similar structured error reporting as scrape tool) ... */
          return { success: false, error: `Screenshot Failed: ${error.message}` };
        } finally {
          // --- CRITICAL Cleanup ---
          /* ... (Close page, context, browser) ... */
        }
      },
    });
    ```
*   **When & Why:** Visual documentation, debugging automation, capturing visual state.
*   **What Used For:** "Screenshot #sales-chart element", "Show example.com homepage visual", "Capture full article page".

---

### Tool: `pptr_playwright_FillFormAndSubmit`

*   **Purpose:** Fills and submits web forms. **HIGH RISK - USE WITH EXTREME CAUTION.**
*   **Suggested Libraries:** `playwright` or `puppeteer`.
*   **How to Use (Implementation Sketch - Playwright Example):**
    ```typescript
    // ... (Imports, ALLOWLIST Definition, Schema as previous draft) ...
    export const fillFormTool = new Tool({
      name: 'pptr_playwright_FillFormAndSubmit',
      description: 'Fills and submits forms on ALLOWED URLs ONLY.',
      schema: schema,
      execute: async ({ input }) => {
        // --- Security Check ---
        if (!ALLOWED_FORM_URLS.some(allowed => input.url.startsWith(allowed))) { /* ... return error ... */ }

        let browser: playwright.Browser | null = null; // etc...
        try {
          // --- Launch & Setup ---
          /* ... (Launch browser, context, page) ... */

          // --- Actions ---
          await page.goto(input.url, { /* ... */ });
          await page.waitForSelector(input.submitSelector, { /* ... */ });
          for (const selector in input.formData) {
             // !! Handle sensitive values securely !!
             await page.locator(selector).fill(input.formData[selector], { /* ... */ });
          }
          if (input.waitForNavigation) { /* ... (Promise.all logic) ... */ }
          else { /* ... (Click logic) ... */ }
          const finalUrl = page.url();

          // --- Success Return ---
          return { success: true, finalUrl: finalUrl };

        } catch (error: any) {
          // --- Error Handling ---
          /* ... (Structured error reporting, mention potential form validation errors) ... */
           return { success: false, error: `Form Submit Failed: ${error.message}` };
        } finally {
          // --- CRITICAL Cleanup ---
          /* ... (Close page, context, browser) ... */
        }
      },
    });
    ```
*   **When & Why:** Automating logins/submissions on **trusted, internal, allowlisted sites** only. Requires secure credential handling. Avoid if possible.
*   **What Used For:** *(Internal, secured)* "Log in to internal-tool.com/login", *(Limited scope)* "Submit query on specific-search-site.com/search".

---

### Tool: `pptr_playwright_ExecuteScript`

*   **Purpose:** Executes JS in page context. **EXTREMELY HIGH RISK - AVOID IF POSSIBLE.**
*   **Suggested Libraries:** `playwright` or `puppeteer`.
*   **How to Use (Implementation Sketch - Playwright Example):**
    ```typescript
    // ... (Imports, URL Allowlist, Script Allowlist Definition, Schema as previous draft) ...
    export const executeScriptTool = new Tool({
      name: 'pptr_playwright_ExecuteScript',
      description: 'Executes PRE-APPROVED JavaScript on ALLOWED URLs ONLY.',
      schema: schema,
      execute: async ({ input }) => {
        // --- Security Checks ---
        if (!ALLOWED_SCRIPT_URLS.some(/* ... */)) { /* ... return error ... */ }
        const scriptToExecute = ALLOWED_SCRIPTS[input.scriptKey];
        if (!scriptToExecute) { /* ... return error ... */ }

        let browser: playwright.Browser | null = null; // etc...
        try {
          // --- Launch & Setup ---
          /* ... (Launch browser, context, page) ... */

          // --- Actions ---
          await page.goto(input.url, { /* ... */ });
          console.log(`Executing pre-approved script: ${input.scriptKey}...`);
          // Pass audited script string and JSON-serializable args
          const result = await page.evaluate(`(${scriptToExecute}).apply(null, ${JSON.stringify(input.scriptArgs)})`);
          const serializableResult = JSON.parse(JSON.stringify(result ?? null));

          // --- Success Return ---
          return { success: true, result: serializableResult };

        } catch (error: any) {
          // --- Error Handling ---
          /* ... (Structured error reporting, catch script execution errors) ... */
           return { success: false, error: `Script Execution Failed: ${error.message}` };
        } finally {
          // --- CRITICAL Cleanup ---
          /* ... (Close page, context, browser) ... */
        }
      },
    });
    ```
*   **When & Why:** **LAST RESORT.** Interacting with complex elements/legacy JS APIs on **fully trusted, internal, allowlisted pages** where no other method works. **NEVER execute arbitrary or LLM-generated code.**
*   **What Used For:** *(Internal, trusted)* "Execute 'getReportData' script", "Run 'getChartConfig' script".

---

## Section 2: Tools using Hyperbrowser SDK

**Prerequisites:**
*   Hyperbrowser Node.js SDK installed (`npm install @hyperbrowser/sdk` - **Verify package name**).
*   Hyperbrowser API Key configured securely (environment variable recommended).
*   **Consult official Hyperbrowser SDK documentation for all details.**

**Note:** The following sketches are **conceptual** and **require validation** against the official Hyperbrowser SDK documentation.

### Tool: `hyperbrowser_NavigateAndScrape`

*   **Purpose:** Uses Hyperbrowser SDK to control cloud browser, navigate, and scrape data. Leverages Hyperbrowser infrastructure and features.
*   **Suggested Libraries:** Hyperbrowser Node.js SDK.
*   **How to Use (Implementation Sketch - Conceptual):**
    ```typescript
    import { Tool } from '@mastra/core';
    import { z } from 'zod';
    // VERIFY SDK IMPORTS AND METHODS WITH OFFICIAL DOCS
    import { HyperbrowserClient, HyperbrowserError } from '@hyperbrowser/sdk';

    // Initialize SDK Client (consider placement for reuse/scoping)
    const hyperbrowser = new HyperbrowserClient({ apiKey: process.env.HYPERBROWSER_API_KEY });

    const schema = z.object({ /* ... (As previous draft, tailor params to SDK) ... */ });

    export const hyperbrowserScrapeTool = new Tool({
      name: 'hyperbrowser_NavigateAndScrape',
      description: 'Uses Hyperbrowser SDK to navigate cloud browser and scrape data.',
      schema: schema,
      execute: async ({ input }) => {
        let currentSessionId = input.sessionId; // Manage session lifecycle
        try {
          // --- Ensure Session ---
          if (!currentSessionId) { /* ... SDK call to create session ... */ }
          if (!currentSessionId) throw new Error("Failed to get session.");

          // --- Actions (Use actual SDK methods) ---
          // await hyperbrowser.sessions.navigate(currentSessionId, { url: input.url, ... });
          // const scrapeResult = await hyperbrowser.sessions.scrape(currentSessionId, { selectors: input.scrapeSelectors, ... });

          // --- Success Return (Adapt to SDK response) ---
          // return { success: true, sessionId: currentSessionId, data: scrapeResult.data };
          return { success: true, sessionId: currentSessionId, data: {} }; // Placeholder

        } catch (error: any) {
          // --- Error Handling (Check for specific SDK errors) ---
          let errorType = 'HyperbrowserSDKError';
          if (error instanceof HyperbrowserError) errorType = 'HyperbrowserAPIError'; // Example
          console.error(`[${errorType}] Hyperbrowser SDK: ${error.message}`);
          return { success: false, error: `Hyperbrowser Failed: ${errorType} - ${error.message}`, sessionId: currentSessionId };
        } finally {
          // --- Session Cleanup (Optional, based on desired lifecycle) ---
          // if (/* should close session */) { await hyperbrowser.sessions.delete(currentSessionId); }
        }
      },
    });
    ```
*   **When & Why:** Offloading browser execution, utilizing Hyperbrowser's anti-bot/scaling features, integrating with existing Hyperbrowser sessions.
*   **What Used For:** "Using Hyperbrowser, scrape product details from difficult site URL", "Navigate user's session `sess_xyz` and extract headlines".

---

### Tool: `hyperbrowser_TakeScreenshot`

*   **Purpose:** Uses Hyperbrowser SDK to take screenshots in cloud sessions.
*   **Suggested Libraries:** Hyperbrowser Node.js SDK.
*   **How to Use (Implementation Sketch - Conceptual):**
    ```typescript
    // ... (Imports, SDK Client Init, Schema adjusting params to SDK) ...
    export const hyperbrowserScreenshotTool = new Tool({
      name: 'hyperbrowser_TakeScreenshot',
      description: 'Uses Hyperbrowser SDK to take a screenshot.',
      schema: schema,
      execute: async ({ input }) => {
        try {
          // --- Actions (Use actual SDK methods) ---
          // const screenshotResult = await hyperbrowser.sessions.takeScreenshot(input.sessionId, { format: input.outputFormat, ... });
          // if (!screenshotResult?.imageDataBase64) throw new Error("No screenshot data returned.");

          // --- Success Return (Adapt to SDK response) ---
          // return { success: true, ..., imageDataBase64: screenshotResult.imageDataBase64, ... };
          return { success: true, sessionId: input.sessionId, imageDataBase64: "...", format: input.outputFormat }; // Placeholder

        } catch (error: any) {
          // --- Error Handling (Check for specific SDK errors) ---
          /* ... (Structured SDK error reporting) ... */
           return { success: false, error: `Hyperbrowser Screenshot Failed: ${error.message}`, sessionId: input.sessionId };
        }
      },
    });
    ```
*   **When & Why:** Capturing visuals from Hyperbrowser sessions without local browsers.
*   **What Used For:** "Get screenshot of current view in Hyperbrowser session `sess_xyz`", "Take PNG screenshot via Hyperbrowser for session `sess_abc`".

---

### Tool: `hyperbrowser_FormSubmit`

*   **Purpose:** Uses Hyperbrowser SDK to fill/submit forms. **HIGH RISK - Apply same security principles.**
*   **Suggested Libraries:** Hyperbrowser Node.js SDK.
*   **How to Use (Implementation Sketch - Conceptual):**
    ```typescript
    // ... (Imports, SDK Client Init, URL Allowlist, Schema adjusting params to SDK) ...
     export const hyperbrowserFormTool = new Tool({
      name: 'hyperbrowser_FormSubmit',
      description: 'Uses Hyperbrowser SDK to fill/submit forms on ALLOWED URLs.',
      schema: schema,
      execute: async ({ input }) => {
         // --- Security Check ---
         // if (!ALLOWED_HB_FORM_URLS.some(...)) { /* ... return error ... */ }
        try {
          // --- Actions (Use actual SDK methods for navigate/fill/submit) ---
          // const submitResult = await hyperbrowser.sessions.submitForm(input.sessionId, { url: input.url, formData: input.formData, ... });

          // --- Success Return (Adapt to SDK response) ---
          // return { success: true, sessionId: input.sessionId, result: submitResult };
           return { success: true, sessionId: input.sessionId, result: {} }; // Placeholder

        } catch (error: any) {
          // --- Error Handling (Check for specific SDK errors) ---
          /* ... (Structured SDK error reporting) ... */
           return { success: false, error: `Hyperbrowser Form Submit Failed: ${error.message}`, sessionId: input.sessionId };
        }
      },
    });
    ```
*   **When & Why:** Automating form interactions on **allowlisted URLs** requiring Hyperbrowser's specific capabilities (e.g., advanced anti-bot). Secure data handling is vital.
*   **What Used For:** *(Internal, allowlisted)* "Using Hyperbrowser, submit search on `specific-internal-tool.com`".

---

## Section 3: Resource Management Strategies (Puppeteer/Playwright)

*   **Launch Per Call (Default Recommended):**
    *   **Pros:** Simple to implement, ensures clean state/isolation for each tool execution.
    *   **Cons:** Higher latency due to browser launch overhead for every call. Can consume significant resources if many tools run concurrently.
    *   **Implementation:** The `launch()`/`close()` calls happen inside each `execute` function's `try...finally` block.
*   **Browser/Context Pooling (Advanced):**
    *   **Pros:** Reduces latency significantly by reusing browser instances/contexts. More resource-efficient for high throughput.
    *   **Cons:** Much more complex to implement reliably (managing pool size, detecting crashed instances, handling state leakage between uses, potential for context contamination). Often requires external libraries (`puppeteer-cluster`) or significant custom logic outside the simple Tool definition.
    *   **Implementation:** Requires a shared module or class managing the pool, acquiring/releasing resources for each tool call. Not shown in basic sketches.
*   **Concurrency Warning:** Avoid executing a large number of browser automation tools *simultaneously*. Each browser instance is heavy. Limit concurrent executions at the application level (e.g., using message queues with limited workers, or Mastra workflow concurrency controls if applicable) to prevent system overload.

---

## Section 4: Debugging Tips

*   **Run Headful (Puppeteer/Playwright):** Launch the browser with `headless: false` in launch options to visually see what the script is doing.
*   **Slow Motion (Puppeteer/Playwright):** Use the `slowMo` launch option (e.g., `slowMo: 100` milliseconds) to slow down execution and observe interactions.
*   **Playwright Inspector / `page.pause()`:** Playwright has a powerful inspector (`PWDEBUG=1 npx playwright test`) and `await page.pause()` method that stops execution and opens an inspector window, allowing step-through debugging and selector exploration.
*   **Verbose Logging:** Add extensive `console.log` statements within the `execute` function to track progress, variable values, and selectors being used.
*   **Screenshots/HTML Dumps on Error:** In `catch` blocks, take a final screenshot (`page.screenshot`) or dump the page HTML (`page.content()`) to understand the state at the time of failure.
*   **Browser DevTools Protocol (Advanced):** Both libraries allow low-level interaction via the Chrome DevTools Protocol for advanced debugging and tracing, though this is complex.

---

## Section 5: General Best Practices

*   **Choose Right Tool:** Use `axios`/`fetch` for simple requests/APIs. Use browser automation only when necessary (JS rendering, complex interactions). Select Puppeteer/Playwright/Hyperbrowser based on needs (cross-browser, BaaS features, etc.).
*   **Robust Error Handling:** Use `try...catch...finally`. Catch specific error types (`TimeoutError`, SDK errors). Return structured error objects `{ success: false, error: string, details?: any }`.
*   **Resource Cleanup (Local):** **ALWAYS** use `finally` blocks to call `page.close()`, `context.close()`, and `browser.close()` for Puppeteer/Playwright to prevent leaks.
*   **Explicit Waits:** Avoid fixed delays (`waitForTimeout`). Use waits for selectors, navigation, network idle states.
*   **Stable Selectors:** Prefer IDs, `data-testid`, or stable attribute selectors over brittle CSS class paths or text content.
*   **Configuration:** Externalize timeouts, user agents, headless mode flags, allowlists, and API keys (use environment variables for secrets). Pass non-secret config via tool inputs or loaded config objects.
*   **Security First:** Validate inputs (URLs!). Use **strict allowlists** for actions. **Never** execute arbitrary scripts. Handle credentials via secure mechanisms.
*   **Anti-Bot Awareness:** Understand that websites actively combat automation. Use techniques like:
    *   Realistic User Agents.
    *   Viewport randomization.
    *   Proxy integration (via launch options or services like Hyperbrowser).
    *   Consider CAPTCHA solving services (integration can be complex).
    *   Leverage "stealth" plugins (`puppeteer-extra-plugin-stealth`) or built-in features (Playwright's robustness, Hyperbrowser's specialized features). Success is not guaranteed.
*   **Idempotency:** Design tools carefully regarding side effects if retries might occur.
*   **Logging:** Implement clear logging within tool execution for traceability.
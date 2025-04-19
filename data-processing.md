# Category: Data Processing & Manipulation

**Overview:** This document details tools for transforming, analyzing, validating, structuring, and manipulating data within Mastra AI agents and workflows. These tools act as building blocks, converting raw or semi-structured inputs into actionable, organized information, enabling more sophisticated agent behavior.

**Key Considerations & Best Practices:**

*   **LLM vs. Deterministic Libraries:**
    *   **LLM (via `mastra.llm` / AI SDK):** Best for tasks requiring nuanced understanding, flexibility with varied input, or natural language generation (summarization, translation, complex extraction). **Cons:** Non-deterministic, potentially slower/costlier, subject to context limits & prompt engineering skill, may hallucinate or fail formatting instructions.
    *   **Libraries/APIs:** Best for tasks needing speed, accuracy, and determinism (math, parsing CSV/XML/YAML, data validation, specific formatting, regex). **Cons:** Less flexible with input variations, require managing dependencies or external API keys/costs.
    *   **Hybrid Approach:** Use libraries for pre-processing (e.g., cleaning text, extracting raw data) before sending to an LLM, or use libraries to validate/structure LLM output.
*   **Robust Error Handling:** Tools MUST implement comprehensive `try...catch` blocks. Catch specific errors (parsing, validation, network, API limits, LLM errors). Return structured error objects (e.g., `{ success: false, error: 'Error message', code: 'ERROR_CODE', details?: any }`) to allow the agent/workflow to potentially understand the failure type and react accordingly.
*   **Data Size & Streaming:** Standard tool execution assumes reasonably sized inputs/outputs. For very large files (many MBs/GBs), consider chunking or investigating Node.js streaming parsers (e.g., `papaparse` stream API, `xml-flow`), acknowledging the implementation complexity within typical tool execution models.
*   **Configuration Management:** Manage reusable schemas, transformation rules, or allowed operations centrally (e.g., in dedicated modules like `/src/schemas/index.ts` or `/src/transformations/index.ts`) and import them into the tool file.
*   **Security & Input Sanitization:** Be cautious with tools evaluating expressions (`performCalculation` - avoid `eval`). Sanitize inputs if passing untrusted data to complex parsing libraries or regex tools to prevent ReDoS (Regular Expression Denial of Service) or other risks.
*   **Idempotency:** Ensure tools are safe to retry where applicable. Most data processing is idempotent, but verify if external state is involved.
*   **Tool Granularity:** Prefer smaller, focused tools over monolithic ones. An agent can better orchestrate multiple simple tools.

---

## Section 1: Core Data Processing Tools

### Tool: `summarizeText`

*   **Purpose:** Condenses longer text into a shorter summary.
*   **Approach:** Primarily LLM-based.
*   **How to Use:** (Sketch as previously defined - uses LLM prompt)
*   **When & Why:** Understanding large text blocks, reducing context size.
*   **What Used For:** "Summarize article", "Bullet points for transcript".

---

### Tool: `translateText`

*   **Purpose:** Translates text between languages.
*   **Approach:** LLM-based or Dedicated Translation API.
*   **How to Use:** (Sketch as previously defined - LLM or API call)
*   **When & Why:** Multilingual content handling. APIs may offer cost/speed/accuracy benefits.
*   **What Used For:** "Translate email German to English", "Translate 'hello' to Japanese".

---

### Tool: `formatData`

*   **Purpose:** Converts JS objects/arrays to string formats (JSON, YAML, CSV, Markdown Table).
*   **Approach:** Deterministic libraries.
*   **How to Use:** (Sketch as previously defined - uses `JSON.stringify`, `js-yaml`, `papaparse`, custom logic)
*   **When & Why:** Preparing data for display, file saving, system interoperability.
*   **What Used For:** "Format list as CSV", "Convert object to pretty JSON", "Display data as Markdown table".

---

### Tool: `parseStructuredText`

*   **Purpose:** Extracts structured data from unstructured text using instructions.
*   **Approach:** Primarily LLM-based.
*   **Prompt Note:** Requires clear prompting, requesting JSON, maybe few-shot examples.
*   **How to Use:** (Sketch as previously defined - uses LLM, `JSON.parse`, optional Zod validation)
*   **When & Why:** Structuring info from free-form text (emails, notes) when regex/keywords fail.
*   **What Used For:** "Extract name, email, company as JSON", "Parse action items from notes".

---

### Tool: `validateDataSchema`

*   **Purpose:** Checks if JS data conforms to a predefined schema (e.g., Zod).
*   **Approach:** Deterministic validation library.
*   **How to Use:** (Sketch as previously defined - loads schema by name, uses `zod.safeParse`)
*   **When & Why:** Ensuring data consistency before saving/processing, validating LLM output.
*   **What Used For:** "Validate extracted user against 'userProfileSchema'", "Check data against 'invoiceSchema'".

---

### Tool: `transformDataStructure`

*   **Purpose:** Remaps/restructures data using predefined rules.
*   **Approach:** Deterministic libraries/custom logic.
*   **How to Use:** (Sketch as previously defined - loads transformation by name, uses `lodash` or custom function)
*   **When & Why:** Adapting data between different schemas/APIs, simplifying/filtering.
*   **What Used For:** "Transform `legacyUserData` using 'legacyToNewUser'", "Flatten `orderDetails`".

---

### Tool: `performCalculation`

*   **Purpose:** Executes specific, safe mathematical/statistical operations.
*   **Approach:** Dedicated math libraries. **Avoid `eval`**.
*   **How to Use:** (Sketch as previously defined - uses specific library functions based on an enum `operation`)
*   **When & Why:** Accurate, safe calculations, statistical analysis.
*   **What Used For:** "Calculate mean of [1, 5, 3]", "Standard deviation of [10, 12, 11]", "sqrt(144)".

---

### Tool: `parseDelimitedText` (CSV, TSV, etc.)

*   **Purpose:** Parses delimiter-separated text into arrays or objects.
*   **Approach:** Deterministic parsing libraries.
*   **How to Use:** (Sketch as previously defined - uses `papaparse`)
*   **When & Why:** Processing CSV/TSV data from uploads, files, simple APIs.
*   **What Used For:** "Parse this CSV string", "Process uploaded `data.tsv`".

---

### Tool: `parseXmlData`

*   **Purpose:** Parses XML text into a JavaScript object.
*   **Approach:** Deterministic XML libraries.
*   **How to Use:** (Sketch as previously defined - uses `xml2js` or `fast-xml-parser`)
*   **When & Why:** Interacting with XML-based APIs (SOAP, RSS) or files.
*   **What Used For:** "Parse XML order details", "Extract items from RSS feed XML".

---

## Section 2: Additional Data Processing Tools

### Tool: `cleanAndNormalizeText`

*   **Purpose:** Performs common text cleaning operations like removing extra whitespace, converting case, removing punctuation (optional), or stripping HTML tags.
*   **Approach:** Deterministic string manipulation, potentially regex.
*   **Suggested Libraries:** Native string methods, potentially `lodash` string functions, `striptags`.
*   **How to Use (Implementation Sketch):**
    *   Define using `new Tool`. Schema (`zod`): `text: z.string()`, optional flags like `toLowerCase: z.boolean()`, `removePunctuation: z.boolean()`, `trimWhitespace: z.boolean().default(true)`, `stripHtml: z.boolean()`.
    *   `execute`: Apply selected operations sequentially. Use `text.trim()`, `text.toLowerCase()`, regex for punctuation (`replace(/[.,!?;:]/g, '')`), `striptags(text)`. Return `{ success: true, cleanedText: result }`.
*   **When & Why:** Pre-processing text before sending to LLM, preparing text for comparison or indexing, cleaning user input.
*   **What Used For:** "Normalize this user comment by converting to lowercase and removing punctuation.", "Strip HTML tags from this fetched web content.", "Remove leading/trailing whitespace from the input."

---

### Tool: `applyRegexPattern`

*   **Purpose:** Finds matches, extracts groups, or replaces parts of text using a specified Regular Expression.
*   **Approach:** Deterministic Regex engine.
*   **How to Use (Implementation Sketch):**
    *   **Security Note:** Avoid constructing regex directy from untrusted user/LLM input due to ReDoS risks. Use predefined patterns or carefully validated inputs.
    *   Define using `new Tool`. Schema (`zod`): `text: z.string()`, `pattern: z.string().describe("The Regex pattern (string). Use double backslashes for escaping.")`, `flags: z.string().optional().default('g').describe("Regex flags (e.g., 'g', 'i', 'm').")`, `action: z.enum(['matchAll', 'extractFirstGroup', 'replace']).default('matchAll')`, `replacementValue: z.string().optional().describe("Value for 'replace' action.")`.
    *   `execute`: Construct `RegExp` object: `new RegExp(input.pattern, input.flags)`. Use `try...catch` for invalid regex patterns. Perform action: `text.matchAll(regex)` (iterate to get all matches/groups), `regex.exec(text)` (get first match/group), `text.replace(regex, replacementValue)`. Return structured results: `{ success: true, matches: [...] / extractedGroup: '...' / replacedText: '...' }`.
*   **When & Why:** Extracting specific structured patterns (like order IDs, phone numbers, dates) when LLM extraction is overkill or inconsistent. Performing rule-based text replacements.
*   **What Used For:** "Extract all email addresses from this text.", "Find the first occurrence of a date in 'YYYY-MM-DD' format.", "Replace all instances of 'userID' with 'accountID' in this log entry."

---

### Tool: `encodeDecodeText`

*   **Purpose:** Encodes or decodes text using common formats like Base64 or URL encoding.
*   **Approach:** Deterministic built-in Node.js functions or libraries.
*   **Suggested Libraries:** Node.js `Buffer` for Base64, `encodeURIComponent`/`decodeURIComponent`.
*   **How to Use (Implementation Sketch):**
    *   Define using `new Tool`. Schema (`zod`): `text: z.string()`, `encoding: z.enum(['Base64', 'URL'])`, `action: z.enum(['encode', 'decode'])`.
    *   `execute`: Use `switch` on `encoding` and `action`. `Base64 encode`: `Buffer.from(text).toString('base64')`. `Base64 decode`: `Buffer.from(text, 'base64').toString('utf8')`. `URL encode`: `encodeURIComponent(text)`. `URL decode`: `decodeURIComponent(text)`. Use `try...catch` for invalid Base64 decoding. Return `{ success: true, result: outputText }`.
*   **When & Why:** Handling data for web requests (URL encoding), processing encoded data from APIs (Base64), simple data obfuscation.
*   **What Used For:** "Encode this JSON string as Base64.", "Decode this URL parameter.", "URL-encode this search query before adding it to a URL."

---

### Tool: `calculateHash`

*   **Purpose:** Calculates a cryptographic hash (e.g., MD5, SHA-256) of a given text input.
*   **Approach:** Deterministic crypto library.
*   **Suggested Libraries:** Node.js built-in `crypto` module.
*   **How to Use (Implementation Sketch):**
    *   Define using `new Tool`. Schema (`zod`): `text: z.string()`, `algorithm: z.enum(['md5', 'sha1', 'sha256', 'sha512']).default('sha256')`.
    *   `execute`: Import `crypto`. `const hash = crypto.createHash(input.algorithm).update(input.text).digest('hex');`. Return `{ success: true, hash: hash }`.
*   **When & Why:** Generating checksums for data integrity verification, creating simple identifiers, comparing data without storing the original (though hashing is one-way). **Note:** MD5 and SHA1 are generally not considered secure for cryptographic purposes like password hashing but are okay for checksums.
*   **What Used For:** "Calculate the SHA-256 hash of this document content.", "Generate an MD5 checksum for this configuration string."

---

### Tool: `manipulateDateTime`

*   **Purpose:** Performs date and time calculations, formatting, or parsing.
*   **Approach:** Deterministic date/time library.
*   **Suggested Libraries:** `date-fns` (popular, immutable), `dayjs` (lightweight moment.js alternative), `luxon` (by Moment team). Avoid legacy `moment.js`.
*   **How to Use (Implementation Sketch - using date-fns):**
    *   Define using `new Tool`. Schema (`zod`): `dateString: z.string().optional().describe("Input date string (defaults to now if omitted).")`, `inputFormat: z.string().optional().describe("Format of input dateString (e.g., 'yyyy-MM-dd').")`, `action: z.enum(['format', 'add', 'subtract', 'difference', 'parse'])`, `outputFormat: z.string().optional().default("yyyy-MM-dd'T'HH:mm:ssXXX").describe("Desired output format string."), `addSubtractAmount: z.number().optional()`, `addSubtractUnit: z.enum(['days', 'weeks', 'months', 'hours', 'minutes']).optional()`, `compareDateString: z.string().optional()`.
    *   `execute`: Import functions from `date-fns` (`parse`, `format`, `addDays`, `subMonths`, `differenceInDays`, etc.). Parse `inputDateString` using `parse(dateString, inputFormat, new Date())` (or use `new Date()` if no input). Perform the requested `action` using appropriate `date-fns` functions. Format the result using `format(resultDate, outputFormat)`. Return `{ success: true, result: formattedResult / calculatedDifference }`. Handle parsing errors.
*   **When & Why:** Handling scheduling, calculating durations, formatting dates for display or APIs, parsing dates from various formats. Libraries handle timezones, leap years, etc., correctly.
*   **What Used For:** "Format today's date as 'MM/dd/yyyy'.", "What is the date 3 weeks from '2024-01-15'?", "Calculate the number of days between '2024-01-01' and '2024-03-15'.", "Parse the string '05 Mar 2024' and show it in ISO format."

---

### Tool: `queryJsonData` (using JSONPath or similar)

*   **Purpose:** Extracts specific values or subsets from a JSON object/array using a path expression language like JSONPath.
*   **Approach:** Deterministic query library.
*   **Suggested Libraries:** `jsonpath-plus`.
*   **How to Use (Implementation Sketch):**
    *   Define using `new Tool`. Schema (`zod`): `jsonData: z.any().describe("The input JSON object or array.")`, `pathExpression: z.string().describe("The JSONPath expression (e.g., '$.store.book[*].author').")`.
    *   `execute`: Import `JSONPath` from `jsonpath-plus`. Use `try...catch`. `const result = JSONPath({ path: input.pathExpression, json: input.jsonData });`. Return `{ success: true, result: result }`. Handle invalid path expressions or non-JSON input.
*   **When & Why:** Precisely extracting deeply nested data from complex JSON structures without manually traversing the object, especially when the structure is known. More robust than regex for JSON.
*   **What Used For:** "From this API response JSON, extract all product names under the 'items' array.", "Get the value of the 'user.address.city' field from the JSON.", "Find all books cheaper than $10 using the JSONPath expression '$.store.book[?(@.price < 10)]'."

---

## Section 3: Troubleshooting Common Issues

*   **LLM Errors (Summarize, Translate, ParseStructured):**
    *   **Problem:** Tool fails with API errors, rate limits, or content filtering messages.
    *   **Solution:** Check API key validity and usage quotas. Review prompt for potentially problematic content. Implement retry logic with exponential backoff for transient network/API issues. Ensure the agent handles the structured error response gracefully.
*   **Incorrect LLM Output (Summarize, ParseStructured):**
    *   **Problem:** LLM doesn't follow formatting instructions (e.g., returns prose instead of JSON), hallucinates data, or provides inaccurate summaries/extractions.
    *   **Solution:** **Refine the prompt:** Be more explicit, provide examples (few-shot), clearly state desired format ("Respond ONLY with the JSON object..."). Lower LLM temperature for more deterministic output. Add a validation step (`validateDataSchema`) after extraction. Consider using a more capable model if available.
*   **Parsing Errors (CSV, XML, JSON):**
    *   **Problem:** Tools fail with errors like "Invalid CSV format", "Malformed XML", "Unexpected token".
    *   **Solution:** Check the input data format rigorously. Ensure delimiters, headers (CSV), and tags (XML) are correct. Validate JSON structure. Use `try...catch` in the tool to catch parsing exceptions and return informative error messages. Log the problematic input data snippet if possible (be careful with sensitive data).
*   **Validation Errors (`validateDataSchema`):**
    *   **Problem:** Tool reports `isValid: false`.
    *   **Solution:** Examine the `errors` payload returned by the tool, which details which fields failed validation and why (e.g., incorrect type, missing required field). Adjust the data source or the schema definition.
*   **Transformation Errors (`transformDataStructure`):**
    *   **Problem:** Tool fails because source data lacks expected fields or has incorrect types for the transformation logic.
    *   **Solution:** Make transformation logic more resilient (e.g., use `lodash` `_.get` with defaults, check for field existence before accessing). Ensure source data conforms to expectations (potentially use `validateDataSchema` first). Improve error messages to indicate which part of the transformation failed.
*   **Regex Errors (`applyRegexPattern`):**
    *   **Problem:** Tool fails with "Invalid regular expression" or doesn't match/replace as expected. ReDoS risk.
    *   **Solution:** Validate regex patterns carefully (use online testers). Ensure correct escaping (double backslashes in JS strings). Use `try...catch` when creating `new RegExp()`. Avoid constructing regex from untrusted input. Test patterns thoroughly on edge cases.
*   **Library Issues (General):**
    *   **Problem:** Tool fails with errors related to missing libraries (`cannot find module...`) or incompatible versions.
    *   **Solution:** Ensure all suggested libraries (`js-yaml`, `papaparse`, `date-fns`, etc.) are installed (`npm install ...`) in the project. Check for version compatibility issues.

---

## Section 4: General Notes & Advanced Patterns

*   **Tool Composability:** The true power emerges when agents chain these tools: Fetch Data -> Clean Text -> Parse Structure -> Validate -> Transform -> Format -> Save/Display. Design tools to be composable units in these chains.
*   **Context Preservation:** Tools are typically stateless. The agent or workflow framework (Mastra) is responsible for maintaining conversation state/memory and passing relevant data between tool calls.
*   **Configuration:** Externalize API keys (use environment variables via `process.env`), model names, schema names, transformation names, and other non-trivial configurations rather than hardcoding them in tool definitions.
*   **Performance:** For performance-critical paths, prefer deterministic library-based tools over LLM calls where possible. Be mindful of the overhead of each tool execution.
*   **Extensibility:** Structure your tools and supporting modules (schemas, transformations) in a way that makes it easy to add new tools, schemas, or transformation rules as your agent's capabilities grow.

---
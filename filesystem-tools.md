# Category: File System Operations

**Overview:** Tools in this category allow Mastra AI agents to interact with the local file system where the agent process is running. Operations are intended to occur **within a designated `.mastra` workspace directory** for security and organization.

**CRITICAL SECURITY WARNINGS & WORKSPACE CONTEXT:**

*   **HIGH RISK:** Granting file system access is dangerous. Agents could read sensitive data, overwrite critical files, delete data, or escape intended boundaries if not strictly controlled.
*   **`.mastra` WORKSPACE:** All file operations performed by these tools **MUST** be confined within a defined workspace directory, typically resolved to `.mastra` within the project root.
*   **MANDATORY PATH VALIDATION:** **Every** file path input received by these tools **MUST** be validated to ensure it resolves to a location *inside* the designated `.mastra` workspace. **Never trust paths directly from LLMs or users without this validation.** (See Validation Helper below).
*   **LEAST PRIVILEGE:** Run the Mastra agent process with the minimum necessary file system permissions for the `.mastra` workspace ONLY. Avoid running as `root`.
*   **SYMBOLIC LINKS (Symlinks):** Be cautious. A symlink within the workspace could potentially point outside. Validation should ideally detect and reject paths containing symlinks unless explicitly handled and understood. Use `fs.lstat` instead of `fs.stat` if you need to check the link itself rather than its target. For simplicity, disallowing symlinks might be safest initially.
*   **DESTRUCTIVE OPERATIONS:** Use extreme caution with `deletePath` and `writeFileContent` (overwrite mode). Limit their scope within the workspace (e.g., to `.mastra/temp` or `.mastra/output`).

**Prerequisites & Libraries:**
*   Relies on Node.js built-in modules `fs/promises` and `path`.
*   `glob` library needed for `findFilesByPattern`. (`npm install glob`)
*   `fs-extra` (`npm install fs-extra`) offers convenient alternatives (e.g., `ensureDir`, `copy`, `move`, `remove`) that handle some edge cases automatically, but base `fs/promises` is sufficient.

**Path Validation Helper (Conceptual):**
*   Define the absolute path to your workspace early in your application context.
*   Use a helper function like this before any `fs` operation in your tools:

```typescript
import path from 'path';
import fs from 'fs/promises'; // Needed for realpath potentially

// Resolve this ONCE when your agent/app starts
// Ensure MASTRA_WORKSPACE points to the correct absolute path of your .mastra directory
const MASTRA_WORKSPACE = path.resolve(process.cwd(), '.mastra');

async function isPathInsideWorkspace(inputPath: string): Promise<string | null> {
  try {
    // Resolve the input path relative to the current working directory
    // Handles cases where inputPath might already be absolute
    const resolvedInputPath = path.resolve(process.cwd(), inputPath);

    // Optional but recommended: Resolve symbolic links to get the real path
    // const realInputPath = await fs.realpath(resolvedInputPath); // Use with caution if symlinks are needed

    // Use resolvedInputPath if not resolving symlinks, or realInputPath if you are
    const finalPathToValidate = resolvedInputPath; // Or realInputPath

    // Check if the resolved path starts with the workspace path (+ path separator)
    // Also ensure it's not IDENTICAL to the workspace path if you want to prevent operating on the root workspace dir directly
    if ((finalPathToValidate.startsWith(MASTRA_WORKSPACE + path.sep) || finalPathToValidate === MASTRA_WORKSPACE)) {
       // Optional: Add checks here to specifically disallow problematic symlinks if needed
       // For example, compare resolvedInputPath and realInputPath if using realpath
       // const stats = await fs.lstat(finalPathToValidate); if(stats.isSymbolicLink()){ return null; }
       return finalPathToValidate; // Return the safe, resolved absolute path
    }
  } catch (error: any) {
     // Handle errors like path does not exist during realpath resolution if needed
     console.error(`Path validation error for "${inputPath}": ${error.message}`);
     return null;
  }
  console.error(`Validation failed: Path "${inputPath}" resolves outside workspace "${MASTRA_WORKSPACE}"`);
  return null; // Path is outside the workspace or validation failed
}
```

// --- Inside a Tool's execute function ---
// const validatedPath = await isPathInsideWorkspace(input.filePath);
// if (!validatedPath) {
//   return { success: false, error: "Path validation failed: Path is outside the allowed workspace.", code: 'PATH_VALIDATION_FAILED' };
// }
// // Proceed using validatedPath for fs operations...
// // e.g., await fs.promises.readFile(validatedPath, ...);
 pasting.

```markdown
# Category: File System Operations

**Overview:** Tools in this category allow Mastra AI agents to interact with the local file system where the agent process is running. Operations are intended to occur **within a designated `.mastra` workspace directory** for security and organization.

**CRITICAL SECURITY WARNINGS & WORKSPACE CONTEXT:**

*   **HIGH RISK:** Granting file system access is dangerous. Agents could read sensitive data, overwrite critical files, delete data, or escape intended boundaries if not strictly controlled.
*   **`.mastra` WORKSPACE:** All file operations performed by these tools **MUST** be confined within a defined workspace directory, typically resolved to `.mastra` within the project root.
*   **MANDATORY PATH VALIDATION:** **Every** file path input received by these tools **MUST** be validated to ensure it resolves to a location *inside* the designated `.mastra` workspace. **Never trust paths directly from LLMs or users without this validation.** (See Validation Helper below).
*   **LEAST PRIVILEGE:** Run the Mastra agent process with the minimum necessary file system permissions for the `.mastra` workspace ONLY. Avoid running as `root`.
*   **SYMBOLIC LINKS (Symlinks):** Be cautious. A symlink within the workspace could potentially point outside. Validation should ideally detect and reject paths containing symlinks unless explicitly handled and understood. Use `fs.lstat` instead of `fs.stat` if you need to check the link itself rather than its target. For simplicity, disallowing symlinks might be safest initially.
*   **DESTRUCTIVE OPERATIONS:** Use extreme caution with `deletePath` and `writeFileContent` (overwrite mode). Limit their scope within the workspace (e.g., to `.mastra/temp` or `.mastra/output`).

**Prerequisites & Libraries:**
*   Relies on Node.js built-in modules `fs/promises` and `path`.
*   `glob` library needed for `findFilesByPattern`. (`npm install glob`)
*   `fs-extra` (`npm install fs-extra`) offers convenient alternatives (e.g., `ensureDir`, `copy`, `move`, `remove`) that handle some edge cases automatically, but base `fs/promises` is sufficient.

**Path Validation Helper (Conceptual):**
*   Define the absolute path to your workspace early in your application context.
*   Use a helper function like this before any `fs` operation in your tools:

```typescript
import path from 'path';
import fs from 'fs/promises'; // Needed for realpath potentially

// Resolve this ONCE when your agent/app starts
// Ensure MASTRA_WORKSPACE points to the correct absolute path of your .mastra directory
const MASTRA_WORKSPACE = path.resolve(process.cwd(), '.mastra');

async function isPathInsideWorkspace(inputPath: string): Promise<string | null> {
  try {
    // Resolve the input path relative to the current working directory
    const resolvedInputPath = path.resolve(process.cwd(), inputPath);

    // Optional but recommended: Resolve symbolic links to get the real path
    // const realInputPath = await fs.realpath(resolvedInputPath); // Use with caution if symlinks are needed

    // Use resolvedInputPath if not resolving symlinks, or realInputPath if you are
    const finalPathToValidate = resolvedInputPath; // Or realInputPath

    // Check if the resolved path starts with the workspace path (+ path separator)
    // Also ensure it's not IDENTICAL to the workspace path if you want to prevent operating on the root workspace dir directly
    if ((finalPathToValidate.startsWith(MASTRA_WORKSPACE + path.sep) || finalPathToValidate === MASTRA_WORKSPACE)) {
       // Optional: Add checks here to specifically disallow problematic symlinks if needed
       // For example, compare resolvedInputPath and realInputPath if using realpath
       // const stats = await fs.lstat(finalPathToValidate); if(stats.isSymbolicLink()){ console.warn(`Path validation warning: Path "${inputPath}" is a symbolic link.`); /* return null; // If disallowing */ }
       return finalPathToValidate; // Return the safe, resolved absolute path
    }
  } catch (error: any) {
     // Handle errors like path does not exist during realpath resolution if needed
     console.error(`Path validation error for "${inputPath}": ${error.message}`);
     return null;
  }
  console.error(`Validation failed: Path "${inputPath}" resolves outside workspace "${MASTRA_WORKSPACE}"`);
  return null; // Path is outside the workspace or validation failed
}

// --- Tool Execute Example Usage ---
// async execute({ input }) {
//   const validatedPath = await isPathInsideWorkspace(input.filePath);
//   if (!validatedPath) {
//     return { success: false, error: "Path validation failed: Path is outside the allowed workspace.", code: 'PATH_VALIDATION_FAILED' };
//   }
//   // Proceed using validatedPath for fs operations...
//   try {
//      const content = await fs.promises.readFile(validatedPath, { encoding: 'utf8' });
//      return { success: true, content: content };
//   } catch (error: any) {
//      // ...```

---

## Section 1: Core File System Tools

### Tool: `readFileContent`

*   **Purpose:** Reads file content within the `.mastra` workspace.
*   **Approach:** `fs/promises.readFile`.
*   **How to Use:** (Schema: `filePath`, `encoding`)
    *   `execute`: **Validate `input.filePath` using `isPathInsideWorkspace`**. If valid, `await fs.promises.readFile(validatedPath, { encoding: input.encoding as BufferEncoding })`. Return content or structured error (check `error.code`: `'ENOENT'`, `'EACCES'`, `'EISDIR'`). Example path: `.mastra/data/input.json`.
*   **When & Why:** Accessing config, data, templates within the agent's workspace.
*   **What Used For:** "Read `.mastra/config/settings.json`.", "Load text from `.mastra/temp/download.txt`."

---

### Tool: `writeFileContent`

*   **Purpose:** Writes/appends content to a file within the `.mastra` workspace. Creates directories if needed.
*   **Approach:** `fs/promises.writeFile/appendFile`, `fs/promises.mkdir`. (`fs-extra.outputFile` or `fs-extra.appendFile` are convenient alternatives).
*   **How to Use:** (Schema: `filePath`, `content`, `encoding`, `mode`)
    *   `execute`: **Validate `input.filePath` using `isPathInsideWorkspace`**. If valid, `await fs.promises.mkdir(path.dirname(validatedPath), { recursive: true })`. Then `await fs.promises.writeFile/appendFile(validatedPath, input.content, { encoding: input.encoding as BufferEncoding })`. Return success or structured error (`'EACCES'`, `'EISDIR'`). Example path: `.mastra/output/summary.md`.
*   **When & Why:** Saving generated content, logs, processed data within the workspace.
*   **What Used For:** "Save summary to `.mastra/output/summary.txt`.", "Append log to `.mastra/logs/agent.log`."

---

### Tool: `checkPathExists`

*   **Purpose:** Checks if a path exists within the `.mastra` workspace and its type (file/directory).
*   **Approach:** `fs/promises.stat`.
*   **How to Use:** (Schema: `pathToCheck`)
    *   `execute`: **Validate `input.pathToCheck` using `isPathInsideWorkspace`**. If valid, `const stats = await fs.promises.stat(validatedPath)`. Return `{ success: true, exists: true, type: stats.isDirectory() ? 'directory' : 'file' }`. Catch `error` where `error.code === 'ENOENT'` -> return `{ success: true, exists: false, type: null }`. Catch other errors (`'EACCES'`) -> return structured error with code `'CHECK_FAILED'`. Example path: `.mastra/output/results.csv`.
*   **When & Why:** Pre-checking before read/write/delete. Conditional logic.
*   **What Used For:** "Check if `.mastra/output/results.csv` exists.", "Is `.mastra/templates` a directory?".

---

### Tool: `listFiles`

*   **Purpose:** Lists files/subdirectories directly within a directory inside `.mastra` workspace.
*   **Approach:** `fs/promises.readdir`.
*   **How to Use:** (Schema: `directoryPath`)
    *   `execute`: **Validate `input.directoryPath` using `isPathInsideWorkspace`**. If valid, `const entries = await fs.promises.readdir(validatedPath)`. Return `{ success: true, entries: entries }`. Catch errors (`'ENOENT'`, `'EACCES'`, `'ENOTDIR'`). Example path: `.mastra/data`.
*   **When & Why:** Exploring workspace contents.
*   **What Used For:** "List files/folders inside `.mastra/data`.", "What `.json` files are in `.mastra/config`?" (Agent filters result).

---

### Tool: `getFileMetadata`

*   **Purpose:** Gets metadata (size, mtime, type) for a path within `.mastra` workspace.
*   **Approach:** `fs/promises.stat`.
*   **How to Use:** (Schema: `pathToStat`)
    *   `execute`: **Validate `input.pathToStat` using `isPathInsideWorkspace`**. If valid, `const stats = await fs.promises.stat(validatedPath)`. Extract `stats.size`, `stats.mtimeMs`, `stats.birthtimeMs`, `stats.isDirectory()`, `stats.isFile()`. Return `{ success: true, metadata: {...} }`. Catch errors (`'ENOENT'`, `'EACCES'`). Example path: `.mastra/config/settings.json`.
*   **When & Why:** Checking file size, modification dates, verifying type.
*   **What Used For:** "Size of `.mastra/cache/large_file.zip`?", "When was `.mastra/config/settings.json` modified?".

---

### Tool: `createDirectory`

*   **Purpose:** Creates a directory within `.mastra` workspace (including parents).
*   **Approach:** `fs/promises.mkdir`. (`fs-extra.ensureDir` is convenient alternative).
*   **How to Use:** (Schema: `directoryPath`)
    *   `execute`: **Validate `input.directoryPath` using `isPathInsideWorkspace`**. If valid, `await fs.promises.mkdir(validatedPath, { recursive: true })`. Return `{ success: true }`. Catch errors (`'EEXIST'` (if file), `'EACCES'`). Example path: `.mastra/output/images`.
*   **When & Why:** Ensuring output directories exist before writing.
*   **What Used For:** "Create directory `.mastra/output/processed_images`.", "Ensure `.mastra/temp` exists."

---

### Tool: `deletePath`

*   **Purpose:** Deletes file/directory within `.mastra` workspace. **EXTREME CAUTION.**
*   **Approach:** `fs/promises.rm`. (`fs-extra.remove` is convenient alternative).
*   **How to Use:** (Schema: `pathToDelete`, `recursive`)
    *   `execute`: **CRITICAL VALIDATION of `input.pathToDelete` using `isPathInsideWorkspace`**. Add extra checks (e.g., prevent deleting `.mastra` itself or critical subdirs like `.mastra/config`). If valid, `await fs.promises.rm(validatedPath, { recursive: input.recursive, force: false /* Use force cautiously */ })`. Return `{ success: true }`. Catch errors (`'ENOENT'`, `'EACCES'`/`'EPERM'`, `'ENOTEMPTY'` if not recursive). Example path: `.mastra/temp/old_file.tmp`.
*   **When & Why:** Cleaning temporary files/dirs. **Use with extreme care.** Consider moving to `.mastra/trash` instead.
*   **What Used For:** "Delete `.mastra/temp/data.tmp`.", *(With safeguards)* "Remove `.mastra/output/old_run` recursively."

---

### Tool: `moveOrRenamePath`

*   **Purpose:** Moves/renames path within `.mastra` workspace.
*   **Approach:** `fs/promises.rename`. (`fs-extra.move` handles cross-device better).
*   **How to Use:** (Schema: `sourcePath`, `destinationPath`)
    *   `execute`: **Validate BOTH paths using `isPathInsideWorkspace`**. If valid, ensure destination dir exists (`mkdir`). `await fs.promises.rename(validatedSource, validatedDest)`. Return `{ success: true }`. Catch errors (`'ENOENT'`, `'EACCES'`, `'EXDEV'` - cross-device). Example: Move `.mastra/temp/file.txt` to `.mastra/processed/file.txt`.
*   **When & Why:** Reorganizing files within the workspace, archiving.
*   **What Used For:** "Rename `.mastra/draft.txt` to `.mastra/final.txt`.", "Move `.mastra/input/data.csv` to `.mastra/archive/data.csv`."

---

### Tool: `copyPath`

*   **Purpose:** Copies file/directory within `.mastra` workspace.
*   **Approach:** `fs/promises.cp` (Node >= 16.7) or `fs.promises.copyFile` + manual recursion / `fs-extra.copy`.
*   **How to Use:** (Schema: `sourcePath`, `destinationPath`, `recursive`)
    *   `execute`: **Validate BOTH paths using `isPathInsideWorkspace`**. If valid, ensure destination dir exists. Use `fs.promises.cp(validatedSource, validatedDest, { recursive: input.recursive })`. Return `{ success: true }`. Catch errors (`'ENOENT'`, `'EACCES'`). Example: Copy `.mastra/templates/report` to `.mastra/reports/march`.
*   **When & Why:** Creating backups, duplicating templates within the workspace.
*   **What Used For:** "Copy `.mastra/config.json` to `.mastra/config.json.bak`.", "Duplicate `.mastra/templates/report` to `.mastra/reports/march`."

---

## Section 2: Advanced File System Tools

### Tool: `findFilesByPattern`

*   **Purpose:** Finds files/dirs matching glob pattern within `.mastra` workspace.
*   **Approach:** `glob` library.
*   **How to Use:** (Schema: `pattern`, optional `baseDirectory` relative to workspace, `options`)
    *   `execute`: **Resolve and Validate `baseDirectory` (defaulting to `.mastra`) using `isPathInsideWorkspace`**. Ensure `pattern` is safe if dynamic. `const matches = await glob(input.pattern, { cwd: validatedBaseDir, dot: input.options?.dot, ignore: input.options?.ignore, absolute: true /* Get absolute paths */ })`. **Re-validate each `match`** using `isPathInsideWorkspace` to prevent glob escaping issues. Return `{ success: true, matches: validatedMatches }`. Catch errors. Example pattern: `output/**/*.log`.
*   **When & Why:** Finding multiple files by convention/type for batch processing.
*   **What Used For:** "Find all `.log` files in `.mastra/logs` recursively.", "List `.jpg` files in `.mastra/images`."

---

### Tool: `createTemporaryFileOrDirectory`

*   **Purpose:** Creates unique temp file/dir within `.mastra/temp` (recommended) or OS default if configured otherwise.
*   **Approach:** `fs/promises`, `path`, `crypto`, `os`.
*   **How to Use:** (Schema: `type`, optional `prefix`, `content`)
    *   `execute`: Define target temp dir (`const tempDir = path.join(MASTRA_WORKSPACE, 'temp')` - recommended). **Ensure `tempDir` exists (`mkdir`) and is validated using `isPathInsideWorkspace`**. Generate unique name (`crypto.randomBytes`). Create file/dir at `path.join(tempDir, uniqueName)`. Return `{ success: true, path: tempPath }`. Catch errors.
*   **When & Why:** Safe temporary storage. **Requires cleanup logic** using `deletePath`.
*   **What Used For:** "Create temp dir in `.mastra/temp`.", "Make temp file in `.mastra/temp`, write content, return path."

---

## Section 3: Troubleshooting Common Issues

*   **Permission Errors (`EACCES`, `EPERM`):** Check process owner's permissions specifically on the `.mastra` directory and its subdirectories/files. Ensure the workspace directory itself exists and is writable by the agent process.
*   **Path Not Found (`ENOENT`):** Verify the path *relative to the project root* or as an absolute path resolves correctly within the `.mastra` workspace. Double-check the `isPathInsideWorkspace` logic.
*   **Validation Errors (`PATH_VALIDATION_FAILED`):** The path resolved outside the allowed `.mastra` workspace. Check agent logic generating the path (e.g., ensure it prepends `./.mastra/` or uses resolved paths correctly). Verify `MASTRA_WORKSPACE` constant is correct.
*   **Is Directory/Not Directory (`EISDIR`, `ENOTDIR`):** Use `checkPathExists` or `getFileMetadata` first to confirm path type.
*   **Directory Not Empty (`ENOTEMPTY`):** Use `deletePath` with `recursive: true` (cautiously!) or delete contents first.
*   **Cross-Device Move (`EXDEV`):** Less likely if staying within `.mastra` on one volume. Use `fs-extra.move` or copy-delete fallback if moving across mount points is possible.
*   **Glob Issues:** Ensure `cwd` option is set correctly to the validated base directory. Validate patterns if dynamic. Re-validate results from `glob` to prevent escape issues via the `isPathInsideWorkspace` check on each result.

---

## Section 4: General Notes & Best Practices

*   **`.mastra` is the Sandbox:** Treat this directory as the agent's dedicated, restricted workspace. Configure tools and validation accordingly. Ensure necessary subdirectories (`temp`, `output`, `logs`, `data`, etc.) are created within `.mastra` during your application's setup phase.
*   **Path Resolution & Validation:** Always use `path.resolve()` for inputs. The `isPathInsideWorkspace` check (or similar) **MUST** precede every `fs` operation accepting a path. Be strict.
*   **Symbolic Links:** Decide on a strategy. Disallowing them via validation (checking `lstat` results in `isPathInsideWorkspace`) is often safest unless specifically needed and handled correctly.
*   **Encoding:** Specify text encoding (`'utf8'`, `'base64'`) clearly when reading/writing.
*   **Atomicity:** For critical updates, use write-to-temp then atomic rename pattern (`fs.promises.rename` is often atomic on POSIX systems).
*   **Concurrency:** If multiple agents/processes might access the same files, use locking (`proper-lockfile`) for write operations, but this adds complexity.
*   **Cleanup:** Implement reliable cleanup logic (using `deletePath`) for temporary files/directories, ideally using `finally` blocks in the agent's higher-level logic or workflow steps.
*   **`fs-extra`:** Consider using `fs-extra` for added convenience, especially `ensureDir`, `copy`, `move`, and `remove`, which often handle common edge cases more smoothly than base `fs/promises`.

---
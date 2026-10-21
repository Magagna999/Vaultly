/**
 * The only module allowed to touch the console (enforced by ESLint).
 * It accepts a fixed message plus an optional error CODE only: never pass
 * credentials, keys, tokens or file contents.
 */
export function logError(context: string, code?: string): void {
  console.error(`[vault] ${context}${code ? ` (${code})` : ''}`);
}

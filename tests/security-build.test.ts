/**
 * Security tests for the build artifacts of the extension.
 *
 * The suite verifies the properties that cannot be observed at runtime:
 *  1. the shipped manifest keeps the least privilege and a strict CSP;
 *  2. `console` is used by the logger module only, and `logError` accepts a
 *     context and a code only (never a secret);
 *  3. the bundle shipped in `dist/` contains no credential, no service role
 *     token and no test master password;
 *  4. the extension loads no remote code (no CDN, no `eval`, no `new Function`);
 *  5. the environment template is safe to publish and the real `.env` is ignored.
 *
 * Real files (manifest, sources, build output, `.env.example`, `.gitignore`)
 * are read from the repository root with `process.cwd()`.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = process.cwd();
const SRC_DIR = join(ROOT, 'src');
const DIST_DIR = join(ROOT, 'dist');
const MANIFEST_PATH = join(ROOT, 'public', 'manifest.json');
const ENV_EXAMPLE_PATH = join(ROOT, '.env.example');
const GITIGNORE_PATH = join(ROOT, '.gitignore');
const ESLINT_PATH = join(ROOT, 'eslint.config.js');

/** The only module of the project allowed to touch the console. */
const LOGGER_RELATIVE = 'src/utils/logger.ts';

/** Master passwords used by the test suite: they must never reach the bundle. */
const TEST_MASTER_PASSWORDS = [
  'M4ster-Passw0rd!-a1b2',
  'M4ster-Passw0rd!-vault',
  'correct horse battery staple!',
  'master password of user a',
  'master password of user b',
];

/** Hosts that would mean that the extension downloads code at runtime. */
const CDN_MARKERS = ['https://cdn', 'http://cdn', 'unpkg', 'jsdelivr', 'cdnjs', 'googleapis.com'];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Path relative to the repository root, always with POSIX separators. */
function rel(path: string): string {
  return relative(ROOT, path).split(sep).join('/');
}

/** Reads a UTF-8 text file. */
function readText(path: string): string {
  return readFileSync(path, 'utf8');
}

/** Recursively lists the files of a directory, optionally filtered by extension. */
function collectFiles(dir: string, extensions: string[] = []): string[] {
  if (!existsSync(dir)) return [];
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(full, extensions));
    } else if (extensions.length === 0 || extensions.some((extension) => entry.name.endsWith(extension))) {
      files.push(full);
    }
  }
  return files.sort();
}

/** A single directive of a Content Security Policy. */
interface CspDirective {
  name: string;
  sources: string[];
}

/** Splits a CSP string into its directives and lower cases every token. */
function parseCsp(csp: string): CspDirective[] {
  return csp
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => {
      const tokens = part.split(/\s+/).filter((token) => token.length > 0);
      const name = (tokens[0] ?? '').toLowerCase();
      const sources = tokens.slice(1).map((token) => token.toLowerCase());
      return { name, sources };
    });
}

/** Finds a directive by name. */
function directive(csp: CspDirective[], name: string): CspDirective | undefined {
  return csp.find((entry) => entry.name === name);
}

/** Matches a JWT (three base64url segments). */
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

/** Decodes the payload of a JWT, or returns null when it is not readable. */
function decodeJwtPayload(token: string): string | null {
  const segments = token.split('.');
  const payload = segments[1];
  if (payload === undefined) return null;
  try {
    return Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch {
    return null;
  }
}

/** Removes the comments of a TypeScript source, keeping the executable code. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');
}

/** The manifest of the extension, as far as the security checks care about it. */
interface ExtensionManifest {
  manifest_version?: number;
  permissions?: string[];
  host_permissions?: string[];
  optional_permissions?: string[];
  content_scripts?: unknown[];
  content_security_policy?: { extension_pages?: string };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SRC_FILES = collectFiles(SRC_DIR, ['.ts', '.tsx']);
const DIST_FILES = collectFiles(DIST_DIR);
const DIST_HTML_FILES = DIST_FILES.filter((file) => file.endsWith('.html'));

/**
 * The application bundles: the service worker and the two UI entry points.
 * Vendor chunks are excluded on purpose, only the extension code is audited.
 */
const APP_SCRIPT_RE = /^(?:background\.js|assets\/popup-[^/]*\.js|assets\/options-[^/]*\.js)$/;
const APP_SCRIPTS = DIST_FILES.filter((file) => APP_SCRIPT_RE.test(rel(file).replace(/^dist\//, '')));

// ---------------------------------------------------------------------------
// 1. Manifest
// ---------------------------------------------------------------------------

describe('extension manifest', () => {
  const manifestText = existsSync(MANIFEST_PATH) ? readText(MANIFEST_PATH) : '';
  const manifest = JSON.parse(manifestText || '{}') as unknown as ExtensionManifest;
  const csp = manifest.content_security_policy?.extension_pages ?? '';
  const directives = parseCsp(csp);

  it('ships a manifest v3', () => {
    expect(existsSync(MANIFEST_PATH)).toBe(true);
    expect(manifest.manifest_version).toBe(3);
  });

  it('requests the storage permission and nothing else', () => {
    expect(manifest.permissions).toEqual(['storage']);
  });

  it('requests no host permission and defines no content script', () => {
    expect(manifest.host_permissions).toBeUndefined();
    expect(manifest.optional_permissions).toBeUndefined();
    expect(manifest.content_scripts).toBeUndefined();
  });

  it('never asks for the all urls pattern', () => {
    expect(manifestText).not.toContain('<all_urls>');
    expect(manifestText).not.toContain('*://');
  });

  it('locks the content security policy of the extension pages', () => {
    expect(csp.length).toBeGreaterThan(0);

    const scriptSrc = directive(directives, 'script-src');
    expect(scriptSrc, 'the script-src directive is missing').toBeDefined();
    const sources = scriptSrc?.sources ?? [];

    expect(sources).toContain("'self'");
    expect(sources).not.toContain("'unsafe-eval'");
    expect(sources).not.toContain("'unsafe-inline'");
    expect(sources).not.toContain('*');
    for (const source of sources) {
      expect(source, 'a remote origin is allowed in script-src').not.toMatch(/^https?:/);
      expect(source, 'a remote origin is allowed in script-src').not.toMatch(/^\*/);
      expect(source, 'a remote origin is allowed in script-src').not.toBe('http:');
    }

    const objectSrc = directive(directives, 'object-src');
    expect(objectSrc?.sources).toEqual(["'none'"]);
  });

  it('lets the extension talk to the Supabase project only', () => {
    const connectSrc = directive(directives, 'connect-src');
    expect(connectSrc, 'the connect-src directive is missing').toBeDefined();
    expect(connectSrc?.sources).toEqual(['https://*.supabase.co']);
  });

  it('keeps the packaged manifest identical to the source manifest', () => {
    const packaged = join(DIST_DIR, 'manifest.json');
    expect(existsSync(packaged)).toBe(true);
    const packagedManifest = JSON.parse(readText(packaged)) as unknown as ExtensionManifest;
    expect(packagedManifest).toEqual(manifest);
  });
});

// ---------------------------------------------------------------------------
// 2. Logging discipline
// ---------------------------------------------------------------------------

describe('logging discipline', () => {
  it('finds the application sources', () => {
    expect(SRC_FILES.length).toBeGreaterThan(0);
    expect(SRC_FILES.some((file) => rel(file) === LOGGER_RELATIVE)).toBe(true);
  });

  it('keeps the console inside the logger module', () => {
    const offenders: string[] = [];
    for (const file of SRC_FILES) {
      if (rel(file) === LOGGER_RELATIVE) continue;
      if (/\bconsole\s*\./.test(readText(file))) offenders.push(rel(file));
    }
    expect(offenders).toEqual([]);
  });

  it('uses the console in the logger module', () => {
    expect(/\bconsole\s*\./.test(readText(join(ROOT, LOGGER_RELATIVE)))).toBe(true);
  });

  it('exposes a logError signature that only accepts a context and a code', () => {
    const source = readText(join(ROOT, LOGGER_RELATIVE));
    const match = /export\s+function\s+logError\s*\(([^)]*)\)/.exec(source);
    expect(match, 'the logError signature was not found').not.toBeNull();

    const parameters = (match?.[1] ?? '')
      .split(',')
      .map((parameter) => parameter.trim())
      .filter((parameter) => parameter.length > 0);

    expect(parameters).toHaveLength(2);

    const names = parameters.map((parameter) => (parameter.split(':')[0] ?? '').replace(/\?$/, '').trim());
    const types = parameters.map((parameter) => (parameter.split(':')[1] ?? '').replace(/\?$/, '').trim());

    expect(names).toEqual(['context', 'code']);
    expect(types).toEqual(['string', 'string']);

    const declaration = parameters.join(' ');
    expect(declaration).not.toMatch(/\bunknown\b/);
    expect(declaration).not.toMatch(/\bError\b/);
    expect(declaration).not.toMatch(/\bany\b/);

    // The helper returns nothing: it never returns the offending value.
    expect(source).toMatch(/export\s+function\s+logError\s*\([^)]*\)\s*:\s*void/);
  });

  it('forbids the console through the linter, except in the logger module', () => {
    const config = readText(ESLINT_PATH);
    expect(config).toMatch(/'no-console'\s*:\s*'error'/);
    expect(config).toContain(LOGGER_RELATIVE);
  });
});

// ---------------------------------------------------------------------------
// 3. No secret in the bundle
// ---------------------------------------------------------------------------

describe('build output contains no secret', () => {
  it('ships a build output to audit', () => {
    expect(existsSync(DIST_DIR)).toBe(true);
    expect(DIST_FILES.length).toBeGreaterThan(0);
  });

  it('never embeds the service role key name in the bundle', () => {
    for (const file of DIST_FILES) {
      expect(readText(file), rel(file)).not.toMatch(/service_role/i);
    }
  });

  it('never embeds a service role token in the bundle', () => {
    for (const file of DIST_FILES) {
      const content = readText(file);
      for (const token of content.match(JWT_RE) ?? []) {
        const payload = decodeJwtPayload(token) ?? '';
        expect(payload, rel(file)).not.toMatch(/"role"\s*:\s*"service_role"/);
        expect(payload, rel(file)).not.toContain('service_role');
      }
    }
  });

  it('never embeds a real secret key in the bundle', () => {
    // The bare `sb_secret_` substring is legitimate: it is the prefix used by
    // the supabase-js library itself. Only a complete key is a leak.
    for (const file of DIST_FILES) {
      expect(readText(file), rel(file)).not.toMatch(/sb_secret_[A-Za-z0-9_-]{20,}/);
    }
  });

  it('never embeds a test master password in the bundle', () => {
    for (const file of DIST_FILES) {
      const content = readText(file);
      for (const master of TEST_MASTER_PASSWORDS) {
        expect(content, `${rel(file)} contains a test master password`).not.toContain(master);
      }
    }
  });

  it('never mentions the service role in the application code', () => {
    for (const file of SRC_FILES) {
      const code = stripComments(readText(file));
      expect(code, rel(file)).not.toMatch(/service_role/i);
    }
  });
});

// ---------------------------------------------------------------------------
// 4. No remote code
// ---------------------------------------------------------------------------

describe('no remote code', () => {
  it('finds the html entry points of the build', () => {
    expect(DIST_HTML_FILES.length).toBeGreaterThan(0);
  });

  it('loads no remote script and no CDN asset from the html pages', () => {
    for (const file of DIST_HTML_FILES) {
      const html = readText(file);
      const name = rel(file);

      expect(html, name).not.toMatch(/<script[^>]*\ssrc\s*=\s*["']?https?:/i);

      const lower = html.toLowerCase();
      for (const marker of CDN_MARKERS) {
        expect(lower, `${name} links to ${marker}`).not.toContain(marker);
      }

      const urls = [...html.matchAll(/\b(?:src|href)\s*=\s*"([^"]*)"/gi)].map((match) => match[1] ?? '');
      for (const url of urls) {
        expect(url, `${name} loads a remote asset`).not.toMatch(/^(?:https?:)?\/\//i);
      }
    }
  });

  it('never evaluates code at runtime in the application bundles', () => {
    expect(APP_SCRIPTS.length).toBeGreaterThan(0);

    for (const file of APP_SCRIPTS) {
      const content = readText(file);
      const name = rel(file);
      expect(content, name).not.toMatch(/\beval\s*\(/);
      expect(content, name).not.toMatch(/\bnew\s+Function\s*\(/);
    }
  });
});

// ---------------------------------------------------------------------------
// 5. Environment files
// ---------------------------------------------------------------------------

describe('environment files', () => {
  it('ships an example environment file with placeholder values', () => {
    expect(existsSync(ENV_EXAMPLE_PATH)).toBe(true);
    const content = readText(ENV_EXAMPLE_PATH);

    const url = content
      .split('\n')
      .map((line) => line.trim())
      .find((line) => line.startsWith('VITE_SUPABASE_URL='));
    expect(url, 'VITE_SUPABASE_URL is missing from .env.example').toBeDefined();
    expect(url ?? '').toContain('YOUR-');

    const key = content
      .split('\n')
      .map((line) => line.trim())
      .find((line) => line.startsWith('VITE_SUPABASE_ANON_KEY='));
    expect(key, 'VITE_SUPABASE_ANON_KEY is missing from .env.example').toBeDefined();
    expect(key ?? '').toContain('YOUR-');
  });

  it('never ships a token in the example environment file', () => {
    const content = readText(ENV_EXAMPLE_PATH);
    expect(content).not.toContain('eyJ');
    expect(content).not.toMatch(/sb_secret_[A-Za-z0-9_-]{20,}/);
  });

  it('keeps the real environment file out of git', () => {
    expect(existsSync(GITIGNORE_PATH)).toBe(true);
    const lines = readText(GITIGNORE_PATH)
      .split('\n')
      .map((line) => line.trim());

    expect(lines).toContain('.env');
    expect(lines).toContain('!.env.example');
  });
});

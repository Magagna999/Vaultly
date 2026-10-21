/**
 * Security tests for the Supabase boundary.
 *
 * The suite verifies three properties:
 *  1. no clear text (password, username, url, name, note) ever reaches Supabase;
 *  2. the SQL migrations enforce owner-only access through row level security;
 *  3. error messages surfaced to the user never contain secrets.
 *
 * No real Supabase instance is contacted: the client is replaced by the
 * `fakeSupabase` helper, which records every call (table, op, payload,
 * options, filters). Real files (migrations, manifest, sources) are read from
 * the repository root with `process.cwd()`.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import type { CredentialData, CredentialRow, EncryptedWrite, VaultMeta } from '@/types';
import { createVault, decryptCredential, encryptCredential } from '@/services/crypto';
import {
  SupabaseCredentialStore,
  SupabaseVaultMetaStore,
  type CredentialStore,
} from '@/services/supabase/stores';
import { SyncService } from '@/services/sync/sync';
import { AppError } from '@/utils/errors';
import { fakeSupabase } from './helpers/fake-supabase';

const ROOT = process.cwd();
const ITERATIONS = 100_000;
const USER_ID = 'user-security';
const ISO = '2024-01-01T00:00:00.000Z';

/**
 * Sentinel secrets. Every character used here is outside the base64 alphabet,
 * so finding one of them inside a payload proves that clear text leaked.
 */
const MASTER_PASSWORD = 'M4ster-Passw0rd!-vault';
const PASSWORD = 'Pl41n-S3cret!';
const USERNAME = 'alice@example.com';
const CRED_URL = 'https://bank.example.com/login?token=abc';
const CRED_NAME = 'Bank Account';
const CRED_NOTE = 'recovery-code-4242';
const SECRETS = [PASSWORD, USERNAME, CRED_URL, CRED_NAME, CRED_NOTE];

/** The only keys an encrypted write is allowed to contain. */
const WRITE_KEYS = ['ciphertext', 'encryption_version', 'id', 'iv'];
/** Keys that must never appear in a payload sent to the server. */
const FORBIDDEN_KEYS = ['password', 'username', 'url', 'name', 'note', 'plaintext', 'user_id'];

const PROTECTED_TABLES = ['vaults', 'credentials'];
const POLICY_COMMANDS = ['select', 'insert', 'update', 'delete'];
const FORBIDDEN_COLUMNS = ['password', 'username', 'url', 'plaintext'];

let key!: CryptoKey;
let vaultMeta!: VaultMeta;

beforeAll(async () => {
  const vault = await createVault(MASTER_PASSWORD, USER_ID, ITERATIONS);
  key = vault.key;
  vaultMeta = vault.meta;
});

function credentialData(overrides: Partial<CredentialData> = {}): CredentialData {
  return {
    name: CRED_NAME,
    url: CRED_URL,
    username: USERNAME,
    password: PASSWORD,
    note: CRED_NOTE,
    ...overrides,
  };
}

function toRow(write: EncryptedWrite, revision = 1): CredentialRow {
  return {
    id: write.id,
    user_id: USER_ID,
    ciphertext: write.ciphertext,
    iv: write.iv,
    encryption_version: write.encryption_version,
    revision,
    created_at: ISO,
    updated_at: ISO,
  };
}

/** Narrows an optional value so the test fails with a readable message. */
function must<T>(value: T | null | undefined, label: string): T {
  if (value === null || value === undefined) throw new Error(`Missing ${label}`);
  return value;
}

/** Narrows an unknown payload to a plain object. */
function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`Expected ${label} to be a plain object`);
  }
  return value as Record<string, unknown>;
}

/** Narrows an unknown payload to an array of plain objects. */
function asRecords(value: unknown, label: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new Error(`Expected ${label} to be an array`);
  const entries: unknown[] = value as unknown[];
  return entries.map((entry) => asRecord(entry, label));
}

/** Runs `fn` and returns the thrown AppError (fails when nothing is thrown). */
async function captureError(fn: () => Promise<unknown>): Promise<AppError> {
  try {
    await fn();
  } catch (e) {
    expect(e).toBeInstanceOf(AppError);
    return e as AppError;
  }
  throw new Error('Expected an AppError to be thrown');
}

describe('clear text never reaches Supabase', () => {
  it('sends only ciphertext, iv, id and version on inserts and updates', async () => {
    const write = await encryptCredential(key, USER_ID, 'rec-leak', credentialData());
    const row = toRow(write);

    const { client, calls } = fakeSupabase((call) => {
      if (call.op === 'update') return { data: [row], error: null };
      return { data: [], error: null };
    });

    const store = new SupabaseCredentialStore(client);
    await store.insertMany([write]);
    await store.update(write, 1);

    expect(calls).toHaveLength(2);

    // Not a single secret is present in the recorded traffic.
    const serialized = JSON.stringify(calls);
    for (const secret of SECRETS) {
      expect(serialized).not.toContain(secret);
    }

    // The insert payload holds exactly the encrypted write and nothing else.
    const insertCall = must(
      calls.find((call) => call.op === 'upsert'),
      'upsert call',
    );
    expect(insertCall.table).toBe('credentials');
    const inserted = asRecords(insertCall.payload, 'insert payload');
    expect(inserted).toHaveLength(1);
    for (const entry of inserted) {
      expect(Object.keys(entry).sort()).toEqual([...WRITE_KEYS].sort());
      for (const forbidden of FORBIDDEN_KEYS) {
        expect(Object.keys(entry)).not.toContain(forbidden);
      }
    }

    // The update payload is restricted to the encrypted columns.
    const updateCall = must(
      calls.find((call) => call.op === 'update'),
      'update call',
    );
    const updated = asRecord(updateCall.payload, 'update payload');
    for (const keyName of Object.keys(updated)) {
      expect(WRITE_KEYS).toContain(keyName);
    }
    expect(Object.keys(updated)).not.toContain('user_id');
    expect(Object.keys(updated)).not.toContain('password');
    expect(Object.keys(updated)).not.toContain('username');

    // The payload is really encrypted: the ciphertext still decrypts locally.
    const restored = await decryptCredential(key, USER_ID, row);
    expect(restored.password).toBe(PASSWORD);
    expect(restored.username).toBe(USERNAME);
    const raw = Buffer.from(row.ciphertext, 'base64');
    expect(raw.includes(Buffer.from(PASSWORD, 'utf8'))).toBe(false);
  });
});

describe('vault metadata store', () => {
  it('creates a vault with public KDF parameters only', async () => {
    const { client, calls } = fakeSupabase();
    const store = new SupabaseVaultMetaStore(client);

    await store.create(vaultMeta);

    expect(calls).toHaveLength(1);
    const call = must(calls[0], 'vault insert call');
    expect(call.table).toBe('vaults');
    expect(call.op).toBe('insert');

    const payload = asRecord(call.payload, 'vault payload');
    expect(Object.keys(payload).sort()).toEqual([
      'encryption_version',
      'kdf',
      'kdf_iterations',
      'salt',
      'verifier_ciphertext',
      'verifier_iv',
    ]);
    expect(Object.keys(payload)).not.toContain('password');
    expect(Object.keys(payload)).not.toContain('key');
    expect(Object.keys(payload)).not.toContain('master_password');

    // The master password is nowhere in the traffic, not even in clear text.
    const serialized = JSON.stringify(calls);
    expect(serialized).not.toContain(MASTER_PASSWORD);
    const verifier = Buffer.from(String(payload['verifier_ciphertext']), 'base64');
    expect(verifier.includes(Buffer.from(MASTER_PASSWORD, 'utf8'))).toBe(false);
  });
});

describe('credential store queries', () => {
  it('scopes updates and deletes by id and revision', async () => {
    const write = await encryptCredential(key, USER_ID, 'rec-rev', credentialData());

    const { client, calls } = fakeSupabase((call) => {
      if (call.op === 'update') return { data: [toRow(write, 2)], error: null };
      if (call.op === 'delete') return { data: [{ id: 'rec-rev' }], error: null };
      return { data: [], error: null };
    });

    const store = new SupabaseCredentialStore(client);
    await store.update(write, 1);
    await store.remove('rec-rev', 2);

    const updateCall = must(
      calls.find((call) => call.op === 'update'),
      'update call',
    );
    const updateFilters = new Map(updateCall.filters);
    expect(updateFilters.get('id')).toBe('rec-rev');
    expect(updateFilters.get('revision')).toBe(1);

    const deleteCall = must(
      calls.find((call) => call.op === 'delete'),
      'delete call',
    );
    const deleteFilters = new Map(deleteCall.filters);
    expect(deleteFilters.get('id')).toBe('rec-rev');
    expect(deleteFilters.get('revision')).toBe(2);
  });

  it('upserts idempotently in batches of at most 100 rows', async () => {
    const rows: EncryptedWrite[] = await Promise.all(
      Array.from({ length: 250 }, (_, i) =>
        encryptCredential(key, USER_ID, `rec-batch-${i}`, credentialData({ name: `Site ${i}` })),
      ),
    );

    const { client, calls } = fakeSupabase();
    const store = new SupabaseCredentialStore(client);

    await store.insertMany(rows);

    expect(calls).toHaveLength(3);
    let total = 0;
    for (const call of calls) {
      expect(call.op).toBe('upsert');
      expect(call.table).toBe('credentials');
      const options = asRecord(call.options, 'upsert options');
      expect(options['ignoreDuplicates']).toBe(true);
      expect(options['onConflict']).toBe('id');
      const batch = asRecords(call.payload, 'batch payload');
      expect(batch.length).toBeLessThanOrEqual(100);
      total += batch.length;
    }
    expect(total).toBe(250);
  });
});

describe('error mapping', () => {
  it('reports a conflict when the update matches no row but the credential exists', async () => {
    const write = await encryptCredential(key, USER_ID, 'rec-conflict', credentialData());

    const { client } = fakeSupabase((call) => {
      if (call.op === 'update') return { data: [], error: null };
      if (call.op === 'select') return { data: [toRow(write, 7)], error: null };
      return { data: [], error: null };
    });

    const store = new SupabaseCredentialStore(client);
    const error = await captureError(() => store.update(write, 1));

    expect(error.code).toBe('CONFLICT');
    expect(error.message).not.toContain(PASSWORD);
  });

  it('reports a missing credential when the row does not exist anymore', async () => {
    const write = await encryptCredential(key, USER_ID, 'rec-missing', credentialData());

    const { client } = fakeSupabase((call) => {
      if (call.op === 'update') return { data: [], error: null };
      if (call.op === 'select') return { data: [], error: null };
      return { data: [], error: null };
    });

    const store = new SupabaseCredentialStore(client);
    const error = await captureError(() => store.update(write, 1));

    expect(error.code).toBe('NOT_FOUND');
    expect(error.message).not.toContain(PASSWORD);
  });

  it('maps a failed fetch to a NETWORK error', async () => {
    const { client } = fakeSupabase(() => ({
      data: null,
      error: { message: 'Failed to fetch' },
    }));

    const store = new SupabaseCredentialStore(client);
    const error = await captureError(() => store.get('rec-network'));

    expect(error.code).toBe('NETWORK');
    expect(error.message).not.toContain(PASSWORD);
  });
});

describe('safe error messages', () => {
  it('never exposes the user password in the sync status error', async () => {
    const sentinel = `write failed for credential ${PASSWORD}`;
    const failingStore: CredentialStore = {
      list: async () => [],
      get: async () => null,
      insertMany: async () => {
        throw new Error(sentinel);
      },
      update: async () => {
        throw new Error(sentinel);
      },
      remove: async () => {
        throw new Error(sentinel);
      },
    };

    const sync = new SyncService({
      store: failingStore,
      userId: USER_ID,
      getKey: () => key,
      retry: { sleep: async () => {}, baseDelayMs: 1 },
    });

    await expect(sync.create(credentialData())).rejects.toThrow();

    expect(sync.status.state).toBe('error');
    expect(sync.status.error ?? '').not.toContain(PASSWORD);
    expect(sync.status.error ?? '').not.toContain(USERNAME);
    expect(sync.status.error ?? '').not.toContain(CRED_URL);
    expect(sync.status.error).toBe('Synchronization failed.');
  });

  it('surfaces a safe application error verbatim', async () => {
    const safeMessage = 'The server is temporarily unavailable. Try again later.';
    const failingStore: CredentialStore = {
      list: async () => [],
      get: async () => null,
      insertMany: async () => {
        throw new AppError('SERVER', safeMessage);
      },
      update: async () => {
        throw new AppError('SERVER', safeMessage);
      },
      remove: async () => {
        throw new AppError('SERVER', safeMessage);
      },
    };

    const sync = new SyncService({
      store: failingStore,
      userId: USER_ID,
      getKey: () => key,
      retry: { sleep: async () => {}, baseDelayMs: 1 },
    });

    await expect(sync.create(credentialData())).rejects.toThrow();

    expect(sync.status.state).toBe('error');
    expect(sync.status.error).toBe(safeMessage);
    expect(sync.status.error ?? '').not.toContain(PASSWORD);
  });
});

// ---------------------------------------------------------------------------
// SQL migrations
// ---------------------------------------------------------------------------

interface Migration {
  name: string;
  sql: string;
}

interface Policy {
  name: string;
  table: string;
  command: string;
  role: string;
  body: string;
}

interface TableDef {
  name: string;
  body: string;
  columns: string[];
}

function readMigrations(): Migration[] {
  const dir = join(ROOT, 'supabase', 'migrations');
  if (!existsSync(dir)) throw new Error('Missing supabase/migrations directory');
  return readdirSync(dir)
    .filter((file) => file.endsWith('.sql'))
    .sort()
    .map((file) => ({ name: file, sql: readFileSync(join(dir, file), 'utf8') }));
}

function parsePolicies(sql: string): Policy[] {
  const policies: Policy[] = [];
  const re =
    /create\s+policy\s+([A-Za-z0-9_]+)\s+on\s+(?:public\.)?([A-Za-z0-9_]+)\s+for\s+(select|insert|update|delete)\s+to\s+([A-Za-z0-9_]+(?:\s*,\s*[A-Za-z0-9_]+)*)\s+([\s\S]*?);/gi;
  let match = re.exec(sql);
  while (match !== null) {
    policies.push({
      name: (match[1] ?? '').toLowerCase(),
      table: (match[2] ?? '').toLowerCase(),
      command: (match[3] ?? '').toLowerCase(),
      role: (match[4] ?? '').replace(/\s+/g, ' ').trim().toLowerCase(),
      body: match[5] ?? '',
    });
    match = re.exec(sql);
  }
  return policies;
}

function parseColumns(body: string): string[] {
  const columns: string[] = [];
  for (const rawLine of body.split('\n')) {
    const line = rawLine.replace(/--.*$/, '').trim();
    if (!line) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s/.exec(line);
    const name = match?.[1]?.toLowerCase();
    if (name) columns.push(name);
  }
  return columns;
}

function parseTables(sql: string): Map<string, TableDef> {
  const tables = new Map<string, TableDef>();
  const re = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?([A-Za-z0-9_]+)\s*\(([\s\S]*?)\);/gi;
  let match = re.exec(sql);
  while (match !== null) {
    const name = (match[1] ?? '').toLowerCase();
    const body = match[2] ?? '';
    tables.set(name, { name, body, columns: parseColumns(body) });
    match = re.exec(sql);
  }
  return tables;
}

const MIGRATIONS = readMigrations();
const ALL_SQL = MIGRATIONS.map((migration) => migration.sql).join('\n');

describe('sql migrations', () => {
  it('ships at least one migration', () => {
    expect(MIGRATIONS.length).toBeGreaterThan(0);
    for (const migration of MIGRATIONS) {
      expect(migration.sql.length).toBeGreaterThan(0);
    }
  });

  it('enables (and forces) row level security on every protected table', () => {
    for (const table of PROTECTED_TABLES) {
      const enable = new RegExp(
        `alter\\s+table\\s+(?:if\\s+exists\\s+)?public\\.${table}\\b[^;]*enable\\s+row\\s+level\\s+security`,
        'i',
      );
      const force = new RegExp(
        `alter\\s+table\\s+(?:if\\s+exists\\s+)?public\\.${table}\\b[^;]*force\\s+row\\s+level\\s+security`,
        'i',
      );
      expect(ALL_SQL, `row level security missing on ${table}`).toMatch(enable);
      expect(ALL_SQL, `force row level security missing on ${table}`).toMatch(force);
    }
  });

  it('revokes every privilege from anon and grants it to authenticated only', () => {
    expect(ALL_SQL).toMatch(/revoke\s+all\b[^;]*\bfrom\b[^;]*\banon\b/i);
    expect(ALL_SQL).toMatch(/grant\b[^;]*\bto\s+authenticated\b/i);
  });

  it('creates owner scoped policies for every operation on every table', () => {
    const policies = parsePolicies(ALL_SQL);
    expect(policies.length).toBeGreaterThan(0);

    for (const table of PROTECTED_TABLES) {
      for (const command of POLICY_COMMANDS) {
        const matching = policies.filter((policy) => policy.table === table && policy.command === command);
        expect(matching.length, `missing ${command} policy on ${table}`).toBeGreaterThan(0);
        for (const policy of matching) {
          expect(policy.role, `${policy.name} must target authenticated`).toBe('authenticated');
          expect(policy.body, `${policy.name} must scope by auth.uid()`).toMatch(/auth\.uid\(\)/i);
        }
      }
    }
  });

  it('never uses a permissive policy', () => {
    expect(ALL_SQL).not.toMatch(/using\s*\(\s*true\s*\)/i);
    expect(ALL_SQL).not.toMatch(/with\s+check\s*\(\s*true\s*\)/i);
  });

  it('stores ciphertext and technical metadata only', () => {
    const tables = parseTables(ALL_SQL);

    for (const table of PROTECTED_TABLES) {
      const def = must(tables.get(table), `definition of ${table}`);
      for (const forbidden of FORBIDDEN_COLUMNS) {
        expect(def.columns, `${table}.${forbidden} must not exist`).not.toContain(forbidden);
      }
    }

    const credentials = must(tables.get('credentials'), 'credentials table');
    expect(credentials.columns).toContain('ciphertext');
    expect(credentials.columns).toContain('iv');
    expect(credentials.columns).toContain('encryption_version');
    expect(credentials.body).toMatch(/user_id[\s\S]*?references\s+auth\.users/i);

    const vaults = must(tables.get('vaults'), 'vaults table');
    expect(vaults.columns).toContain('encryption_version');
    expect(vaults.body).toMatch(/user_id[\s\S]*?references\s+auth\.users/i);
  });
});

// ---------------------------------------------------------------------------
// Extension hardening
// ---------------------------------------------------------------------------

function collectFiles(dir: string, extensions: string[]): string[] {
  if (!existsSync(dir)) return [];
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(full, extensions));
    } else if (extensions.some((extension) => entry.name.endsWith(extension))) {
      files.push(full);
    }
  }
  return files;
}

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

/**
 * True when the content contains a JWT whose payload grants the `service_role`
 * role. The public anon key is a JWT too, but it only carries the `anon` role.
 */
function hasServiceRoleToken(content: string): boolean {
  const tokens = content.match(JWT_RE);
  if (!tokens) return false;
  for (const token of tokens) {
    const payload = token.split('.')[1];
    if (!payload) continue;
    const decoded = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    if (decoded.includes('service_role')) return true;
  }
  return false;
}

describe('extension hardening', () => {
  it('keeps the manifest at least privilege', () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, 'public', 'manifest.json'), 'utf8')) as {
      permissions?: string[];
      host_permissions?: string[];
      content_security_policy?: { extension_pages?: string };
    };

    const allowed = new Set(['storage']);
    for (const permission of manifest.permissions ?? []) {
      expect(allowed.has(permission), `unexpected permission: ${permission}`).toBe(true);
    }
    expect(manifest.host_permissions ?? []).toEqual([]);

    const csp = manifest.content_security_policy?.extension_pages ?? '';
    expect(csp).toContain('connect-src https://*.supabase.co');
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).not.toContain('unsafe-inline');
  });

  it('embeds no service role credential in the sources or in the build', () => {
    const sourceFiles = collectFiles(join(ROOT, 'src'), ['.ts', '.tsx', '.js']);
    expect(sourceFiles.length).toBeGreaterThan(0);

    for (const file of sourceFiles) {
      const content = readFileSync(file, 'utf8');
      expect(content, file).not.toMatch(/service_role/i);
      expect(hasServiceRoleToken(content), file).toBe(false);
    }

    // The build is optional while the extension has not been packaged yet.
    for (const file of collectFiles(join(ROOT, 'dist'), ['.js', '.css', '.html', '.map'])) {
      const content = readFileSync(file, 'utf8');
      expect(content, file).not.toMatch(/sb_secret_[A-Za-z0-9_-]{20,}/);
      expect(hasServiceRoleToken(content), file).toBe(false);
    }
  });
});

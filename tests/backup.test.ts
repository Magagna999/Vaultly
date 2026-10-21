import { describe, expect, it } from 'vitest';
import type { Credential, CredentialData } from '@/types';
import {
  BACKUP_FORMAT,
  BACKUP_VERSION,
  backupFilename,
  createBackup,
  restoreBackup,
  type BackupFile,
} from '@/services/export/backup';
import { exportPlainCsv } from '@/services/export/csv';
import { parseChromeCsv, type ImportRow } from '@/services/import/chrome';
import { buildPlan, classifyDuplicates } from '@/services/import/duplicates';
import { executeImport } from '@/services/import/importer';
import { SyncService } from '@/services/sync/sync';
import { createVault } from '@/services/crypto';
import { IV_BYTES, SALT_BYTES } from '@/services/crypto/constants';
import { base64ToBytes, bytesToBase64 } from '@/utils/base64';
import { AppError, isAppError, type ErrorCode } from '@/utils/errors';
import { FakeServer } from './helpers/fake-server';

const ITERATIONS = 100_000;
const PASSPHRASE = 'correct horse battery staple';
const WRONG_PASSPHRASE = 'definitely-not-the-passphrase';
const NOW = new Date('2024-03-04T10:00:00Z');
const USER_A = 'user-a';
const USER_B = 'user-b';
const MASTER_A = 'master password of user a';
const MASTER_B = 'master password of user b';

const SAMPLE_DATA: CredentialData[] = [
  {
    name: 'Café ☕',
    url: 'https://example.com/ünïcode',
    username: '用户😀',
    password: 'p@ss-"quoted"-🔑',
    note: 'prima riga\nseconda riga "citata"',
  },
  {
    name: 'Acme, Inc',
    url: 'https://acme.example/path?a=b&c=d',
    username: "o'brien",
    password: 'a,b"c',
    note: 'virgola, virgoletta " e accapo',
  },
  {
    name: 'مرحبا',
    url: 'https://例子.example',
    username: 'مستخدم',
    password: 'سري🔒',
    note: '',
  },
];

function credential(id: string, d: CredentialData): Credential {
  return {
    id,
    revision: 1,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    ...d,
  };
}

const SAMPLE: Credential[] = SAMPLE_DATA.map((d, i) => credential(`id-sentinel-${i + 1}`, d));

function dataOf(c: Credential): CredentialData {
  return {
    name: c.name,
    url: c.url,
    username: c.username,
    password: c.password,
    note: c.note,
  };
}

function sortedData(list: CredentialData[]): CredentialData[] {
  return [...list].sort((a, b) => a.name.localeCompare(b.name));
}

/** Narrows `T | null | undefined` so a missing value fails with a useful message instead of `any`. */
function value<T>(input: T | null | undefined, label: string): T {
  if (input === null || input === undefined) throw new Error(`Missing ${label}`);
  return input;
}

function parseFile(text: string): BackupFile {
  return JSON.parse(text) as BackupFile;
}

function stringifyFile(file: BackupFile): string {
  return JSON.stringify(file, null, 2);
}

/** Flips one byte of a base64 payload, keeping the string valid base64. */
function flipByte(b64: string, index: number): string {
  const bytes = new Uint8Array(base64ToBytes(b64));
  bytes[index] = (bytes[index] ?? 0) ^ 0xff;
  return bytesToBase64(bytes);
}

/** Returns the envelope JSON with one field removed (simulating a damaged file). */
function withoutField(file: BackupFile, field: 'salt' | 'iv' | 'ciphertext' | 'kdf'): string {
  const copy: Partial<BackupFile> = { ...file };
  if (field === 'salt') delete copy.salt;
  else if (field === 'iv') delete copy.iv;
  else if (field === 'ciphertext') delete copy.ciphertext;
  else delete copy.kdf;
  return JSON.stringify(copy);
}

/** Awaits a promise that must reject with an AppError carrying `code`. */
async function expectAppError(promise: Promise<unknown>, code: ErrorCode): Promise<AppError> {
  try {
    await promise;
  } catch (e) {
    if (!isAppError(e, code)) {
      const actual = isAppError(e) ? e.code : `non-AppError (${String(e)})`;
      throw new Error(`Expected AppError "${code}", received "${actual}"`);
    }
    expect(e).toBeInstanceOf(AppError);
    return e;
  }
  throw new Error(`Expected an AppError "${code}" to be thrown`);
}

function makeSync(server: FakeServer, userId: string, getKey: () => CryptoKey): SyncService {
  return new SyncService({
    store: server.storeFor(userId),
    userId,
    getKey,
    retry: { sleep: async () => {}, baseDelayMs: 1 },
  });
}

describe('encrypted backup round trip', () => {
  // Case 1: three credentials with Unicode, quotes and newlines survive the round trip.
  it('restores the same five fields and drops ids and revisions', async () => {
    const backup = await createBackup(SAMPLE, PASSPHRASE, ITERATIONS, NOW);

    const restored = await restoreBackup(backup, PASSPHRASE);

    expect(restored).toHaveLength(3);
    expect(restored).toEqual(SAMPLE_DATA);
    const first = value(restored[0], 'first restored credential');
    expect(Object.keys(first).sort()).toEqual(['name', 'note', 'password', 'url', 'username']);
    expect(first).not.toHaveProperty('id');
    expect(first).not.toHaveProperty('revision');
    expect(first).not.toHaveProperty('createdAt');
    expect(first).not.toHaveProperty('updatedAt');
    // Unicode, quotes and embedded newlines are preserved byte for byte.
    expect(first.name).toBe('Café ☕');
    expect(first.username).toBe('用户😀');
    expect(first.note).toBe('prima riga\nseconda riga "citata"');
  });

  // Case 8: an empty vault round-trips into an empty array.
  it('restores an empty vault as an empty array', async () => {
    const backup = await createBackup([], PASSPHRASE, ITERATIONS, NOW);

    const restored = await restoreBackup(backup, PASSPHRASE);

    expect(restored).toEqual([]);
    expect(restored).toHaveLength(0);
  });
});

describe('backup file format', () => {
  // Case 2: header, KDF parameters, base64 payloads and absence of cleartext data.
  it('writes a versioned JSON envelope with base64 payloads and no cleartext data', async () => {
    const backup = await createBackup(SAMPLE, PASSPHRASE, ITERATIONS, NOW);

    const file = parseFile(backup);
    // The shipped implementation brands the envelope as "vaultly-backup" v1.
    expect(BACKUP_FORMAT).toBe('vaultly-backup');
    expect(BACKUP_VERSION).toBe(1);
    expect(file.format).toBe(BACKUP_FORMAT);
    expect(file.version).toBe(1);
    expect(file.encryptionVersion).toBe(1);
    expect(file.kdf).toBe('PBKDF2-SHA256');
    expect(file.iterations).toBe(100_000);
    expect(file.createdAt).toBe(NOW.toISOString());

    // salt / iv / ciphertext are base64 encoded binary blobs.
    expect(() => base64ToBytes(file.salt)).not.toThrow();
    expect(() => base64ToBytes(file.iv)).not.toThrow();
    expect(() => base64ToBytes(file.ciphertext)).not.toThrow();
    expect(base64ToBytes(file.salt)).toHaveLength(SALT_BYTES);
    expect(base64ToBytes(file.iv)).toHaveLength(IV_BYTES);
    expect(base64ToBytes(file.ciphertext).length).toBeGreaterThan(16);

    // No password, username, url, note, name or id leaks in cleartext.
    const leaks = SAMPLE.flatMap((c) => [c.name, c.url, c.username, c.password, c.note, c.id]).filter(
      (s) => s.length > 0,
    );
    expect(leaks.length).toBeGreaterThan(0);
    for (const leak of leaks) {
      expect(backup).not.toContain(leak);
    }
    expect(backup).not.toContain(PASSPHRASE);
  });

  // Case 3: two backups of the same data use fresh salt, iv and ciphertext.
  it('uses a fresh salt, iv and ciphertext for every backup', async () => {
    const first = parseFile(await createBackup(SAMPLE, PASSPHRASE, ITERATIONS, NOW));
    const second = parseFile(await createBackup(SAMPLE, PASSPHRASE, ITERATIONS, NOW));

    expect(first.salt).not.toBe(second.salt);
    expect(first.iv).not.toBe(second.iv);
    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(first.createdAt).toBe(second.createdAt);
    // Both are still valid backups of the same data.
    await expect(restoreBackup(stringifyFile(first), PASSPHRASE)).resolves.toEqual(SAMPLE_DATA);
    await expect(restoreBackup(stringifyFile(second), PASSPHRASE)).resolves.toEqual(SAMPLE_DATA);
  });

  // Case 7: the file name is derived from the date.
  it('builds the backup file name from the given date', () => {
    const name = backupFilename(new Date('2024-03-04T10:00:00Z'));

    // The shipped implementation uses the "vaultly-backup-<date>.json" layout.
    expect(name).toBe('vaultly-backup-2024-03-04.json');
    expect(name).toContain('2024-03-04');
    expect(name.endsWith('.json')).toBe(true);
  });
});

describe('wrong passphrase and tampered files', () => {
  // Case 4: wrong passphrase and every tampered field fail with WRONG_PASSWORD.
  it('rejects a wrong passphrase and any tampered field with WRONG_PASSWORD', async () => {
    const backup = await createBackup(SAMPLE, PASSPHRASE, ITERATIONS, NOW);
    const file = parseFile(backup);

    const wrongPass = await expectAppError(restoreBackup(backup, WRONG_PASSPHRASE), 'WRONG_PASSWORD');
    expect(wrongPass.message).toMatch(/passphrase|corrupt/i);

    const tamperedFiles: { label: string; file: BackupFile }[] = [
      { label: 'ciphertext', file: { ...file, ciphertext: flipByte(file.ciphertext, 0) } },
      { label: 'iv', file: { ...file, iv: flipByte(file.iv, 0) } },
      { label: 'salt', file: { ...file, salt: flipByte(file.salt, 0) } },
      { label: 'iterations', file: { ...file, iterations: 250_000 } },
    ];

    for (const tampered of tamperedFiles) {
      const error = await expectAppError(
        restoreBackup(stringifyFile(tampered.file), PASSPHRASE),
        'WRONG_PASSWORD',
      );
      expect(error.message, `tampered ${tampered.label}`).toMatch(/passphrase|corrupt/i);

      // The error message must not leak any partial or decrypted data.
      const leaks = [
        ...SAMPLE.flatMap((c) => [c.name, c.url, c.username, c.password, c.note, c.id]),
        PASSPHRASE,
        WRONG_PASSPHRASE,
        file.ciphertext,
        file.salt,
        file.iv,
      ].filter((s) => s.length > 0);
      for (const leak of leaks) {
        expect(error.message, `tampered ${tampered.label}`).not.toContain(leak);
      }
    }
  });
});

describe('malformed backup files', () => {
  // Case 5: broken envelopes are rejected as IMPORT, out-of-range iterations as VALIDATION.
  it('rejects broken envelopes with IMPORT and out-of-range iterations with VALIDATION', async () => {
    const backup = await createBackup(SAMPLE, PASSPHRASE, ITERATIONS, NOW);
    const file = parseFile(backup);

    // Not a JSON file at all.
    await expectAppError(restoreBackup('this is not a backup file', PASSPHRASE), 'IMPORT');

    // JSON, but without the "format" marker.
    await expectAppError(
      restoreBackup(JSON.stringify({ version: 1, kdf: 'PBKDF2-SHA256' }), PASSPHRASE),
      'IMPORT',
    );

    // Unsupported format version.
    await expectAppError(restoreBackup(JSON.stringify({ ...file, version: 2 }), PASSPHRASE), 'IMPORT');
    await expectAppError(
      restoreBackup(JSON.stringify({ ...file, encryptionVersion: 2 }), PASSPHRASE),
      'IMPORT',
    );

    // Damaged envelope: missing fields.
    for (const field of ['salt', 'iv', 'ciphertext', 'kdf'] as const) {
      await expectAppError(restoreBackup(withoutField(file, field), PASSPHRASE), 'IMPORT');
    }

    // Unsupported KDF name.
    await expectAppError(restoreBackup(JSON.stringify({ ...file, kdf: 'scrypt' }), PASSPHRASE), 'IMPORT');

    // Iterations outside the supported range.
    await expectAppError(restoreBackup(JSON.stringify({ ...file, iterations: 1 }), PASSPHRASE), 'VALIDATION');
    await expectAppError(
      restoreBackup(JSON.stringify({ ...file, iterations: 50_000 }), PASSPHRASE),
      'VALIDATION',
    );
  });

  // Case 6: the backup passphrase has a minimum length.
  it('refuses to create a backup with a passphrase shorter than 12 characters', async () => {
    const error = await expectAppError(createBackup(SAMPLE, 'short', ITERATIONS, NOW), 'VALIDATION');
    expect(error.message).toMatch(/12/);

    await expectAppError(createBackup(SAMPLE, 'elevenchars', ITERATIONS, NOW), 'VALIDATION');

    // Exactly 12 characters is accepted.
    await expect(createBackup(SAMPLE, 'twelvechars!', ITERATIONS, NOW)).resolves.toContain(BACKUP_FORMAT);
  });
});

describe('end-to-end restore into another account', () => {
  // Case 9: backup of user A restored into the empty vault of user B, idempotent on re-run.
  it('imports the backup into another account and does not duplicate it on a second run', async () => {
    const server = new FakeServer();
    const { key: keyA } = await createVault(MASTER_A, USER_A, ITERATIONS);
    const { key: keyB } = await createVault(MASTER_B, USER_B, ITERATIONS);

    // User A fills its own vault.
    const syncA = makeSync(server, USER_A, () => keyA);
    for (const c of SAMPLE) await syncA.create(dataOf(c));
    const loadedA = await syncA.load();
    expect(loadedA.credentials).toHaveLength(3);
    expect(loadedA.undecryptable).toBe(0);

    // Backup of user A, restored by user B.
    const backup = await createBackup(loadedA.credentials, PASSPHRASE, ITERATIONS, NOW);
    const restored = await restoreBackup(backup, PASSPHRASE);
    expect(restored).toHaveLength(3);

    // The vault of user B is still empty: nothing is a duplicate yet.
    const rows: ImportRow[] = restored.map((d, i) => ({ line: i + 2, data: d }));
    const classified = classifyDuplicates(rows, []);
    expect(classified.map((c) => c.kind)).toEqual(['new', 'new', 'new']);

    const plan = buildPlan(classified, 'skip');
    expect(plan.toInsert).toHaveLength(3);
    expect(plan.toReplace).toHaveLength(0);
    expect(plan.skipped).toBe(0);

    const syncB = makeSync(server, USER_B, () => keyB);
    const summary = await executeImport(plan, 0, syncB);
    expect(summary).toEqual({
      imported: 3,
      replaced: 0,
      skipped: 0,
      invalid: 0,
      failed: 0,
      conflicts: 0,
      error: null,
    });

    // The rows are readable by user B and hold the same data.
    const loadedB = await syncB.load();
    expect(loadedB.undecryptable).toBe(0);
    expect(loadedB.credentials).toHaveLength(3);
    expect(sortedData(loadedB.credentials.map(dataOf))).toEqual(sortedData(restored));
    await expect(server.storeFor(USER_B).list()).resolves.toHaveLength(3);

    // Running the same restore again must not create duplicates.
    const rowsBefore = server.rows.size;
    const classifiedAgain = classifyDuplicates(rows, loadedB.credentials);
    expect(classifiedAgain.map((c) => c.kind)).toEqual(['identical', 'identical', 'identical']);

    const planAgain = buildPlan(classifiedAgain, 'skip');
    expect(planAgain.toInsert).toHaveLength(0);
    expect(planAgain.toReplace).toHaveLength(0);
    expect(planAgain.skipped).toBe(3);

    const summaryAgain = await executeImport(planAgain, 0, syncB);
    expect(summaryAgain.imported).toBe(0);
    expect(summaryAgain.replaced).toBe(0);
    expect(summaryAgain.skipped).toBe(3);
    expect(summaryAgain.failed).toBe(0);
    expect(summaryAgain.error).toBeNull();

    expect(server.rows.size).toBe(rowsBefore);
    await expect(server.storeFor(USER_B).list()).resolves.toHaveLength(3);

    const loadedAgain = await syncB.load();
    expect(loadedAgain.credentials).toHaveLength(3);
    expect(sortedData(loadedAgain.credentials.map(dataOf))).toEqual(sortedData(restored));
  });
});

describe('plaintext CSV export', () => {
  // Case 10: header, CRLF line endings, RFC 4180 quoting and re-import.
  it('exports a Chrome-compatible CSV that can be parsed back', () => {
    const credentials: CredentialData[] = [
      {
        name: 'Acme, "Inc"',
        url: 'https://acme.example/a,b',
        username: 'user"name',
        password: 'p,a"s',
        note: 'line one\r\nline two',
      },
      {
        name: 'GitHub',
        url: 'https://github.com',
        username: 'octocat',
        password: 'hunter2',
        note: 'work',
      },
    ];

    const exported = exportPlainCsv(credentials);

    // Header and row layout, exactly as Chrome writes them.
    expect(exported.startsWith('name,url,username,password,note\r\n')).toBe(true);
    expect(exported.endsWith('\r\n')).toBe(true);
    expect(exported).toContain(
      '"Acme, ""Inc""","https://acme.example/a,b","user""name","p,a""s","line one\r\nline two"',
    );
    expect(exported).toContain('GitHub,https://github.com,octocat,hunter2,work');

    // CRLF everywhere: no lone LF and no lone CR.
    const withoutCrlf = exported.replace(/\r\n/g, '');
    expect(withoutCrlf).not.toContain('\n');
    expect(withoutCrlf).not.toContain('\r');

    // The export is readable by the Chrome CSV parser and yields the same data.
    const parsed = parseChromeCsv(exported);
    expect(parsed.delimiter).toBe(',');
    expect(parsed.invalid).toHaveLength(0);
    expect(parsed.valid).toHaveLength(2);
    expect(parsed.valid.map((v) => v.data)).toEqual(credentials);
  });
});

describe('backup size limit', () => {
  it('rejects oversized backup files before parsing them', async () => {
    const { MAX_BACKUP_BYTES } = await import('@/services/export/backup');
    await expect(
      restoreBackup('x'.repeat(MAX_BACKUP_BYTES + 1), 'any passphrase here'),
    ).rejects.toMatchObject({
      code: 'IMPORT',
    });
  });
});

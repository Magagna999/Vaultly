import { beforeAll, describe, expect, it } from 'vitest';
import type { CredentialData, CredentialRow } from '@/types';
import { createVault, encryptCredential } from '@/services/crypto';
import { SyncService } from '@/services/sync/sync';
import { AppError } from '@/utils/errors';
import { FakeServer } from './helpers/fake-server';

const ITERATIONS = 100_000;
const USER_A = 'user-a';
const USER_B = 'user-b';
const MASTER_A = 'correct horse battery';
const MASTER_B = 'correct horse battery b';

let keyA!: CryptoKey;
let keyB!: CryptoKey;

beforeAll(async () => {
  keyA = (await createVault(MASTER_A, USER_A, ITERATIONS)).key;
  keyB = (await createVault(MASTER_B, USER_B, ITERATIONS)).key;
});

function data(overrides: Partial<CredentialData> = {}): CredentialData {
  return {
    name: 'Example',
    url: 'https://example.com',
    username: 'alice',
    password: 'S3cret-Passw0rd!',
    note: '',
    ...overrides,
  };
}

function makeItems(count: number): CredentialData[] {
  return Array.from({ length: count }, (_, i) =>
    data({
      name: `Site ${i}`,
      url: `https://site-${i}.example`,
      username: `user-${i}`,
      password: `password-${i}`,
      note: `note ${i}`,
    }),
  );
}

function makeSync(
  server: FakeServer,
  userId: string,
  getKey: () => CryptoKey,
  now?: () => Date,
): SyncService {
  return new SyncService({
    store: server.storeFor(userId),
    userId,
    getKey,
    now,
    retry: { sleep: async () => {}, baseDelayMs: 1 },
  });
}

/** Narrows `T | null | undefined` so tests can fail with a useful message instead of `any`. */
function value<T>(input: T | null | undefined, label: string): T {
  if (input === null || input === undefined) throw new Error(`Missing ${label}`);
  return input;
}

describe('encryption and reload', () => {
  it('reloads the same decrypted credential and never sends plaintext to the server', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    const secret = 'S3cret-Passw0rd!';
    const input = data({
      name: 'GitHub',
      url: 'https://github.com',
      username: 'octocat',
      password: secret,
      note: 'work',
    });

    const created = await sync.create(input);
    expect(created.id).toBeTruthy();
    expect(created.revision).toBe(1);

    const reloadedSync = makeSync(server, USER_A, () => keyA);
    const reloaded = await reloadedSync.load();

    expect(reloaded.undecryptable).toBe(0);
    expect(reloaded.credentials).toHaveLength(1);
    const restored = value(reloaded.credentials[0], 'restored credential');
    expect(restored).toEqual(created);
    expect({
      name: restored.name,
      url: restored.url,
      username: restored.username,
      password: restored.password,
      note: restored.note,
    }).toEqual(input);

    const rows = [...server.rows.values()];
    expect(rows).toHaveLength(1);
    const row = value(rows[0], 'stored row');
    expect(Object.keys(row).sort()).toEqual(
      [
        'ciphertext',
        'created_at',
        'encryption_version',
        'id',
        'iv',
        'revision',
        'updated_at',
        'user_id',
      ].sort(),
    );
    expect(row).not.toHaveProperty('password');
    expect(row).not.toHaveProperty('name');
    expect(row.ciphertext).not.toContain(secret);
    expect(JSON.stringify(rows)).not.toContain(secret);
    expect(JSON.stringify(server.received)).not.toContain(secret);
  });
});

describe('updates', () => {
  it('increments the revision but preserves createdAt', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    const created = await sync.create(data({ name: 'Before', password: 'old-secret' }));

    const updated = await sync.update(created.id, data({ name: 'After', password: 'new-secret' }));

    expect(updated.ok).toBe(true);
    if (!updated.ok) throw new Error('Expected the update to succeed');
    expect(updated.credential.revision).toBe(created.revision + 1);
    expect(updated.credential.name).toBe('After');
    expect(updated.credential.createdAt).toBe(created.createdAt);
    expect(updated.credential.updatedAt).not.toBe(created.updatedAt);
  });
});

describe('conflict resolution', () => {
  it('detects a stale update and does not overwrite the server', async () => {
    const server = new FakeServer();
    const deviceA = makeSync(server, USER_A, () => keyA);
    const deviceB = makeSync(server, USER_A, () => keyA);

    const created = await deviceA.create(data({ name: 'Original', password: 'original' }));
    await deviceB.load();

    const resultA = await deviceA.update(created.id, data({ name: 'A version', password: 'from-a' }));
    expect(resultA.ok).toBe(true);
    const rowAfterA = { ...value(server.rows.get(created.id), 'row after A update') };

    const resultB = await deviceB.update(created.id, data({ name: 'B version', password: 'from-b' }));

    expect(resultB.ok).toBe(false);
    if (resultB.ok) throw new Error('Expected a conflict');
    const serverCredential = value(resultB.conflict.server, 'server credential');
    expect(serverCredential.name).toBe('A version');
    expect(serverCredential.password).toBe('from-a');
    expect(serverCredential.revision).toBe(2);

    // A stale write must not touch the row.
    expect(value(server.rows.get(created.id), 'row after conflict')).toEqual(rowAfterA);

    const overwrite = await deviceB.overwriteWithMine(
      created.id,
      data({ name: 'B wins', password: 'from-b' }),
      serverCredential.revision,
    );
    expect(overwrite.ok).toBe(true);
    if (!overwrite.ok) throw new Error('Expected the overwrite to succeed');
    expect(overwrite.credential.password).toBe('from-b');
    expect(overwrite.credential.revision).toBe(3);
    expect(value(server.rows.get(created.id), 'row after overwrite').revision).toBe(3);
  });

  it('adopts the server version after a conflict', async () => {
    const server = new FakeServer();
    const deviceA = makeSync(server, USER_A, () => keyA);
    const deviceB = makeSync(server, USER_A, () => keyA);

    const created = await deviceA.create(data({ name: 'Original', password: 'original' }));
    await deviceB.load();
    const resultA = await deviceA.update(created.id, data({ name: 'A version', password: 'from-a' }));
    if (!resultA.ok) throw new Error('Expected the update to succeed');

    const resultB = await deviceB.update(created.id, data({ name: 'B version', password: 'from-b' }));
    expect(resultB.ok).toBe(false);

    const adopted = await deviceB.adoptServer(created.id);
    expect(value(adopted, 'adopted credential').password).toBe('from-a');
    expect(
      value(
        deviceB.list().find((c) => c.id === created.id),
        'cached credential',
      ).password,
    ).toBe('from-a');
  });
});

describe('deletion conflicts', () => {
  it('rejects a stale remove, accepts the current revision and is idempotent', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);

    const created = await sync.create(data());
    const updated = await sync.update(created.id, data({ password: 'second-version' }));
    if (!updated.ok) throw new Error('Expected the update to succeed');

    const stale = await sync.remove(created.id, created.revision);
    expect(stale).toEqual({ ok: false, conflict: true });
    expect(server.rows.has(created.id)).toBe(true);

    const removed = await sync.remove(created.id, updated.credential.revision);
    expect(removed).toEqual({ ok: true });
    expect(server.rows.has(created.id)).toBe(false);

    // Deleting an already deleted row is a no-op success.
    const removedAgain = await sync.remove(created.id, updated.credential.revision);
    expect(removedAgain).toEqual({ ok: true });
  });

  it('rejects an update when the credential was deleted elsewhere', async () => {
    const server = new FakeServer();
    const deviceA = makeSync(server, USER_A, () => keyA);
    const deviceB = makeSync(server, USER_A, () => keyA);

    const created = await deviceA.create(data());
    await deviceB.load();
    const removed = await deviceA.remove(created.id, created.revision);
    expect(removed).toEqual({ ok: true });
    expect(server.rows.size).toBe(0);

    // SyncService.update only converts CONFLICT into a result; NOT_FOUND is rethrown.
    await expect(
      deviceB.update(created.id, data({ name: 'After delete', password: 'new' })),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    expect(server.rows.size).toBe(0);
    expect(deviceB.status.state).toBe('error');
  });
});

describe('retry policy', () => {
  it('retries transient network failures and inserts exactly one row', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    server.failNext(new AppError('NETWORK', 'Network unavailable.'), 2);

    const created = await sync.create(data());

    expect(created.id).toBeTruthy();
    expect(server.rows.size).toBe(1);
    expect(server.received).toHaveLength(1);
    expect(sync.status.state).toBe('idle');
  });

  it('gives up after three attempts and reports a network error', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    server.failNext(new AppError('NETWORK', 'Network unavailable.'), 5);

    await expect(sync.create(data())).rejects.toMatchObject({ code: 'NETWORK' });

    expect(server.calls).toBe(3);
    expect(server.rows.size).toBe(0);
    expect(sync.status.state).toBe('error');
    expect(sync.status.error).toBe('Network unavailable.');
  });

  it('does not retry authentication errors', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    server.failNext(new AppError('AUTH', 'Authentication failed.'));

    await expect(sync.create(data())).rejects.toMatchObject({ code: 'AUTH' });

    expect(server.calls).toBe(1);
    expect(server.rows.size).toBe(0);
  });
});

describe('sync status', () => {
  it('tracks the last successful sync and keeps error messages free of secrets', async () => {
    const server = new FakeServer();
    const now = (): Date => new Date('2024-05-05T10:00:00Z');
    const sync = makeSync(server, USER_A, () => keyA, now);

    const loaded = await sync.load();
    expect(loaded.credentials).toEqual([]);
    expect(loaded.undecryptable).toBe(0);
    expect(sync.status.state).toBe('idle');
    expect(sync.status.error).toBeNull();
    expect(sync.status.lastSyncedAt).toBe('2024-05-05T10:00:00.000Z');

    const events: string[] = [];
    const unsubscribe = sync.subscribe((s) => {
      events.push(s.state);
    });

    const secret = 'NeverLeakThis!';
    server.failNext(new AppError('AUTH', 'Authentication failed.'));
    await expect(sync.create(data({ password: secret }))).rejects.toMatchObject({ code: 'AUTH' });

    expect(sync.status.state).toBe('error');
    expect(typeof sync.status.error).toBe('string');
    expect(sync.status.error).not.toContain(secret);
    expect(sync.status.error).toBe('Authentication failed.');
    expect(events).toEqual(['syncing', 'error']);
    unsubscribe();
  });
});

describe('duplicate protection', () => {
  it('keeps a single row when the same encrypted row is inserted twice', async () => {
    const server = new FakeServer();
    const row = await encryptCredential(keyA, USER_A, 'fixed-id', data());
    const store = server.storeFor(USER_A);

    await store.insertMany([row]);
    await store.insertMany([row]);

    expect(server.rows.size).toBe(1);
    await expect(store.list()).resolves.toHaveLength(1);
  });

  it('shares one request between two concurrent identical updates', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    const created = await sync.create(data());

    const first = data({ name: 'First click', password: 'one' });
    const second = data({ name: 'Second click', password: 'two' });
    const [r1, r2] = await Promise.all([
      sync.update(created.id, first, created.revision),
      sync.update(created.id, second, created.revision),
    ]);

    expect(r1.ok).toBe(true);
    if (!r1.ok || !r2.ok) throw new Error('Expected both updates to succeed');
    expect(r1).toEqual(r2);
    // The first operation wins because the second one joins the in-flight promise.
    expect(r1.credential.name).toBe('First click');
    expect(server.rows.size).toBe(1);
    // insert + get for create, then a single update.
    expect(server.calls).toBe(3);
  });

  it('creates a single row when create() is repeated with the same idempotency id', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    const id = crypto.randomUUID();

    const [c1, c2] = await Promise.all([sync.create(data(), id), sync.create(data(), id)]);

    expect(c1.id).toBe(id);
    expect(c2).toEqual(c1);
    expect(server.rows.size).toBe(1);
  });
});

describe('user isolation', () => {
  it('does not let another user read, update or delete credentials', async () => {
    const server = new FakeServer();
    const syncA = makeSync(server, USER_A, () => keyA);
    const a1 = await syncA.create(data({ name: 'A only', password: 'a-secret' }));
    await syncA.create(data({ name: 'A second', password: 'a-secret-2' }));

    const storeB = server.storeFor(USER_B);
    await expect(storeB.list()).resolves.toEqual([]);
    await expect(storeB.get(a1.id)).resolves.toBeNull();

    const rowBefore = { ...value(server.rows.get(a1.id), 'A row') };
    await expect(storeB.update(rowBefore, a1.revision)).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await expect(storeB.remove(a1.id, a1.revision)).resolves.toBeUndefined();

    expect(server.rows.size).toBe(2);
    expect(value(server.rows.get(a1.id), 'A row')).toEqual(rowBefore);
    expect(value(server.rows.get(a1.id), 'A row').user_id).toBe(USER_A);
  });

  it('counts a row copied under another user as undecryptable', async () => {
    const server = new FakeServer();
    const syncA = makeSync(server, USER_A, () => keyA);
    const created = await syncA.create(data({ name: 'A only', password: 'a-secret' }));

    const original = value(server.rows.get(created.id), 'A row');
    const copied: CredentialRow = { ...original, id: 'copied-row', user_id: USER_B };
    server.rows.set(copied.id, copied);

    const syncB = makeSync(server, USER_B, () => keyB);
    const loaded = await syncB.load();

    expect(loaded.credentials).toEqual([]);
    expect(loaded.undecryptable).toBe(1);
  });
});

describe('corrupted data', () => {
  it('returns the other credentials and counts the corrupted row', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    const first = await sync.create(data({ name: 'One' }));
    const second = await sync.create(data({ name: 'Two' }));
    const third = await sync.create(data({ name: 'Three' }));

    const corrupted = value(server.rows.get(second.id), 'row to corrupt');
    const firstChar = corrupted.ciphertext.charAt(0);
    corrupted.ciphertext = (firstChar === 'A' ? 'B' : 'A') + corrupted.ciphertext.slice(1);

    const loaded = await sync.load();

    expect(loaded.undecryptable).toBe(1);
    expect(loaded.credentials.map((c) => c.id).sort()).toEqual([first.id, third.id].sort());
    expect(loaded.credentials.some((c) => c.id === second.id)).toBe(false);
  });
});

describe('locked vault', () => {
  it('rejects load and create with VAULT_LOCKED and clear() empties the cache', async () => {
    const server = new FakeServer();
    let locked = false;
    const getKey = (): CryptoKey => {
      if (locked) throw new AppError('VAULT_LOCKED', 'The vault is locked.');
      return keyA;
    };
    const sync = makeSync(server, USER_A, getKey);

    await sync.create(data());
    expect(sync.list()).toHaveLength(1);

    locked = true;
    await expect(sync.load()).rejects.toMatchObject({ code: 'VAULT_LOCKED' });
    await expect(sync.create(data({ name: 'Blocked' }))).rejects.toMatchObject({
      code: 'VAULT_LOCKED',
    });
    expect(sync.status.state).toBe('error');

    sync.clear();
    expect(sync.list()).toEqual([]);
    expect(server.rows.size).toBe(1);
  });
});

describe('bulk import', () => {
  it('imports 250 items in three chunks', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    const items = makeItems(250);
    const progress: number[] = [];

    const result = await sync.createMany(items, (done) => {
      progress.push(done);
    });

    expect(result).toEqual({ done: 250, failed: 0, conflicts: 0, error: null });
    expect(progress).toEqual([100, 200, 250]);
    expect(server.rows.size).toBe(250);
    await expect(server.storeFor(USER_A).list()).resolves.toHaveLength(250);
  });

  it('reports a failing second chunk and keeps the first chunk', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    const items = makeItems(250);

    const result = await sync.createMany(items, (done) => {
      if (done === 100) {
        server.failNext(new AppError('NETWORK', 'Network unavailable.'), 10);
      }
    });

    expect(result.done).toBe(100);
    expect(result.failed).toBe(150);
    expect(result.conflicts).toBe(0);
    expect(result.error).toBe('Network unavailable.');
    expect(server.rows.size).toBe(100);
    // One insert for chunk 1 plus the three attempts for chunk 2.
    expect(server.calls).toBe(4);
    expect(sync.status.state).toBe('error');
  });

  it('does not duplicate a chunk when its insert is retried', async () => {
    const server = new FakeServer();
    const sync = makeSync(server, USER_A, () => keyA);
    server.failNext(new AppError('NETWORK', 'Network unavailable.'), 2);

    const result = await sync.createMany(makeItems(10));

    expect(result.done).toBe(10);
    expect(result.failed).toBe(0);
    expect(result.error).toBeNull();
    expect(server.rows.size).toBe(10);
  });

  // NOTE: createMany() assigns new random UUIDs on every invocation. The retry above
  // is safe because `withRetry` reuses the same encrypted rows, but re-running a whole
  // failed import would insert the already-saved items again under new ids.
});

import type { Credential, CredentialData } from '@/types';
import { decryptCredential, encryptCredential } from '@/services/crypto';
import type { CredentialStore } from '@/services/supabase/stores';
import { AppError, isAppError } from '@/utils/errors';
import { withRetry, type RetryOptions } from '@/utils/retry';
import { assertValidCredentialData } from '@/utils/validation';

export type SyncState = 'idle' | 'syncing' | 'error';

export interface SyncStatus {
  state: SyncState;
  /** ISO timestamp of the last fully successful server round-trip. */
  lastSyncedAt: string | null;
  /** Safe, user-facing message of the last failure. */
  error: string | null;
}

export interface LoadResult {
  credentials: Credential[];
  /** Rows that failed authenticated decryption; never shown partially. */
  undecryptable: number;
}

export type UpdateResult =
  { ok: true; credential: Credential } | { ok: false; conflict: { server: Credential | null } };

export interface BulkResult {
  done: number;
  failed: number;
  conflicts: number;
  error: string | null;
}

export interface SyncDeps {
  store: CredentialStore;
  userId: string;
  /** Returns the unlocked key or throws VAULT_LOCKED. */
  getKey: () => CryptoKey;
  now?: () => Date;
  retry?: RetryOptions;
}

const CHUNK = 100;

/**
 * Orchestrates encrypt/decrypt + persistence. The cache lives in memory only and is
 * dropped by `clear()` (called on lock/sign-out).
 */
export class SyncService {
  private cache = new Map<string, Credential>();
  private inflight = new Map<string, Promise<unknown>>();
  private _status: SyncStatus = { state: 'idle', lastSyncedAt: null, error: null };
  private listeners = new Set<(s: SyncStatus) => void>();

  constructor(private readonly deps: SyncDeps) {}

  get status(): SyncStatus {
    return this._status;
  }

  subscribe(fn: (s: SyncStatus) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  list(): Credential[] {
    return [...this.cache.values()];
  }

  clear(): void {
    this.cache.clear();
    this.inflight.clear();
  }

  async load(): Promise<LoadResult> {
    return this.track(async () => {
      const key = this.deps.getKey();
      const rows = await this.retry(() => this.deps.store.list());
      const next = new Map<string, Credential>();
      let undecryptable = 0;
      for (const row of rows) {
        try {
          next.set(row.id, await decryptCredential(key, this.deps.userId, row));
        } catch {
          undecryptable++;
        }
      }
      this.cache = next;
      return { credentials: this.list(), undecryptable };
    });
  }

  /** `id` is an idempotency key: repeating the call with the same id never creates a second row. */
  async create(data: CredentialData, id: string = crypto.randomUUID()): Promise<Credential> {
    assertValidCredentialData(data);
    return this.once(`create:${id}`, id, () =>
      this.track(async () => {
        const key = this.deps.getKey();
        const row = await encryptCredential(key, this.deps.userId, id, data);
        await this.retry(() => this.deps.store.insertMany([row]));
        const stored = await this.retry(() => this.deps.store.get(id));
        if (!stored) throw new AppError('SERVER', 'The credential was not saved. Please retry.');
        const cred = await decryptCredential(key, this.deps.userId, stored);
        this.cache.set(id, cred);
        return cred;
      }),
    );
  }

  /** Updates using the revision we last saw; a mismatch returns a conflict instead of overwriting. */
  async update(id: string, data: CredentialData, baseRevision?: number): Promise<UpdateResult> {
    assertValidCredentialData(data);
    const current = this.cache.get(id);
    const revision = baseRevision ?? current?.revision;
    if (revision === undefined) throw new AppError('NOT_FOUND', 'The credential no longer exists.');
    return this.once(`update:${id}:${revision}`, id, () =>
      this.track(async (): Promise<UpdateResult> => {
        const key = this.deps.getKey();
        const row = await encryptCredential(key, this.deps.userId, id, data);
        try {
          const saved = await this.retry(() => this.deps.store.update(row, revision));
          const cred = await decryptCredential(key, this.deps.userId, saved);
          this.cache.set(id, cred);
          return { ok: true, credential: cred };
        } catch (e) {
          if (!isAppError(e, 'CONFLICT')) throw e;
          return { ok: false, conflict: { server: await this.fetchServer(id) } };
        }
      }),
    );
  }

  /** Conflict resolution "keep mine": rewrite on top of the server's current revision. */
  async overwriteWithMine(id: string, data: CredentialData, serverRevision: number): Promise<UpdateResult> {
    return this.update(id, data, serverRevision);
  }

  /** Conflict resolution "use server": adopt the server version in the cache. */
  async adoptServer(id: string): Promise<Credential | null> {
    const server = await this.fetchServer(id);
    if (server) this.cache.set(id, server);
    else this.cache.delete(id);
    return server;
  }

  async remove(id: string, baseRevision?: number): Promise<{ ok: true } | { ok: false; conflict: true }> {
    const revision = baseRevision ?? this.cache.get(id)?.revision;
    if (revision === undefined) {
      this.cache.delete(id);
      return { ok: true };
    }
    return this.once(`remove:${id}`, id, () =>
      this.track(async () => {
        try {
          await this.retry(() => this.deps.store.remove(id, revision));
          this.cache.delete(id);
          return { ok: true } as const;
        } catch (e) {
          if (isAppError(e, 'CONFLICT')) return { ok: false, conflict: true } as const;
          throw e;
        }
      }),
    );
  }

  /** Bulk create in chunks. Ids are fixed per record, so a retried chunk can never duplicate. */
  async createMany(
    items: CredentialData[],
    onProgress?: (done: number, total: number) => void,
  ): Promise<BulkResult> {
    const res: BulkResult = { done: 0, failed: 0, conflicts: 0, error: null };
    await this.track(async () => {
      const key = this.deps.getKey();
      for (let i = 0; i < items.length; i += CHUNK) {
        const slice = items.slice(i, i + CHUNK);
        try {
          const rows = await Promise.all(
            slice.map((d) => encryptCredential(key, this.deps.userId, crypto.randomUUID(), d)),
          );
          await this.retry(() => this.deps.store.insertMany(rows));
          res.done += slice.length;
          onProgress?.(res.done, items.length);
        } catch (e) {
          res.failed = items.length - res.done;
          res.error = e instanceof AppError ? e.message : 'Import interrupted.';
          throw e;
        }
      }
    }).catch(() => undefined);
    return res;
  }

  async replaceMany(items: { id: string; revision: number; data: CredentialData }[]): Promise<BulkResult> {
    const res: BulkResult = { done: 0, failed: 0, conflicts: 0, error: null };
    const key = (() => {
      try {
        return this.deps.getKey();
      } catch (e) {
        res.failed = items.length;
        res.error = e instanceof AppError ? e.message : 'Vault locked.';
        return null;
      }
    })();
    if (!key) return res;
    for (const it of items) {
      try {
        const row = await encryptCredential(key, this.deps.userId, it.id, it.data);
        await this.retry(() => this.deps.store.update(row, it.revision));
        res.done++;
      } catch (e) {
        if (isAppError(e, 'CONFLICT')) res.conflicts++;
        else {
          res.failed++;
          res.error = e instanceof AppError ? e.message : 'Update failed.';
        }
      }
    }
    return res;
  }

  // ---- internals ---------------------------------------------------------

  private async fetchServer(id: string): Promise<Credential | null> {
    const row = await this.retry(() => this.deps.store.get(id));
    return row ? decryptCredential(this.deps.getKey(), this.deps.userId, row) : null;
  }

  private retry<T>(fn: () => Promise<T>): Promise<T> {
    return withRetry(fn, this.deps.retry);
  }

  /** Same operation requested twice (double click / retry) shares one request. */
  private once<T>(opKey: string, recordId: string, fn: () => Promise<T>): Promise<T> {
    const existing = this.inflight.get(opKey);
    if (existing) return existing as Promise<T>;
    for (const k of this.inflight.keys()) {
      if (k.includes(recordId)) {
        return Promise.reject(
          new AppError('VALIDATION', 'Another operation on this credential is in progress.'),
        );
      }
    }
    const p = fn().finally(() => this.inflight.delete(opKey));
    this.inflight.set(opKey, p);
    return p;
  }

  private async track<T>(fn: () => Promise<T>): Promise<T> {
    this.setStatus({ state: 'syncing', error: null });
    try {
      const out = await fn();
      this.setStatus({
        state: 'idle',
        lastSyncedAt: (this.deps.now?.() ?? new Date()).toISOString(),
        error: null,
      });
      return out;
    } catch (e) {
      this.setStatus({
        state: 'error',
        error: e instanceof AppError ? e.message : 'Synchronization failed.',
      });
      throw e;
    }
  }

  private setStatus(patch: Partial<SyncStatus>): void {
    this._status = { ...this._status, ...patch };
    for (const l of this.listeners) l(this._status);
  }
}

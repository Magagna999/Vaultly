import type { CredentialRow, EncryptedWrite } from '@/types';
import type { CredentialStore } from '@/services/supabase/stores';
import { AppError } from '@/utils/errors';

/**
 * In-memory stand-in for the Supabase `credentials` table that emulates the RLS policies
 * (every operation is scoped to the calling user) and the server-side revision trigger.
 * It records every payload it receives so tests can assert nothing sensitive was sent.
 */
export class FakeServer {
  readonly rows = new Map<string, CredentialRow>();
  readonly received: unknown[] = [];
  private failures: AppError[] = [];
  calls = 0;
  private clock = 0;

  /** Makes the next N store calls throw `error`. */
  failNext(error: AppError, times = 1): void {
    for (let i = 0; i < times; i++) this.failures.push(error);
  }

  private maybeFail(): void {
    this.calls++;
    const f = this.failures.shift();
    if (f) throw f;
  }

  private stamp(): string {
    return new Date(Date.UTC(2024, 0, 1, 0, 0, this.clock++)).toISOString();
  }

  /** A store authenticated as `userId` (auth.uid()). */
  storeFor(userId: string): CredentialStore {
    const mine = () => [...this.rows.values()].filter((r) => r.user_id === userId);
    return {
      list: async () => {
        this.maybeFail();
        return mine().map((r) => ({ ...r }));
      },
      get: async (id) => {
        this.maybeFail();
        const r = this.rows.get(id);
        return r && r.user_id === userId ? { ...r } : null;
      },
      insertMany: async (rows: EncryptedWrite[]) => {
        this.maybeFail();
        this.received.push(...rows);
        for (const w of rows) {
          if (this.rows.has(w.id)) continue; // ON CONFLICT DO NOTHING
          const t = this.stamp();
          this.rows.set(w.id, { ...w, user_id: userId, revision: 1, created_at: t, updated_at: t });
        }
      },
      update: async (w: EncryptedWrite, expectedRevision) => {
        this.maybeFail();
        this.received.push(w);
        const r = this.rows.get(w.id);
        if (!r || r.user_id !== userId) throw new AppError('NOT_FOUND', 'The credential no longer exists.');
        if (r.revision !== expectedRevision)
          throw new AppError('CONFLICT', 'The credential was modified elsewhere.');
        const next: CredentialRow = {
          ...r,
          ciphertext: w.ciphertext,
          iv: w.iv,
          encryption_version: w.encryption_version,
          revision: r.revision + 1,
          updated_at: this.stamp(),
        };
        this.rows.set(w.id, next);
        return { ...next };
      },
      remove: async (id, expectedRevision) => {
        this.maybeFail();
        const r = this.rows.get(id);
        if (!r || r.user_id !== userId) return;
        if (r.revision !== expectedRevision)
          throw new AppError('CONFLICT', 'The credential was modified elsewhere.');
        this.rows.delete(id);
      },
    };
  }
}

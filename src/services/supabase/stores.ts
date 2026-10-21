import type { SupabaseClient } from '@supabase/supabase-js';
import type { CredentialRow, EncryptedWrite, VaultMeta } from '@/types';
import { AppError } from '@/utils/errors';
import { mapSupabaseError } from './errors';

/**
 * Persistence ports. The app (and the tests) depend on these interfaces, so the
 * Supabase implementation can be swapped for an in-memory fake. Implementations only
 * ever receive ciphertext + technical metadata.
 */
export interface CredentialStore {
  list(): Promise<CredentialRow[]>;
  get(id: string): Promise<CredentialRow | null>;
  /** Idempotent: rows whose id already exists are left untouched (safe to retry). */
  insertMany(rows: EncryptedWrite[]): Promise<void>;
  /** Optimistic concurrency: throws CONFLICT if the stored revision differs. */
  update(row: EncryptedWrite, expectedRevision: number): Promise<CredentialRow>;
  /** Throws CONFLICT if the stored revision differs. Deleting a missing row succeeds. */
  remove(id: string, expectedRevision: number): Promise<void>;
}

export interface VaultMetaStore {
  get(): Promise<VaultMeta | null>;
  create(meta: VaultMeta): Promise<void>;
}

const PAGE = 1000;
const INSERT_BATCH = 100;

export class SupabaseCredentialStore implements CredentialStore {
  constructor(private readonly db: SupabaseClient) {}

  async list(): Promise<CredentialRow[]> {
    const out: CredentialRow[] = [];
    for (let from = 0; ; from += PAGE) {
      const { data, error } = await this.db
        .from('credentials')
        .select('*')
        .order('created_at', { ascending: true })
        .order('id', { ascending: true })
        .range(from, from + PAGE - 1);
      if (error) throw mapSupabaseError(error, 'Unable to load credentials.');
      const rows = (data ?? []) as CredentialRow[];
      out.push(...rows);
      if (rows.length < PAGE) return out;
    }
  }

  async get(id: string): Promise<CredentialRow | null> {
    const { data, error } = await this.db.from('credentials').select('*').eq('id', id).maybeSingle();
    if (error) throw mapSupabaseError(error, 'Unable to load the credential.');
    return (data as CredentialRow | null) ?? null;
  }

  async insertMany(rows: EncryptedWrite[]): Promise<void> {
    for (let i = 0; i < rows.length; i += INSERT_BATCH) {
      const batch = rows.slice(i, i + INSERT_BATCH);
      // user_id is filled by the column default auth.uid() and enforced by RLS.
      const { error } = await this.db
        .from('credentials')
        .upsert(batch, { onConflict: 'id', ignoreDuplicates: true });
      if (error) throw mapSupabaseError(error, 'Unable to save credentials.');
    }
  }

  async update(row: EncryptedWrite, expectedRevision: number): Promise<CredentialRow> {
    const { data, error } = await this.db
      .from('credentials')
      .update({ ciphertext: row.ciphertext, iv: row.iv, encryption_version: row.encryption_version })
      .eq('id', row.id)
      .eq('revision', expectedRevision)
      .select('*')
      .maybeSingle();
    if (error) throw mapSupabaseError(error, 'Unable to update the credential.');
    if (data) return data as CredentialRow;
    const current = await this.get(row.id);
    if (!current) throw new AppError('NOT_FOUND', 'The credential no longer exists.');
    throw new AppError('CONFLICT', 'The credential was modified elsewhere.');
  }

  async remove(id: string, expectedRevision: number): Promise<void> {
    const { data, error } = await this.db
      .from('credentials')
      .delete()
      .eq('id', id)
      .eq('revision', expectedRevision)
      .select('id');
    if (error) throw mapSupabaseError(error, 'Unable to delete the credential.');
    if (data && data.length > 0) return;
    const current = await this.get(id);
    if (current) throw new AppError('CONFLICT', 'The credential was modified elsewhere.');
  }
}

interface VaultRow {
  kdf: 'PBKDF2-SHA256';
  kdf_iterations: number;
  salt: string;
  verifier_ciphertext: string;
  verifier_iv: string;
  encryption_version: number;
}

export class SupabaseVaultMetaStore implements VaultMetaStore {
  constructor(private readonly db: SupabaseClient) {}

  async get(): Promise<VaultMeta | null> {
    const { data, error } = await this.db.from('vaults').select('*').maybeSingle();
    if (error) throw mapSupabaseError(error, 'Unable to load vault parameters.');
    if (!data) return null;
    const r = data as VaultRow;
    return {
      kdf: r.kdf,
      kdfIterations: r.kdf_iterations,
      salt: r.salt,
      verifierCiphertext: r.verifier_ciphertext,
      verifierIv: r.verifier_iv,
      encryptionVersion: r.encryption_version,
    };
  }

  async create(meta: VaultMeta): Promise<void> {
    const { error } = await this.db.from('vaults').insert({
      kdf: meta.kdf,
      kdf_iterations: meta.kdfIterations,
      salt: meta.salt,
      verifier_ciphertext: meta.verifierCiphertext,
      verifier_iv: meta.verifierIv,
      encryption_version: meta.encryptionVersion,
    });
    if (error) throw mapSupabaseError(error, 'Unable to create the vault.');
  }
}

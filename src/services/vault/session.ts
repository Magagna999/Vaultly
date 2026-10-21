import type { VaultMeta } from '@/types';
import { createVault, unlockVault } from '@/services/crypto';
import { AppError } from '@/utils/errors';

export type VaultState = 'locked' | 'unlocked';

export interface Timers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const realTimers: Timers = {
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

/**
 * Holds the derived key in memory only while the vault is unlocked.
 *
 * Memory limits: JavaScript offers no way to zero memory. Locking drops every reference
 * to the (non-extractable) CryptoKey so it becomes unreachable and collectable, but the
 * garbage collector decides when the bytes are actually reclaimed, and the master password
 * string passed by the UI may linger until collected. Closing the popup/tab frees the page.
 */
export class VaultSession {
  private key: CryptoKey | null = null;
  private timer: unknown = null;
  private autoLockMs = 0;
  private listeners = new Set<(s: VaultState) => void>();

  constructor(private readonly timers: Timers = realTimers) {}

  get state(): VaultState {
    return this.key ? 'unlocked' : 'locked';
  }

  /** The key, or a VAULT_LOCKED error. Any use counts as activity. */
  getKey(): CryptoKey {
    if (!this.key) throw new AppError('VAULT_LOCKED', 'The vault is locked. Enter your master password.');
    return this.key;
  }

  async create(masterPassword: string, userId: string, iterations?: number): Promise<VaultMeta> {
    const { meta, key } = await createVault(masterPassword, userId, iterations);
    this.setKey(key);
    return meta;
  }

  async unlock(masterPassword: string, userId: string, meta: VaultMeta): Promise<void> {
    const key = await unlockVault(masterPassword, userId, meta);
    this.setKey(key);
  }

  lock(): void {
    this.clearTimer();
    const was = this.key !== null;
    this.key = null;
    if (was) this.emit();
  }

  /** Minutes of inactivity before auto-lock; 0 disables. */
  setAutoLockMinutes(minutes: number): void {
    this.autoLockMs = Math.max(0, Math.floor(minutes * 60_000));
    this.touch();
  }

  /** Call on user activity to restart the inactivity countdown. */
  touch(): void {
    this.clearTimer();
    if (this.key && this.autoLockMs > 0) {
      this.timer = this.timers.setTimeout(() => this.lock(), this.autoLockMs);
    }
  }

  subscribe(fn: (s: VaultState) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private setKey(key: CryptoKey): void {
    const changed = this.key === null;
    this.key = key;
    this.touch();
    if (changed) this.emit();
  }

  private clearTimer(): void {
    if (this.timer !== null) this.timers.clearTimeout(this.timer);
    this.timer = null;
  }

  private emit(): void {
    for (const l of this.listeners) l(this.state);
  }
}

import type { VaultSettings } from '@/types';
import { createExtensionStore } from './storage';

const store = createExtensionStore('local');
const KEY = 'cpv-settings';
export const DEFAULT_SETTINGS: VaultSettings = { autoLockMinutes: 5 };
export const AUTO_LOCK_CHOICES = [1, 5, 15, 30, 60, 0];

/** Non-secret preferences only (never keys, tokens or credentials). */
export async function loadSettings(): Promise<VaultSettings> {
  try {
    const raw = await store.getItem(KEY);
    if (!raw) return DEFAULT_SETTINGS;
    const p = JSON.parse(raw) as Partial<VaultSettings>;
    const m = p.autoLockMinutes;
    return {
      autoLockMinutes: typeof m === 'number' && m >= 0 && m <= 1440 ? m : DEFAULT_SETTINGS.autoLockMinutes,
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function saveSettings(s: VaultSettings): Promise<void> {
  await store.setItem(KEY, JSON.stringify(s));
}

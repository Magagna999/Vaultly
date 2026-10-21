/**
 * Tiny key-value helpers. `session` data (auth tokens) lives in chrome.storage.session
 * (memory only, cleared when the browser closes); `local` data holds non-secret settings.
 */
export interface KeyValueStore {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

type Area = 'session' | 'local';

function chromeArea(area: Area): chrome.storage.StorageArea | null {
  try {
    return typeof chrome !== 'undefined' && chrome.storage ? (chrome.storage[area] ?? null) : null;
  } catch {
    return null;
  }
}

export function createExtensionStore(area: Area): KeyValueStore {
  const memory = new Map<string, string>(); // fallback outside the extension (dev/tests): memory only
  return {
    async getItem(key) {
      const a = chromeArea(area);
      if (!a) return memory.get(key) ?? null;
      const r = await a.get(key);
      const v = r[key];
      return typeof v === 'string' ? v : null;
    },
    async setItem(key, value) {
      const a = chromeArea(area);
      if (!a) memory.set(key, value);
      else await a.set({ [key]: value });
    },
    async removeItem(key) {
      const a = chromeArea(area);
      if (!a) memory.delete(key);
      else await a.remove(key);
    },
  };
}

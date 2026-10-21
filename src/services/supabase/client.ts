import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { createExtensionStore } from '@/utils/storage';
import { AppError } from '@/utils/errors';
import { getSupabaseConfig } from './config';

let client: SupabaseClient | null = null;

/**
 * Creates the Supabase client with the PUBLIC anon key only. Auth tokens are kept in
 * chrome.storage.session (never in localStorage, never persisted to disk by the extension).
 */
export function getSupabase(): SupabaseClient {
  if (client) return client;
  const cfg = getSupabaseConfig();
  if (!cfg) {
    throw new AppError(
      'SERVER',
      'Supabase is not configured. Copy .env.example to .env, fill in your project values and rebuild.',
    );
  }
  client = createClient(cfg.url, cfg.anonKey, {
    auth: {
      storage: createExtensionStore('session'),
      storageKey: 'cpv-auth',
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  });
  return client;
}

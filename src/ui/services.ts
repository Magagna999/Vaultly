import { getSupabase } from '@/services/supabase/client';
import { AuthService, type AuthApi } from '@/services/supabase/auth';
import {
  SupabaseCredentialStore,
  SupabaseVaultMetaStore,
  type VaultMetaStore,
} from '@/services/supabase/stores';
import { SyncService } from '@/services/sync/sync';
import { VaultSession } from '@/services/vault/session';

export interface Services {
  auth: AuthService;
  session: VaultSession;
  meta: VaultMetaStore;
  makeSync(userId: string): SyncService;
}

export function createServices(): Services {
  const sb = getSupabase();
  const session = new VaultSession();
  return {
    auth: new AuthService(sb.auth as unknown as AuthApi),
    session,
    meta: new SupabaseVaultMetaStore(sb),
    makeSync: (userId) =>
      new SyncService({ store: new SupabaseCredentialStore(sb), userId, getKey: () => session.getKey() }),
  };
}

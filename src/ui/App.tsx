import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Credential, CredentialData, VaultMeta, VaultSettings } from '@/types';
import type { SyncService, SyncStatus } from '@/services/sync/sync';
import type { AuthUser } from '@/services/supabase/auth';
import { getSupabaseConfig } from '@/services/supabase/config';
import { createServices, type Services } from './services';
import { DEFAULT_SETTINGS, loadSettings, saveSettings } from '@/utils/settings';
import { userMessage } from '@/utils/errors';
import { logError } from '@/utils/logger';
import { LoginScreen, UnlockScreen, VaultSetupScreen } from '@/components/AuthScreens';
import { Dashboard } from '@/components/Dashboard';
import { Detail } from '@/components/Detail';
import { CredentialForm } from '@/components/Form';
import { ImportWizard } from '@/components/ImportWizard';
import { SettingsView } from '@/components/Settings';
import { Notice } from '@/components/common';

type Phase = 'loading' | 'unconfigured' | 'signed-out' | 'vault-setup' | 'locked' | 'unlocked';
type View =
  | { name: 'list' }
  | { name: 'detail'; id: string }
  | { name: 'form'; id: string | null }
  | { name: 'import'; mode: 'csv' | 'backup' }
  | { name: 'settings' };

export function App({ mode }: { mode: 'popup' | 'options' }) {
  const configured = getSupabaseConfig() !== null;
  const services = useMemo<Services | null>(() => (configured ? createServices() : null), [configured]);
  const [phase, setPhase] = useState<Phase>(configured ? 'loading' : 'unconfigured');
  const [user, setUser] = useState<AuthUser | null>(null);
  const [meta, setMeta] = useState<VaultMeta | null>(null);
  const [sync, setSync] = useState<SyncService | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [undecryptable, setUndecryptable] = useState(0);
  const [status, setStatus] = useState<SyncStatus>({ state: 'idle', lastSyncedAt: null, error: null });
  const [settings, setSettings] = useState<VaultSettings>(DEFAULT_SETTINGS);
  const [view, setView] = useState<View>(mode === 'options' ? { name: 'settings' } : { name: 'list' });
  const [banner, setBanner] = useState<string | null>(null);
  const settingsRef = useRef(settings);
  settingsRef.current = settings;

  const refresh = useCallback(async (s: SyncService) => {
    try {
      const r = await s.load();
      setCredentials(r.credentials);
      setUndecryptable(r.undecryptable);
    } catch (e) {
      setBanner(userMessage(e));
    }
  }, []);

  const resetToSignedOut = useCallback(() => {
    services?.session.lock();
    setSync(null);
    setCredentials([]);
    setUser(null);
    setMeta(null);
    setPhase('signed-out');
  }, [services]);

  // Initial session check + settings.
  useEffect(() => {
    if (!services) return;
    let cancelled = false;
    void (async () => {
      const s = await loadSettings();
      if (cancelled) return;
      setSettings(s);
      services.session.setAutoLockMinutes(s.autoLockMinutes);
      try {
        const u = await services.auth.currentUser();
        if (cancelled) return;
        if (!u) return setPhase('signed-out');
        await enter(u);
      } catch (e) {
        if (!cancelled) {
          setBanner(userMessage(e));
          setPhase('signed-out');
        }
      }
    })();
    const offEnd = services.auth.onSessionEnded(() => resetToSignedOut());
    const offLock = services.session.subscribe((st) => {
      if (st === 'locked') {
        setCredentials([]);
        setSync((cur) => {
          cur?.clear();
          return cur;
        });
        setPhase((p) => (p === 'unlocked' ? 'locked' : p));
        setView(mode === 'options' ? { name: 'settings' } : { name: 'list' });
      }
    });
    return () => {
      cancelled = true;
      offEnd();
      offLock();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [services]);

  // User activity resets the inactivity timer.
  useEffect(() => {
    if (!services) return;
    const touch = () => services.session.touch();
    const events = ['pointerdown', 'keydown'] as const;
    events.forEach((e) => window.addEventListener(e, touch));
    return () => events.forEach((e) => window.removeEventListener(e, touch));
  }, [services]);

  async function enter(u: AuthUser) {
    if (!services) return;
    setUser(u);
    const m = await services.meta.get();
    setMeta(m);
    const s = services.makeSync(u.id);
    s.subscribe(setStatus);
    setSync(s);
    setPhase(m ? 'locked' : 'vault-setup');
  }

  if (!services) {
    return (
      <main className={`app ${mode}`}>
        <Notice kind="error">
          Supabase is not configured. Copy <code>.env.example</code> to <code>.env</code>, fill in your
          project URL and public anon key, then rebuild (see README).
        </Notice>
      </main>
    );
  }

  async function afterUnlock(s: SyncService) {
    setPhase('unlocked');
    setView(mode === 'options' ? { name: 'settings' } : { name: 'list' });
    await refresh(s);
  }

  const current =
    view.name === 'detail' || (view.name === 'form' && view.id)
      ? (credentials.find((c) => c.id === (view as { id: string }).id) ?? null)
      : null;

  let body: JSX.Element;
  if (phase === 'loading') body = <p role="status">Loading…</p>;
  else if (phase === 'signed-out') {
    body = (
      <LoginScreen
        onSignIn={async (email, password) => {
          await services.auth.signIn(email, password).then(enter);
          setBanner(null);
        }}
        onSignUp={async (email, password) => {
          const u = await services.auth.signUp(email, password);
          if (!u) return 'Account created. Confirm your email address, then sign in.';
          await enter(u);
          return null;
        }}
      />
    );
  } else if (phase === 'vault-setup' && user && sync) {
    body = (
      <VaultSetupScreen
        onSignOut={() => void services.auth.signOut().then(resetToSignedOut)}
        onCreate={async (pw, iterations) => {
          const m = await services.session.create(pw, user.id, iterations);
          try {
            await services.meta.create(m);
          } catch (e) {
            services.session.lock();
            throw e;
          }
          setMeta(m);
          await afterUnlock(sync);
        }}
      />
    );
  } else if (phase === 'locked' && user && sync && meta) {
    body = (
      <UnlockScreen
        email={user.email}
        message={banner}
        onSignOut={() => void services.auth.signOut().then(resetToSignedOut)}
        onUnlock={async (pw) => {
          await services.session.unlock(pw, user.id, meta);
          setBanner(null);
          await afterUnlock(sync);
        }}
      />
    );
  } else if (phase === 'unlocked' && sync && user) {
    const back = () => setView({ name: 'list' });
    const lock = () => services.session.lock();
    switch (view.name) {
      case 'detail':
        body = current ? (
          <Detail
            credential={current}
            onBack={back}
            onEdit={() => setView({ name: 'form', id: current.id })}
            onActivity={() => services.session.touch()}
            onDelete={async () => {
              const r = await sync.remove(current.id);
              if (!r.ok) throw new Error('It was modified elsewhere. Sync and try again.');
              setCredentials(sync.list());
              back();
            }}
          />
        ) : (
          <Notice kind="error">Credential not found.</Notice>
        );
        break;
      case 'form':
        body = (
          <CredentialForm
            existing={current}
            onCancel={back}
            onSaved={() => {
              setCredentials(sync.list());
              back();
            }}
            onCreate={async (d: CredentialData, id: string) => {
              await sync.create(d, id);
            }}
            onUpdate={(d) => sync.update((current as Credential).id, d)}
            onKeepMine={(d, rev) => sync.overwriteWithMine((current as Credential).id, d, rev)}
            onUseServer={async () => {
              await sync.adoptServer((current as Credential).id);
            }}
          />
        );
        break;
      case 'import':
        body = (
          <ImportWizard
            mode={view.mode}
            existing={credentials}
            sync={sync}
            onClose={back}
            onImported={() => void refresh(sync)}
          />
        );
        break;
      case 'settings':
        body = (
          <SettingsView
            email={user.email}
            settings={settings}
            meta={meta}
            credentials={credentials}
            lastSyncedAt={status.lastSyncedAt}
            onChange={(s) => {
              setSettings(s);
              services.session.setAutoLockMinutes(s.autoLockMinutes);
              void saveSettings(s).catch(() => logError('settings save failed'));
            }}
            onRestore={() => setView({ name: 'import', mode: 'backup' })}
            onBack={back}
            onSignOut={() => void services.auth.signOut().then(resetToSignedOut)}
          />
        );
        break;
      default:
        body = (
          <Dashboard
            credentials={credentials}
            status={status}
            undecryptable={undecryptable}
            onOpen={(id) => setView({ name: 'detail', id })}
            onAdd={() => setView({ name: 'form', id: null })}
            onImport={() => setView({ name: 'import', mode: 'csv' })}
            onSettings={() => setView({ name: 'settings' })}
            onSync={() => void refresh(sync)}
            onLock={lock}
          />
        );
    }
  } else body = <p role="status">Loading…</p>;

  return (
    <main className={`app ${mode}`}>
      {banner && phase !== 'locked' && <Notice kind="error">{banner}</Notice>}
      {body}
    </main>
  );
}

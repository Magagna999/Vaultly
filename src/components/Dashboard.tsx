import { useMemo, useState } from 'react';
import type { Credential } from '@/types';
import type { SyncStatus } from '@/services/sync/sync';
import { hostnameOf } from '@/utils/validation';
import { Notice, formatDate } from './common';

export function matches(c: Credential, q: string): boolean {
  const s = q.trim().toLowerCase();
  if (!s) return true;
  return [c.name, c.username, hostnameOf(c.url), c.url].some((v) => v.toLowerCase().includes(s));
}

export function Dashboard(props: {
  credentials: Credential[];
  status: SyncStatus;
  undecryptable: number;
  onOpen: (id: string) => void;
  onAdd: () => void;
  onImport: () => void;
  onSettings: () => void;
  onSync: () => void;
  onLock: () => void;
}) {
  const [query, setQuery] = useState('');
  const shown = useMemo(
    () =>
      props.credentials
        .filter((c) => matches(c, query))
        .sort((a, b) => (a.name || a.url).localeCompare(b.name || b.url)),
    [props.credentials, query],
  );

  return (
    <section aria-labelledby="dash-title">
      <header className="toolbar">
        <h1 id="dash-title">Credentials</h1>
        <div className="actions">
          <button onClick={props.onAdd} className="primary">
            Add
          </button>
          <button onClick={props.onImport}>Import</button>
          <button onClick={props.onSettings}>Settings</button>
          <button onClick={props.onLock}>Lock</button>
        </div>
      </header>
      <div className="field">
        <label htmlFor="search">Search by site, domain or username</label>
        <input
          id="search"
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          autoComplete="off"
          autoFocus
        />
      </div>
      <p className="muted status" aria-live="polite">
        {props.status.state === 'syncing'
          ? 'Syncing…'
          : `Last synced: ${formatDate(props.status.lastSyncedAt)}`}{' '}
        <button className="link" onClick={props.onSync} disabled={props.status.state === 'syncing'}>
          Sync now
        </button>
      </p>
      {props.status.error && <Notice kind="error">{props.status.error}</Notice>}
      {props.undecryptable > 0 && (
        <Notice kind="error">
          {props.undecryptable} record(s) could not be decrypted and are hidden (wrong key or corrupted data).
        </Notice>
      )}
      {shown.length === 0 ? (
        <p className="muted">
          {props.credentials.length === 0 ? 'No credentials yet. Add one or import a CSV.' : 'No results.'}
        </p>
      ) : (
        <ul className="list">
          {shown.map((c) => (
            <li key={c.id}>
              <button className="row" onClick={() => props.onOpen(c.id)}>
                <span className="row-title">{c.name || hostnameOf(c.url) || c.url}</span>
                <span className="row-sub">
                  {c.username || '—'} · {hostnameOf(c.url) || '—'}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

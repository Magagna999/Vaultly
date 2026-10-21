import { useState } from 'react';
import type { Credential, VaultMeta, VaultSettings } from '@/types';
import { AUTO_LOCK_CHOICES } from '@/utils/settings';
import { backupFilename, createBackup } from '@/services/export/backup';
import { exportPlainCsv } from '@/services/export/csv';
import { downloadText } from '@/utils/download';
import { userMessage } from '@/utils/errors';
import { Field, Notice, formatDate } from './common';

export function SettingsView(props: {
  email: string;
  settings: VaultSettings;
  meta: VaultMeta | null;
  credentials: Credential[];
  lastSyncedAt: string | null;
  onChange: (s: VaultSettings) => void;
  onRestore: () => void;
  onBack: () => void;
  onSignOut: () => void;
}) {
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const [msg, setMsg] = useState<{ kind: 'error' | 'success'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [csvAck, setCsvAck] = useState(false);

  async function backup() {
    setMsg(null);
    if (pass !== pass2) return setMsg({ kind: 'error', text: 'The two passphrases do not match.' });
    setBusy(true);
    try {
      const text = await createBackup(props.credentials, pass, props.meta?.kdfIterations);
      downloadText(backupFilename(), text, 'application/json');
      setPass('');
      setPass2('');
      setMsg({
        kind: 'success',
        text: 'Encrypted backup created. Store the passphrase safely: without it the backup is unrecoverable.',
      });
    } catch (e) {
      setMsg({ kind: 'error', text: userMessage(e) });
    } finally {
      setBusy(false);
    }
  }

  function exportCsv() {
    if (
      !window.confirm(
        'This file will contain ALL your passwords in plain text. Anyone who gets it can read them. Continue?',
      )
    )
      return;
    downloadText('password-vault-PLAINTEXT.csv', exportPlainCsv(props.credentials), 'text/csv');
    setCsvAck(false);
  }

  return (
    <section aria-labelledby="set-title">
      <header className="toolbar">
        <button onClick={props.onBack}>← Back</button>
        <h1 id="set-title">Settings</h1>
      </header>
      {msg && <Notice kind={msg.kind}>{msg.text}</Notice>}

      <h2>Session</h2>
      <p className="muted">
        Signed in as {props.email}. Last synced: {formatDate(props.lastSyncedAt)}.
      </p>
      <div className="field">
        <label htmlFor="autolock">Auto-lock after inactivity</label>
        <select
          id="autolock"
          value={props.settings.autoLockMinutes}
          onChange={(e) => props.onChange({ ...props.settings, autoLockMinutes: Number(e.target.value) })}
        >
          {AUTO_LOCK_CHOICES.map((m) => (
            <option key={m} value={m}>
              {m === 0 ? 'Never (not recommended)' : `${m} minute${m > 1 ? 's' : ''}`}
            </option>
          ))}
        </select>
      </div>
      <button onClick={props.onSignOut}>Sign out</button>

      <h2>Vault</h2>
      <p className="muted">
        Encryption: AES-256-GCM, key derived with {props.meta?.kdf ?? '—'} (
        {props.meta?.kdfIterations?.toLocaleString() ?? '—'} iterations), format v
        {props.meta?.encryptionVersion ?? '—'}. Changing the master password is not supported in this version.
      </p>

      <h2>Encrypted backup</h2>
      <Field
        id="bk1"
        label="Backup passphrase"
        type="password"
        value={pass}
        onChange={setPass}
        autoComplete="new-password"
        hint="At least 12 characters. Needed to restore; cannot be recovered."
      />
      <Field
        id="bk2"
        label="Confirm passphrase"
        type="password"
        value={pass2}
        onChange={setPass2}
        autoComplete="new-password"
      />
      <div className="actions">
        <button className="primary" onClick={backup} disabled={busy || !pass}>
          Download encrypted backup
        </button>
        <button onClick={props.onRestore}>Restore from backup…</button>
      </div>

      <h2>Danger zone</h2>
      <Notice kind="error">
        Plain-text CSV export writes every password unencrypted. Prefer the encrypted backup above. If you
        export, delete the file securely after use.
      </Notice>
      <label className="check">
        <input type="checkbox" checked={csvAck} onChange={(e) => setCsvAck(e.target.checked)} /> I understand
        the risks of a plain-text export.
      </label>
      <button className="danger" disabled={!csvAck || props.credentials.length === 0} onClick={exportCsv}>
        Export plain-text CSV
      </button>
    </section>
  );
}

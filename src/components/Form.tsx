import { useRef, useState, type FormEvent } from 'react';
import type { Credential, CredentialData } from '@/types';
import type { UpdateResult } from '@/services/sync/sync';
import { emptyCredentialData, validateCredentialData } from '@/utils/validation';
import { userMessage } from '@/utils/errors';
import { generatePassword } from '@/utils/download';
import { Field, Notice } from './common';

export function CredentialForm(props: {
  existing: Credential | null;
  onCancel: () => void;
  onCreate: (d: CredentialData, id: string) => Promise<void>;
  onUpdate: (d: CredentialData) => Promise<UpdateResult>;
  onKeepMine: (d: CredentialData, serverRevision: number) => Promise<UpdateResult>;
  onUseServer: () => Promise<void>;
  onSaved: () => void;
}) {
  const [data, setData] = useState<CredentialData>(
    props.existing
      ? {
          name: props.existing.name,
          url: props.existing.url,
          username: props.existing.username,
          password: props.existing.password,
          note: props.existing.note,
        }
      : emptyCredentialData(),
  );
  const newId = useRef(crypto.randomUUID()); // stable per form: a double submit cannot create two rows
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState<{ server: Credential | null } | null>(null);
  const set = (k: keyof CredentialData) => (v: string) => setData({ ...data, [k]: v });

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return; // protects against double submission
    const errs = validateCredentialData(data);
    if (errs.length) return setError(errs.join(' '));
    setBusy(true);
    setError(null);
    try {
      if (!props.existing) await props.onCreate(data, newId.current);
      else {
        const r = await props.onUpdate(data);
        if (!r.ok) {
          setConflict(r.conflict);
          return;
        }
      }
      props.onSaved();
    } catch (err) {
      setError(userMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function keepMine() {
    if (!conflict?.server) return;
    setBusy(true);
    try {
      const r = await props.onKeepMine(data, conflict.server.revision);
      if (r.ok) props.onSaved();
      else setConflict(r.conflict);
    } catch (err) {
      setError(userMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} aria-labelledby="form-title" className="card">
      <h1 id="form-title">{props.existing ? 'Edit credential' : 'Add credential'}</h1>
      {error && <Notice kind="error">{error}</Notice>}
      {conflict && (
        <div className="notice notice-error" role="alert">
          <p>
            {conflict.server
              ? 'This credential was changed on another device while you were editing.'
              : 'This credential was deleted on another device.'}
          </p>
          {conflict.server && (
            <button type="button" onClick={keepMine} disabled={busy}>
              Keep my version
            </button>
          )}{' '}
          <button
            type="button"
            onClick={async () => {
              await props.onUseServer();
              props.onSaved();
            }}
          >
            {conflict.server ? 'Use the server version' : 'Discard my changes'}
          </button>
        </div>
      )}
      <Field id="f-name" label="Site name" value={data.name} onChange={set('name')} autoFocus />
      <Field id="f-url" label="URL" value={data.url} onChange={set('url')} />
      <Field
        id="f-user"
        label="Username"
        value={data.username}
        onChange={set('username')}
        autoComplete="off"
      />
      <Field
        id="f-pass"
        label="Password"
        type={showPw ? 'text' : 'password'}
        value={data.password}
        onChange={set('password')}
        autoComplete="new-password"
        required
      />
      <div className="actions">
        <button type="button" onClick={() => setShowPw(!showPw)} aria-pressed={showPw}>
          {showPw ? 'Hide password' : 'Show password'}
        </button>
        <button type="button" onClick={() => setData({ ...data, password: generatePassword() })}>
          Generate password
        </button>
      </div>
      <Field id="f-note" label="Note" value={data.note} onChange={set('note')} multiline />
      <div className="actions">
        <button type="submit" className="primary" disabled={busy}>
          {busy ? 'Saving…' : 'Save'}
        </button>
        <button type="button" onClick={props.onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

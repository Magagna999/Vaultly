import { useEffect, useRef, useState } from 'react';
import type { Credential } from '@/types';
import { copyToClipboard } from '@/utils/download';
import { Notice, formatDate } from './common';

const REVEAL_MS = 30_000;

export function Detail(props: {
  credential: Credential;
  onBack: () => void;
  onEdit: () => void;
  onDelete: () => Promise<void>;
  onActivity: () => void;
}) {
  const c = props.credential;
  const [revealed, setRevealed] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!revealed) return;
    timer.current = setTimeout(() => setRevealed(false), REVEAL_MS);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [revealed]);

  async function copy(label: string, value: string) {
    props.onActivity();
    try {
      await copyToClipboard(value);
      setMsg(`${label} copied to the clipboard. It will be cleared in 30 seconds.`);
    } catch {
      setMsg(null);
      setError('Unable to access the clipboard.');
    }
  }

  const safeUrl = /^https?:\/\//i.test(c.url) ? c.url : null;

  return (
    <section aria-labelledby="detail-title">
      <header className="toolbar">
        <button onClick={props.onBack}>← Back</button>
        <div className="actions">
          <button onClick={props.onEdit}>Edit</button>
          <button className="danger" onClick={() => setConfirmDelete(true)}>
            Delete
          </button>
        </div>
      </header>
      <h1 id="detail-title">{c.name || c.url}</h1>
      {msg && <Notice kind="success">{msg}</Notice>}
      {error && <Notice kind="error">{error}</Notice>}
      {confirmDelete && (
        <div className="notice notice-error" role="alertdialog" aria-label="Confirm deletion">
          <p>Delete this credential permanently?</p>
          <button
            className="danger"
            onClick={async () => {
              try {
                await props.onDelete();
              } catch (e) {
                setConfirmDelete(false);
                setError(e instanceof Error ? e.message : 'Delete failed.');
              }
            }}
          >
            Yes, delete
          </button>{' '}
          <button onClick={() => setConfirmDelete(false)}>Cancel</button>
        </div>
      )}
      <dl className="details">
        <dt>URL</dt>
        <dd>
          {safeUrl ? (
            <a href={safeUrl} target="_blank" rel="noopener noreferrer">
              {c.url}
            </a>
          ) : (
            c.url || '—'
          )}
        </dd>
        <dt>Username</dt>
        <dd>
          {c.username || '—'}{' '}
          {c.username && (
            <button onClick={() => copy('Username', c.username)} aria-label="Copy username">
              Copy username
            </button>
          )}
        </dd>
        <dt>Password</dt>
        <dd>
          <span className="secret" aria-live="polite">
            {revealed ? c.password : '••••••••••••'}
          </span>{' '}
          <button
            onClick={() => {
              props.onActivity();
              setRevealed(!revealed);
            }}
            aria-pressed={revealed}
          >
            {revealed ? 'Hide password' : 'Show password'}
          </button>{' '}
          <button onClick={() => copy('Password', c.password)} aria-label="Copy password to clipboard">
            Copy password
          </button>
        </dd>
        {c.note && (
          <>
            <dt>Note</dt>
            <dd className="pre">{c.note}</dd>
          </>
        )}
        <dt>Created</dt>
        <dd>{formatDate(c.createdAt)}</dd>
        <dt>Modified</dt>
        <dd>{formatDate(c.updatedAt)}</dd>
      </dl>
    </section>
  );
}

import { useState, type FormEvent } from 'react';
import { Field, Notice } from './common';
import { userMessage } from '@/utils/errors';
import { validateMasterPassword } from '@/utils/validation';
import { DEFAULT_KDF_ITERATIONS, MAX_KDF_ITERATIONS, MIN_KDF_ITERATIONS } from '@/services/crypto/constants';

export function LoginScreen(props: {
  onSignIn: (email: string, password: string) => Promise<void>;
  onSignUp: (email: string, password: string) => Promise<string | null>;
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState<'in' | 'up'>('in');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      if (mode === 'in') await props.onSignIn(email, password);
      else {
        const msg = await props.onSignUp(email, password);
        if (msg) setInfo(msg);
      }
      setPassword('');
    } catch (err) {
      setError(userMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="card" aria-labelledby="login-title">
      <h1 id="login-title">{mode === 'in' ? 'Sign in' : 'Create account'}</h1>
      {error && <Notice kind="error">{error}</Notice>}
      {info && <Notice kind="info">{info}</Notice>}
      <Field
        id="email"
        label="Email"
        type="email"
        value={email}
        onChange={setEmail}
        autoComplete="email"
        required
        autoFocus
      />
      <Field
        id="account-password"
        label="Account password"
        type="password"
        value={password}
        onChange={setPassword}
        autoComplete={mode === 'in' ? 'current-password' : 'new-password'}
        required
        hint="This signs you in to the server. It is NOT your vault master password."
      />
      <button type="submit" className="primary" disabled={busy}>
        {busy ? 'Please wait…' : mode === 'in' ? 'Sign in' : 'Create account'}
      </button>
      <button type="button" className="link" onClick={() => setMode(mode === 'in' ? 'up' : 'in')}>
        {mode === 'in' ? 'No account? Create one' : 'Have an account? Sign in'}
      </button>
    </form>
  );
}

export function VaultSetupScreen(props: {
  onCreate: (masterPassword: string, iterations: number) => Promise<void>;
  onSignOut: () => void;
}) {
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [iterations, setIterations] = useState(String(DEFAULT_KDF_ITERATIONS));
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const weak = validateMasterPassword(pw);
    const it = Number(iterations);
    if (weak) return setError(weak);
    if (pw !== confirm) return setError('The two master passwords do not match.');
    if (!Number.isInteger(it) || it < MIN_KDF_ITERATIONS || it > MAX_KDF_ITERATIONS) {
      return setError(`Iterations must be between ${MIN_KDF_ITERATIONS} and ${MAX_KDF_ITERATIONS}.`);
    }
    setBusy(true);
    try {
      await props.onCreate(pw, it);
      setPw('');
      setConfirm('');
    } catch (err) {
      setError(userMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="card" aria-labelledby="setup-title">
      <h1 id="setup-title">Create your vault</h1>
      <Notice kind="info">
        Choose a master password. It encrypts your data on this device and is never sent to the server or
        stored.
        <strong> If you forget it, your data cannot be recovered.</strong> Use a password different from your
        account password.
      </Notice>
      {error && <Notice kind="error">{error}</Notice>}
      <Field
        id="master"
        label="Master password"
        type="password"
        value={pw}
        onChange={setPw}
        autoComplete="new-password"
        required
        autoFocus
        hint="At least 12 characters."
      />
      <Field
        id="master2"
        label="Confirm master password"
        type="password"
        value={confirm}
        onChange={setConfirm}
        autoComplete="new-password"
        required
      />
      <Field
        id="iters"
        label="PBKDF2 iterations"
        type="number"
        value={iterations}
        onChange={setIterations}
        hint="Higher is slower to brute-force (and to unlock). Default 600,000."
      />
      <label className="check">
        <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> I understand that a
        lost master password cannot be recovered.
      </label>
      <button type="submit" className="primary" disabled={busy || !ack}>
        {busy ? 'Creating…' : 'Create vault'}
      </button>
      <button type="button" className="link" onClick={props.onSignOut}>
        Sign out
      </button>
    </form>
  );
}

export function UnlockScreen(props: {
  email: string;
  onUnlock: (masterPassword: string) => Promise<void>;
  onSignOut: () => void;
  message?: string | null;
}) {
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await props.onUnlock(pw);
      setPw('');
    } catch (err) {
      setError(userMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="card" aria-labelledby="unlock-title">
      <h1 id="unlock-title">Vault locked</h1>
      <p className="muted">Signed in as {props.email}</p>
      {props.message && <Notice kind="info">{props.message}</Notice>}
      {error && <Notice kind="error">{error}</Notice>}
      <Field
        id="unlock-pw"
        label="Master password"
        type="password"
        value={pw}
        onChange={setPw}
        autoComplete="off"
        required
        autoFocus
      />
      <button type="submit" className="primary" disabled={busy}>
        {busy ? 'Unlocking…' : 'Unlock'}
      </button>
      <button type="button" className="link" onClick={props.onSignOut}>
        Sign out
      </button>
    </form>
  );
}

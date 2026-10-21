/**
 * Session, authentication and vault lock/unlock tests.
 *
 * The VaultSession clock is injected through the `Timers` interface (a deterministic fake clock)
 * or through vitest fake timers, so the auto-lock behaviour is verified without waiting in real
 * time and without depending on WebCrypto promise resolution while the clock is faked.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CredentialRow, VaultMeta, VaultSettings } from '@/types';
import { ENCRYPTION_VERSION, decryptCredential, encryptCredential } from '@/services/crypto';
import { VaultSession, type Timers } from '@/services/vault/session';
import { AuthService, type AuthApi } from '@/services/supabase/auth';
import { mapSupabaseError } from '@/services/supabase/errors';
import { withRetry } from '@/utils/retry';
import { DEFAULT_SETTINGS, loadSettings, saveSettings } from '@/utils/settings';
import { AppError, isAppError, type ErrorCode } from '@/utils/errors';

const ITERATIONS = 100_000;
const USER = 'user-1';
const EMAIL = 'user@example.com';
const PASSWORD = 'S3cret-Passw0rd!';
const MASTER = 'correct horse battery staple!';
const CRED_ID = 'cred-1';
const ISO = '2024-01-01T00:00:00Z';

/* -------------------------------------------------------------------------- */
/* helpers                                                                    */
/* -------------------------------------------------------------------------- */

/** Runs `fn` and returns the AppError it must throw. */
function expectAppError(fn: () => unknown, code: ErrorCode): AppError {
  try {
    fn();
  } catch (e) {
    expect(isAppError(e, code)).toBe(true);
    if (e instanceof AppError) return e;
    throw new Error('Expected an AppError');
  }
  throw new Error(`Expected an AppError with code "${code}"`);
}

/** Awaits `promise` and returns the AppError it must reject with. */
async function expectAppErrorAsync(promise: Promise<unknown>, code: ErrorCode): Promise<AppError> {
  try {
    await promise;
  } catch (e) {
    expect(isAppError(e, code)).toBe(true);
    if (e instanceof AppError) return e;
    throw new Error('Expected an AppError');
  }
  throw new Error(`Expected an AppError with code "${code}"`);
}

interface FakeClock {
  timers: Timers;
  advance(ms: number): void;
  readonly pending: number;
}

/** A minimal, deterministic clock injected into the VaultSession. */
function createFakeClock(): FakeClock {
  let current = 0;
  let nextId = 0;
  const scheduled = new Map<number, { id: number; dueAt: number; fn: () => void }>();

  const timers: Timers = {
    setTimeout(fn: () => void, ms: number): unknown {
      const id = ++nextId;
      scheduled.set(id, { id, dueAt: current + ms, fn });
      return id;
    },
    clearTimeout(handle: unknown): void {
      if (typeof handle === 'number') scheduled.delete(handle);
    },
  };

  return {
    timers,
    advance(ms: number): void {
      const target = current + ms;
      for (;;) {
        let next: { id: number; dueAt: number; fn: () => void } | undefined;
        for (const timer of scheduled.values()) {
          if (timer.dueAt <= target && (!next || timer.dueAt < next.dueAt)) next = timer;
        }
        if (!next) break;
        scheduled.delete(next.id);
        current = next.dueAt;
        next.fn();
      }
      current = target;
    },
    get pending(): number {
      return scheduled.size;
    },
  };
}

/* -------------------------------------------------------------------------- */
/* fake Supabase auth API                                                     */
/* -------------------------------------------------------------------------- */

interface FakeSession {
  user: { id: string; email?: string | null };
}

interface FakeAuthError {
  message?: string;
  status?: number;
  code?: string;
}

interface FakeAuthResult {
  data: { session?: FakeSession | null; user?: { id: string; email?: string | null } | null };
  error: FakeAuthError | null;
}

/** Records every call and lets each test decide the answer. */
class FakeAuthApi implements AuthApi {
  readonly signInCalls: { email: string; password: string }[] = [];
  readonly signUpCalls: { email: string; password: string }[] = [];
  readonly signOutCalls: { scope?: 'local' | 'global' | 'others' }[] = [];
  getSessionCalls = 0;
  unsubscribed = false;

  signInResult: FakeAuthResult = { data: { session: null }, error: null };
  signUpResult: FakeAuthResult = { data: { session: null }, error: null };
  signOutThrows: unknown = null;
  getSessionResult: { data: { session: FakeSession | null }; error: { message?: string } | null } = {
    data: { session: null },
    error: null,
  };
  getSessionThrows: unknown = null;

  private listener: ((event: string, session: FakeSession | null) => void) | null = null;

  async signInWithPassword(credentials: { email: string; password: string }): Promise<FakeAuthResult> {
    this.signInCalls.push({ ...credentials });
    return this.signInResult;
  }

  async signUp(credentials: { email: string; password: string }): Promise<FakeAuthResult> {
    this.signUpCalls.push({ ...credentials });
    return this.signUpResult;
  }

  async signOut(options?: {
    scope?: 'local' | 'global' | 'others';
  }): Promise<{ error: { message?: string } | null }> {
    this.signOutCalls.push(options ?? {});
    if (this.signOutThrows) throw this.signOutThrows;
    return { error: null };
  }

  async getSession(): Promise<{
    data: { session: FakeSession | null };
    error: { message?: string } | null;
  }> {
    this.getSessionCalls += 1;
    if (this.getSessionThrows) throw this.getSessionThrows;
    return this.getSessionResult;
  }

  onAuthStateChange(cb: (event: string, session: FakeSession | null) => void): {
    data: { subscription: { unsubscribe(): void } };
  } {
    this.listener = cb;
    return {
      data: {
        subscription: {
          unsubscribe: () => {
            this.unsubscribed = true;
            if (this.listener === cb) this.listener = null;
          },
        },
      },
    };
  }

  emit(event: string, session: FakeSession | null): void {
    this.listener?.(event, session);
  }
}

const SESSION: FakeSession = { user: { id: USER, email: EMAIL } };

/* -------------------------------------------------------------------------- */
/* VaultSession                                                               */
/* -------------------------------------------------------------------------- */

describe('VaultSession', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // Case 1: the vault starts locked.
  it('starts locked and refuses to hand out a key', () => {
    const session = new VaultSession();

    expect(session.state).toBe('locked');

    const error = expectAppError(() => session.getKey(), 'VAULT_LOCKED');
    expect(error.message.length).toBeGreaterThan(0);
    expect(() => session.getKey()).toThrowError(AppError);
  });

  // Case 2: create -> unlocked, non-extractable key, lock -> locked, one event per transition.
  it('creates the vault, exposes a non-extractable key and locks again', async () => {
    const clock = createFakeClock();
    const session = new VaultSession(clock.timers);
    const states: string[] = [];
    const unsubscribe = session.subscribe((s) => states.push(s));

    const meta = await session.create(MASTER, USER, ITERATIONS);

    expect(meta.kdf).toBe('PBKDF2-SHA256');
    expect(meta.kdfIterations).toBe(ITERATIONS);
    expect(meta.encryptionVersion).toBe(ENCRYPTION_VERSION);
    expect(meta.salt.length).toBeGreaterThan(0);
    expect(meta.verifierCiphertext.length).toBeGreaterThan(0);
    expect(meta.verifierIv.length).toBeGreaterThan(0);
    // The public parameters never contain the master password.
    expect(JSON.stringify(meta)).not.toContain(MASTER);

    expect(session.state).toBe('unlocked');
    const key = session.getKey();
    expect(key.extractable).toBe(false);
    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.usages).toEqual(expect.arrayContaining(['encrypt', 'decrypt']));

    session.lock();
    expect(session.state).toBe('locked');
    expect(() => session.getKey()).toThrowError(AppError);

    // Locking twice must not emit a second "locked" event.
    session.lock();
    expect(states).toEqual(['unlocked', 'locked']);

    unsubscribe();
    session.lock();
    expect(states).toEqual(['unlocked', 'locked']);
  });

  // Case 3: right password unlocks, wrong password is rejected and never swaps the key.
  it('unlocks with the right password and rejects a wrong one without touching the key', async () => {
    const clock = createFakeClock();
    const creator = new VaultSession(clock.timers);
    const meta: VaultMeta = await creator.create(MASTER, USER, ITERATIONS);
    creator.lock();

    const session = new VaultSession(clock.timers);

    const wrong = await expectAppErrorAsync(session.unlock('wrong password', USER, meta), 'WRONG_PASSWORD');
    expect(wrong.message).not.toContain('wrong password');
    expect(session.state).toBe('locked');
    expect(() => session.getKey()).toThrowError(AppError);

    await session.unlock(MASTER, USER, meta);
    expect(session.state).toBe('unlocked');
    const keyBefore = session.getKey();

    // A failed attempt on an already unlocked session must keep the current key.
    await expectAppErrorAsync(session.unlock('wrong password', USER, meta), 'WRONG_PASSWORD');
    expect(session.state).toBe('unlocked');
    expect(session.getKey()).toBe(keyBefore);
  });

  // Case 4: auto-lock countdown, restart on touch, disabled with 0 minutes.
  it('auto-locks after one minute of inactivity and restarts the countdown on touch', async () => {
    const clock = createFakeClock();
    const session = new VaultSession(clock.timers);
    const states: string[] = [];
    session.subscribe((s) => states.push(s));

    await session.create(MASTER, USER, ITERATIONS);
    expect(states).toEqual(['unlocked']);

    session.setAutoLockMinutes(1);
    expect(clock.pending).toBe(1);

    clock.advance(59_000);
    expect(session.state).toBe('unlocked');

    // Activity at second 59 restarts the countdown.
    session.touch();
    clock.advance(59_000);
    expect(session.state).toBe('unlocked');

    clock.advance(1_000);
    expect(session.state).toBe('locked');
    expect(states).toEqual(['unlocked', 'locked']);
  });

  // Case 4 (same behaviour, vitest fake timers instead of the injected clock).
  it('auto-locks with vitest fake timers', async () => {
    const session = new VaultSession();
    // The key derivation runs before the clock is faked, so the WebCrypto promises resolve normally.
    await session.create(MASTER, USER, ITERATIONS);

    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      session.setAutoLockMinutes(1);
      vi.advanceTimersByTime(59_000);
      expect(session.state).toBe('unlocked');

      vi.advanceTimersByTime(1_000);
      expect(session.state).toBe('locked');
    } finally {
      vi.useRealTimers();
    }
  });

  // Case 4: 0 minutes (and negative values) disable the auto-lock.
  it('never auto-locks when the auto-lock is disabled', async () => {
    const clock = createFakeClock();
    const session = new VaultSession(clock.timers);
    await session.create(MASTER, USER, ITERATIONS);

    session.setAutoLockMinutes(0);
    expect(clock.pending).toBe(0);
    clock.advance(6 * 60 * 60 * 1000);
    expect(session.state).toBe('unlocked');

    session.setAutoLockMinutes(-5);
    expect(clock.pending).toBe(0);
    clock.advance(6 * 60 * 60 * 1000);
    expect(session.state).toBe('unlocked');
  });

  // Case 5: after a lock the same password unlocks again and the old data is still readable.
  it('unlocks again after a lock and decrypts the data sealed before the lock', async () => {
    const clock = createFakeClock();
    const session = new VaultSession(clock.timers);
    const meta = await session.create(MASTER, USER, ITERATIONS);
    const firstKey = session.getKey();

    const secret = 'S3cret-Passw0rd!';
    const sealed = await encryptCredential(firstKey, USER, CRED_ID, {
      name: 'GitHub',
      url: 'https://github.com',
      username: 'octocat',
      password: secret,
      note: 'work',
    });

    session.lock();
    expect(session.state).toBe('locked');
    expect(() => session.getKey()).toThrowError(AppError);

    await session.unlock(MASTER, USER, meta);
    expect(session.state).toBe('unlocked');
    const secondKey = session.getKey();
    // The key is derived again, so it is a different (but equivalent) CryptoKey object.
    expect(secondKey).not.toBe(firstKey);

    const row: CredentialRow = {
      id: CRED_ID,
      user_id: USER,
      ciphertext: sealed.ciphertext,
      iv: sealed.iv,
      encryption_version: sealed.encryption_version,
      revision: 3,
      created_at: ISO,
      updated_at: ISO,
    };
    const restored = await decryptCredential(secondKey, USER, row);

    expect(restored.password).toBe(secret);
    expect(restored.username).toBe('octocat');
    expect(restored.name).toBe('GitHub');
    expect(restored.revision).toBe(3);
  });
});

/* -------------------------------------------------------------------------- */
/* AuthService                                                                */
/* -------------------------------------------------------------------------- */

describe('AuthService', () => {
  // Case 6: successful sign-in, wrong credentials, network failure, server failure.
  it('signs in and returns the user id and email', async () => {
    const api = new FakeAuthApi();
    api.signInResult = { data: { session: SESSION }, error: null };
    const service = new AuthService(api);

    const user = await service.signIn(`  ${EMAIL}  `, PASSWORD);

    expect(user).toEqual({ id: USER, email: EMAIL });
    expect(api.signInCalls).toHaveLength(1);
    expect(api.signInCalls[0]).toEqual({ email: EMAIL, password: PASSWORD });
  });

  it('maps wrong credentials to a generic AUTH error that never echoes the password', async () => {
    const api = new FakeAuthApi();
    api.signInResult = {
      data: { session: null },
      error: { message: 'Invalid login credentials', status: 400 },
    };
    const service = new AuthService(api);

    const error = await expectAppErrorAsync(service.signIn(EMAIL, PASSWORD), 'AUTH');

    expect(error.message).not.toContain(PASSWORD);
    expect(error.message).not.toContain('Invalid login credentials');
    expect(error.message.toLowerCase()).not.toContain('invalid login');
  });

  it('maps a "Failed to fetch" error to NETWORK and a 503 to SERVER', async () => {
    const api = new FakeAuthApi();
    const service = new AuthService(api);

    api.signInResult = { data: { session: null }, error: { message: 'Failed to fetch' } };
    const network = await expectAppErrorAsync(service.signIn(EMAIL, PASSWORD), 'NETWORK');
    expect(network.message).not.toContain('Failed to fetch');

    api.signInResult = {
      data: { session: null },
      error: { message: 'Service unavailable', status: 503 },
    };
    const server = await expectAppErrorAsync(service.signIn(EMAIL, PASSWORD), 'SERVER');
    expect(server.message).not.toContain('Service unavailable');
  });

  // Case 7: empty credentials are rejected before the API is called.
  it('rejects empty credentials without calling the API', async () => {
    const api = new FakeAuthApi();
    const service = new AuthService(api);

    await expectAppErrorAsync(service.signIn('', PASSWORD), 'VALIDATION');
    await expectAppErrorAsync(service.signIn('   ', PASSWORD), 'VALIDATION');
    await expectAppErrorAsync(service.signIn(EMAIL, ''), 'VALIDATION');

    expect(api.signInCalls).toHaveLength(0);
  });

  // Case 8: sign-up without a session (email confirmation pending) and short passwords.
  it('returns null when the sign-up needs an email confirmation', async () => {
    const api = new FakeAuthApi();
    api.signUpResult = { data: { session: null, user: { id: USER, email: EMAIL } }, error: null };
    const service = new AuthService(api);

    const user = await service.signUp(EMAIL, PASSWORD);

    expect(user).toBeNull();
    expect(api.signUpCalls).toHaveLength(1);
    expect(api.signUpCalls[0]).toEqual({ email: EMAIL, password: PASSWORD });
  });

  it('rejects a sign-up with a password shorter than 8 characters', async () => {
    const api = new FakeAuthApi();
    const service = new AuthService(api);

    await expectAppErrorAsync(service.signUp(EMAIL, 'short'), 'VALIDATION');
    await expectAppErrorAsync(service.signUp('', 'longenough'), 'VALIDATION');

    expect(api.signUpCalls).toHaveLength(0);
  });

  // Case 9: sign-out uses the local scope and never propagates an API failure.
  it('signs out with the local scope and never throws', async () => {
    const api = new FakeAuthApi();
    const service = new AuthService(api);

    await service.signOut();

    expect(api.signOutCalls).toEqual([{ scope: 'local' }]);

    api.signOutThrows = new Error('network down');
    await expect(service.signOut()).resolves.toBeUndefined();
    expect(api.signOutCalls).toHaveLength(2);
  });

  // Case 10: current user resolution.
  it('returns the current user or null when there is no usable session', async () => {
    const api = new FakeAuthApi();
    const service = new AuthService(api);

    api.getSessionResult = { data: { session: SESSION }, error: null };
    await expect(service.currentUser()).resolves.toEqual({ id: USER, email: EMAIL });

    api.getSessionResult = { data: { session: null }, error: null };
    await expect(service.currentUser()).resolves.toBeNull();

    api.getSessionResult = { data: { session: null }, error: { message: 'no session' } };
    await expect(service.currentUser()).resolves.toBeNull();

    api.getSessionThrows = new Error('boom');
    await expect(service.currentUser()).resolves.toBeNull();
  });

  // Case 10: session-ended notifications and unsubscribe.
  it('notifies when the session ends and stops after unsubscribing', () => {
    const api = new FakeAuthApi();
    const service = new AuthService(api);
    let ended = 0;
    const unsubscribe = service.onSessionEnded(() => {
      ended += 1;
    });

    api.emit('SIGNED_OUT', SESSION);
    expect(ended).toBe(1);

    // A missing session always ends the session.
    api.emit('TOKEN_REFRESHED', null);
    expect(ended).toBe(2);

    // A valid session with a refreshed token does not end the session.
    api.emit('TOKEN_REFRESHED', SESSION);
    expect(ended).toBe(2);

    api.emit('SIGNED_OUT', null);
    expect(ended).toBe(3);

    unsubscribe();
    expect(api.unsubscribed).toBe(true);

    api.emit('SIGNED_OUT', null);
    expect(ended).toBe(3);
  });
});

/* -------------------------------------------------------------------------- */
/* mapSupabaseError                                                           */
/* -------------------------------------------------------------------------- */

describe('mapSupabaseError', () => {
  const SENTINEL = 'secret-payload';

  // Case 11: status/code mapping.
  it('maps auth, network, server and validation failures to safe codes', () => {
    expect(mapSupabaseError({ status: 401, message: SENTINEL }).code).toBe('AUTH');
    expect(mapSupabaseError({ status: 403, message: SENTINEL }).code).toBe('AUTH');
    expect(mapSupabaseError({ message: `Invalid JWT: ${SENTINEL}` }).code).toBe('AUTH');
    expect(mapSupabaseError({ message: 'Failed to fetch' }).code).toBe('NETWORK');
    expect(mapSupabaseError({ status: 500, message: SENTINEL }).code).toBe('SERVER');
    expect(mapSupabaseError({ status: 503, message: SENTINEL }).code).toBe('SERVER');
    expect(mapSupabaseError({ code: '42501', message: SENTINEL }).code).toBe('AUTH');
    expect(mapSupabaseError({ code: '23514', message: SENTINEL }).code).toBe('VALIDATION');
    expect(mapSupabaseError({ code: '23505', message: SENTINEL }).code).toBe('CONFLICT');
  });

  // Case 11: the original message is never echoed back to the user.
  it('never includes the original error message', () => {
    const rawErrors: unknown[] = [
      { status: 401, message: SENTINEL },
      { message: `JWT ${SENTINEL}` },
      { message: `Failed to fetch ${SENTINEL}` },
      { status: 500, message: SENTINEL },
      { code: '42501', message: SENTINEL },
      { code: '23514', message: SENTINEL },
      { code: '23505', message: SENTINEL },
      { message: SENTINEL },
    ];

    for (const raw of rawErrors) {
      const mapped = mapSupabaseError(raw);
      expect(mapped).toBeInstanceOf(AppError);
      expect(mapped.message).not.toContain(SENTINEL);
      expect(mapped.message.length).toBeGreaterThan(0);
    }
  });
});

/* -------------------------------------------------------------------------- */
/* withRetry                                                                  */
/* -------------------------------------------------------------------------- */

describe('withRetry', () => {
  // Case 12: transient failures are retried with an exponential backoff.
  it('retries transient failures with an exponential backoff', async () => {
    const sleeps: number[] = [];
    let calls = 0;

    const result = await withRetry(
      async () => {
        calls += 1;
        if (calls < 3) throw new AppError('NETWORK', 'Network unavailable.');
        return 'ok';
      },
      {
        attempts: 4,
        baseDelayMs: 10,
        sleep: async (ms: number) => {
          sleeps.push(ms);
        },
      },
    );

    expect(result).toBe('ok');
    expect(calls).toBe(3);
    expect(sleeps).toEqual([10, 20]);
  });

  // Case 12: the retry loop stops after the configured number of attempts.
  it('gives up after the configured number of attempts', async () => {
    const sleeps: number[] = [];
    let calls = 0;

    const error = await expectAppErrorAsync(
      withRetry(
        async () => {
          calls += 1;
          throw new AppError('SERVER', 'Server unavailable.');
        },
        {
          attempts: 3,
          baseDelayMs: 10,
          sleep: async (ms: number) => {
            sleeps.push(ms);
          },
        },
      ),
      'SERVER',
    );

    expect(error.message).toBe('Server unavailable.');
    expect(calls).toBe(3);
    expect(sleeps).toEqual([10, 20]);
  });

  // Case 12: permanent failures are not retried.
  it('does not retry authentication, validation or conflict errors', async () => {
    const codes: ErrorCode[] = ['AUTH', 'VALIDATION', 'CONFLICT'];

    for (const code of codes) {
      const sleeps: number[] = [];
      let calls = 0;

      await expectAppErrorAsync(
        withRetry(
          async () => {
            calls += 1;
            throw new AppError(code, 'Permanent failure.');
          },
          {
            attempts: 5,
            baseDelayMs: 10,
            sleep: async (ms: number) => {
              sleeps.push(ms);
            },
          },
        ),
        code,
      );

      expect(calls).toBe(1);
      expect(sleeps).toEqual([]);
    }
  });
});

/* -------------------------------------------------------------------------- */
/* settings                                                                   */
/* -------------------------------------------------------------------------- */

describe('settings', () => {
  // Case 13: defaults, round-trip and invalid values.
  // The store lives in memory (no chrome.storage outside the extension) and the tests below
  // run in declaration order, so the default is read before anything is saved.
  it('defaults to five minutes of auto-lock', async () => {
    expect(DEFAULT_SETTINGS.autoLockMinutes).toBe(5);
    await expect(loadSettings()).resolves.toEqual({ autoLockMinutes: 5 });
  });

  it('saves and loads the settings back', async () => {
    await saveSettings({ autoLockMinutes: 15 });
    await expect(loadSettings()).resolves.toEqual({ autoLockMinutes: 15 });
  });

  it('falls back to the default for invalid values', async () => {
    await saveSettings({ autoLockMinutes: -1 });
    await expect(loadSettings()).resolves.toEqual({ autoLockMinutes: 5 });

    const invalid: VaultSettings = { autoLockMinutes: 'not-a-number' } as unknown as VaultSettings;
    await saveSettings(invalid);
    await expect(loadSettings()).resolves.toEqual({ autoLockMinutes: 5 });
  });
});

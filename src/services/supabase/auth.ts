import { AppError } from '@/utils/errors';
import { mapSupabaseError } from './errors';

export interface AuthUser {
  id: string;
  email: string;
}

interface SessionLike {
  user: { id: string; email?: string | null };
}
interface AuthResult {
  data: { session?: SessionLike | null; user?: { id: string; email?: string | null } | null };
  error: { message?: string; status?: number; code?: string } | null;
}

/** Subset of supabase.auth used by the app (lets tests inject a fake). */
export interface AuthApi {
  signInWithPassword(c: { email: string; password: string }): Promise<AuthResult>;
  signUp(c: { email: string; password: string }): Promise<AuthResult>;
  signOut(o?: { scope?: 'local' | 'global' | 'others' }): Promise<{ error: { message?: string } | null }>;
  getSession(): Promise<{ data: { session: SessionLike | null }; error: { message?: string } | null }>;
  onAuthStateChange(cb: (event: string, session: SessionLike | null) => void): {
    data: { subscription: { unsubscribe(): void } };
  };
}

function toUser(s: SessionLike | null | undefined): AuthUser | null {
  return s ? { id: s.user.id, email: s.user.email ?? '' } : null;
}

export class AuthService {
  constructor(private readonly auth: AuthApi) {}

  async signIn(email: string, password: string): Promise<AuthUser> {
    if (!email.trim() || !password) throw new AppError('VALIDATION', 'Enter email and password.');
    let res: AuthResult;
    try {
      res = await this.auth.signInWithPassword({ email: email.trim(), password });
    } catch (e) {
      throw mapSupabaseError(e);
    }
    if (res.error) {
      if (res.error.status && res.error.status >= 500) throw mapSupabaseError(res.error);
      if (/fetch|network/i.test(res.error.message ?? '')) throw mapSupabaseError(res.error);
      throw new AppError('AUTH', 'Invalid email or password, or email not confirmed.');
    }
    const user = toUser(res.data.session);
    if (!user) throw new AppError('AUTH', 'Sign-in failed. Please try again.');
    return user;
  }

  /** Returns the user, or null when the project requires email confirmation first. */
  async signUp(email: string, password: string): Promise<AuthUser | null> {
    if (!email.trim() || password.length < 8) {
      throw new AppError('VALIDATION', 'Enter an email and an account password of at least 8 characters.');
    }
    let res: AuthResult;
    try {
      res = await this.auth.signUp({ email: email.trim(), password });
    } catch (e) {
      throw mapSupabaseError(e);
    }
    if (res.error) {
      if (/fetch|network/i.test(res.error.message ?? '') || (res.error.status ?? 0) >= 500) {
        throw mapSupabaseError(res.error);
      }
      throw new AppError('AUTH', 'Unable to create the account. The email may already be registered.');
    }
    return toUser(res.data.session);
  }

  async signOut(): Promise<void> {
    // Local scope: ends this browser's session; failures must not keep the user "signed in".
    try {
      await this.auth.signOut({ scope: 'local' });
    } catch {
      /* the local session is cleared by the client regardless */
    }
  }

  async currentUser(): Promise<AuthUser | null> {
    try {
      const { data, error } = await this.auth.getSession();
      if (error) return null;
      return toUser(data.session);
    } catch {
      return null;
    }
  }

  /** Notifies when the session ends (sign-out or failed refresh). Returns an unsubscribe fn. */
  onSessionEnded(cb: () => void): () => void {
    const { data } = this.auth.onAuthStateChange((event, session) => {
      if (event === 'SIGNED_OUT' || !session) cb();
    });
    return () => data.subscription.unsubscribe();
  }
}

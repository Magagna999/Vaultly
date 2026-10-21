import { AppError } from '@/utils/errors';

interface PostgrestLikeError {
  message?: string;
  code?: string;
  status?: number;
}

/** Maps Supabase/network failures into safe, user-facing AppErrors (no payload echo). */
export function mapSupabaseError(e: unknown, fallback = 'Server request failed.'): AppError {
  if (e instanceof AppError) return e;
  const err = (e ?? {}) as PostgrestLikeError;
  const msg = (err.message ?? '').toLowerCase();
  const status = err.status;
  if (
    msg.includes('failed to fetch') ||
    msg.includes('networkerror') ||
    msg.includes('network request failed') ||
    msg.includes('load failed') ||
    (e instanceof TypeError && msg.includes('fetch'))
  ) {
    return new AppError('NETWORK', 'Network error: unable to reach the server. Check your connection.');
  }
  if (status === 401 || status === 403 || msg.includes('jwt') || err.code === 'PGRST301') {
    return new AppError('AUTH', 'Your session is invalid or expired. Please sign in again.');
  }
  if (err.code === '42501') {
    return new AppError('AUTH', 'Access denied by the server security policy.');
  }
  if (err.code === '23505') {
    return new AppError('CONFLICT', 'This record already exists on the server.');
  }
  if (err.code === '23514' || err.code === '22P02') {
    return new AppError('VALIDATION', 'The server rejected the data as invalid.');
  }
  if (typeof status === 'number' && status >= 500) {
    return new AppError('SERVER', 'The server is temporarily unavailable. Try again later.');
  }
  return new AppError('SERVER', fallback);
}

import type { CredentialData } from '@/types';
import { AppError } from './errors';

export const LIMITS = {
  name: 200,
  url: 2048,
  username: 320,
  password: 1024,
  note: 10_000,
} as const;

export const MIN_MASTER_PASSWORD_LENGTH = 12;

/** Validates user-entered credential data. Returns a list of field errors. */
export function validateCredentialData(d: CredentialData): string[] {
  const errors: string[] = [];
  if (!d.name.trim() && !d.url.trim()) errors.push('Enter a site name or a URL.');
  if (!d.password) errors.push('Password is required.');
  (Object.keys(LIMITS) as (keyof typeof LIMITS)[]).forEach((k) => {
    if (d[k].length > LIMITS[k]) errors.push(`${k} is too long (max ${LIMITS[k]} characters).`);
  });
  if (
    d.url.trim() &&
    !/^[a-z][a-z0-9+.-]*:\/\//i.test(d.url.trim()) &&
    !/^[^\s/]+\.[^\s/]+/.test(d.url.trim())
  ) {
    errors.push('URL looks invalid.');
  }
  return errors;
}

export function assertValidCredentialData(d: CredentialData): void {
  const errors = validateCredentialData(d);
  if (errors.length) throw new AppError('VALIDATION', errors[0] ?? 'Invalid data.');
}

export function validateMasterPassword(pw: string): string | null {
  if (pw.length < MIN_MASTER_PASSWORD_LENGTH) {
    return `The master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters.`;
  }
  return null;
}

/** Extracts a normalized hostname from a URL or bare domain; '' if not parsable. */
export function hostnameOf(url: string): string {
  const raw = url.trim();
  if (!raw) return '';
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
    return new URL(withScheme).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}

export function emptyCredentialData(): CredentialData {
  return { name: '', url: '', username: '', password: '', note: '' };
}

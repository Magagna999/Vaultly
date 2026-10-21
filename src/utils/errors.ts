export type ErrorCode =
  | 'NETWORK'
  | 'AUTH'
  | 'CONFLICT'
  | 'VALIDATION'
  | 'CRYPTO'
  | 'WRONG_PASSWORD'
  | 'VAULT_LOCKED'
  | 'NOT_FOUND'
  | 'IMPORT'
  | 'SERVER';

/**
 * Application error. Messages are user-facing and must NEVER contain secrets
 * (passwords, keys, tokens, file contents).
 */
export class AppError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = 'AppError';
    this.code = code;
  }
}

export function isAppError(e: unknown, code?: ErrorCode): e is AppError {
  return e instanceof AppError && (code === undefined || e.code === code);
}

/** Converts any thrown value into a safe, user-facing message. */
export function userMessage(e: unknown): string {
  if (e instanceof AppError) return e.message;
  return 'Unexpected error. Please try again.';
}

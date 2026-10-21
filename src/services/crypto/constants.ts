/** Current version of the cryptographic format stored with every ciphertext. */
export const ENCRYPTION_VERSION = 1;
export const KDF_NAME = 'PBKDF2-SHA256' as const;
export const IV_BYTES = 12; // 96-bit nonce, recommended for AES-GCM
export const SALT_BYTES = 16;
/** OWASP (2023) recommendation for PBKDF2-HMAC-SHA256. */
export const DEFAULT_KDF_ITERATIONS = 600_000;
export const MIN_KDF_ITERATIONS = 100_000;
export const MAX_KDF_ITERATIONS = 10_000_000;

/**
 * Client-side authenticated encryption built exclusively on the standard Web Crypto API.
 *
 * Format v1:
 *  - key:  AES-256-GCM, derived with PBKDF2-HMAC-SHA256 from the master password
 *          (NFKC-normalized) and a random per-vault salt. The CryptoKey is created
 *          non-extractable, so page scripts cannot export the raw key bytes.
 *  - data: JSON, UTF-8 encoded, encrypted with a fresh random 96-bit IV per operation.
 *  - AAD:  "cpv:<version>:<userId>:<recordId>" binds a ciphertext to its owner and row,
 *          so a server cannot swap ciphertexts between rows/users without detection.
 *  - Decryption failure (wrong key, modified ciphertext/IV/AAD) always yields a generic
 *    CRYPTO error and never partial plaintext (GCM verifies the tag before releasing data).
 */
import { AppError } from '@/utils/errors';
import { base64ToBytes, bytesToBase64, type Bytes } from '@/utils/base64';
import {
  ENCRYPTION_VERSION,
  IV_BYTES,
  MAX_KDF_ITERATIONS,
  MIN_KDF_ITERATIONS,
  SALT_BYTES,
} from './constants';

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

export function randomBytes(n: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function generateSalt(): Bytes {
  return randomBytes(SALT_BYTES);
}

export function buildAad(version: number, userId: string, recordId: string): Bytes {
  return enc.encode(`cpv:${version}:${userId}:${recordId}`);
}

export function assertIterations(iterations: number): void {
  if (!Number.isInteger(iterations) || iterations < MIN_KDF_ITERATIONS || iterations > MAX_KDF_ITERATIONS) {
    throw new AppError(
      'VALIDATION',
      `KDF iterations must be between ${MIN_KDF_ITERATIONS} and ${MAX_KDF_ITERATIONS}.`,
    );
  }
}

/** Derives a non-extractable AES-256-GCM key from a password with PBKDF2-HMAC-SHA256. */
export async function deriveKey(password: string, salt: Bytes, iterations: number): Promise<CryptoKey> {
  assertIterations(iterations);
  if (salt.length < SALT_BYTES) throw new AppError('CRYPTO', 'Invalid vault parameters.');
  const material = await crypto.subtle.importKey(
    'raw',
    enc.encode(password.normalize('NFKC')),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export interface Sealed {
  ciphertext: string; // base64 (includes the 128-bit GCM tag)
  iv: string; // base64
}

export async function encryptBytes(key: CryptoKey, plaintext: Bytes, aad: Bytes): Promise<Sealed> {
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    plaintext,
  );
  return { ciphertext: bytesToBase64(new Uint8Array(ct)), iv: bytesToBase64(iv) };
}

export async function decryptBytes(key: CryptoKey, sealed: Sealed, aad: Bytes): Promise<Bytes> {
  try {
    const iv = base64ToBytes(sealed.iv);
    if (iv.length !== IV_BYTES) throw new Error('bad iv');
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      key,
      base64ToBytes(sealed.ciphertext),
    );
    return new Uint8Array(pt);
  } catch {
    throw new AppError('CRYPTO', 'Decryption failed: wrong key or corrupted data.');
  }
}

export async function encryptJson(key: CryptoKey, value: unknown, aad: Bytes): Promise<Sealed> {
  return encryptBytes(key, enc.encode(JSON.stringify(value)), aad);
}

export async function decryptJson<T>(key: CryptoKey, sealed: Sealed, aad: Bytes): Promise<T> {
  const bytes = await decryptBytes(key, sealed, aad);
  try {
    return JSON.parse(dec.decode(bytes)) as T;
  } catch {
    throw new AppError('CRYPTO', 'Decryption failed: wrong key or corrupted data.');
  }
}

export function assertSupportedVersion(version: number): void {
  if (version !== ENCRYPTION_VERSION) {
    throw new AppError('CRYPTO', `Unsupported encryption format version ${version}. Update the extension.`);
  }
}

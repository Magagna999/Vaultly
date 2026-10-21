/**
 * Encrypted backup format "cpv-backup" v1 (JSON file chosen/saved by the user):
 *
 *  { format, version, kdf: "PBKDF2-SHA256", iterations, salt, iv, ciphertext, createdAt, encryptionVersion }
 *
 * The key is derived from a BACKUP passphrase (not necessarily the master password) with
 * PBKDF2-HMAC-SHA256 and a fresh random salt; the payload { credentials: [...] } is sealed with
 * AES-256-GCM (AAD "cpv:backup:1"). Ids/revisions are not exported, so a backup can be restored
 * into any account. Losing the passphrase makes the backup unrecoverable.
 */
import type { Credential, CredentialData } from '@/types';
import { AppError } from '@/utils/errors';
import { base64ToBytes, bytesToBase64 } from '@/utils/base64';
import {
  decryptJson,
  deriveKey,
  encryptJson,
  generateSalt,
  assertIterations,
} from '@/services/crypto/cipher';
import { DEFAULT_KDF_ITERATIONS, ENCRYPTION_VERSION } from '@/services/crypto/constants';
import { MIN_MASTER_PASSWORD_LENGTH, validateCredentialData } from '@/utils/validation';

export const BACKUP_FORMAT = 'cpv-backup';
export const BACKUP_VERSION = 1;
const AAD = new TextEncoder().encode(`cpv:backup:${BACKUP_VERSION}`);

export interface BackupFile {
  format: typeof BACKUP_FORMAT;
  version: number;
  encryptionVersion: number;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
  createdAt: string;
}

interface BackupPayload {
  credentials: CredentialData[];
}

export async function createBackup(
  credentials: Credential[],
  passphrase: string,
  iterations: number = DEFAULT_KDF_ITERATIONS,
  now: Date = new Date(),
): Promise<string> {
  if (passphrase.length < MIN_MASTER_PASSWORD_LENGTH) {
    throw new AppError(
      'VALIDATION',
      `The backup passphrase must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters.`,
    );
  }
  assertIterations(iterations);
  const salt = generateSalt();
  const key = await deriveKey(passphrase, salt, iterations);
  const payload: BackupPayload = {
    credentials: credentials.map(({ name, url, username, password, note }) => ({
      name,
      url,
      username,
      password,
      note,
    })),
  };
  const sealed = await encryptJson(key, payload, AAD);
  const file: BackupFile = {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    encryptionVersion: ENCRYPTION_VERSION,
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: bytesToBase64(salt),
    iv: sealed.iv,
    ciphertext: sealed.ciphertext,
    createdAt: now.toISOString(),
  };
  return JSON.stringify(file, null, 2);
}

function parseBackupFile(text: string): BackupFile {
  let f: Partial<BackupFile>;
  try {
    f = JSON.parse(text) as Partial<BackupFile>;
  } catch {
    throw new AppError('IMPORT', 'This is not a valid backup file.');
  }
  if (f.format !== BACKUP_FORMAT) throw new AppError('IMPORT', 'This is not a Password Vault backup.');
  if (f.version !== BACKUP_VERSION || f.encryptionVersion !== ENCRYPTION_VERSION) {
    throw new AppError('IMPORT', 'Unsupported backup version.');
  }
  if (
    f.kdf !== 'PBKDF2-SHA256' ||
    typeof f.iterations !== 'number' ||
    typeof f.salt !== 'string' ||
    typeof f.iv !== 'string' ||
    typeof f.ciphertext !== 'string'
  ) {
    throw new AppError('IMPORT', 'The backup file is damaged.');
  }
  return f as BackupFile;
}

/** Decrypts and validates a backup. Wrong passphrase / tampering -> WRONG_PASSWORD, no partial data. */
export async function restoreBackup(text: string, passphrase: string): Promise<CredentialData[]> {
  const f = parseBackupFile(text);
  assertIterations(f.iterations);
  let payload: BackupPayload;
  try {
    const key = await deriveKey(passphrase, base64ToBytes(f.salt), f.iterations);
    payload = await decryptJson<BackupPayload>(key, { ciphertext: f.ciphertext, iv: f.iv }, AAD);
  } catch (e) {
    if (e instanceof AppError && e.code === 'VALIDATION') throw e;
    throw new AppError('WRONG_PASSWORD', 'Wrong passphrase, or the backup file is corrupted.');
  }
  if (!payload || !Array.isArray(payload.credentials)) {
    throw new AppError('IMPORT', 'The backup file is damaged.');
  }
  return payload.credentials.map((c) => {
    const d: CredentialData = {
      name: String(c.name ?? ''),
      url: String(c.url ?? ''),
      username: String(c.username ?? ''),
      password: String(c.password ?? ''),
      note: String(c.note ?? ''),
    };
    if (validateCredentialData(d).length)
      throw new AppError('IMPORT', 'The backup contains invalid records.');
    return d;
  });
}

export function backupFilename(now: Date = new Date()): string {
  return `password-vault-backup-${now.toISOString().slice(0, 10)}.cpvbackup.json`;
}

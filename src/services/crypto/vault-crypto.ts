import type { Credential, CredentialData, CredentialRow, EncryptedWrite, VaultMeta } from '@/types';
import { AppError } from '@/utils/errors';
import { base64ToBytes, bytesToBase64, type Bytes } from '@/utils/base64';
import {
  assertSupportedVersion,
  buildAad,
  decryptBytes,
  decryptJson,
  deriveKey,
  encryptBytes,
  encryptJson,
  generateSalt,
  assertIterations,
} from './cipher';
import { DEFAULT_KDF_ITERATIONS, ENCRYPTION_VERSION, KDF_NAME } from './constants';

/** Constant plaintext used to verify a master password without touching user data. */
const VERIFIER_PLAINTEXT = 'cpv-vault-verifier';
const VERIFIER_RECORD_ID = 'verifier';
const enc = new TextEncoder();
const dec = new TextDecoder();

/** Creates the public vault parameters and the unlock key for a new vault. */
export async function createVault(
  masterPassword: string,
  userId: string,
  iterations: number = DEFAULT_KDF_ITERATIONS,
): Promise<{ meta: VaultMeta; key: CryptoKey }> {
  assertIterations(iterations);
  const salt = generateSalt();
  const key = await deriveKey(masterPassword, salt, iterations);
  const sealed = await encryptBytes(
    key,
    enc.encode(VERIFIER_PLAINTEXT),
    buildAad(ENCRYPTION_VERSION, userId, VERIFIER_RECORD_ID),
  );
  const meta: VaultMeta = {
    kdf: KDF_NAME,
    kdfIterations: iterations,
    salt: bytesToBase64(salt),
    verifierCiphertext: sealed.ciphertext,
    verifierIv: sealed.iv,
    encryptionVersion: ENCRYPTION_VERSION,
  };
  return { meta, key };
}

/** Derives the key from the password and checks it against the stored verifier. */
export async function unlockVault(
  masterPassword: string,
  userId: string,
  meta: VaultMeta,
): Promise<CryptoKey> {
  assertSupportedVersion(meta.encryptionVersion);
  if (meta.kdf !== KDF_NAME) throw new AppError('CRYPTO', 'Unsupported key derivation function.');
  let salt: Bytes;
  try {
    salt = base64ToBytes(meta.salt);
  } catch {
    throw new AppError('CRYPTO', 'Invalid vault parameters.');
  }
  const key = await deriveKey(masterPassword, salt, meta.kdfIterations);
  try {
    const pt = await decryptBytes(
      key,
      { ciphertext: meta.verifierCiphertext, iv: meta.verifierIv },
      buildAad(meta.encryptionVersion, userId, VERIFIER_RECORD_ID),
    );
    if (dec.decode(pt) !== VERIFIER_PLAINTEXT) throw new Error('mismatch');
  } catch {
    throw new AppError('WRONG_PASSWORD', 'Wrong master password.');
  }
  return key;
}

const FIELDS: (keyof CredentialData)[] = ['name', 'url', 'username', 'password', 'note'];

export function pickData(d: CredentialData): CredentialData {
  return { name: d.name, url: d.url, username: d.username, password: d.password, note: d.note };
}

/** Encrypts every sensitive field of a credential into one AES-GCM blob. */
export async function encryptCredential(
  key: CryptoKey,
  userId: string,
  id: string,
  data: CredentialData,
): Promise<EncryptedWrite> {
  const sealed = await encryptJson(key, pickData(data), buildAad(ENCRYPTION_VERSION, userId, id));
  return { id, ciphertext: sealed.ciphertext, iv: sealed.iv, encryption_version: ENCRYPTION_VERSION };
}

export async function decryptCredential(
  key: CryptoKey,
  userId: string,
  row: CredentialRow,
): Promise<Credential> {
  assertSupportedVersion(row.encryption_version);
  const raw = await decryptJson<Partial<CredentialData>>(
    key,
    { ciphertext: row.ciphertext, iv: row.iv },
    buildAad(row.encryption_version, userId, row.id),
  );
  const data = {} as CredentialData;
  for (const f of FIELDS) data[f] = typeof raw[f] === 'string' ? (raw[f] as string) : '';
  return {
    ...data,
    id: row.id,
    revision: row.revision,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

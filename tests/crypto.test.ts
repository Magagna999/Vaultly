/**
 * Tests for the client-side cryptographic layer (`src/services/crypto/`).
 *
 * Every test uses the minimum allowed PBKDF2 iteration count (100_000) to
 * keep the suite fast. No secret is ever logged or asserted in clear text:
 * the checks below only look for the *absence* of plaintext.
 */
import { describe, expect, it } from 'vitest';
import type { CredentialData, CredentialRow, EncryptedWrite } from '@/types';
import {
  ENCRYPTION_VERSION,
  buildAad,
  createVault,
  decryptBytes,
  decryptCredential,
  decryptJson,
  deriveKey,
  encryptCredential,
  encryptJson,
  generateSalt,
  unlockVault,
} from '@/services/crypto';
import { AppError } from '@/utils/errors';

const ITERATIONS = 100_000;
const MIN_ITERATIONS = 100_000;
const USER_A = 'user-a';
const USER_B = 'user-b';
const ISO = '2024-01-01T00:00:00.000Z';

/**
 * Master password. The '-', '!' and digits are not part of the base64
 * alphabet, so the password can never show up inside an encoded payload.
 */
const MASTER = 'M4ster-Passw0rd!-a1b2';
/** Sentinel plaintext used to prove that it never leaks into ciphertexts. */
const SENTINEL = 'pl4intext-S3cret-Ω-9f2a';
const USERNAME = 'user-name-Ω-42';
const PASSWORD = 'S3cret!Pass-9f2a';
const INVALID_ITERATIONS = [0, 1_000, MIN_ITERATIONS - 1, 10_000_001, 100_000.5];

function credentialData(overrides: Partial<CredentialData> = {}): CredentialData {
  return {
    name: 'Example Site',
    url: 'https://example.com',
    username: 'alice@example.com',
    password: PASSWORD,
    note: '',
    ...overrides,
  };
}

function toRow(write: EncryptedWrite, userId: string): CredentialRow {
  return {
    id: write.id,
    user_id: userId,
    ciphertext: write.ciphertext,
    iv: write.iv,
    encryption_version: write.encryption_version,
    revision: 1,
    created_at: ISO,
    updated_at: ISO,
  };
}

/** Runs `fn` and returns the thrown AppError, failing when nothing is thrown. */
async function captureError(fn: () => Promise<unknown>): Promise<AppError> {
  try {
    await fn();
  } catch (e) {
    expect(e).toBeInstanceOf(AppError);
    return e as AppError;
  }
  throw new Error('Expected an AppError to be thrown');
}

describe('encryptJson / decryptJson round trip', () => {
  // Case 1: Unicode, emoji and empty strings survive the round trip untouched.
  it('round-trips Unicode, emoji, CJK, RTL text and empty strings', async () => {
    const key = await deriveKey(MASTER, generateSalt(), ITERATIONS);
    const aad = buildAad(ENCRYPTION_VERSION, USER_A, 'rec-unicode');
    const payload = {
      emoji: '🔐🚀🧊',
      accented: 'Café déjà vu — naïve',
      chinese: '密码管理器',
      arabic: 'مرحبا بالعالم',
      empty: '',
      emptyObject: {},
      emptyArray: [],
      nested: { list: [1, 'two', { deep: '' }] },
      count: 42,
      enabled: true,
      missing: null,
    };

    const sealed = await encryptJson(key, payload, aad);

    expect(sealed.ciphertext).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(sealed.iv).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(sealed.ciphertext).not.toContain(SENTINEL);

    const restored = await decryptJson<typeof payload>(key, sealed, aad);
    expect(restored).toEqual(payload);
    expect(restored.empty).toBe('');
    expect(restored.emoji).toBe('🔐🚀🧊');
    expect(restored.chinese).toBe('密码管理器');
  });
});

describe('vault creation and unlocking', () => {
  // Case 2: a wrong password is rejected with WRONG_PASSWORD, the right one works.
  it('rejects a wrong master password with WRONG_PASSWORD', async () => {
    const { meta, key } = await createVault(MASTER, USER_A, ITERATIONS);

    const wrong = await captureError(() =>
      unlockVault('totally-wrong-password', USER_A, meta),
    );
    expect(wrong.code).toBe('WRONG_PASSWORD');
    expect(wrong.message).not.toContain(MASTER);

    // The right password returns a key that decrypts a record encrypted
    // with the key returned by createVault.
    const unlocked = await unlockVault(MASTER, USER_A, meta);
    expect(unlocked.algorithm.name).toBe('AES-GCM');
    expect(unlocked.extractable).toBe(false);

    const write = await encryptCredential(key, USER_A, 'rec-unlock', credentialData());
    const credential = await decryptCredential(unlocked, USER_A, toRow(write, USER_A));
    expect(credential.id).toBe('rec-unlock');
    expect(credential.password).toBe(PASSWORD);
  });

  // Case 3: a key derived from another password cannot decrypt, the error leaks nothing.
  it('fails with CRYPTO for a key derived from a different password', async () => {
    const salt = generateSalt();
    const keyA = await deriveKey('password-alpha', salt, ITERATIONS);
    const keyB = await deriveKey('password-beta', salt, ITERATIONS);
    const aad = buildAad(ENCRYPTION_VERSION, USER_A, 'rec-wrong-key');
    const sealed = await encryptJson(keyA, { secret: SENTINEL }, aad);

    const error = await captureError(() => decryptJson(keyB, sealed, aad));
    expect(error.code).toBe('CRYPTO');
    expect(error.message).not.toContain(SENTINEL);
    expect(error.message).not.toContain('password-alpha');
    expect(error.message).not.toContain('password-beta');
  });
});

describe('tamper detection', () => {
  // Case 4: modified ciphertext, modified IV and truncated ciphertext all fail.
  it('rejects a modified ciphertext, a modified IV and a truncated one', async () => {
    const key = await deriveKey(MASTER, generateSalt(), ITERATIONS);
    const aad = buildAad(ENCRYPTION_VERSION, USER_A, 'rec-tamper');
    const sealed = await encryptJson(key, { secret: SENTINEL }, aad);

    // One single byte of the ciphertext is flipped.
    const ct = Buffer.from(sealed.ciphertext, 'base64');
    expect(ct.length).toBeGreaterThan(16);
    ct[0] = (ct[0] ?? 0) ^ 0xff;
    const modifiedCt = await captureError(() =>
      decryptJson(key, { ciphertext: ct.toString('base64'), iv: sealed.iv }, aad),
    );
    expect(modifiedCt.code).toBe('CRYPTO');
    expect(modifiedCt.message).not.toContain(SENTINEL);

    // One single byte of the IV is flipped (the length stays valid).
    const iv = Buffer.from(sealed.iv, 'base64');
    expect(iv.length).toBe(12);
    iv[0] = (iv[0] ?? 0) ^ 0xff;
    const modifiedIv = await captureError(() =>
      decryptJson(key, { ciphertext: sealed.ciphertext, iv: iv.toString('base64') }, aad),
    );
    expect(modifiedIv.code).toBe('CRYPTO');

    // The ciphertext is truncated.
    const truncated = Buffer.from(sealed.ciphertext, 'base64').subarray(0, 20);
    const truncatedError = await captureError(() =>
      decryptJson(key, { ciphertext: truncated.toString('base64'), iv: sealed.iv }, aad),
    );
    expect(truncatedError.code).toBe('CRYPTO');

    // A ciphertext that is not valid base64 must not leak a raw error either.
    const invalidBase64 = await captureError(() =>
      decryptJson(key, { ciphertext: 'not base64!!', iv: sealed.iv }, aad),
    );
    expect(invalidBase64.code).toBe('CRYPTO');
  });

  // Case 5: the AAD binds a ciphertext to its row and to its owner.
  it('binds a ciphertext to its record id and to its user through the AAD', async () => {
    const keyA = await deriveKey(MASTER, generateSalt(), ITERATIONS);
    const keyB = await deriveKey(MASTER, generateSalt(), ITERATIONS);
    const write = await encryptCredential(keyA, USER_A, 'rec-a', credentialData());
    const row = toRow(write, USER_A);

    const original = await decryptCredential(keyA, USER_A, row);
    expect(original.id).toBe('rec-a');

    // Same ciphertext, different record id.
    const otherRecord = await captureError(() =>
      decryptCredential(keyA, USER_A, { ...row, id: 'rec-b' }),
    );
    expect(otherRecord.code).toBe('CRYPTO');

    // Same ciphertext, different user.
    const otherUser = await captureError(() =>
      decryptCredential(keyA, USER_B, row),
    );
    expect(otherUser.code).toBe('CRYPTO');

    // The ciphertext of another record is swapped into this row.
    const other = await encryptCredential(
      keyA,
      USER_A,
      'rec-b',
      credentialData({ password: 'other-secret' }),
    );
    const swapped = await captureError(() =>
      decryptCredential(keyA, USER_A, {
        ...row,
        ciphertext: other.ciphertext,
        iv: other.iv,
      }),
    );
    expect(swapped.code).toBe('CRYPTO');

    // A key from another vault cannot read the row either.
    const otherKey = await captureError(() =>
      decryptCredential(keyB, USER_A, row),
    );
    expect(otherKey.code).toBe('CRYPTO');
  });
});

describe('nonce handling', () => {
  // Case 6: every encryption uses a fresh 96-bit IV.
  it('uses a distinct 12-byte IV and a distinct ciphertext for 500 encryptions', async () => {
    const key = await deriveKey(MASTER, generateSalt(), ITERATIONS);
    const aad = buildAad(ENCRYPTION_VERSION, USER_A, 'rec-iv');
    const ivs: string[] = [];
    const ciphertexts: string[] = [];

    for (let i = 0; i < 500; i++) {
      const sealed = await encryptJson(key, { i }, aad);
      ivs.push(sealed.iv);
      ciphertexts.push(sealed.ciphertext);
    }

    expect(ivs).toHaveLength(500);
    expect(new Set(ivs).size).toBe(500);
    expect(new Set(ciphertexts).size).toBe(500);
    for (const iv of ivs) {
      expect(Buffer.from(iv, 'base64').length).toBe(12);
    }

    // The first and the last ciphertext still decrypt to their own payload.
    const first = await decryptJson<{ i: number }>(
      key,
      { ciphertext: ciphertexts[0] ?? '', iv: ivs[0] ?? '' },
      aad,
    );
    const last = await decryptJson<{ i: number }>(
      key,
      { ciphertext: ciphertexts[499] ?? '', iv: ivs[499] ?? '' },
      aad,
    );
    expect(first.i).toBe(0);
    expect(last.i).toBe(499);
  });
});

describe('vault parameters', () => {
  // Case 7: every vault gets its own salt and therefore its own key.
  it('generates a unique 16-byte salt per vault and non interchangeable keys', async () => {
    const first = await createVault(MASTER, USER_A, ITERATIONS);
    const second = await createVault(MASTER, USER_A, ITERATIONS);

    expect(first.meta.salt).not.toBe(second.meta.salt);
    expect(Buffer.from(first.meta.salt, 'base64').length).toBe(16);
    expect(Buffer.from(second.meta.salt, 'base64').length).toBe(16);

    // The verifier of the first vault cannot be opened with the key of the second.
    const verifierError = await captureError(() =>
      decryptBytes(
        second.key,
        { ciphertext: first.meta.verifierCiphertext, iv: first.meta.verifierIv },
        buildAad(ENCRYPTION_VERSION, USER_A, 'verifier'),
      ),
    );
    expect(verifierError.code).toBe('CRYPTO');

    // A credential of the first vault cannot be read with the key of the second.
    const write = await encryptCredential(
      first.key,
      USER_A,
      'rec-salt',
      credentialData(),
    );
    const credentialError = await captureError(() =>
      decryptCredential(second.key, USER_A, toRow(write, USER_A)),
    );
    expect(credentialError.code).toBe('CRYPTO');
  });

  // Case 8: derived keys are non extractable.
  it('derives non extractable AES-GCM keys that cannot be exported', async () => {
    const key = await deriveKey(MASTER, generateSalt(), ITERATIONS);

    expect(key.extractable).toBe(false);
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');

    // The raw key bytes must not be reachable from a page script.
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toBeDefined();
    const outcome = await crypto.subtle.exportKey('raw', key).then(
      () => 'resolved',
      () => 'rejected',
    );
    expect(outcome).toBe('rejected');
  });

  // Case 9: the metadata is public and never contains the master password.
  it('stores public parameters only and never the master password', async () => {
    const { meta } = await createVault(MASTER, USER_A, ITERATIONS);
    const serialized = JSON.stringify(meta);

    expect(serialized).not.toContain(MASTER);
    expect(meta.kdf).toBe('PBKDF2-SHA256');
    expect(meta.encryptionVersion).toBe(1);
    expect(meta.kdfIterations).toBe(ITERATIONS);
    expect(Object.keys(meta).sort()).toEqual([
      'encryptionVersion',
      'kdf',
      'kdfIterations',
      'salt',
      'verifierCiphertext',
      'verifierIv',
    ]);
    expect(meta).not.toHaveProperty('key');
    expect(meta).not.toHaveProperty('password');
    expect(meta).not.toHaveProperty('masterPassword');

    // The password is not even present in the raw bytes of the verifier.
    const verifier = Buffer.from(meta.verifierCiphertext, 'base64');
    expect(verifier.includes(Buffer.from(MASTER, 'utf8'))).toBe(false);
  });

  // Case 10: the KDF iteration count is validated.
  it('rejects KDF iteration counts outside the allowed range', async () => {
    for (const iterations of INVALID_ITERATIONS) {
      const error = await captureError(() =>
        createVault(MASTER, USER_A, iterations),
      );
      expect(error.code).toBe('VALIDATION');
    }

    const deriveError = await captureError(() =>
      deriveKey(MASTER, generateSalt(), 1_000),
    );
    expect(deriveError.code).toBe('VALIDATION');

    // The minimum is accepted.
    const { meta } = await createVault(MASTER, USER_A, MIN_ITERATIONS);
    expect(meta.kdfIterations).toBe(MIN_ITERATIONS);
  });
});

describe('format versioning', () => {
  // Case 11: rows written with an unknown format version are rejected.
  it('rejects rows with an unknown encryption version', async () => {
    const key = await deriveKey(MASTER, generateSalt(), ITERATIONS);
    const write = await encryptCredential(key, USER_A, 'rec-version', credentialData());
    const row = toRow(write, USER_A);

    const error = await captureError(() =>
      decryptCredential(key, USER_A, { ...row, encryption_version: 99 }),
    );
    expect(error.code).toBe('CRYPTO');
    expect(error.message).not.toContain(row.ciphertext);

    // The same applies to the vault metadata.
    const { meta } = await createVault(MASTER, USER_A, ITERATIONS);
    const metaError = await captureError(() =>
      unlockVault(MASTER, USER_A, { ...meta, encryptionVersion: 99 }),
    );
    expect(metaError.code).toBe('CRYPTO');
  });
});

describe('password normalization', () => {
  // Case 12: the composed and the decomposed form of the same password are equivalent.
  it('derives the same key from the NFC and the NFD form of a password', async () => {
    const composed = '\u00E9'; // é
    const decomposed = 'e\u0301'; // e + combining acute accent
    expect(composed).not.toBe(decomposed);
    expect(composed.normalize('NFKC')).toBe(decomposed.normalize('NFKC'));

    const { meta, key } = await createVault(composed, USER_A, ITERATIONS);

    // The vault created with the composed password is unlocked with the other form.
    const unlocked = await unlockVault(decomposed, USER_A, meta);
    expect(unlocked.algorithm.name).toBe('AES-GCM');

    const write = await encryptCredential(key, USER_A, 'rec-nfkc', credentialData());
    const credential = await decryptCredential(unlocked, USER_A, toRow(write, USER_A));
    expect(credential.password).toBe(PASSWORD);

    // And the other way round.
    const other = await createVault(decomposed, USER_A, ITERATIONS);
    const unlockedOther = await unlockVault(composed, USER_A, other.meta);
    const writeOther = await encryptCredential(
      other.key,
      USER_A,
      'rec-nfkc',
      credentialData(),
    );
    const credentialOther = await decryptCredential(
      unlockedOther,
      USER_A,
      toRow(writeOther, USER_A),
    );
    expect(credentialOther.password).toBe(PASSWORD);
  });
});

describe('clear text leakage', () => {
  // Case 13: the encrypted write contains no plaintext.
  it('never stores the username or the password in clear text', async () => {
    const key = await deriveKey(MASTER, generateSalt(), ITERATIONS);
    const data = credentialData({ username: USERNAME, password: PASSWORD });

    const write = await encryptCredential(key, USER_A, 'rec-clear', data);
    const serialized = JSON.stringify(write);

    expect(write.id).toBe('rec-clear');
    expect(write.encryption_version).toBe(ENCRYPTION_VERSION);
    expect(serialized).not.toContain(data.username);
    expect(serialized).not.toContain(data.password);
    expect(write.ciphertext).not.toContain(data.password);
    expect(write.iv).not.toContain(data.password);
    expect(write.ciphertext).not.toContain(data.username);
    expect(write.iv).not.toContain(data.username);

    // The raw bytes of the ciphertext do not contain the secrets either.
    const raw = Buffer.from(write.ciphertext, 'base64');
    expect(raw.includes(Buffer.from(data.password, 'utf8'))).toBe(false);
    expect(raw.includes(Buffer.from(data.username, 'utf8'))).toBe(false);

    // The record still round-trips correctly.
    const credential = await decryptCredential(key, USER_A, toRow(write, USER_A));
    expect(credential.username).toBe(data.username);
    expect(credential.password).toBe(data.password);
  });
});

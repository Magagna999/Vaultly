/** Decrypted credential payload. Exists only in memory while the vault is unlocked. */
export interface CredentialData {
  name: string;
  url: string;
  username: string;
  password: string;
  note: string;
}

/** A decrypted credential together with its (non-secret) sync metadata. */
export interface Credential extends CredentialData {
  id: string;
  /** Server revision used for optimistic concurrency. */
  revision: number;
  createdAt: string;
  updatedAt: string;
}

/** Row as stored in Supabase: only ciphertext + technical metadata. */
export interface CredentialRow {
  id: string;
  user_id: string;
  ciphertext: string;
  iv: string;
  encryption_version: number;
  revision: number;
  created_at: string;
  updated_at: string;
}

/** Payload sent to Supabase when creating/updating a credential. */
export interface EncryptedWrite {
  id: string;
  ciphertext: string;
  iv: string;
  encryption_version: number;
}

/** Public key-derivation parameters + password verifier. Contains no secret. */
export interface VaultMeta {
  kdf: 'PBKDF2-SHA256';
  kdfIterations: number;
  /** Base64 salt, unique per vault. */
  salt: string;
  verifierCiphertext: string;
  verifierIv: string;
  encryptionVersion: number;
}

export interface VaultSettings {
  /** Minutes of inactivity before the vault locks. 0 disables (not recommended). */
  autoLockMinutes: number;
}

export type ImportAction = 'import' | 'skip' | 'replace';

import type { CredentialData } from '@/types';
import { toCsvLine } from '@/services/import/csv';

/**
 * PLAINTEXT export in Chrome's CSV layout. Passwords are written in clear text:
 * the UI must warn and require explicit confirmation before calling this.
 */
export function exportPlainCsv(credentials: CredentialData[]): string {
  const lines = [toCsvLine(['name', 'url', 'username', 'password', 'note'])];
  for (const c of credentials) lines.push(toCsvLine([c.name, c.url, c.username, c.password, c.note]));
  return lines.join('\r\n') + '\r\n';
}

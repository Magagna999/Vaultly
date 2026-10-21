import type { Credential, CredentialData, ImportAction } from '@/types';
import { hostnameOf } from '@/utils/validation';
import type { ImportRow } from './chrome';

export type DuplicateKind =
  | 'new'
  | 'identical' // same site + username + password already in the vault
  | 'different' // same site + username, different password already in the vault
  | 'file-identical' // repeated in the same file with the same password
  | 'file-different'; // repeated in the same file with another password

export interface ClassifiedRow {
  row: ImportRow;
  kind: DuplicateKind;
  /** Existing vault credential this row collides with (identical / different). */
  existing?: Credential;
}

export type DuplicatePolicy = 'skip' | 'replace' | 'keep-both';

/** Identity of a login: normalized host (or name) + case-insensitive username. */
export function duplicateKey(d: Pick<CredentialData, 'url' | 'name' | 'username'>): string {
  const site = hostnameOf(d.url) || d.name.trim().toLowerCase();
  return `${site}\u0000${d.username.trim().toLowerCase()}`;
}

export function classifyDuplicates(rows: ImportRow[], existing: Credential[]): ClassifiedRow[] {
  const byKey = new Map<string, Credential[]>();
  for (const c of existing) {
    const k = duplicateKey(c);
    byKey.set(k, [...(byKey.get(k) ?? []), c]);
  }
  const seenInFile = new Map<string, string[]>(); // key -> passwords seen

  return rows.map((row) => {
    const k = duplicateKey(row.data);
    const matches = byKey.get(k);
    if (matches?.length) {
      const same = matches.find((m) => m.password === row.data.password);
      if (same) return { row, kind: 'identical', existing: same };
      return { row, kind: 'different', existing: matches[0] };
    }
    const seen = seenInFile.get(k);
    if (seen) {
      const kind: DuplicateKind = seen.includes(row.data.password) ? 'file-identical' : 'file-different';
      seen.push(row.data.password);
      return { row, kind };
    }
    seenInFile.set(k, [row.data.password]);
    return { row, kind: 'new' };
  });
}

/** Default action for a row given the user's policy for conflicting duplicates. */
export function defaultAction(kind: DuplicateKind, policy: DuplicatePolicy): ImportAction {
  switch (kind) {
    case 'new':
      return 'import';
    case 'identical':
    case 'file-identical':
      return 'skip';
    case 'different':
      return policy === 'replace' ? 'replace' : policy === 'keep-both' ? 'import' : 'skip';
    case 'file-different':
      return policy === 'skip' ? 'skip' : 'import';
  }
}

export interface ImportPlan {
  toInsert: CredentialData[];
  toReplace: { id: string; revision: number; data: CredentialData }[];
  skipped: number;
}

/** Turns classified rows + policy (+ optional per-row overrides keyed by line) into a plan. */
export function buildPlan(
  classified: ClassifiedRow[],
  policy: DuplicatePolicy,
  overrides: Record<number, ImportAction> = {},
): ImportPlan {
  const plan: ImportPlan = { toInsert: [], toReplace: [], skipped: 0 };
  for (const c of classified) {
    let action = overrides[c.row.line] ?? defaultAction(c.kind, policy);
    // 'replace' only makes sense when there is a vault credential to replace.
    if (action === 'replace' && !c.existing) action = 'import';
    if (action === 'skip') plan.skipped++;
    else if (action === 'import') plan.toInsert.push(c.row.data);
    else if (c.existing) {
      plan.toReplace.push({ id: c.existing.id, revision: c.existing.revision, data: c.row.data });
    }
  }
  return plan;
}

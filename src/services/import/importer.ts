import type { SyncService } from '@/services/sync/sync';
import type { ImportPlan } from './duplicates';

export interface ImportSummary {
  imported: number;
  replaced: number;
  skipped: number;
  invalid: number;
  failed: number;
  conflicts: number;
  error: string | null;
}

/**
 * Executes a confirmed plan. Records are encrypted locally before leaving the page and
 * written in idempotent chunks: if the run is interrupted, re-importing the same file
 * detects what was already stored (identical duplicates) instead of creating copies.
 */
export async function executeImport(
  plan: ImportPlan,
  invalidCount: number,
  sync: SyncService,
  onProgress?: (done: number, total: number) => void,
): Promise<ImportSummary> {
  const ins = await sync.createMany(plan.toInsert, onProgress);
  const rep = ins.error
    ? { done: 0, failed: plan.toReplace.length, conflicts: 0, error: ins.error }
    : await sync.replaceMany(plan.toReplace);
  return {
    imported: ins.done,
    replaced: rep.done,
    skipped: plan.skipped,
    invalid: invalidCount,
    failed: ins.failed + rep.failed,
    conflicts: rep.conflicts,
    error: ins.error ?? rep.error,
  };
}

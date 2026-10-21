import type { SupabaseClient } from '@supabase/supabase-js';

export interface RecordedCall {
  table: string;
  op: 'select' | 'insert' | 'upsert' | 'update' | 'delete';
  payload?: unknown;
  options?: unknown;
  filters: [string, unknown][];
}

type Result = { data: unknown; error: unknown };

/**
 * Chainable fake of the supabase-js query builder. It records every call (table, operation,
 * payload, filters) and answers with `respond(call)`.
 */
export function fakeSupabase(respond: (call: RecordedCall) => Result = () => ({ data: [], error: null })) {
  const calls: RecordedCall[] = [];
  const client = {
    from(table: string) {
      const call: RecordedCall = { table, op: 'select', filters: [] };
      const builder: Record<string, unknown> = {};
      const chain = () => builder;
      const set = (op: RecordedCall['op']) => (payload?: unknown, options?: unknown) => {
        if (payload !== undefined && typeof payload !== 'string') call.payload = payload;
        if (options !== undefined) call.options = options;
        if (op !== 'select' || call.op === 'select') call.op = op;
        return builder;
      };
      builder.select = set('select');
      builder.insert = set('insert');
      builder.upsert = set('upsert');
      builder.update = set('update');
      builder.delete = () => {
        call.op = 'delete';
        return builder;
      };
      builder.eq = (col: string, val: unknown) => {
        call.filters.push([col, val]);
        return builder;
      };
      builder.order = chain;
      builder.range = chain;
      const finish = () => {
        calls.push(call);
        return Promise.resolve(respond(call));
      };
      builder.maybeSingle = () =>
        finish().then((r) => ({ ...r, data: Array.isArray(r.data) ? (r.data[0] ?? null) : r.data }));
      builder.then = (ok: (v: Result) => unknown, bad?: (e: unknown) => unknown) => finish().then(ok, bad);
      return builder;
    },
  };
  return { client: client as unknown as SupabaseClient, calls };
}

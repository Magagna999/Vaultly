import { describe, expect, it } from 'vitest';
import type { Credential, CredentialData, ImportAction } from '@/types';
import { detectDelimiter, parseCsv, toCsvLine } from '@/services/import/csv';
import { MAX_CSV_BYTES, parseChromeCsv } from '@/services/import/chrome';
import type { ImportRow } from '@/services/import/chrome';
import {
  buildPlan,
  classifyDuplicates,
  duplicateKey,
  type ClassifiedRow,
  type DuplicatePolicy,
  type ImportPlan,
} from '@/services/import/duplicates';
import { executeImport } from '@/services/import/importer';
import { exportPlainCsv } from '@/services/export/csv';
import type { SyncService } from '@/services/sync/sync';
import { AppError, isAppError } from '@/utils/errors';

const ISO = '2024-01-01T00:00:00Z';

function data(name: string, url: string, username: string, password: string, note = ''): CredentialData {
  return { name, url, username, password, note };
}

function credential(id: string, d: CredentialData, revision = 1): Credential {
  return { id, revision, createdAt: ISO, updatedAt: ISO, ...d };
}

function row(line: number, d: CredentialData): ImportRow {
  return { line, data: d };
}

function expectImportError(fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    expect(isAppError(e, 'IMPORT')).toBe(true);
    expect(e).toBeInstanceOf(AppError);
    return;
  }
  throw new Error('Expected an IMPORT AppError to be thrown');
}

interface FakeBulkResult {
  done: number;
  failed: number;
  conflicts: number;
  error: string | null;
}

interface FakeSyncCalls {
  createItems: CredentialData[];
  replaceItems: ImportPlan['toReplace'];
  replaceCalls: number;
}

function makeFakeSync(
  createResult: FakeBulkResult,
  replaceResult: FakeBulkResult,
): { sync: SyncService; calls: FakeSyncCalls } {
  const calls: FakeSyncCalls = { createItems: [], replaceItems: [], replaceCalls: 0 };
  const sync = {
    createMany: async (items: CredentialData[]) => {
      calls.createItems = items;
      return createResult;
    },
    replaceMany: async (items: ImportPlan['toReplace']) => {
      calls.replaceCalls++;
      calls.replaceItems = items;
      return replaceResult;
    },
  } as unknown as SyncService;
  return { sync, calls };
}

describe('CSV parsing primitives', () => {
  it('detects comma, semicolon and tab delimiters', () => {
    expect(detectDelimiter('name,url,username,password')).toBe(',');
    expect(detectDelimiter('name;url;username;password')).toBe(';');
    expect(detectDelimiter('name\turl\tusername\tpassword')).toBe('\t');
  });

  it('parses escaped quotes, embedded newlines (CRLF and LF) and tracks record lines', () => {
    const text = 'h1,h2\r\n"a ""b"" c","x\r\ny"\r\n"p\nq",z\r\n';
    const parsed = parseCsv(text, ',');

    expect(parsed.unterminatedQuoteLine).toBeNull();
    expect(parsed.rows).toHaveLength(3);
    expect(parsed.rows[1]?.cells).toEqual(['a "b" c', 'x\r\ny']);
    expect(parsed.rows[1]?.line).toBe(2);
    expect(parsed.rows[2]?.cells).toEqual(['p\nq', 'z']);
    // Embedded newlines do not change the 1-based line where the record starts.
    expect(parsed.rows[2]?.line).toBe(4);
  });

  it('serializes cells with RFC 4180 quoting', () => {
    expect(toCsvLine(['plain', 'a,b', 'say "hi"', 'line\nbreak'])).toBe(
      'plain,"a,b","say ""hi""","line\nbreak"',
    );
  });
});

describe('Chrome CSV import', () => {
  // Case 1: valid 5-column Chrome export.
  it('imports a valid Chrome CSV with five columns and multiple rows', () => {
    const csv = [
      'name,url,username,password,note',
      'GitHub,https://github.com,octocat,pw1,work',
      'Example,https://example.com,user2,pw2,',
    ].join('\n');

    const result = parseChromeCsv(csv);

    expect(result.delimiter).toBe(',');
    expect(result.recognizedFields).toEqual(['name', 'url', 'username', 'password', 'note']);
    expect(result.invalid).toHaveLength(0);
    expect(result.valid.map((v) => v.line)).toEqual([2, 3]);
    expect(result.valid[0]?.data).toEqual(data('GitHub', 'https://github.com', 'octocat', 'pw1', 'work'));
    expect(result.valid[1]?.data).toEqual(data('Example', 'https://example.com', 'user2', 'pw2', ''));
  });

  // Case 2: four columns and header aliases / mixed case.
  it('accepts four columns without note and recognizes header aliases', () => {
    const csv = ['Title,login_uri,user,pass', 'My Site,https://alias.example,alice,secret'].join('\n');

    const result = parseChromeCsv(csv);

    expect(result.invalid).toHaveLength(0);
    expect(result.recognizedFields).toEqual(['name', 'url', 'username', 'password']);
    expect(result.valid).toHaveLength(1);
    expect(result.valid[0]?.data).toEqual(data('My Site', 'https://alias.example', 'alice', 'secret', ''));
  });

  // Case 3: semicolon and tab delimiters, commas inside quoted fields.
  it('detects semicolon and tab delimiters and keeps commas inside quoted fields', () => {
    const semi = 'name;url;username;password\nAcme;https://semi.example;alice;pw';
    const tab = 'name\turl\tusername\tpassword\nAcme\thttps://tab.example\talice\tpw';
    const comma = 'name,url,username,password\n"Acme, Inc",https://comma.example,alice,pw';

    const semiResult = parseChromeCsv(semi);
    expect(detectDelimiter(semi)).toBe(';');
    expect(semiResult.delimiter).toBe(';');
    expect(semiResult.valid[0]?.data.name).toBe('Acme');

    const tabResult = parseChromeCsv(tab);
    expect(detectDelimiter(tab)).toBe('\t');
    expect(tabResult.delimiter).toBe('\t');
    expect(tabResult.valid[0]?.data.url).toBe('https://tab.example');

    const commaResult = parseChromeCsv(comma);
    expect(commaResult.delimiter).toBe(',');
    expect(commaResult.valid[0]?.data.name).toBe('Acme, Inc');
  });

  // Case 4: BOM, blank lines, escaped quotes and embedded newlines in a full import.
  it('handles a BOM, ignores blank lines and preserves embedded LF in quoted fields', () => {
    const csv =
      '\uFEFFname,url,username,password\r\n' +
      'A,https://a.example,u,p\r\n' +
      '\r\n' +
      'B,https://b.example,u2,"line1\nline2"\r\n';

    const result = parseChromeCsv(csv);

    expect(result.valid).toHaveLength(2);
    expect(result.invalid).toHaveLength(0);
    expect(result.valid[0]?.line).toBe(2);
    // The blank line is skipped, so the second record starts on line 4.
    expect(result.valid[1]?.line).toBe(4);
    expect(result.valid[1]?.data.password).toBe('line1\nline2');
  });

  // Case 5: Unicode is preserved; only the password keeps surrounding whitespace.
  it('preserves Unicode in all fields, trims text fields and never trims passwords', () => {
    const csv = [
      'name,url,username,password,note',
      '  Café 😀  ,https://例子.example,  用户🚀  ,  päss🔑 中文  ,note',
      '  مرحبًا  ,https://arabic.example,مستخدم,سري🔒,',
    ].join('\n');

    const result = parseChromeCsv(csv);

    expect(result.invalid).toHaveLength(0);
    expect(result.valid[0]?.data.name).toBe('Café 😀');
    expect(result.valid[0]?.data.username).toBe('用户🚀');
    expect(result.valid[0]?.data.password).toBe('  päss🔑 中文  ');
    expect(result.valid[0]?.data.url).toBe('https://例子.example');
    expect(result.valid[1]?.data.name).toBe('مرحبًا');
    expect(result.valid[1]?.data.username).toBe('مستخدم');
    expect(result.valid[1]?.data.password).toBe('سري🔒');
  });

  // Case 6: empty username is valid, empty password / missing site are invalid.
  it('accepts an empty username and rejects empty passwords or rows without name and url', () => {
    const csv = [
      'name,url,username,password',
      'NoUser,https://nouser.example,,pw',
      'NoPass,https://nopass.example,u,',
      ',,u,pw',
    ].join('\n');

    const result = parseChromeCsv(csv);

    expect(result.valid).toHaveLength(1);
    expect(result.valid[0]?.data.username).toBe('');
    expect(result.invalid.map((i) => i.line)).toEqual([3, 4]);
    expect(result.invalid[0]?.reason).toContain('Password');
    expect(result.invalid[1]?.reason).toContain('site name or a URL');
  });

  // Case 7: wrong column count and unterminated quote.
  it('reports malformed rows with the correct line and keeps preceding valid rows', () => {
    const wrongColumns = [
      'name,url,username,password',
      'A,https://a.example,u1,p1',
      'B,https://b.example,u2',
      'C,https://c.example,u3,p3',
    ].join('\n');

    const wrongResult = parseChromeCsv(wrongColumns);
    expect(wrongResult.valid.map((v) => v.line)).toEqual([2, 4]);
    expect(wrongResult.invalid).toHaveLength(1);
    expect(wrongResult.invalid[0]?.line).toBe(3);
    expect(wrongResult.invalid[0]?.reason).toBe('Wrong number of columns.');

    const unterminatedText =
      'name,url,username,password\nA,https://a.example,u1,p1\nB,https://b.example,u2,"unclosed';

    const parsed = parseCsv(unterminatedText, ',');
    expect(parsed.unterminatedQuoteLine).toBe(3);
    expect(parsed.rows).toHaveLength(2);

    const unterminatedResult = parseChromeCsv(unterminatedText);
    expect(unterminatedResult.valid.map((v) => v.line)).toEqual([2]);
    expect(unterminatedResult.invalid.some((i) => i.line === 3)).toBe(true);
    expect(unterminatedResult.invalid[0]?.reason).toContain('Unterminated');
  });

  // Case 8: invalid reasons must never echo file contents.
  it('never includes row content in invalid reasons', () => {
    const sentinel = 'S3cretMarker!';
    const csv = [
      'name,url,username,password',
      `A,https://a.example,u,${sentinel}`,
      `Too,Many,Cols,${sentinel},extra`,
      `Bad,not a valid url,u,${sentinel}`,
    ].join('\n');

    const result = parseChromeCsv(csv);

    expect(result.valid).toHaveLength(1);
    expect(result.invalid).toHaveLength(2);
    expect(JSON.stringify(result.invalid)).not.toContain(sentinel);
    expect(result.invalid.every((i) => !i.reason.includes(sentinel))).toBe(true);
  });

  // Case 9: file-level errors.
  it('throws an IMPORT AppError for empty files, unknown headers and oversized files', () => {
    expectImportError(() => parseChromeCsv(''));
    expectImportError(() => parseChromeCsv('   \n\t  '));
    expectImportError(() => parseChromeCsv('a,b,c\n1,2,3'));
    expectImportError(() => parseChromeCsv('x'.repeat(MAX_CSV_BYTES + 1)));
  });
});

describe('duplicate detection', () => {
  // Case 10: all duplicate kinds.
  it('classifies identical, different, file-identical, file-different and new rows', () => {
    const existing = [credential('e1', data('GitHub', 'https://github.com', 'octocat', 'old-pass'))];
    const rows = [
      // Same host (www + case insensitive) and username, same password.
      row(2, data('GitHub', 'https://WWW.GitHub.com', 'OcToCat', 'old-pass')),
      // Same key, different password.
      row(3, data('GitHub', 'https://www.github.com', 'octocat', 'new-pass')),
      // First occurrence in the file.
      row(4, data('GitLab', 'https://gitlab.com', 'alice', 'same')),
      // Repeated in the file with the same password.
      row(5, data('GitLab', 'https://gitlab.com', 'Alice', 'same')),
      // Repeated in the file with another password.
      row(6, data('GitLab', 'https://gitlab.com', 'alice', 'other')),
      // Unrelated credential.
      row(7, data('Other', 'https://other.example', 'bob', 'pw')),
    ];

    const result = classifyDuplicates(rows, existing);

    expect(result.map((r) => r.kind)).toEqual([
      'identical',
      'different',
      'new',
      'file-identical',
      'file-different',
      'new',
    ]);
    expect(result[0]?.existing?.id).toBe('e1');
    expect(result[1]?.existing?.id).toBe('e1');
    expect(result[2]?.existing).toBeUndefined();
    expect(duplicateKey(data('x', 'https://www.Example.com/path', 'User', 'p'))).toBe(
      duplicateKey(data('x', 'https://example.com', 'user', 'q')),
    );
  });
});

describe('import plan', () => {
  const existing = credential('vault-1', data('Diff', 'https://diff.example', 'u', 'old'), 7);
  const rows: ClassifiedRow[] = [
    {
      row: row(2, data('New', 'https://new.example', 'u', 'p')),
      kind: 'new',
    },
    {
      row: row(3, data('Diff', 'https://diff.example', 'u', 'p2')),
      kind: 'different',
      existing,
    },
    {
      row: row(4, data('Ident', 'https://ident.example', 'u', 'p3')),
      kind: 'identical',
      existing,
    },
    {
      row: row(5, data('FileDiff', 'https://fd.example', 'u', 'p4')),
      kind: 'file-different',
    },
    {
      row: row(6, data('FileIdent', 'https://fi.example', 'u', 'p5')),
      kind: 'file-identical',
    },
  ];

  // Case 11: policies, identical rows and per-line overrides.
  it('applies skip / replace / keep-both policies', () => {
    const policyCases: { policy: DuplicatePolicy; inserts: number; replaces: number; skipped: number }[] = [
      { policy: 'skip', inserts: 1, replaces: 0, skipped: 4 },
      { policy: 'replace', inserts: 2, replaces: 1, skipped: 2 },
      { policy: 'keep-both', inserts: 3, replaces: 0, skipped: 2 },
    ];

    for (const c of policyCases) {
      const plan = buildPlan(rows, c.policy);
      expect(plan.toInsert).toHaveLength(c.inserts);
      expect(plan.toReplace).toHaveLength(c.replaces);
      expect(plan.skipped).toBe(c.skipped);
    }
  });

  it('never replaces an identical row by default', () => {
    for (const policy of ['skip', 'replace', 'keep-both'] as DuplicatePolicy[]) {
      const plan = buildPlan(rows, policy);
      expect(plan.toReplace.every((r) => r.data.password !== 'p3')).toBe(true);
      expect(plan.toInsert.every((r) => r.password !== 'p3')).toBe(true);
    }
  });

  it('honours per-line overrides and turns replace without existing into insert', () => {
    const overrides: Record<number, ImportAction> = {
      2: 'replace', // no existing => insert
      3: 'import',
      4: 'replace', // identical, but explicitly replaced
      5: 'skip',
    };

    const plan = buildPlan(rows, 'skip', overrides);

    expect(plan.toInsert.map((r) => r.password)).toEqual(['p', 'p2']);
    expect(plan.skipped).toBe(2); // line 5 override + line 6 default
    expect(plan.toReplace).toHaveLength(1);
    expect(plan.toReplace[0]).toEqual({ id: 'vault-1', revision: 7, data: rows[2]?.row.data });
  });
});

describe('executeImport', () => {
  // Case 12: summary with a fake sync service.
  it('returns the correct summary and passes the plan to the sync service', async () => {
    const plan: ImportPlan = {
      toInsert: [data('A', 'https://a.example', 'u', 'p1'), data('B', 'https://b.example', 'u', 'p2')],
      toReplace: [{ id: 'vault-1', revision: 4, data: data('C', 'https://c.example', 'u', 'p3') }],
      skipped: 3,
    };
    const { sync, calls } = makeFakeSync(
      { done: 2, failed: 0, conflicts: 0, error: null },
      { done: 1, failed: 0, conflicts: 0, error: null },
    );

    const summary = await executeImport(plan, 1, sync);

    expect(summary).toEqual({
      imported: 2,
      replaced: 1,
      skipped: 3,
      invalid: 1,
      failed: 0,
      conflicts: 0,
      error: null,
    });
    expect(calls.createItems).toEqual(plan.toInsert);
    expect(calls.replaceCalls).toBe(1);
    expect(calls.replaceItems).toEqual(plan.toReplace);
  });

  it('skips replacements and counts them as failed when createMany returns an error', async () => {
    const plan: ImportPlan = {
      toInsert: [data('A', 'https://a.example', 'u', 'p1'), data('B', 'https://b.example', 'u', 'p2')],
      toReplace: [
        { id: 'vault-1', revision: 1, data: data('C', 'https://c.example', 'u', 'p3') },
        { id: 'vault-2', revision: 2, data: data('D', 'https://d.example', 'u', 'p4') },
      ],
      skipped: 0,
    };
    const { sync, calls } = makeFakeSync(
      { done: 1, failed: 1, conflicts: 0, error: 'network down' },
      { done: 0, failed: 0, conflicts: 0, error: null },
    );

    const summary = await executeImport(plan, 0, sync);

    expect(calls.replaceCalls).toBe(0);
    expect(summary).toEqual({
      imported: 1,
      replaced: 0,
      skipped: 0,
      invalid: 0,
      failed: 3, // 1 failed insert + 2 replacements never attempted
      conflicts: 0,
      error: 'network down',
    });
  });
});

describe('CSV round trip', () => {
  // Case 13: exportPlainCsv -> parseChromeCsv.
  it('preserves commas, quotes, newlines and Unicode through export and import', () => {
    const credentials = [
      data('Acme, "Inc"', 'https://example.com/a,b', '用户🚀', 'p,a"s\nline2', 'line one\nline two'),
      data('مرحبا', 'https://example.org', 'bob', '  spaced  ', 'quote " and comma,'),
    ];

    const exported = exportPlainCsv(credentials);
    const parsed = parseChromeCsv(exported);

    expect(parsed.invalid).toHaveLength(0);
    expect(parsed.valid.map((v) => v.data)).toEqual(credentials);
  });
});

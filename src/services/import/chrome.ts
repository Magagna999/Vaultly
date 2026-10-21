/**
 * Chrome password CSV import.
 *
 * Chrome (chrome://password-manager/settings -> "Export passwords") writes a UTF-8 CSV with the
 * header line:   name,url,username,password,note
 * (older Chrome/Edge versions omit `note`). Other managers use different names, so headers
 * are matched case-insensitively against the aliases below.
 */
import type { CredentialData } from '@/types';
import { AppError } from '@/utils/errors';
import { validateCredentialData } from '@/utils/validation';
import { detectDelimiter, parseCsv, stripBom } from './csv';

export const CHROME_HEADERS = ['name', 'url', 'username', 'password', 'note'] as const;

const ALIASES: Record<keyof CredentialData, string[]> = {
  name: ['name', 'title', 'site', 'sitename'],
  url: ['url', 'login_uri', 'website', 'origin', 'uri'],
  username: ['username', 'login_username', 'user', 'login', 'email'],
  password: ['password', 'login_password', 'pass'],
  note: ['note', 'notes', 'comment', 'extra'],
};

export const MAX_CSV_BYTES = 10 * 1024 * 1024;
export const MAX_CSV_ROWS = 50_000;

export interface ImportRow {
  /** 1-based line number in the source file. */
  line: number;
  data: CredentialData;
}

export interface InvalidRow {
  line: number;
  /** Generic reason; never includes file content. */
  reason: string;
}

export interface CsvImportParse {
  delimiter: string;
  /** Which CSV column feeds each field (index), for display. */
  recognizedFields: (keyof CredentialData)[];
  valid: ImportRow[];
  invalid: InvalidRow[];
}

function mapHeaders(headerCells: string[]): Partial<Record<keyof CredentialData, number>> {
  const norm = headerCells.map((h) => h.trim().toLowerCase());
  const map: Partial<Record<keyof CredentialData, number>> = {};
  for (const field of Object.keys(ALIASES) as (keyof CredentialData)[]) {
    const idx = norm.findIndex((h) => ALIASES[field].includes(h));
    if (idx >= 0) map[field] = idx;
  }
  return map;
}

export function parseChromeCsv(text: string): CsvImportParse {
  if (text.length > MAX_CSV_BYTES) {
    throw new AppError('IMPORT', 'The file is too large to import (max 10 MB).');
  }
  const clean = stripBom(text);
  if (!clean.trim()) throw new AppError('IMPORT', 'The file is empty.');

  const delimiter = detectDelimiter(clean);
  const { rows, unterminatedQuoteLine } = parseCsv(clean, delimiter);
  const header = rows[0];
  if (!header) throw new AppError('IMPORT', 'No header row found.');

  const cols = mapHeaders(header.cells);
  if (cols.password === undefined || (cols.url === undefined && cols.name === undefined)) {
    throw new AppError(
      'IMPORT',
      `Unrecognized CSV format. Expected Chrome headers: ${CHROME_HEADERS.join(', ')}.`,
    );
  }
  const body = rows.slice(1);
  if (body.length > MAX_CSV_ROWS) {
    throw new AppError('IMPORT', `Too many rows (max ${MAX_CSV_ROWS}).`);
  }

  const valid: ImportRow[] = [];
  const invalid: InvalidRow[] = [];
  const get = (cells: string[], f: keyof CredentialData) => {
    const i = cols[f];
    return i === undefined ? '' : (cells[i] ?? '').trim();
  };

  for (const row of body) {
    if (row.cells.length !== header.cells.length) {
      invalid.push({ line: row.line, reason: 'Wrong number of columns.' });
      continue;
    }
    const data: CredentialData = {
      name: get(row.cells, 'name'),
      url: get(row.cells, 'url'),
      username: get(row.cells, 'username'),
      // Passwords are kept verbatim (no trimming): whitespace may be significant.
      password: cols.password === undefined ? '' : (row.cells[cols.password] ?? ''),
      note: cols.note === undefined ? '' : (row.cells[cols.note] ?? ''),
    };
    if (!data.name) data.name = data.url;
    const errs = validateCredentialData(data);
    if (errs.length) {
      invalid.push({ line: row.line, reason: errs[0] ?? 'Invalid row.' });
      continue;
    }
    valid.push({ line: row.line, data });
  }
  if (unterminatedQuoteLine !== null) {
    invalid.push({
      line: unterminatedQuoteLine,
      reason: 'Unterminated quoted field; remaining rows skipped.',
    });
  }
  return {
    delimiter,
    recognizedFields: Object.keys(cols) as (keyof CredentialData)[],
    valid,
    invalid,
  };
}

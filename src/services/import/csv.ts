/**
 * RFC 4180-style CSV reader (quotes, escaped quotes, embedded newlines, CRLF/LF, BOM)
 * with delimiter detection. The content is never logged and never leaves the page.
 */
export interface CsvRow {
  /** 1-based line number where the record starts. */
  line: number;
  cells: string[];
}

export interface CsvParseResult {
  rows: CsvRow[];
  /** Set when a quoted field is never closed; parsing stops there. */
  unterminatedQuoteLine: number | null;
}

export const SUPPORTED_DELIMITERS = [',', ';', '\t'] as const;

export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/** Picks the delimiter that occurs most often (outside quotes) in the header line. */
export function detectDelimiter(text: string): string {
  const header = stripBom(text).split(/\r\n|\n|\r/, 1)[0] ?? '';
  let best = ',';
  let bestCount = 0;
  for (const d of SUPPORTED_DELIMITERS) {
    let count = 0;
    let inQuotes = false;
    for (const ch of header) {
      if (ch === '"') inQuotes = !inQuotes;
      else if (ch === d && !inQuotes) count++;
    }
    if (count > bestCount) {
      best = d;
      bestCount = count;
    }
  }
  return best;
}

export function parseCsv(input: string, delimiter: string): CsvParseResult {
  const text = stripBom(input);
  const rows: CsvRow[] = [];
  let cells: string[] = [];
  let field = '';
  let inQuotes = false;
  let quoteStartLine = 0;
  let line = 1;
  let recordLine = 1;
  let fieldHadContent = false; // distinguishes an empty trailing record from `""`

  const endField = () => {
    cells.push(field);
    field = '';
    fieldHadContent = false;
  };
  const endRecord = () => {
    endField();
    // Skip fully blank lines (single empty cell).
    if (!(cells.length === 1 && cells[0] === '')) rows.push({ line: recordLine, cells });
    cells = [];
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        if (ch === '\n') line++;
        field += ch;
      }
      continue;
    }
    if (ch === '"' && field === '' && !fieldHadContent) {
      inQuotes = true;
      quoteStartLine = line;
      fieldHadContent = true;
    } else if (ch === delimiter) {
      endField();
    } else if (ch === '\r' || ch === '\n') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      endRecord();
      line++;
      recordLine = line;
    } else {
      field += ch;
      fieldHadContent = true;
    }
  }
  if (inQuotes) {
    return { rows, unterminatedQuoteLine: quoteStartLine };
  }
  if (field !== '' || cells.length > 0 || fieldHadContent) endRecord();
  return { rows, unterminatedQuoteLine: null };
}

/** Serializes cells to one CSV line, quoting when needed (RFC 4180). */
export function toCsvLine(cells: string[], delimiter = ','): string {
  return cells
    .map((c) => (/[",\r\n]/.test(c) || c.includes(delimiter) ? `"${c.replace(/"/g, '""')}"` : c))
    .join(delimiter);
}

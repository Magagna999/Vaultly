import { useMemo, useState } from 'react';
import type { Credential, ImportAction } from '@/types';
import type { SyncService } from '@/services/sync/sync';
import { parseChromeCsv, type ImportRow, type InvalidRow, CHROME_HEADERS } from '@/services/import/chrome';
import {
  buildPlan,
  classifyDuplicates,
  type ClassifiedRow,
  type DuplicateKind,
  type DuplicatePolicy,
} from '@/services/import/duplicates';
import { executeImport, type ImportSummary } from '@/services/import/importer';
import { restoreBackup } from '@/services/export/backup';
import { userMessage } from '@/utils/errors';
import { hostnameOf } from '@/utils/validation';
import { Field, Notice } from './common';

type Step = 'select' | 'preview' | 'importing' | 'done';

const KIND_LABEL: Record<DuplicateKind, string> = {
  new: 'New',
  identical: 'Already in vault (identical)',
  different: 'In vault, different password',
  'file-identical': 'Repeated in file (identical)',
  'file-different': 'Repeated in file (different password)',
};

export function ImportWizard(props: {
  mode: 'csv' | 'backup';
  existing: Credential[];
  sync: SyncService;
  onClose: () => void;
  onImported: () => void;
}) {
  const [step, setStep] = useState<Step>('select');
  const [file, setFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [rows, setRows] = useState<ImportRow[]>([]);
  const [invalid, setInvalid] = useState<InvalidRow[]>([]);
  const [policy, setPolicy] = useState<DuplicatePolicy>('skip');
  const [overrides, setOverrides] = useState<Record<number, ImportAction>>({});
  const [confirmed, setConfirmed] = useState(false);
  const [progress, setProgress] = useState<[number, number]>([0, 0]);
  const [summary, setSummary] = useState<ImportSummary | null>(null);

  const classified: ClassifiedRow[] = useMemo(
    () => classifyDuplicates(rows, props.existing),
    [rows, props.existing],
  );
  const plan = useMemo(() => buildPlan(classified, policy, overrides), [classified, policy, overrides]);
  const dupes = classified.filter((c) => c.kind !== 'new');

  async function readFile() {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const text = await file.text(); // local only; never uploaded or persisted
      if (props.mode === 'csv') {
        const parsed = parseChromeCsv(text);
        setRows(parsed.valid);
        setInvalid(parsed.invalid);
      } else {
        const list = await restoreBackup(text, passphrase);
        setRows(list.map((data, i) => ({ line: i + 1, data })));
        setInvalid([]);
      }
      setPassphrase('');
      setStep('preview');
    } catch (e) {
      setError(userMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function run() {
    setStep('importing');
    const result = await executeImport(plan, invalid.length, props.sync, (d, t) => setProgress([d, t]));
    // Drop the parsed plaintext records from component state as soon as they are not needed.
    setRows([]);
    setFile(null);
    setSummary(result);
    setStep('done');
    props.onImported();
  }

  return (
    <section aria-labelledby="imp-title" className="card">
      <h1 id="imp-title">
        {props.mode === 'csv' ? 'Import passwords from CSV' : 'Restore encrypted backup'}
      </h1>

      {step === 'select' && (
        <>
          {props.mode === 'csv' ? (
            <>
              <Notice kind="info">
                In Chrome open <strong>chrome://password-manager/settings</strong> → Export passwords. The
                file uses the headers <code>{CHROME_HEADERS.join(', ')}</code>. It contains your passwords in{' '}
                <strong>plain text</strong>: the file is read locally and never uploaded, but delete it
                securely after importing.
              </Notice>
            </>
          ) : (
            <Notice kind="info">
              Select a <code>.cpvbackup.json</code> file and enter the passphrase used to create it.
            </Notice>
          )}
          {error && <Notice kind="error">{error}</Notice>}
          <div className="field">
            <label htmlFor="imp-file">{props.mode === 'csv' ? 'CSV file' : 'Backup file'}</label>
            <input
              id="imp-file"
              type="file"
              accept={props.mode === 'csv' ? '.csv,text/csv' : '.json,application/json'}
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </div>
          {props.mode === 'backup' && (
            <Field
              id="imp-pass"
              label="Backup passphrase"
              type="password"
              value={passphrase}
              onChange={setPassphrase}
              autoComplete="off"
            />
          )}
          <div className="actions">
            <button
              className="primary"
              disabled={!file || busy || (props.mode === 'backup' && !passphrase)}
              onClick={readFile}
            >
              {busy ? 'Reading…' : 'Preview'}
            </button>
            <button onClick={props.onClose}>Cancel</button>
          </div>
        </>
      )}

      {step === 'preview' && (
        <>
          <p>
            <strong>{rows.length}</strong> valid, <strong>{invalid.length}</strong> invalid,{' '}
            <strong>{dupes.length}</strong> duplicates. Will import <strong>{plan.toInsert.length}</strong>,
            replace <strong>{plan.toReplace.length}</strong>, skip <strong>{plan.skipped}</strong>.
          </p>
          {invalid.length > 0 && (
            <details>
              <summary>{invalid.length} invalid row(s)</summary>
              <ul>
                {invalid.slice(0, 100).map((r) => (
                  <li key={`${r.line}-${r.reason}`}>
                    Line {r.line}: {r.reason}
                  </li>
                ))}
              </ul>
            </details>
          )}
          <fieldset>
            <legend>When a login already exists with a different password</legend>
            {(['skip', 'replace', 'keep-both'] as DuplicatePolicy[]).map((p) => (
              <label key={p} className="check">
                <input
                  type="radio"
                  name="policy"
                  checked={policy === p}
                  onChange={() => {
                    setPolicy(p);
                    setOverrides({});
                  }}
                />{' '}
                {p === 'skip'
                  ? 'Skip (keep the vault version)'
                  : p === 'replace'
                    ? 'Replace the vault version'
                    : 'Keep both'}
              </label>
            ))}
          </fieldset>
          <table className="preview">
            <caption>Preview (passwords are not shown)</caption>
            <thead>
              <tr>
                <th>Site</th>
                <th>Username</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {classified.slice(0, 200).map((c) => (
                <tr key={c.row.line}>
                  <td>{c.row.data.name || hostnameOf(c.row.data.url)}</td>
                  <td>{c.row.data.username || '—'}</td>
                  <td>{KIND_LABEL[c.kind]}</td>
                  <td>
                    {c.kind === 'new' ? (
                      'Import'
                    ) : (
                      <select
                        aria-label={`Action for line ${c.row.line}`}
                        value={overrides[c.row.line] ?? 'default'}
                        onChange={(e) => {
                          const v = e.target.value;
                          const next = { ...overrides };
                          if (v === 'default') delete next[c.row.line];
                          else next[c.row.line] = v as ImportAction;
                          setOverrides(next);
                        }}
                      >
                        <option value="default">Default</option>
                        <option value="skip">Skip</option>
                        <option value="import">Import as new</option>
                        {c.existing && <option value="replace">Replace existing</option>}
                      </select>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {classified.length > 200 && (
            <p className="muted">Showing the first 200 of {classified.length} rows.</p>
          )}
          <label className="check">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> I
            confirm the import. Records are encrypted on this device before being sent.
          </label>
          <div className="actions">
            <button
              className="primary"
              disabled={!confirmed || (plan.toInsert.length === 0 && plan.toReplace.length === 0)}
              onClick={run}
            >
              Import
            </button>
            <button onClick={props.onClose}>Cancel</button>
          </div>
        </>
      )}

      {step === 'importing' && (
        <p role="status">
          Encrypting and uploading… {progress[0]} / {progress[1]}
        </p>
      )}

      {step === 'done' && summary && (
        <>
          <Notice kind={summary.error || summary.failed ? 'error' : 'success'}>
            Imported {summary.imported}, replaced {summary.replaced}, skipped {summary.skipped}, invalid{' '}
            {summary.invalid}
            {summary.conflicts ? `, conflicts ${summary.conflicts}` : ''}
            {summary.failed ? `, failed ${summary.failed}` : ''}.{summary.error ? ` ${summary.error}` : ''}
          </Notice>
          {summary.failed > 0 && (
            <p>
              Re-run the import with the same file: records already saved are detected as duplicates and
              skipped.
            </p>
          )}
          {props.mode === 'csv' && (
            <Notice kind="info">
              The original CSV still contains your passwords in plain text. Delete it securely (and empty the
              trash) now.
            </Notice>
          )}
          <button className="primary" onClick={props.onClose}>
            Done
          </button>
        </>
      )}
    </section>
  );
}

import type { ReactNode } from 'react';

export type NoticeKind = 'error' | 'success' | 'info';

export function Notice({ kind, children }: { kind: NoticeKind; children: ReactNode }) {
  return (
    <div className={`notice notice-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      {children}
    </div>
  );
}

export function Field(props: {
  id: string;
  label: string;
  type?: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete?: string;
  required?: boolean;
  hint?: string;
  multiline?: boolean;
  autoFocus?: boolean;
}) {
  const { id, label, value, onChange, hint } = props;
  const describedBy = hint ? `${id}-hint` : undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {props.multiline ? (
        <textarea
          id={id}
          value={value}
          rows={3}
          onChange={(e) => onChange(e.target.value)}
          aria-describedby={describedBy}
        />
      ) : (
        <input
          id={id}
          type={props.type ?? 'text'}
          value={value}
          required={props.required}
          autoComplete={props.autoComplete ?? 'off'}
          autoFocus={props.autoFocus}
          spellCheck={false}
          onChange={(e) => onChange(e.target.value)}
          aria-describedby={describedBy}
        />
      )}
      {hint && (
        <small id={`${id}-hint`} className="hint">
          {hint}
        </small>
      )}
    </div>
  );
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? 'unknown' : d.toLocaleString();
}

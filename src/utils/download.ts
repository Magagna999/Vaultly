/** Saves a text file through the browser's normal download flow (user-initiated only). */
export function downloadText(filename: string, content: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function generatePassword(length = 20): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
  const out: string[] = [];
  const limit = 256 - (256 % chars.length); // rejection sampling: no modulo bias
  while (out.length < length) {
    for (const b of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (b < limit && out.length < length) out.push(chars[b % chars.length] as string);
    }
  }
  return out.join('');
}

export const CLIPBOARD_CLEAR_MS = 30_000;

/** Copies on explicit user action and (best effort) clears the clipboard afterwards. */
export async function copyToClipboard(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
  setTimeout(() => {
    void navigator.clipboard.writeText('').catch(() => undefined);
  }, CLIPBOARD_CLEAR_MS);
}

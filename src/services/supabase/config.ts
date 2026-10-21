/** Public Supabase settings, injected at build time (see .env.example). */
export function getSupabaseConfig(): { url: string; anonKey: string } | null {
  const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
  const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;
  if (!url || !anonKey || url.includes('YOUR-PROJECT') || anonKey.startsWith('YOUR-')) return null;
  return { url, anonKey };
}

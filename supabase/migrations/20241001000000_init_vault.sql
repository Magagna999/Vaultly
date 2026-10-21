-- Chrome Password Vault - initial schema (idempotent, safe to re-run).
-- The server only ever stores ciphertext. Passwords, usernames, URLs and notes
-- are encrypted client-side (AES-256-GCM) before they reach these tables.

create extension if not exists pgcrypto;

---------------------------------------------------------------------------
-- vaults: public key-derivation parameters (NO secrets) + password verifier
---------------------------------------------------------------------------
create table if not exists public.vaults (
  user_id             uuid primary key default auth.uid() references auth.users (id) on delete cascade,
  kdf                 text        not null default 'PBKDF2-SHA256' check (kdf = 'PBKDF2-SHA256'),
  kdf_iterations      integer     not null check (kdf_iterations between 100000 and 10000000),
  -- base64 of 16..64 random bytes -> 24..88 chars
  salt                text        not null check (char_length(salt) between 24 and 88),
  verifier_ciphertext text        not null check (char_length(verifier_ciphertext) between 1 and 512),
  -- base64 of a 12-byte IV is exactly 16 chars
  verifier_iv         text        not null check (char_length(verifier_iv) = 16),
  encryption_version  smallint    not null default 1 check (encryption_version >= 1),
  schema_version      smallint    not null default 1,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);

---------------------------------------------------------------------------
-- credentials: one encrypted blob per credential
---------------------------------------------------------------------------
create table if not exists public.credentials (
  id                 uuid        primary key default gen_random_uuid(),
  user_id            uuid        not null default auth.uid() references auth.users (id) on delete cascade,
  ciphertext         text        not null check (char_length(ciphertext) between 24 and 262144),
  iv                 text        not null check (char_length(iv) = 16),
  encryption_version smallint    not null default 1 check (encryption_version >= 1),
  -- incremented by trigger on every update; used for optimistic concurrency
  revision           integer     not null default 1,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

create index if not exists credentials_user_id_updated_at_idx
  on public.credentials (user_id, updated_at desc);

---------------------------------------------------------------------------
-- Triggers: server-controlled revision/timestamps; immutable ownership
---------------------------------------------------------------------------
create or replace function public.vault_touch_row()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if new.user_id is distinct from old.user_id then
    raise exception 'user_id is immutable';
  end if;
  new.created_at := old.created_at;
  new.updated_at := now();
  if tg_table_name = 'credentials' then
    if new.id is distinct from old.id then
      raise exception 'id is immutable';
    end if;
    new.revision := old.revision + 1;
  end if;
  return new;
end;
$$;

drop trigger if exists credentials_touch on public.credentials;
create trigger credentials_touch before update on public.credentials
  for each row execute function public.vault_touch_row();

drop trigger if exists vaults_touch on public.vaults;
create trigger vaults_touch before update on public.vaults
  for each row execute function public.vault_touch_row();

---------------------------------------------------------------------------
-- Row Level Security: owner-only, per operation. No anonymous access.
---------------------------------------------------------------------------
alter table public.vaults      enable row level security;
alter table public.vaults      force  row level security;
alter table public.credentials enable row level security;
alter table public.credentials force  row level security;

revoke all on public.vaults, public.credentials from anon, public;
grant select, insert, update, delete on public.vaults, public.credentials to authenticated;

drop policy if exists vaults_select_own on public.vaults;
drop policy if exists vaults_insert_own on public.vaults;
drop policy if exists vaults_update_own on public.vaults;
drop policy if exists vaults_delete_own on public.vaults;
create policy vaults_select_own on public.vaults for select to authenticated
  using (user_id = (select auth.uid()));
create policy vaults_insert_own on public.vaults for insert to authenticated
  with check (user_id = (select auth.uid()));
create policy vaults_update_own on public.vaults for update to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy vaults_delete_own on public.vaults for delete to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists credentials_select_own on public.credentials;
drop policy if exists credentials_insert_own on public.credentials;
drop policy if exists credentials_update_own on public.credentials;
drop policy if exists credentials_delete_own on public.credentials;
create policy credentials_select_own on public.credentials for select to authenticated
  using (user_id = (select auth.uid()));
create policy credentials_insert_own on public.credentials for insert to authenticated
  with check (user_id = (select auth.uid()));
create policy credentials_update_own on public.credentials for update to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy credentials_delete_own on public.credentials for delete to authenticated
  using (user_id = (select auth.uid()));

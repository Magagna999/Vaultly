-- MANUAL check (needs a real Supabase/Postgres). Run in the SQL editor or psql
-- AFTER applying the migration. Creates two fake users, verifies isolation, rolls back.
begin;
insert into auth.users (id, instance_id, aud, role, email)
values ('00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-000000000000','authenticated','authenticated','a@test.invalid'),
       ('00000000-0000-0000-0000-0000000000b2','00000000-0000-0000-0000-000000000000','authenticated','authenticated','b@test.invalid');

set local role authenticated;

-- user A inserts a row
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-0000000000a1","role":"authenticated"}', true);
insert into public.credentials (id, ciphertext, iv) values
  ('11111111-1111-1111-1111-111111111111', repeat('A', 32), 'AAAAAAAAAAAAAAAA');

-- user B must see nothing, and cannot update/delete/insert-as-A
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-0000000000b2","role":"authenticated"}', true);
do $$
declare n int;
begin
  select count(*) into n from public.credentials;
  if n <> 0 then raise exception 'FAIL: B can read A rows (%).', n; end if;
  update public.credentials set ciphertext = repeat('B', 32);
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL: B updated A rows'; end if;
  delete from public.credentials;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL: B deleted A rows'; end if;
  begin
    insert into public.credentials (user_id, ciphertext, iv)
    values ('00000000-0000-0000-0000-0000000000a1', repeat('C', 32), 'AAAAAAAAAAAAAAAA');
    raise exception 'FAIL: B inserted a row owned by A';
  exception when insufficient_privilege then null;
  end;
end $$;

-- anon has no access at all
reset role; set local role anon;
do $$
begin
  perform 1 from public.credentials;
  raise exception 'FAIL: anon can query credentials';
exception when insufficient_privilege then null;
end $$;
rollback;
select 'RLS isolation checks passed' as result;

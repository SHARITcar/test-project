-- routes/login.py already reads profiles.account_status (to block suspended/deleted
-- accounts at login) but no prior migration defines it -- formalizing it here so the
-- schema matches what the app actually depends on. Also adds the storage bucket used
-- for profile photo uploads, mirroring the existing group-photos bucket pattern.
-- Apply this migration in Supabase SQL editor.

alter table public.profiles
  add column if not exists account_status text not null default 'active'
    check (account_status in ('active', 'suspended', 'deleted'));

insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true)
on conflict (id) do nothing;

drop policy if exists avatars_public_read on storage.objects;
create policy avatars_public_read
on storage.objects
for select
using (bucket_id = 'avatars');

drop policy if exists avatars_owner_write on storage.objects;
create policy avatars_owner_write
on storage.objects
for insert
with check (bucket_id = 'avatars' and auth.uid() is not null);

drop policy if exists avatars_owner_update on storage.objects;
create policy avatars_owner_update
on storage.objects
for update
using (bucket_id = 'avatars' and auth.uid() is not null);

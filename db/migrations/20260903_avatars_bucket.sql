-- The avatars bucket referenced by routes/profile_settings.py
-- (upload_profile_photo, AVATAR_BUCKET env var default) never existed,
-- so every profile photo upload failed regardless of file size.
-- Mirrors the existing group-photos/trip-photos bucket policy pattern.
-- Apply this migration in Supabase SQL editor.

insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true)
on conflict (id) do nothing;

drop policy if exists avatars_public_read on storage.objects;
create policy avatars_public_read
on storage.objects
for select
using (bucket_id = 'avatars');

drop policy if exists avatars_member_write on storage.objects;
create policy avatars_member_write
on storage.objects
for insert
with check (bucket_id = 'avatars' and auth.role() = 'authenticated');

drop policy if exists avatars_member_update on storage.objects;
create policy avatars_member_update
on storage.objects
for update
using (bucket_id = 'avatars' and auth.role() = 'authenticated');

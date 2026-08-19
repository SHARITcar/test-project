-- Fix: the Supabase client always does INSERT ... RETURNING, which requires the new
-- row to pass a SELECT policy too. car_sharing_groups only had groups_select_member
-- (requires an existing group_members row) and groups_select_inviteable (requires an
-- existing invitation_links row) -- neither exists yet at the moment a group itself is
-- being created, so group creation always failed with 42501 (RLS violation) before this
-- fix. Pre-existing gap from the very first groups migration, never exercised end-to-end
-- until now.
-- Apply this migration in Supabase SQL editor.

drop policy if exists groups_select_creator on public.car_sharing_groups;
create policy groups_select_creator
on public.car_sharing_groups
for select
using (created_by = auth.uid());

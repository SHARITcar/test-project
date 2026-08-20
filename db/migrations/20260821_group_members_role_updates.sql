-- Multi-owner groups: an owner can promote other members to owner or demote co-owners
-- back to member (app layer enforces at least one owner always remains). This requires
-- an UPDATE policy on group_members, which didn't exist before -- RLS was silently
-- blocking the ownership-transfer-on-leave update added in the previous change.
-- Apply this migration in Supabase SQL editor, after 20260818_fix_group_members_rls_recursion.sql.

drop policy if exists members_update_owner on public.group_members;
create policy members_update_owner
on public.group_members
for update
using (public.is_group_owner(group_members.group_id, auth.uid()))
with check (public.is_group_owner(group_members.group_id, auth.uid()));

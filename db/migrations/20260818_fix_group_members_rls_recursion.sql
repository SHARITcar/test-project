-- Fix: members_select_group and members_delete_owner (from 20260818_group_management.sql)
-- subquery group_members from within a policy ON group_members, which makes Postgres
-- re-evaluate the same RLS policy recursively (infinite recursion, error 42P17). This
-- broke every query touching group_members, and by extension car_sharing_groups, trips,
-- costs, and invites (their policies subquery group_members too, cascading the failure).
-- Apply this migration in Supabase SQL editor.

create or replace function public.is_group_member(p_group_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.group_members
    where group_id = p_group_id and user_id = p_user_id
  );
$$;

create or replace function public.is_group_owner(p_group_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.group_members
    where group_id = p_group_id and user_id = p_user_id and role = 'owner'
  );
$$;

drop policy if exists members_select_group on public.group_members;
create policy members_select_group
on public.group_members
for select
using (public.is_group_member(group_members.group_id, auth.uid()));

drop policy if exists members_delete_owner on public.group_members;
create policy members_delete_owner
on public.group_members
for delete
using (public.is_group_owner(group_members.group_id, auth.uid()));

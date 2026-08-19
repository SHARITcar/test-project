-- Group management: edit group settings, view/leave/remove members
-- Apply this migration in Supabase SQL editor, after the previous group migrations.

-- Members can edit group settings (name, license plate, price/km, reminder type,
-- internal agreements). CLAUDE.md trust model: "Edit group settings: Yes" for any member.
drop policy if exists groups_update_member on public.car_sharing_groups;
create policy groups_update_member
on public.car_sharing_groups
for update
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = car_sharing_groups.id
      and gm.user_id = auth.uid()
  )
)
with check (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = car_sharing_groups.id
      and gm.user_id = auth.uid()
  )
);

-- Members can see the full member list of groups they belong to
-- (previously each user could only see their own membership row).
drop policy if exists members_select_group on public.group_members;
create policy members_select_group
on public.group_members
for select
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = group_members.group_id
      and gm.user_id = auth.uid()
  )
);

-- A member can remove their own membership (leave group).
drop policy if exists members_delete_own on public.group_members;
create policy members_delete_own
on public.group_members
for delete
using (user_id = auth.uid());

-- The group owner can remove other members.
drop policy if exists members_delete_owner on public.group_members;
create policy members_delete_owner
on public.group_members
for delete
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = group_members.group_id
      and gm.user_id = auth.uid()
      and gm.role = 'owner'
  )
);

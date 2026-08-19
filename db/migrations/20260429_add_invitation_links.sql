-- SRS-IHKUC7RHIFEC: Join Group Via Invitation Link
-- Apply this migration after 20260429_create_car_sharing_groups.sql

create extension if not exists pgcrypto;

create table if not exists public.invitation_links (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.car_sharing_groups(id) on delete cascade,
  token text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  max_uses integer check (max_uses is null or max_uses > 0),
  use_count integer not null default 0,
  is_active boolean not null default true
);

create index if not exists idx_invitation_links_group_id
  on public.invitation_links(group_id);

create index if not exists idx_invitation_links_active
  on public.invitation_links(is_active, expires_at);

create table if not exists public.invitation_link_usage (
  id uuid primary key default gen_random_uuid(),
  invitation_link_id uuid not null references public.invitation_links(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  accepted_at timestamptz not null default now(),
  invited_email text,
  unique (invitation_link_id, user_id)
);

create index if not exists idx_invitation_link_usage_user
  on public.invitation_link_usage(user_id);

alter table public.car_sharing_groups
  add column if not exists member_count integer not null default 0;

update public.car_sharing_groups g
set member_count = counts.total_members
from (
  select group_id, count(*)::int as total_members
  from public.group_members
  group by group_id
) counts
where counts.group_id = g.id;

-- Backfill invitation links from existing group invite_link URLs.
insert into public.invitation_links(group_id, token, created_at)
select
  g.id,
  split_part(g.invite_link, '/invite/', 2),
  g.created_at
from public.car_sharing_groups g
where g.invite_link is not null
  and g.invite_link like '%/invite/%'
  and split_part(g.invite_link, '/invite/', 2) <> ''
on conflict (token) do nothing;

alter table public.invitation_links enable row level security;
alter table public.invitation_link_usage enable row level security;

-- Public invite validation by token.
drop policy if exists invitation_links_select_active on public.invitation_links;
create policy invitation_links_select_active
on public.invitation_links
for select
using (is_active = true);

-- Group members can create links for groups they are part of.
drop policy if exists invitation_links_insert_member on public.invitation_links;
create policy invitation_links_insert_member
on public.invitation_links
for insert
with check (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = invitation_links.group_id
      and gm.user_id = auth.uid()
  )
);

-- Group members can update links for groups they are part of.
drop policy if exists invitation_links_update_member on public.invitation_links;
create policy invitation_links_update_member
on public.invitation_links
for update
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = invitation_links.group_id
      and gm.user_id = auth.uid()
  )
)
with check (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = invitation_links.group_id
      and gm.user_id = auth.uid()
  )
);

-- Users can read/write their own invitation usage records.
drop policy if exists invitation_usage_select_own on public.invitation_link_usage;
create policy invitation_usage_select_own
on public.invitation_link_usage
for select
using (user_id = auth.uid());

drop policy if exists invitation_usage_insert_own on public.invitation_link_usage;
create policy invitation_usage_insert_own
on public.invitation_link_usage
for insert
with check (user_id = auth.uid());

-- Expose inviteable groups for invite-preview/join screens.
drop policy if exists groups_select_inviteable on public.car_sharing_groups;
create policy groups_select_inviteable
on public.car_sharing_groups
for select
using (
  exists (
    select 1 from public.invitation_links il
    where il.group_id = car_sharing_groups.id
      and il.is_active = true
      and (il.expires_at is null or il.expires_at > now())
      and (il.max_uses is null or il.use_count < il.max_uses)
  )
);

-- Expose members of inviteable groups for participant preview.
drop policy if exists members_select_inviteable_group on public.group_members;
create policy members_select_inviteable_group
on public.group_members
for select
using (
  exists (
    select 1 from public.invitation_links il
    where il.group_id = group_members.group_id
      and il.is_active = true
      and (il.expires_at is null or il.expires_at > now())
      and (il.max_uses is null or il.use_count < il.max_uses)
  )
);

-- SRS-5ZZ4KZAIJVHK: Create Car-Sharing Group
-- Apply this migration in Supabase SQL editor.

create extension if not exists pgcrypto;

create table if not exists public.car_sharing_groups (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  license_plate text,
  photo_url text,
  price_per_km numeric(10, 4) not null check (price_per_km > 0),
  reminder_type text not null,
  internal_agreements jsonb,
  invite_link text not null unique,
  created_by uuid not null references auth.users(id) on delete cascade,
  idempotency_key text,
  shipping_address jsonb,
  payment_completed boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (created_by, idempotency_key)
);

create table if not exists public.group_members (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.car_sharing_groups(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member',
  joined_at timestamptz not null default now(),
  unique (group_id, user_id)
);

create table if not exists public.group_fixed_costs (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.car_sharing_groups(id) on delete cascade,
  cost_type text not null,
  amount numeric(10, 2) not null check (amount >= 0),
  description text,
  created_at timestamptz not null default now()
);

create table if not exists public.reminder_types (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text,
  is_physical boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.profiles
  add column if not exists active_group_id uuid references public.car_sharing_groups(id);

create index if not exists idx_groups_created_by
  on public.car_sharing_groups(created_by);

create index if not exists idx_group_members_user_id
  on public.group_members(user_id);

create index if not exists idx_group_fixed_costs_group_id
  on public.group_fixed_costs(group_id);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_car_sharing_groups_updated_at on public.car_sharing_groups;
create trigger trg_car_sharing_groups_updated_at
before update on public.car_sharing_groups
for each row execute function public.set_updated_at();

insert into public.reminder_types(name, description, is_physical)
values
  ('Push notification', 'In-app and push reminders', false),
  ('Email reminder', 'Reminder sent to your email', false),
  ('Physical sticker', 'Mailed physical reminder sticker for the car', true)
on conflict (name) do nothing;

alter table public.car_sharing_groups enable row level security;
alter table public.group_members enable row level security;
alter table public.group_fixed_costs enable row level security;
alter table public.reminder_types enable row level security;

-- Users can create and view groups they belong to.
drop policy if exists groups_select_member on public.car_sharing_groups;
create policy groups_select_member
on public.car_sharing_groups
for select
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = car_sharing_groups.id
      and gm.user_id = auth.uid()
  )
);

drop policy if exists groups_insert_creator on public.car_sharing_groups;
create policy groups_insert_creator
on public.car_sharing_groups
for insert
with check (created_by = auth.uid());

drop policy if exists members_select_own on public.group_members;
create policy members_select_own
on public.group_members
for select
using (user_id = auth.uid());

drop policy if exists members_insert_own on public.group_members;
create policy members_insert_own
on public.group_members
for insert
with check (user_id = auth.uid());

drop policy if exists fixed_costs_select_member on public.group_fixed_costs;
create policy fixed_costs_select_member
on public.group_fixed_costs
for select
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = group_fixed_costs.group_id
      and gm.user_id = auth.uid()
  )
);

drop policy if exists fixed_costs_insert_member on public.group_fixed_costs;
create policy fixed_costs_insert_member
on public.group_fixed_costs
for insert
with check (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = group_fixed_costs.group_id
      and gm.user_id = auth.uid()
  )
);

-- Reminder types are readable by authenticated users.
drop policy if exists reminder_types_select_auth on public.reminder_types;
create policy reminder_types_select_auth
on public.reminder_types
for select
using (auth.role() = 'authenticated');

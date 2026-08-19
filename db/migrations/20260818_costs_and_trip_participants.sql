-- Costs tab (expense tracking) + trip participants (usage weighting for cost splits)
-- Apply this migration in Supabase SQL editor, after 20260818_create_trips.sql.

create table if not exists public.trip_participants (
  trip_id uuid not null references public.trips(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  primary key (trip_id, user_id)
);

create index if not exists idx_trip_participants_user on public.trip_participants(user_id);

alter table public.trip_participants enable row level security;

drop policy if exists trip_participants_select_member on public.trip_participants;
create policy trip_participants_select_member
on public.trip_participants
for select
using (
  exists (
    select 1 from public.trips t
    join public.group_members gm on gm.group_id = t.group_id
    where t.id = trip_participants.trip_id
      and gm.user_id = auth.uid()
  )
);

drop policy if exists trip_participants_insert_member on public.trip_participants;
create policy trip_participants_insert_member
on public.trip_participants
for insert
with check (
  exists (
    select 1 from public.trips t
    join public.group_members gm on gm.group_id = t.group_id
    where t.id = trip_participants.trip_id
      and gm.user_id = auth.uid()
  )
);

drop policy if exists trip_participants_delete_member on public.trip_participants;
create policy trip_participants_delete_member
on public.trip_participants
for delete
using (
  exists (
    select 1 from public.trips t
    join public.group_members gm on gm.group_id = t.group_id
    where t.id = trip_participants.trip_id
      and gm.user_id = auth.uid()
  )
);

create table if not exists public.costs (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.car_sharing_groups(id) on delete cascade,
  category text not null check (category in ('Insurance', 'Gasoline', 'Tax', 'Maintenance')),
  paid_by uuid not null references auth.users(id) on delete cascade,
  amount numeric(10, 2) not null check (amount > 0),
  cost_date date not null default current_date,
  notes text,
  logged_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_costs_group_id on public.costs(group_id);

drop trigger if exists trg_costs_updated_at on public.costs;
create trigger trg_costs_updated_at
before update on public.costs
for each row execute function public.set_updated_at();

alter table public.costs enable row level security;

drop policy if exists costs_select_member on public.costs;
create policy costs_select_member
on public.costs
for select
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = costs.group_id
      and gm.user_id = auth.uid()
  )
);

drop policy if exists costs_insert_member on public.costs;
create policy costs_insert_member
on public.costs
for insert
with check (
  logged_by = auth.uid()
  and exists (
    select 1 from public.group_members gm
    where gm.group_id = costs.group_id
      and gm.user_id = auth.uid()
  )
);

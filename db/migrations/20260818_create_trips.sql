-- Core tracking: odometer-based trip logging
-- Apply this migration in Supabase SQL editor, after the group migrations.

create table if not exists public.trips (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.car_sharing_groups(id) on delete cascade,
  logged_by uuid not null references auth.users(id) on delete cascade,
  odometer_reading numeric(10, 1) not null check (odometer_reading >= 0),
  previous_odometer_reading numeric(10, 1),
  distance_km numeric(10, 1),
  price_per_km_snapshot numeric(10, 4),
  cost numeric(10, 2),
  photo_url text,
  notes text,
  trip_date date not null default current_date,
  large_distance_confirmed boolean not null default false,
  edited_at timestamptz,
  edited_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_trips_group_id on public.trips(group_id);
create index if not exists idx_trips_group_created on public.trips(group_id, created_at);

-- Reuses public.set_updated_at() from the car_sharing_groups migration.
drop trigger if exists trg_trips_updated_at on public.trips;
create trigger trg_trips_updated_at
before update on public.trips
for each row execute function public.set_updated_at();

alter table public.trips enable row level security;

-- Transparency: any group member can view all trips for their group.
drop policy if exists trips_select_member on public.trips;
create policy trips_select_member
on public.trips
for select
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = trips.group_id
      and gm.user_id = auth.uid()
  )
);

-- Any group member can log a trip for their group.
drop policy if exists trips_insert_member on public.trips;
create policy trips_insert_member
on public.trips
for insert
with check (
  logged_by = auth.uid()
  and exists (
    select 1 from public.group_members gm
    where gm.group_id = trips.group_id
      and gm.user_id = auth.uid()
  )
);

-- CLAUDE.md trust model: "Edit trips you're part of: Yes" -- any group member, not just the logger.
drop policy if exists trips_update_member on public.trips;
create policy trips_update_member
on public.trips
for update
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = trips.group_id
      and gm.user_id = auth.uid()
  )
)
with check (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = trips.group_id
      and gm.user_id = auth.uid()
  )
);

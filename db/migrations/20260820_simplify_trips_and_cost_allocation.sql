-- Simplify trip tracking to a single flow (start + end odometer, every trip), and give
-- fixed costs an explicit participant snapshot + allocation method instead of splitting
-- every cost equally across whoever happens to be a member today.
-- Apply this migration in Supabase SQL editor, after 20260819_trip_tracking_methods.sql.

-- Trips: drop the GPS / start-only / end-only variants. odometer_start and odometer_end
-- (added in 20260819_trip_tracking_methods.sql) are now required for every trip, enforced
-- at the application layer -- not as a NOT NULL constraint here, since existing rows may
-- predate this migration and only have odometer_reading set.
alter table public.trips drop column if exists odometer_reading;
alter table public.trips drop column if exists previous_odometer_reading;
alter table public.trips drop column if exists tracking_method;

alter table public.car_sharing_groups drop column if exists tracking_method;
alter table public.car_sharing_groups drop column if exists odometer_mode;

-- Costs: snapshot which members a cost is split across (so someone who joins later
-- doesn't retroactively inherit a share of costs logged before they joined), and how.
alter table public.costs
  add column if not exists participants uuid[] not null default '{}',
  add column if not exists allocation_method text not null default 'equal'
    check (allocation_method in ('equal', 'per_km'));

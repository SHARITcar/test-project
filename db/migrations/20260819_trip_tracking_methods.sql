-- Trip tracking methods: odometer (start/end/both) vs GPS, configurable per group,
-- editable later in group settings but defaulted from group creation.
-- Apply this migration in Supabase SQL editor.

alter table public.car_sharing_groups
  add column if not exists tracking_method text not null default 'odometer'
    check (tracking_method in ('odometer', 'gps')),
  add column if not exists odometer_mode text not null default 'end_only'
    check (odometer_mode in ('start_only', 'end_only', 'both'));

alter table public.trips
  add column if not exists odometer_start numeric(10, 1),
  add column if not exists odometer_end numeric(10, 1),
  add column if not exists tracking_method text not null default 'odometer'
    check (tracking_method in ('odometer', 'gps'));

-- GPS-tracked trips have no odometer reading at all.
alter table public.trips alter column odometer_reading drop not null;

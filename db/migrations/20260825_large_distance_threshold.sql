-- Configurable per-group "long trip" confirmation threshold (was a hardcoded 150km,
-- now defaults to 250km and can be changed per group in group settings).
-- Apply this migration in Supabase SQL editor.

alter table public.car_sharing_groups
  add column if not exists large_distance_threshold_km numeric(6, 1) not null default 250
    check (large_distance_threshold_km > 0);

-- Cost-splitting v2: fuel becomes an automatic per-trip charge (split by participant km),
-- fixed costs become an equal split, and trips track calibration state.
-- Apply this migration in Supabase SQL editor, after 20260818_costs_and_trip_participants.sql.

alter table public.trips
  add column if not exists provisional boolean not null default true;

-- Fixed-cost categories only: fuel is no longer manually logged (see routes/trips.py --
-- it's priced automatically per trip via price_per_km_snapshot / ratePerKmAtTimeOfTrip).
alter table public.costs drop constraint if exists costs_category_check;
alter table public.costs
  add constraint costs_category_check check (category in ('Insurance', 'Tax', 'Depreciation'));

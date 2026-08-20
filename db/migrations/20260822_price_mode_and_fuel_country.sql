-- Persist the price-per-km mode (auto-suggest vs. fixed manual) and the fuel-price
-- country used to compute the suggestion, so both survive past group creation and can
-- be changed later in group settings.
-- Apply this migration in Supabase SQL editor.

alter table public.car_sharing_groups
  add column if not exists price_per_km_mode text not null default 'manual'
    check (price_per_km_mode in ('auto', 'manual')),
  add column if not exists fuel_country text not null default 'NL'
    check (fuel_country in ('NL', 'BE', 'DE'));

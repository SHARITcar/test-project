-- Fixed costs need a payer (who may not be a group member yet -- stored as a
-- plain name to be linked to a real member later from group settings) and a
-- billing period, since users think in monthly amounts for things like
-- insurance even though the underlying figure should be comparable on a
-- consistent (annual) basis.
-- Apply this migration in Supabase SQL editor.

alter table public.group_fixed_costs
  add column if not exists paid_by_name text,
  add column if not exists period text not null default 'year'
    check (period in ('month', 'quarter', 'year'));

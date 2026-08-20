-- Receipt photos for logged costs, mirroring trips.photo_url / the existing
-- trip-photos storage bucket pattern.
-- Apply this migration in Supabase SQL editor.

alter table public.costs
  add column if not exists photo_url text;

-- Any group member can edit a cost, matching the existing trips_update_member policy
-- and the trust model ("Edit trips you're part of: Yes").
drop policy if exists costs_update_member on public.costs;
create policy costs_update_member
on public.costs
for update
using (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = costs.group_id
      and gm.user_id = auth.uid()
  )
)
with check (
  exists (
    select 1 from public.group_members gm
    where gm.group_id = costs.group_id
      and gm.user_id = auth.uid()
  )
);

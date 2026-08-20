-- Group creation wizard v2: simplified reminder options, fixed-cost split method,
-- and a unified fixed-cost category taxonomy shared with the ongoing Costs tab.
-- No real users/groups exist yet, so old reminder_types rows are safely removable.
-- Apply this migration in Supabase SQL editor.

delete from public.reminder_types where name in ('Push notification', 'Email reminder');

update public.reminder_types
set name = 'Physical reminder',
    description = 'A QR sticker or NFC tag mailed to your address'
where name = 'Physical sticker';

insert into public.reminder_types (name, description, is_physical)
values ('No reminder', 'Skip the physical reminder for now', false)
on conflict (name) do nothing;

alter table public.group_fixed_costs
  add column if not exists split_method text not null default 'equal'
    check (split_method in ('equal', 'per_km'));

alter table public.costs drop constraint if exists costs_category_check;

update public.costs set category = 'Car insurance' where category = 'Insurance';
update public.costs set category = 'Road tax' where category = 'Tax';
update public.costs set category = 'Fixed depreciation' where category = 'Depreciation';

alter table public.costs
  add constraint costs_category_check
    check (category in ('Car insurance', 'Road tax', 'Parking permit', 'Fixed depreciation'));

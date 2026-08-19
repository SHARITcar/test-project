-- First-time onboarding + contextual tips.
-- `onboarding_completed` (existing column) is reused as the account-level
-- hasCompletedOnboarding flag -- it already gates entry to /dashboard and
-- create_group, which is exactly this spec's trigger semantics.
-- Apply this migration in Supabase SQL editor.

alter table public.profiles
  add column if not exists seen_tips text[] not null default '{}';

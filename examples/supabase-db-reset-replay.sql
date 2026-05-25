-- Redacted note from a local Supabase replay check.
-- A teammate asked whether supabase db reset will replay historical migrations
-- with the new Data API explicit-grants default.

create table public.launch_notes (
  id uuid primary key,
  owner_id uuid not null,
  body text not null
);

alter table public.launch_notes enable row level security;

create policy launch_notes_owner_read
on public.launch_notes for select
to authenticated
using ((select auth.uid()) = owner_id);

-- Missing from historical migration:
-- grant select on table public.launch_notes to authenticated;
-- alter default privileges for role postgres in schema public revoke select, insert, update, delete on tables from anon, authenticated;

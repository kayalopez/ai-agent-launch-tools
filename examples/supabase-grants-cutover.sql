-- Redacted launch packet for the 2026 Supabase Data API grants cutover.
-- Fictional identifiers only. Do not paste real user data or credentials.

-- Browser smoke test now returns:
-- code: 42501
-- message: permission denied for table project_notes

create table public.project_notes (
  id uuid primary key,
  project_id uuid not null,
  owner_id uuid not null,
  note text not null,
  created_at timestamptz not null default now()
);

alter table public.project_notes enable row level security;

create policy project_notes_owner_read
on public.project_notes
for select
to authenticated
using ((select auth.uid()) = owner_id);

-- Temporary launch fix pasted during debugging. The reviewer should block this.
grant all on public.project_notes to anon, authenticated;

create policy temporary_project_notes_read
on public.project_notes
for select
to anon
using (true);

create or replace function public.project_summary(project_id uuid)
returns jsonb
language sql
security invoker
as $$
  select jsonb_build_object('project_id', project_id, 'status', 'redacted');
$$;

-- No default privilege revoke evidence is included yet.
-- No function EXECUTE revoke/grant evidence is included for this RPC yet.

-- Redacted packet for a supabase db pull migration that replays 42501 locally.
-- Source: supabase db pull generated migration, then supabase db reset.

revoke select on table "public"."project_notes" from "anon";
revoke select on table "public"."project_notes" from "authenticated";
revoke insert on table "public"."project_notes" from "authenticated";
revoke update on table "public"."project_notes" from "authenticated";

alter table "public"."project_notes" enable row level security;

create policy "owners can read notes"
on "public"."project_notes"
for select
to authenticated
using ((select auth.uid()) = owner_id);

-- Local reset symptom:
-- {"code":"42501","message":"permission denied for table project_notes"}
-- No reviewed grant patch is included yet.

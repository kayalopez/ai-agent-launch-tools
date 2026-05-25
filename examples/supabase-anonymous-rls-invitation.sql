-- Redacted packet: anonymous sign-in is enabled for a launch preview.
-- The app lets users start without email, then upgrade later.

alter table public.team_invitations enable row level security;

create policy "invited users can accept invitations"
on public.team_invitations
for update
to authenticated
using (
  invited_email = (
    select email
    from auth.users
    where id = (select auth.uid())
  )
)
with check (
  invited_email = (
    select email
    from auth.users
    where id = (select auth.uid())
  )
);

grant update on public.team_invitations to authenticated;

-- Known historical fixture: some old invitation rows have invited_email = null.
-- Expected review: anonymous signed-in sessions must not accept invitations.

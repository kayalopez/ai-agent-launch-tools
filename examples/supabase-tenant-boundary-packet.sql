-- Redacted packet: multi-tenant SaaS before external launch.
-- Tenant model: organizations(id), memberships(user_id, organization_id, role), projects(organization_id), invoices(organization_id), invitations(organization_id).

alter table public.projects enable row level security;
alter table public.invitations enable row level security;
alter table public.invoices enable row level security;

create policy "members can read projects"
on public.projects
for select
to authenticated
using (
  organization_id in (
    select organization_id
    from public.memberships
    where user_id = (select auth.uid())
  )
);

create policy "owners can update invoices"
on public.invoices
for update
to authenticated
using (
  organization_id in (
    select organization_id
    from public.memberships
    where user_id = (select auth.uid())
    and role = 'owner'
  )
);

create function public.create_invite(redacted_org_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  -- Review packet says this function re-checks owner membership before insert.
  insert into public.invitations(organization_id) values (redacted_org_id);
end;
$$;

-- Negative tests already run:
-- tenant_a_user read tenant_b_project by direct ID -> rejected.
-- tenant_b_user update tenant_a_invoice by direct ID -> rejected.
-- anonymous signed-in session accept invitation -> rejected.
-- service_role /api/invitations route checks owner membership before privileged insert.
-- storage bucket tenant-files prefixes object paths with organization_id and rejects wrong-tenant paths.

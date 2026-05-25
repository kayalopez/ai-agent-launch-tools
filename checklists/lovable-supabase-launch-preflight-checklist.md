# Lovable Supabase Launch Preflight Checklist

Use this checklist before shipping a Lovable, Bolt, v0, Cursor, or other generated Supabase app to real users.

The goal is a redacted launch packet, not private database access. Do not paste service-role keys, connection strings, API keys, OAuth material, customer rows, private screenshots, payment records, full names, private handles, or full transaction identifiers.

## 1. Backend ownership

- Identify whether the app is using Lovable Cloud, a directly managed Supabase project, or both.
- Record who can change schema, RLS policies, Storage policies, Edge Functions, and environment variables.
- Confirm the launch owner has a non-secret way to reproduce schema and policy state from migrations or documented setup steps.

## 2. Generated public tables

- List every generated `public` table that browser code calls through `supabase-js`, REST, or GraphQL.
- Put explicit `GRANT` statements beside the table and policy migration for intended Data API callers.
- Treat broad grants as rollback SQL, not the final launch migration.
- Run a local replay check so `supabase db reset` rebuilds the same reachability instead of depending on dashboard defaults.

## 3. RLS evidence

For each table that stores user, tenant, billing, profile, membership, invitation, or owner state, record smoke-test evidence for:

- no session
- anonymous user, if anonymous sign-in is enabled
- authenticated owner
- wrong owner
- wrong tenant or wrong organization
- deleted, transferred, or downgraded owner state

Do not count "RLS is enabled" as evidence by itself. The policy shape and negative tests matter.

## 4. Storage upsert evidence

For avatar, profile-image, document, attachment, export, or generated-file buckets, record:

- upload/insert behavior
- overwrite or `upsert: true` behavior
- list behavior
- download behavior
- delete behavior
- wrong-tenant or wrong-path behavior

Storage object policies are separate from table RLS. An app can have reasonable table policies and still fail or overexpose object paths.

## 5. RPC, function, and view reachability

- List browser-callable RPCs and views.
- Record intended callable roles.
- Confirm explicit `EXECUTE` or `SELECT` grants where needed.
- Review `SECURITY DEFINER`, search path, and caller-context assumptions before using an RPC to bypass a permission error.

## 6. Redacted next step

Use the no-login preflight page to turn the notes above into a packet:

<https://ai-launch-risk-check-public.vercel.app/lovable-supabase-launch-preflight.html>

Then run the generated-app checker or grants checker:

- <https://ai-launch-risk-check-public.vercel.app/supabase-generated-app-launch-check.html>
- <https://ai-launch-risk-check-public.vercel.app/supabase-api-grants-readiness.html>

For CI or local generated migration review:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.29 supabase-grants-cutover --file supabase_grants.redacted.sql --fail-on high
```

## Fixed-scope report fit

Use the fixed-scope Supabase Launch Risk Report only when one redacted packet needs a second pass within 24 hours:

<https://ai-launch-risk-check-public.vercel.app/supabase-launch-risk-report.html>

# Supabase Data API Grants Deadline Checklist

Use this checklist when a Supabase project reaches the May 30, 2026 new-project default or the October 30, 2026 existing-project rollout for explicit Data API grants.

This is for redacted migration review only. Do not paste service-role keys, connection strings, JWTs, customer records, payment records, private dashboard screenshots, full names, private handles, or full transaction identifiers into public issues, comments, AI prompts, or shared reports.

## What Changed

Supabase is moving public-schema Data API exposure from implicit grants to explicit grants. A table can have good RLS and still be unreachable through `supabase-js`, REST, or GraphQL if the role lacks a grant. The opposite is also risky: a broad grant can restore reachability while exposing tables or functions that should have stayed internal.

Review these as separate layers:

- **Grant reachability:** can `anon`, `authenticated`, or `service_role` reach the table, sequence, view, or function through the Data API?
- **RLS behavior:** after the role can reach the object, do policies still deny rows outside the intended user, tenant, account, or public-content boundary?
- **RPC/function access:** does each callable function have explicit `EXECUTE` revoke/grant evidence and a caller-context test?

## Redacted Packet To Prepare

Create one redacted text packet with:

- The `CREATE TABLE`, `ALTER TABLE`, `GRANT`, `REVOKE`, and `CREATE POLICY` statements for the affected tables.
- Any `ALTER DEFAULT PRIVILEGES` statements for tables, functions, and sequences in `public`.
- Any `42501` PostgREST error hint, with project refs, emails, tokens, and IDs removed.
- Any `supabase db pull` generated `REVOKE` block, `supabase db reset`, or local replay note showing whether historical migrations include the new explicit grants.
- The app path that should reach each object: no session, `anon`, authenticated user, service-side code, or admin-only path.
- One expected-pass and one expected-deny smoke test per role.
- Function/RPC `EXECUTE` grants, especially for functions created by AI tools or migration generators.

## Review Steps

1. List every public-schema table the browser or mobile app calls through `supabase-js`, REST, or GraphQL.
2. For each table, write the minimum role-specific grants next to the table migration.
3. Enable RLS and keep the policy next to the grant in the same migration review.
4. Reject broad restore commands unless there is a reviewed reason for every table and role.
5. Run `supabase db reset` against a disposable local project to confirm historical migrations replay the grants.
6. Check sequences separately if inserts depend on generated IDs.
7. Check functions separately because table RLS does not control function execution.
8. Run one no-session request, one `anon` request, and one authenticated request against the new table path.
9. If the app is multi-tenant, add a wrong-tenant read/update/delete test for the same table.
10. If an Edge Function uses service role, map the endpoint to its caller authorization check.
11. Save the final role matrix as launch evidence before the migration ships.

## CLI Gate

Run the dependency-free local checker on a redacted packet:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.29 supabase-grants-cutover --file supabase_grants.redacted.sql --fail-on high
```

The CLI does not connect to Supabase. It only reads local redacted text and flags missing grants, local `db reset` replay gaps, `db pull` generated `REVOKE` replay risk, broad grants, default-privilege state, function `EXECUTE` evidence, disabled RLS, permissive policies, anonymous-session boundaries, and `42501` grant hints.

## Browser Tools

- Free grants checker: <https://ai-launch-risk-check-public.vercel.app/supabase-api-grants-readiness.html>
- db pull REVOKE replay checker: <https://ai-launch-risk-check-public.vercel.app/supabase-db-pull-revoke-replay.html>
- Grant migration builder: <https://ai-launch-risk-check-public.vercel.app/supabase-grant-migration-builder.html>
- Sample Supabase report: <https://ai-launch-risk-check-public.vercel.app/sample-supabase-grants-rls-report.md>
- Fixed-scope report overview: <https://ai-launch-risk-check-public.vercel.app/supabase-launch-risk-report.html>

## Good Paid-Report Fit

Use the fixed-scope Supabase Launch Risk Report when:

- The free checker returns a high or medium finding.
- A generated migration adds broad grants, missing grants, or new functions.
- A launch depends on the May 30 or October 30 grant behavior.
- You need one concise 24-hour Markdown report for a redacted packet, not a deep source-code audit.

Do not buy the report if you need legal advice, compliance certification, penetration testing, incident response, or review of private production data.

## Sources

- Supabase discussion `#45329`: <https://github.com/orgs/supabase/discussions/45329>
- Supabase Data API security docs: <https://supabase.com/docs/guides/api/securing-your-api>

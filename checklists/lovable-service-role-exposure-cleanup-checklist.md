# Lovable / Supabase Service-Role Exposure Cleanup Checklist

Use this when a Lovable, v0, Bolt, Cursor, or other generated Supabase app may have exposed a `service_role` key, `sb_secret_...` key, database URL, or privileged Supabase client path in browser code.

Do not paste raw keys, OAuth tokens, cookies, customer records, private logs, payment data, screenshots of private dashboards, full names, private handles, or full transaction identifiers into public issues, public comments, AI chats, or this checklist.

## First 30 Minutes

- Rotate the exposed service-role or secret key in Supabase.
- Update every server-side location that legitimately needed the old value: Edge Functions, backend services, CI secrets, Vercel or hosting env vars, worker platforms, and internal automation.
- Redeploy the affected frontend and backend surfaces.
- Invalidate or replace client assets that may have cached the old value: service worker cache, CDN cache, static bundle artifacts, preview deployments, and old build outputs.
- Record a non-sensitive incident label and timestamp for your own follow-up notes.

## Find Every Copy

Search redacted evidence, not live secrets:

- source files and generated files
- frontend bundle output
- service worker and cache manifests
- deployment logs and build logs
- CI output
- `.env.example`, docs, generated migration notes, and AI chat transcripts
- old preview URLs and branch deployments
- third-party tools that were given the key for automation

For each copy, record only the redacted location, for example:

```text
frontend bundle: dist/assets/app.[hash].js contained SUPABASE_SERVICE_ROLE_KEY placeholder
hosting env: old SERVICE_ROLE_KEY value rotated on production and preview
chat transcript: AI assistant suggested server client in frontend file; no raw value retained
```

## Confirm Server-Only Boundaries

- Browser code should use only publishable / anon client configuration intended for public use.
- Service-role, `sb_secret_...`, direct database URLs, and admin clients should stay in server-side code only.
- Any Edge Function or backend route that uses privileged credentials should validate the caller and input before touching tenant data.
- Generated client factories should make it obvious which code path is browser-safe and which code path is privileged.

## RLS And Grant Smoke Tests

After rotation and cleanup, verify the security fix did not turn into a broad permission change:

- no-session read/write attempt
- anon or public-user read/write attempt
- authenticated owner read/write attempt
- wrong-owner or wrong-tenant attempt
- privileged server path that is expected to pass
- Storage upload, overwrite/upsert, list, download, delete, and wrong-path checks if buckets are in scope

If a test fails with `42501`, fix the narrow grant or policy evidence instead of adding broad grants or `USING (true)` policies.

## Free Local Packet Builder

Use the local browser checker to turn redacted notes into a cleanup packet:

https://ai-launch-risk-check-public.vercel.app/lovable-service-role-exposure-check.html

It does not fetch your site, use browser storage, or need raw keys. Paste only redacted filenames, snippets, and notes.

## Good Fixed-Scope Packet

A good packet has:

- redacted exposure locations
- rotation evidence
- cache and redeploy notes
- repo/history/chat/log cleanup notes
- server-only boundary notes
- RLS/grant smoke-test results
- any remaining uncertainty that needs review

If the packet still has high-risk findings and you want a second pass, use the linked Lovable Cloud migration / generated Supabase report path from the public site after the scope is clear. Do not post checkout links in public threads.

# AI Agent Launch Tools

Small, dependency-free checks for builders launching AI agents, MCP servers, and tool-using workflows.

The first tool is a public launch-surface scanner for sites you own or have permission to test. It checks basic launch hygiene signals before you ship:

- Security headers
- Overbroad CORS
- Cookie flags
- Source-map exposure hints
- Public build variable clues

The repo also includes practical MCP/tool-call launch checklists:

- [MCP prompt-injection launch checklist](checklists/mcp-prompt-injection-launch-checklist.md)
- [MCP mutation replay guard checklist](checklists/mcp-mutation-replay-guard-checklist.md)
- [MCP trust verification checklist](checklists/mcp-trust-verification-checklist.md)

It now includes a small config reviewer and `tools/list` importer. The config reviewer turns a redacted Claude Desktop-style MCP config into a pre-install BLOCK / CAUTION / REVIEW report. The importer turns MCP tool metadata into an allow / ask / deny permission matrix with a snapshot digest for re-reviewing changed tools, without invoking any tools. It also recursively scans tool names, descriptions, and every string inside `inputSchema` for metadata/schema injection signals, including nested parameter descriptions, enum values, defaults, and titles. It flags schema-quality drift such as missing or empty `inputSchema`, object schemas without properties, missing `required` arrays, undocumented parameters, boolean/null/array property-schema entries, union `type` arrays that need target-client regression coverage, and JSON Schema `$ref` entries that some MCP clients or LLM tool adapters may not dereference before argument generation. It now also flags missing or incomplete `outputSchema` metadata for tools that appear to return structured data, so teams can review whether `structuredContent` can be validated and rendered reliably. It also flags missing or incomplete MCP `annotations` hints that clients can use for read-only, destructive, idempotent, and open-world approval prompts. It can also print a Codex `config.toml` review snippet that keeps sandbox settings separate from MCP tool approval.

The repo also includes Supabase launch CLIs for redacted SQL/RPC/view/Security Advisor notes. `supabase-rpc-audit` checks local text only and flags public-schema definer functions, public views missing `security_invoker`, broad `EXECUTE` or `SELECT` grants, default-`EXECUTE` revoke mismatches, callable-RPC ACL or REST smoke-test evidence, missing `search_path` hardening, `Function Search Path Mutable` review packets, SQL-function inlining tradeoffs, `SET search_path FROM CURRENT` evidence needs, and privileged functions or views that can bypass caller RLS expectations. `supabase-grants-cutover` reviews redacted Data API grants and policy packets for the 2026 explicit-grants default, including missing table grants, default privilege state, broad grant quick fixes, function `EXECUTE` evidence, disabled RLS, permissive policies, anonymous sign-in boundaries, and `auth.uid()` null behavior. It also extracts redacted PostgREST `42501` grant hints into reviewable `GRANT ...` statements plus role-matrix smoke tests, so teams can fix missing reachability without turning it into a broad RLS or policy change. Use `--fail-on high` in CI to block generated migrations that drop launch-blocking grants, views, or RPC safety markers.

The public browser tools also include Supabase launch checks for teams pairing AI agents with Supabase. Use them to review redacted Data API grants, explicit grant migration skeletons, anonymous sign-in RLS boundaries, Security Definer RPCs, default `EXECUTE` exposure packets, `security_invoker` view drift, exposed views, Security Advisor `search_path` warnings, auth signup trigger failures, and project-scoped Supabase MCP branching before an agent applies migrations or touches production data. The grants checker now covers the May 30, 2026 new-project Data API default and the October 30, 2026 rollout for existing projects, including default-privilege state and function `EXECUTE` evidence.

For a focused paid handoff, the Supabase Launch Risk Report page explains the one-packet `$25` scope and links the free triage tools plus sample report before checkout. It is the right next step when a free checker returns a high or medium finding and you want one 24-hour Markdown report with severity, likely failure mode, and launch smoke tests for a redacted packet:

https://ai-launch-risk-check-public.vercel.app/supabase-launch-risk-report.html

For a redacted default-`EXECUTE` packet before that handoff:

https://ai-launch-risk-check-public.vercel.app/supabase-rpc-exposure-packet-builder.html

For the 2026 Supabase Data API grants cutover:

https://ai-launch-risk-check-public.vercel.app/supabase-api-grants-readiness.html

For a redacted explicit-grants migration skeleton and role-matrix test packet:

https://ai-launch-risk-check-public.vercel.app/supabase-grant-migration-builder.html

Need the full launch workflow? The $25 AI Agent Launch Pack includes the local app, safe-intake builder, checklist, templates, sample report, and optional fixed-scope 24-hour review path:

https://ai-launch-risk-check-public.vercel.app/

## Buy Now If

The paid pack is a fit when:

- You are launching one agent workflow this week.
- The workflow can read private context or trigger tool calls.
- You need launch evidence, templates, and a safer intake path today.

Start with the free tools instead when:

- You cannot describe one workflow without secrets or customer records.
- You need legal advice, compliance certification, or penetration testing.
- You only need general reading and the free checklists already cover it.

Free readiness report:

https://ai-launch-risk-check-public.vercel.app/launch-readiness-report.html

If the scope fits, the digital pack checkout starts here:

https://ai-launch-risk-check-public.vercel.app/checkout-after-scope.html#digital-pack

## Use

Run the MCP trust verification planner:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 mcp-trust-check --server "candidate MCP server" --workflow "one AI workflow that can read docs and call approved tools"
```

Review redacted Supabase SQL/RPC/view notes for Security Definer and security-invoker risk:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.23 supabase-rpc-audit --file supabase_rpc.redacted.sql
```

Review redacted Supabase Data API grants and RLS policy notes for the 2026 explicit-grants cutover:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.23 supabase-grants-cutover --file supabase_grants.redacted.sql --fail-on high
```

When either Supabase CLI returns `BLOCK` or `CAUTION`, use the generated digest and redacted packet as the intake boundary. Do not send live credentials, connection strings, service-role strings, OAuth material, customer records, payment records, private screenshots, full names, private handles, or full transaction identifiers.

Fail CI on high-severity migration drift:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.23 supabase-rpc-audit --file supabase_migration.redacted.sql --fail-on high
```

Try the included Supabase RPC example after cloning:

```bash
node scripts/supabase-rpc-audit.mjs --file examples/supabase-security-definer-rpc.sql
```

Try the included Supabase view example after cloning:

```bash
node scripts/supabase-rpc-audit.mjs --file examples/supabase-security-invoker-view.sql
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.23 supabase-rpc-audit --file supabase_rpc.redacted.sql --json
```

Review a redacted Supabase Security Advisor `Function Search Path Mutable` tradeoff packet:

```bash
node scripts/supabase-rpc-audit.mjs --file examples/supabase-function-search-path-inline.sql
```

Review a redacted self-hosted/local Supabase hard-coded search-path packet:

```bash
node scripts/supabase-rpc-audit.mjs --file examples/supabase-self-hosted-search-path.sql
```

Review a redacted default `EXECUTE` exposure packet:

```bash
node scripts/supabase-rpc-audit.mjs --file examples/supabase-default-execute-exposure.sql
```

Review the included redacted Data API grants cutover packet:

```bash
node scripts/supabase-grants-cutover.mjs --file examples/supabase-grants-cutover.sql
```

Extract a redacted PostgREST `42501` grant hint into a review packet:

```bash
node scripts/supabase-grants-cutover.mjs --file examples/supabase-42501-grant-hint.txt
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.23 supabase-grants-cutover --file supabase_grants.redacted.sql --json
```

Review a redacted MCP client config before installing or approving servers:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 mcp-config-risk --file claude_desktop_config.redacted.json
```

Try the included redacted example after cloning:

```bash
node scripts/mcp-config-risk.mjs --file examples/mcp-client-config-redacted.json
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 mcp-config-risk --file claude_desktop_config.redacted.json --json
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 mcp-trust-check --server "candidate MCP server" --json
```

Generate an MCP permission matrix from a `tools/list` JSON result:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 mcp-permission-matrix --file tools-list.json --server "candidate MCP server"
```

Try the included example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-example.json
```

Try the schema-injection example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-schema-injection-example.json
```

Try the schema-quality example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-schema-quality-example.json
```

Try the `$ref` schema-risk example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-schema-ref-example.json
```

Try the annotations review example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-annotations-example.json
```

Try the output-schema review example after cloning:

```bash
node scripts/mcp-permission-matrix.mjs --file examples/mcp-tools-list-output-schema-example.json
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 mcp-permission-matrix --file tools-list.json --json
```

Compare against a prior JSON matrix snapshot:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 mcp-permission-matrix --file tools-list.json --baseline previous-matrix.json
```

Print only a Codex `config.toml` review snippet:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 mcp-permission-matrix --file tools-list.json --server "candidate MCP server" --codex-config
```

Run the public launch-surface scanner from GitHub:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 public-surface-scan https://example.com
```

Or after cloning:

```bash
node scripts/public-surface-scan.mjs https://example.com
```

JSON output:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 public-surface-scan https://example.com --json
```

Markdown report:

```bash
npx --package github:kayalopez/ai-agent-launch-tools#v0.1.15 public-surface-scan https://example.com --markdown
```

The scanner blocks localhost, private, reserved, and non-standard-port targets. It is for public launch hygiene only, not penetration testing, vulnerability scanning, legal advice, compliance certification, or a security guarantee.

The MCP trust planner blocks obvious secret-like inputs and prints a non-sensitive launch checklist. The MCP config reviewer refuses likely unredacted secret env values, prints env key names but not values, and never starts servers, calls tools, fetches URLs, or validates safety. The MCP permission matrix importer reads metadata only, never invokes MCP tools, recursively scans nested schema strings for prompt-injection and tool-selection-bias signals, flags schema-quality drift that can make clients lose argument metadata, and now highlights `$ref`-based schemas, non-object property schemas, union `type` arrays, missing/incomplete `outputSchema` metadata for structured results, and missing/incomplete MCP `annotations` hints that may need target-client regression coverage before launch. It can compare a new metadata snapshot against a prior JSON matrix so added, removed, or changed tools re-enter review. The Codex snippet maps `allow` to `approval_mode = "approve"`, `ask` maps to `approval_mode = "prompt"`, and `deny` maps to `disabled_tools`; it does not disable sandboxing. The Supabase CLIs read local redacted text only; they do not connect to Supabase, fetch URLs, call RPCs, inspect private data, or prove safety. These tools are for review planning only, not approval automation, penetration testing, compliance certification, or a guarantee that a server or database is safe.

## Free Browser Tools

These no-login tools are live:

- Launch readiness report: https://ai-launch-risk-check-public.vercel.app/launch-readiness-report.html
- Public surface scan: https://ai-launch-risk-check-public.vercel.app/public-surface-scan.html
- MCP fixture generator: https://ai-launch-risk-check-public.vercel.app/mcp-fixture-generator.html
- MCP prompt-injection eval guide: https://ai-launch-risk-check-public.vercel.app/mcp-prompt-injection-eval.html
- MCP prompt-injection fixture library: https://ai-launch-risk-check-public.vercel.app/mcp-prompt-injection-fixtures.html
- MCP tools/list health report: https://ai-launch-risk-check-public.vercel.app/mcp-tools-list-health-report.html
- Agent tool permission matrix: https://ai-launch-risk-check-public.vercel.app/agent-tool-permission-matrix.html
- MCP first-invoke approval checklist: https://ai-launch-risk-check-public.vercel.app/mcp-first-invoke-approval-checklist.html
- MCP tool approval criteria generator: https://ai-launch-risk-check-public.vercel.app/mcp-tool-approval-criteria.html
- MCP trust verification generator: https://ai-launch-risk-check-public.vercel.app/mcp-trust-verification-generator.html
- Agent API key bootstrap checklist: https://ai-launch-risk-check-public.vercel.app/agent-api-key-bootstrap-checklist.html
- Supabase Launch Risk Report: https://ai-launch-risk-check-public.vercel.app/supabase-launch-risk-report.html
- Supabase API grants readiness checker: https://ai-launch-risk-check-public.vercel.app/supabase-api-grants-readiness.html
- Supabase grant migration builder: https://ai-launch-risk-check-public.vercel.app/supabase-grant-migration-builder.html
- Supabase anonymous RLS audit matrix: https://ai-launch-risk-check-public.vercel.app/supabase-anonymous-rls-audit.html
- Supabase Security Definer RPC audit: https://ai-launch-risk-check-public.vercel.app/supabase-security-definer-rpc-audit.html
- Supabase RPC exposure packet builder: https://ai-launch-risk-check-public.vercel.app/supabase-rpc-exposure-packet-builder.html
- Supabase MCP branching readiness checker: https://ai-launch-risk-check-public.vercel.app/supabase-mcp-branching-readiness.html
- Supabase Security Advisor fix planner: https://ai-launch-risk-check-public.vercel.app/supabase-security-advisor-fix-planner.html
- Supabase signup trigger debugger: https://ai-launch-risk-check-public.vercel.app/supabase-signup-trigger-debugger.html
- Supabase security_invoker view drift checker: https://ai-launch-risk-check-public.vercel.app/supabase-security-invoker-view-drift.html
- Sample Supabase grants/RLS report: https://ai-launch-risk-check-public.vercel.app/sample-supabase-grants-rls-report.md

The full paid pack and fixed-scope review are described on the product page:

https://ai-launch-risk-check-public.vercel.app/

## Safe Use

Only scan public URLs you own or have permission to assess. Do not paste secrets, tokens, private customer data, cookies, payment pages, internal hosts, or non-public endpoints into this tool.

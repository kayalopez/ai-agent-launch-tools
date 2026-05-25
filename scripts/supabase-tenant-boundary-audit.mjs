#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";

const SECRET_PATTERNS = [
  /\b(?:postgres|postgresql):\/\/[^:\s]+:[^@\s]+@/i,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_]{12,}\b/,
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/,
  /\b(?:api[_-]?key|bearer|password|secret|service[_-]?role[_-]?key|token)\b\s*[:=]\s*["']?[^"',\s]{8,}/i,
];

const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };
const TENANT_WORDS = /\b(?:tenant|tenants|tenant_id|organization|organizations|organization_id|organisation|organisations|organisation_id|org_id|orgs|workspace|workspaces|workspace_id|account_id|company_id|team_id|household_id|family_id)\b/i;
const MEMBERSHIP_WORDS = /\b(?:membership|memberships|member|members|role|roles|owner|admin)\b/i;

function usage() {
  return [
    "Usage: supabase-tenant-boundary-audit [options]",
    "",
    "Reads a redacted Supabase multi-tenant launch packet and prints an RLS boundary report.",
    "",
    "Options:",
    "  --file <path>          Read notes/SQL from a file instead of stdin.",
    "  --label <label>        Report label.",
    "  --json                 Print structured JSON.",
    "  --markdown             Print Markdown. Default.",
    "  --fail-on <severity>   Exit 2 when a finding is at or above low, medium, or high.",
    "  --help                 Show this help.",
    "",
    "Redact secrets before use. This tool never connects to Supabase, fetches URLs,",
    "calls APIs, starts servers, reads private files, or validates safety. It pattern-matches local text only.",
  ].join("\n");
}

function readOption(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value.`);
  return value;
}

function readInput(args) {
  const file = readOption(args, "--file", "");
  if (file) return fs.readFileSync(file, "utf8");
  if (process.stdin.isTTY) throw new Error("No input provided. Pass --file <path> or pipe redacted notes on stdin.");
  return fs.readFileSync(0, "utf8");
}

function validateRedacted(raw) {
  const hit = SECRET_PATTERNS.find((pattern) => pattern.test(raw));
  if (hit) {
    throw new Error("Input appears to contain an unredacted secret, token, credentialed database URL, or service-role key. Redact it before review.");
  }
}

function shortDigest(text) {
  return crypto.createHash("sha256").update(text).digest("hex").slice(0, 12);
}

function stripSqlComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--.*$/gm, " ");
}

function add(findings, severity, code, title, detail) {
  findings.push({ severity, code, title, detail });
}

function parseFailOn(value) {
  if (!value) return "";
  const normalized = value.toLowerCase();
  if (!Object.hasOwn(SEVERITY_RANK, normalized)) {
    throw new Error("--fail-on must be one of: low, medium, high.");
  }
  return normalized;
}

function shouldFail(findings, failOn) {
  if (!failOn) return false;
  return findings.some((finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[failOn]);
}

function extractPolicyStatements(sql) {
  return sql.match(/create\s+policy\b[\s\S]*?(?:;|$)/gi) || [];
}

function policyName(statement) {
  const quoted = statement.match(/create\s+policy\s+"([^"]+)"/i);
  if (quoted) return quoted[1];
  const bare = statement.match(/create\s+policy\s+([a-z_][\w$]*)/i);
  return bare ? bare[1] : "unnamed_policy";
}

function tableName(statement) {
  const match = statement.match(/\bon\s+(?:(?:table)\s+)?(?:"?public"?\.)?"?([a-z_][\w$]*)"?/i);
  return match ? match[1] : "";
}

function policyOperation(statement) {
  const match = statement.match(/\bfor\s+(select|insert|update|delete|all)\b/i);
  return match ? match[1].toLowerCase() : "all";
}

function policyRoles(statement) {
  const match = statement.match(/\bto\s+([^;\n]+?)(?:\s+using|\s+with\s+check|\s+as\s+|\s*$)/i);
  if (!match) return ["public"];
  return match[1]
    .split(",")
    .map((role) => role.replace(/["']/g, "").trim().toLowerCase())
    .filter(Boolean);
}

function hasTenantBoundary(text) {
  return TENANT_WORDS.test(text) && (MEMBERSHIP_WORDS.test(text) || /auth\.uid\s*\(/i.test(text));
}

function summarizePolicy(statement) {
  return {
    name: policyName(statement),
    table: tableName(statement),
    operation: policyOperation(statement),
    roles: policyRoles(statement),
    hasTenantBoundary: hasTenantBoundary(statement),
  };
}

function review(raw) {
  validateRedacted(raw);
  const text = raw.trim();
  const sql = stripSqlComments(raw);
  const findings = [];
  const policies = extractPolicyStatements(sql);
  const hasNegativeTest = /\b(?:reject|rejected|deny|denied|blocked|403|401|permission denied|0 rows|empty result|fails?|failed)\b/i.test(raw);
  const hasWrongTenantTest = /\b(?:wrong[-\s]?tenant|cross[-\s]?tenant|tenant_[ab]|tenant a|tenant b|other tenant|direct id|direct-id)\b/i.test(raw);
  const serviceRole = /service[_ -]?role|service role/i.test(raw);
  const securityDefiner = /security\s+definer/i.test(sql);
  const storage = /\b(?:bucket|storage|signed url|signed-url|object path|objects)\b/i.test(raw);
  const billingOwner = /\b(?:stripe|billing|invoice|subscription|customer|owner|admin transfer|ownership)\b/i.test(raw);
  const broadGrant = /grant\s+(?:all|select|insert|update|delete|execute)[\s\S]{0,180}\bto\s+(?:anon|authenticated|public)\b/i.test(sql);
  const truePolicy = /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(sql);
  const anonymousState = /anonymous|is_anonymous|signInAnonymously/i.test(raw);

  if (!text) {
    add(findings, "medium", "no_redacted_input", "No redacted tenant-boundary packet provided", "Paste a redacted schema summary, policy excerpt, test note, or service/storage path note to classify the launch risk.");
    return { findings, policies: [] };
  }

  if (!policies.length && !TENANT_WORDS.test(raw)) {
    add(findings, "medium", "tenant_model_missing", "Tenant model is not visible in the packet", "Name the redacted tenant boundary, for example organizations, teams, workspaces, or accounts, before reviewing table policies.");
  }

  if (!hasNegativeTest || !hasWrongTenantTest) {
    add(findings, "high", "wrong_tenant_negative_tests_missing", "Wrong-tenant negative test evidence is missing", "A multi-tenant launch packet should show at least one tenant A user trying tenant B direct IDs for read and write paths.");
  }

  for (const statement of policies) {
    const summary = summarizePolicy(statement);
    const label = `${summary.name}${summary.table ? ` on ${summary.table}` : ""}`;
    if (!summary.hasTenantBoundary) {
      add(findings, "high", "tenant_boundary_missing_in_policy", `${label} does not show a tenant boundary`, "Policies that only check auth.uid(), role, or true can pass single-user tests while allowing cross-tenant reads or writes.");
    }
    if (/auth\.role\s*\(\s*\)\s*=\s*['"]authenticated|to\s+authenticated/i.test(statement) && !summary.hasTenantBoundary) {
      add(findings, "high", "authenticated_role_without_tenant_check", `${label} uses authenticated role without tenant membership evidence`, "Authenticated only proves a session exists. Multi-tenant policies need membership or ownership checks tied to the tenant row.");
    }
    if (truePolicy) {
      add(findings, "high", "true_policy_needs_public_data_proof", `${label} includes a true policy marker`, "A true policy should be launch-blocking unless the table is deliberately public and documented outside tenant data.");
    }
  }

  if (anonymousState && !/is_anonymous/i.test(sql)) {
    add(findings, "medium", "anonymous_state_needs_role_matrix", "Anonymous sign-in is mentioned without policy guards", "Anonymous signed-in users can use the authenticated database role; include anonymous-session tests for invites, memberships, billing, and ownership transitions.");
  }

  if (serviceRole && !/membership|owner|tenant|organization|workspace|account/i.test(raw)) {
    add(findings, "medium", "service_role_path_needs_tenant_mapping", "Service-role path lacks tenant ownership evidence", "Map every service-role endpoint or function to the tenant check it performs before privileged reads or writes.");
  } else if (serviceRole) {
    add(findings, "low", "service_role_path_mapped_for_review", "Service-role path is present and should be reviewed separately", "Keep service-role paths out of the browser and test them as privileged bypass paths, not normal RLS behavior.");
  }

  if (securityDefiner) {
    add(findings, "medium", "security_definer_needs_caller_context_tests", "SECURITY DEFINER path needs caller-context tests", "Definer functions can bypass table RLS. Confirm caller tenant, role, search_path, and wrong-tenant rejection.");
  }

  if (storage && !TENANT_WORDS.test(raw)) {
    add(findings, "medium", "storage_policy_tenant_boundary_missing", "Storage path is mentioned without tenant boundary evidence", "Storage bucket policies and signed URL creation should be tested separately from table RLS.");
  } else if (storage) {
    add(findings, "low", "storage_policy_in_scope", "Storage policy is in scope", "Run bucket object path tests for tenant A, tenant B, no session, and signed URL generation.");
  }

  if (broadGrant) {
    add(findings, "medium", "broad_grant_requires_role_matrix", "Broad grant marker needs role-matrix review", "GRANT reachability is separate from RLS. Confirm anon, authenticated, service_role, and wrong-tenant behavior after grants are applied.");
  }

  if (billingOwner) {
    add(findings, "low", "billing_owner_transition_review", "Billing or ownership state needs tenant-scoped checks", "Payment, subscription, customer, owner, and admin state should be authorized by tenant membership, not just webhook or route reachability.");
  }

  if (!findings.some((finding) => finding.severity === "high")) {
    add(findings, "low", "ready_for_tenant_boundary_review", "No high-priority tenant-boundary marker found", "Still hand-review every tenant-scoped policy and run a two-tenant fixture before launch.");
  }

  return { findings, policies: policies.map(summarizePolicy) };
}

function statusFromFindings(findings) {
  if (findings.some((finding) => finding.severity === "high")) return "BLOCK";
  if (findings.some((finding) => finding.severity === "medium")) return "CAUTION";
  return "REVIEW";
}

function buildReport(raw, label) {
  const result = review(raw);
  return {
    generatedBy: "ai-agent-launch-tools supabase-tenant-boundary-audit",
    label,
    inputDigest: shortDigest(raw),
    status: statusFromFindings(result.findings),
    findings: result.findings,
    policies: result.policies,
    roleMatrix: [
      "No session: confirm unauthenticated calls cannot read or mutate tenant rows.",
      "Anonymous signed-in session: confirm temporary users cannot join teams, accept invites, edit billing, or touch owner-only state unless explicitly intended.",
      "Tenant A member: confirm intended tenant A reads/writes succeed.",
      "Tenant A member using tenant B direct IDs: confirm reads and writes are rejected.",
      "Tenant B member using tenant A direct IDs: confirm reads and writes are rejected.",
      "Service-role endpoint: prove tenant ownership before privileged reads or writes.",
      "Storage signed URL: prove bucket object paths mirror table tenant boundaries.",
    ],
    links: {
      browserPacket: "https://ai-launch-risk-check-public.vercel.app/supabase-tenant-boundary-packet.html",
      sampleReport: "https://ai-launch-risk-check-public.vercel.app/sample-supabase-grants-rls-report.md",
      paidReportOverview: "https://ai-launch-risk-check-public.vercel.app/supabase-launch-risk-report.html",
    },
    safety: "Local pattern review only. Do not paste secrets, connection strings, service-role keys, customer records, payment records, private screenshots, full names, private handles, or full transaction identifiers.",
  };
}

function markdown(report) {
  const lines = [
    "# Supabase Multi-Tenant Boundary Audit",
    "",
    `Label: ${report.label}`,
    `Status: ${report.status}`,
    `Input digest: ${report.inputDigest}`,
    "",
    "## Findings",
    "",
  ];
  for (const finding of report.findings) {
    lines.push(`- ${finding.severity.toUpperCase()} ${finding.code}: ${finding.title}`);
    lines.push(`  - ${finding.detail}`);
  }
  lines.push("", "## Policies Seen", "");
  if (report.policies.length) {
    for (const policy of report.policies) {
      lines.push(`- ${policy.name}: ${policy.operation} on ${policy.table || "unknown table"} to ${policy.roles.join(", ")}; tenant boundary: ${policy.hasTenantBoundary ? "yes" : "no"}`);
    }
  } else {
    lines.push("- No create policy statements detected.");
  }
  lines.push("", "## Role Matrix", "");
  for (const item of report.roleMatrix) lines.push(`- ${item}`);
  lines.push("", "## Links", "");
  lines.push(`- Browser packet builder: ${report.links.browserPacket}`);
  lines.push(`- Sample report: ${report.links.sampleReport}`);
  if (report.status !== "REVIEW") lines.push(`- Paid report overview: ${report.links.paidReportOverview}`);
  lines.push("", `Safety: ${report.safety}`);
  return lines.join("\n");
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log(usage());
    return 0;
  }
  const outputJson = args.includes("--json");
  const failOn = parseFailOn(readOption(args, "--fail-on", ""));
  const label = readOption(args, "--label", "redacted Supabase tenant-boundary packet");
  const raw = readInput(args);
  const report = buildReport(raw, label);
  if (outputJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(markdown(report));
  }
  return shouldFail(report.findings, failOn) ? 2 : 0;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(`supabase-tenant-boundary-audit: ${error.message}`);
  process.exitCode = 1;
}

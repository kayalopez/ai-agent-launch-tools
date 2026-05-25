#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";

const SECRET_PATTERNS = [
  /\b(?:postgres|postgresql):\/\/[^:\s]+:[^@\s]+@/i,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_]{12,}\b/,
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/,
  /\b(?:api[_-]?key|bearer|password|secret|service[_-]?role[_-]?key|token)\b\s*[:=]\s*["']?[^"',\s]{8,}/i,
];

const SEVERITY_RANK = {
  low: 1,
  medium: 2,
  high: 3,
};

const SENSITIVE_TABLE_WORDS = /\b(?:team|teams|tenant|tenants|member|members|membership|memberships|invite|invitation|invitations|billing|subscription|subscriptions|payment|payments|admin|admins|owner|owners|profile|profiles|user|users|account|accounts|organization|organizations|orgs|document|documents|file|files)\b/i;

function usage() {
  return [
    "Usage: supabase-anonymous-rls-audit [options]",
    "",
    "Reads redacted Supabase RLS policy SQL/notes and prints an anonymous sign-in authorization report.",
    "",
    "Options:",
    "  --file <path>          Read SQL/notes from a file instead of stdin.",
    "  --label <label>        Report label.",
    "  --json                 Print structured JSON.",
    "  --markdown             Print Markdown. Default.",
    "  --fail-on <severity>   Exit 2 when a finding is at or above low, medium, or high.",
    "  --help                 Show this help.",
    "",
    "Redact secrets before use. This tool never connects to Supabase, fetches URLs,",
    "calls APIs, starts servers, or validates safety. It pattern-matches local text only.",
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
  if (process.stdin.isTTY) throw new Error("No input provided. Pass --file <path> or pipe redacted SQL on stdin.");
  return fs.readFileSync(0, "utf8");
}

function shortDigest(text) {
  return crypto.createHash("sha256").update(text).digest("hex").slice(0, 12);
}

function stripSqlComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--.*$/gm, " ");
}

function validateRedacted(raw) {
  const hit = SECRET_PATTERNS.find((pattern) => pattern.test(raw));
  if (hit) {
    throw new Error("Input appears to contain an unredacted secret, token, credentialed database URL, or service-role key. Redact it before review.");
  }
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
  const threshold = SEVERITY_RANK[failOn];
  return findings.some((finding) => SEVERITY_RANK[finding.severity] >= threshold);
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

function isWriteOperation(operation) {
  return ["insert", "update", "delete", "all"].includes(operation);
}

function reachesAuthenticated(statement) {
  return policyRoles(statement).some((role) => role === "authenticated" || role === "public");
}

function reachesAnonRole(statement) {
  return policyRoles(statement).some((role) => role === "anon" || role === "public");
}

function hasAnonymousGuard(statement) {
  return /is_anonymous/i.test(statement) || /auth\.jwt\s*\(\s*\)\s*[-=]>>?\s*['"]is_anonymous['"]/i.test(statement);
}

function hasAuthUsersEmailLookup(statement) {
  return /auth\.users[\s\S]{0,220}\bemail\b|\bemail\b[\s\S]{0,220}auth\.users/i.test(statement);
}

function hasNullableIdentitySignal(statement) {
  return /\bemail\b|phone|raw_user_meta_data|raw_app_meta_data|user_metadata|app_metadata|coalesce\s*\(|is\s+not\s+distinct\s+from|\bis\s+null\b/i.test(statement);
}

function hasAuthUid(statement) {
  return /auth\.uid\s*\(/i.test(statement);
}

function hasAuthUidNonNull(statement) {
  return /(?:auth\.uid\s*\(\s*\)|\(\s*select\s+auth\.uid\s*\(\s*\)\s*\))\s+is\s+not\s+null/i.test(statement);
}

function summarizePolicy(statement) {
  return {
    name: policyName(statement),
    table: tableName(statement),
    operation: policyOperation(statement),
    roles: policyRoles(statement),
    hasAnonymousGuard: hasAnonymousGuard(statement),
  };
}

function review(raw) {
  validateRedacted(raw);
  const text = raw.trim();
  const sql = stripSqlComments(raw);
  const findings = [];
  const policies = extractPolicyStatements(sql);
  const anonymousEnabled = /anonymous\s+sign-?in|signInAnonymously|allow\s+anonymous|is_anonymous|auth\.jwt\s*\(\s*\)[\s\S]{0,80}is_anonymous/i.test(raw);
  const hasAuthenticatedPolicy = policies.some(reachesAuthenticated);
  const hasAnonymousGuard = /is_anonymous/i.test(sql);
  const securityDefiner = /security\s+definer/i.test(sql);
  const bypassMarker = /service_role|bypassrls|bypass\s+rls/i.test(sql);
  const grantToAuthenticated = /grant\s+(?:select|insert|update|delete|all|execute)[\s\S]{0,220}\bto\s+authenticated\b/i.test(sql);
  const truePolicy = /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(sql);

  if (!text) {
    add(findings, "medium", "no_redacted_input", "No redacted RLS policy text provided", "Paste a redacted policy excerpt, migration note, or anonymous sign-in review packet to classify the launch risk.");
    return { findings, policies: [] };
  }

  if (anonymousEnabled && hasAuthenticatedPolicy && !hasAnonymousGuard) {
    add(findings, "high", "anonymous_signin_authenticated_role_drift", "Anonymous sign-in can satisfy authenticated policies", "Anonymous users use the authenticated role. Policies for sensitive actions need an explicit is_anonymous boundary before launch.");
  } else if (hasAuthenticatedPolicy && !hasAnonymousGuard) {
    add(findings, "medium", "authenticated_policy_anonymous_state_unrecorded", "Authenticated policies have no anonymous-user state", "If anonymous sign-ins are enabled now or later, these policies should be reviewed with an anonymous-session test case.");
  }

  for (const statement of policies) {
    const summary = summarizePolicy(statement);
    const label = `${summary.name}${summary.table ? ` on ${summary.table}` : ""}`;
    const sensitiveTable = SENSITIVE_TABLE_WORDS.test(summary.table) || SENSITIVE_TABLE_WORDS.test(summary.name);
    if (reachesAuthenticated(statement) && isWriteOperation(summary.operation) && !summary.hasAnonymousGuard) {
      add(findings, sensitiveTable ? "high" : "medium", "authenticated_write_without_anonymous_guard", `${label} writes as authenticated without anonymous guard`, "Review whether a temporary anonymous session should be able to insert, update, delete, or accept state transitions here.");
    }
    if (reachesAuthenticated(statement) && sensitiveTable && hasNullableIdentitySignal(statement) && !summary.hasAnonymousGuard) {
      add(findings, "high", "nullable_identity_match_without_anonymous_guard", `${label} has nullable identity matching without anonymous guard`, "Email, phone, metadata, null, or coalesce-based checks can behave differently for anonymous users. Add a non-anonymous check and a null fixture regression.");
    }
    if (hasAuthUsersEmailLookup(statement) && !summary.hasAnonymousGuard) {
      add(findings, "high", "auth_users_email_lookup_without_anonymous_guard", `${label} looks up auth.users email without anonymous guard`, "Anonymous users can have a null email. Invitation, membership, or ownership policies should deny anonymous sessions before comparing email-derived identity.");
    }
    if (reachesAnonRole(statement) && truePolicy && sensitiveTable) {
      add(findings, "high", "public_or_anon_true_policy_on_sensitive_table", `${label} exposes a sensitive table with a true policy`, "A true policy on sensitive data should be treated as launch-blocking unless the table is deliberately public and documented.");
    }
    if (hasAuthUid(statement) && !hasAuthUidNonNull(statement) && reachesAnonRole(statement)) {
      add(findings, "medium", "auth_uid_null_behavior_implicit", `${label} relies on auth.uid() without explicit non-null behavior`, "Add an explicit non-null or no-session regression check so unauthenticated behavior is intentional.");
    }
  }

  if (grantToAuthenticated && !hasAnonymousGuard) {
    add(findings, "medium", "grant_to_authenticated_needs_anonymous_matrix", "Grant to authenticated needs anonymous-session matrix", "A grant makes the object reachable to authenticated-role sessions, including anonymous sign-ins. Pair it with RLS tests for anonymous, upgraded, and wrong-tenant users.");
  }

  if (securityDefiner) {
    add(findings, "medium", "security_definer_needs_caller_check", "SECURITY DEFINER code needs caller-state review", "Definer functions can bypass table RLS. Confirm they check caller identity, anonymous state, membership, and tenant scope before touching sensitive rows.");
  }

  if (bypassMarker) {
    add(findings, "medium", "privileged_bypass_path_review", "Privileged bypass marker needs separate review", "Service-role and BYPASSRLS paths should stay server-side and should not mask anonymous-session authorization bugs.");
  }

  if (!findings.some((finding) => finding.severity === "high")) {
    add(findings, "low", "ready_for_anonymous_role_matrix", "No high-priority anonymous RLS marker found", "Still run a role matrix for no session, anonymous signed-in session, upgraded user, wrong user, and wrong tenant before launch.");
  }

  return {
    findings,
    policies: policies.map(summarizePolicy),
  };
}

function statusFromFindings(findings) {
  if (findings.some((finding) => finding.severity === "high")) return "BLOCK";
  if (findings.some((finding) => finding.severity === "medium")) return "CAUTION";
  return "REVIEW";
}

function buildReport(raw, label) {
  const result = review(raw);
  const digest = shortDigest(raw);
  return {
    generatedBy: "ai-agent-launch-tools supabase-anonymous-rls-audit",
    label,
    inputDigest: digest,
    status: statusFromFindings(result.findings),
    findings: result.findings,
    policies: result.policies,
    roleMatrix: [
      "No session: confirm unauthenticated calls cannot read or mutate sensitive rows.",
      "Anonymous signed-in session: confirm temporary users cannot accept invites, join teams, change ownership, edit billing, or mutate private records unless explicitly intended.",
      "Upgraded real user: confirm the intended action succeeds only after the non-anonymous identity state exists.",
      "Wrong user or wrong tenant: confirm ownership, membership, and tenant checks deny access.",
      "Null identity fixture: include a row with null email/phone/metadata where old test data could accidentally match anonymous users.",
    ],
    links: {
      browserMatrix: "https://ai-launch-risk-check-public.vercel.app/supabase-anonymous-rls-audit.html",
      sampleReport: "https://ai-launch-risk-check-public.vercel.app/sample-supabase-grants-rls-report.md",
      paidReportOverview: "https://ai-launch-risk-check-public.vercel.app/supabase-launch-risk-report.html",
    },
    safety: "Local pattern review only. Do not paste secrets, connection strings, service-role keys, customer records, payment records, private screenshots, full names, private handles, or full transaction identifiers.",
  };
}

function markdown(report) {
  const lines = [
    "# Supabase Anonymous RLS Audit",
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
      lines.push(`- ${policy.name}: ${policy.operation} on ${policy.table || "unknown table"} to ${policy.roles.join(", ")}; anonymous guard: ${policy.hasAnonymousGuard ? "yes" : "no"}`);
    }
  } else {
    lines.push("- No create policy statements detected.");
  }
  lines.push("", "## Role Matrix", "");
  for (const item of report.roleMatrix) lines.push(`- ${item}`);
  lines.push("", "## Links", "");
  lines.push(`- Browser matrix: ${report.links.browserMatrix}`);
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
  const label = readOption(args, "--label", "redacted Supabase anonymous RLS packet");
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
  console.error(`supabase-anonymous-rls-audit: ${error.message}`);
  process.exitCode = 1;
}

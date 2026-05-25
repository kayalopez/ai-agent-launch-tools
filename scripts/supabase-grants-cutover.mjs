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

function usage() {
  return [
    "Usage: supabase-grants-cutover [options]",
    "",
    "Reads redacted Supabase SQL, migration notes, or Data API errors and prints a grants cutover report.",
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
    "calls RPCs, starts servers, or validates safety. It pattern-matches local text only.",
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

function extractPolicyStatements(sql) {
  const matches = sql.match(/create\s+policy\b[\s\S]*?(?:;|$)/gi);
  return matches || [];
}

function policyOperation(statement) {
  const match = statement.match(/\bfor\s+(select|insert|update|delete|all)\b/i);
  return match ? match[1].toLowerCase() : "all";
}

function isWritePolicy(statement) {
  return ["insert", "update", "delete", "all"].includes(policyOperation(statement));
}

function usesAuthenticatedRole(statement) {
  return /\bto\s+authenticated\b/i.test(statement);
}

function usesAnonymousReachableRole(statement) {
  return !/\bto\s+\w+/i.test(statement) || /\bto\s+(?:anon|public)\b/i.test(statement);
}

function hasAnonymousUserGuard(statement) {
  return /is_anonymous|anonymous/i.test(statement);
}

function hasAuthUid(statement) {
  return /auth\.uid\s*\(/i.test(statement);
}

function hasExplicitAuthUidNonNull(statement) {
  return /(?:auth\.uid\s*\(\s*\)|\(\s*select\s+auth\.uid\s*\(\s*\)\s*\))\s+is\s+not\s+null/i.test(statement);
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

function reviewGrants(raw) {
  validateRedacted(raw);
  const findings = [];
  const text = raw.trim();
  const sql = stripSqlComments(raw);
  const hasPublicTable = /create\s+table\s+(?:if\s+not\s+exists\s+)?public\./i.test(sql);
  const hasGrant = /grant\s+(?:select|insert|update|delete|all|usage|execute)[\s\S]{0,220}\bto\s+(?:anon|authenticated|service_role|public)\b/i.test(sql);
  const hasTableGrant = /grant\s+(?:select|insert|update|delete|all)[\s\S]{0,220}\bon\s+(?:table\s+)?public\./i.test(sql);
  const hasFunctionCreate = /create\s+(?:or\s+replace\s+)?function\s+(?:public\.)?[a-z_][\w$]*\s*\(/i.test(sql);
  const hasExecuteEvidence = /\b(?:grant|revoke)\s+execute\b|\bproacl\b|=X|\/rpc\//i.test(raw);
  const broadTableGrant = /grant\s+all[\s\S]{0,220}\bto\s+(?:anon|authenticated|public)\b|grant\s+(?:select|insert|update|delete)[\s,]+(?:select|insert|update|delete)[\s\S]{0,220}\bto\s+anon\b/i.test(sql);
  const broadExecuteGrant = /grant\s+execute[\s\S]{0,220}\bto\s+(?:anon|authenticated|public)\b/i.test(sql);
  const defaultTablesRevoked = /alter\s+default\s+privileges[\s\S]{0,320}revoke[\s\S]{0,160}(?:select|insert|update|delete)[\s\S]{0,160}on\s+tables/i.test(sql);
  const defaultFunctionsRevoked = /alter\s+default\s+privileges[\s\S]{0,320}revoke[\s\S]{0,120}execute[\s\S]{0,160}on\s+functions/i.test(sql);
  const defaultSequencesRevoked = /alter\s+default\s+privileges[\s\S]{0,320}revoke[\s\S]{0,160}(?:usage|select)[\s\S]{0,160}on\s+sequences/i.test(sql);
  const permissionDenied = /42501|permission\s+denied\s+for\s+(?:table|schema|function)|permission\s+denied/i.test(raw);
  const postgrestHint = /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|EXECUTE)\s+ON/i.test(raw);
  const rlsEnabled = /enable\s+row\s+level\s+security/i.test(sql);
  const rlsDisabled = /disable\s+row\s+level\s+security/i.test(sql);
  const usingTrue = /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(sql);
  const policyStatements = extractPolicyStatements(sql);
  const serviceRole = /service_role|bypassrls|bypass\s+rls/i.test(sql);

  if (!text) {
    add(findings, "medium", "no_redacted_input", "No redacted SQL or Data API error text provided", "Paste a redacted migration, grant snippet, policy excerpt, or 42501 error note to classify the cutover risk.");
    return findings;
  }

  if (permissionDenied && !hasGrant) {
    add(findings, "high", "grant_missing_for_data_api", "Permission-denied error has no matching grant evidence", "This looks like a Data API grant problem. Add the narrow role privilege needed before changing RLS policy logic.");
  } else if (permissionDenied && postgrestHint) {
    add(findings, "medium", "postgrest_grant_hint_present", "PostgREST grant hint is present", "Keep the exact hinted grant in the review packet, then confirm the matching RLS policy still blocks unintended rows.");
  }

  if (hasPublicTable && !hasTableGrant && !defaultTablesRevoked) {
    add(findings, "high", "may30_cutover_grant_inventory_missing", "May 30 Data API grant inventory is missing", "A new public-schema table appears without explicit table grants or default-privilege revocation evidence. Record intended role reachability before relying on the new default.");
  } else if (hasPublicTable && !hasTableGrant) {
    add(findings, "medium", "new_public_table_without_table_grant", "Public table has no explicit table grant evidence", "For projects under the changed default, a public table may exist but not be reachable through the Data API until a role is granted the needed table privilege.");
  }

  if (hasPublicTable && !defaultTablesRevoked) {
    add(findings, "medium", "default_table_privileges_state_missing", "Default table privilege state is unrecorded", "Record whether the project has opted into revoked default table privileges before the May 30 and October 30 rollout dates.");
  } else if (defaultTablesRevoked) {
    add(findings, "low", "default_table_privileges_revoked", "Default table privilege revoke evidence is present", "Keep explicit grants for intended Data API tables in the same migration or packet.");
  }

  if (defaultSequencesRevoked) {
    add(findings, "low", "default_sequence_privileges_revoked", "Default sequence privilege revoke evidence is present", "Sequence usage can affect insert paths; keep sequence grants or generated-identity behavior in the same role matrix.");
  }

  if (hasFunctionCreate && !hasExecuteEvidence && !defaultFunctionsRevoked) {
    add(findings, "medium", "function_execute_evidence_missing", "Function EXECUTE evidence is missing", "Functions and RPCs need their own EXECUTE revoke/grant evidence. Table grants do not prove callable RPC boundaries.");
  } else if (defaultFunctionsRevoked) {
    add(findings, "low", "default_function_execute_revoked", "Default function EXECUTE revoke evidence is present", "Confirm intended RPC callers have explicit grants and REST/RPC smoke tests.");
  }

  if (broadTableGrant) {
    add(findings, "high", "broad_table_grant_quick_fix", "Broad table grant appears in the pasted text", "Avoid using broad table grants as a quick fix. Grant only the operation and role required, then let RLS enforce row boundaries.");
  }

  if (broadExecuteGrant) {
    add(findings, "high", "broad_execute_grant_quick_fix", "Broad function EXECUTE grant appears in the pasted text", "Avoid restoring callable RPC access broadly. Revoke broad function execution first, then grant only the exact role that should call the RPC.");
  }

  if (rlsDisabled) {
    add(findings, "high", "rls_disabled", "RLS disable statement found", "A grant plus disabled RLS can expose all rows reachable by that role. Confirm this is not part of launch scope.");
  } else if (hasPublicTable && !rlsEnabled) {
    add(findings, "medium", "rls_enable_evidence_missing", "No explicit RLS enable evidence found", "Include RLS enable lines in the review packet so grant readiness is not confused with row-policy readiness.");
  }

  if (usingTrue) {
    add(findings, "high", "policy_allows_every_matching_role", "Policy uses true as the row condition", "A permissive policy can turn a narrow grant into broad row access. Replace it with an ownership, membership, tenant, or public-content condition.");
  }

  const authenticatedWritePolicyWithoutAnonymousGuard = policyStatements.some((statement) => (
    usesAuthenticatedRole(statement) && isWritePolicy(statement) && !hasAnonymousUserGuard(statement)
  ));
  if (authenticatedWritePolicyWithoutAnonymousGuard) {
    add(findings, "medium", "authenticated_policy_anonymous_boundary_missing", "Authenticated write policy lacks anonymous-session boundary", "Anonymous sign-ins use the authenticated role. Sensitive writes should usually check the is_anonymous claim explicitly.");
  }

  const authUidPolicyWithoutNullGuard = policyStatements.some((statement) => (
    hasAuthUid(statement) && usesAnonymousReachableRole(statement) && !hasExplicitAuthUidNonNull(statement)
  ));
  if (authUidPolicyWithoutNullGuard) {
    add(findings, "medium", "auth_uid_null_behavior_implicit", "auth.uid() null behavior is implicit", "Use an explicit non-null check or a specific TO role so unauthenticated behavior is intentional and easier to test.");
  }

  if (serviceRole) {
    add(findings, "medium", "service_role_or_bypass_review", "Privileged bypass marker needs separate review", "Service-role and RLS-bypass paths should stay server-side and should not be used as browser fixes for grant or policy errors.");
  }

  if (!findings.some((finding) => finding.severity === "high")) {
    add(findings, "low", "ready_for_role_matrix_tests", "No high-priority grants cutover marker found", "Still run a role matrix test for anon, authenticated, service_role, and no-session calls before launch.");
  }

  return findings;
}

function summarize(findings) {
  if (findings.some((finding) => finding.severity === "high")) return "BLOCK";
  if (findings.some((finding) => finding.severity === "medium")) return "CAUTION";
  return "REVIEW";
}

function buildReport({ label, raw, failOn }) {
  const findings = reviewGrants(raw);
  const failOnMatched = shouldFail(findings, failOn);
  return {
    ok: true,
    label,
    generatedBy: "ai-agent-launch-tools supabase-grants-cutover",
    inputDigest: shortDigest(raw),
    verdict: summarize(findings),
    sourceDates: {
      newProjectsDefault: "2026-05-30",
      existingProjectsRollout: "2026-10-30",
    },
    ci: {
      failOn: failOn || null,
      wouldFail: failOnMatched,
    },
    findings,
    nextChecks: [
      "Record whether default table, function, and sequence privileges are revoked for future public-schema objects.",
      "For every browser-facing table, record the exact anon/authenticated/service_role grants needed.",
      "For every callable RPC, record function-specific EXECUTE revoke/grant evidence.",
      "Run one Data API smoke test as anon, one as authenticated, and one with no session.",
      "Confirm RLS policies still block unintended rows after grants are added.",
    ],
  };
}

function markdown(report) {
  const lines = [
    `# Supabase Grants Cutover Report: ${report.label}`,
    "",
    `Verdict: ${report.verdict}`,
    `Input digest: ${report.inputDigest}`,
    `Generated by: ${report.generatedBy}`,
    "",
    "## Cutover dates",
    "",
    "- May 30, 2026: new projects use the explicit-grants default.",
    "- October 30, 2026: the rollout reaches existing projects.",
    "",
    "## Findings",
    "",
  ];
  for (const finding of report.findings) {
    lines.push(`- ${finding.severity.toUpperCase()} ${finding.code}: ${finding.title}`);
    lines.push(`  - ${finding.detail}`);
  }
  lines.push("", "## Next checks", "");
  for (const check of report.nextChecks) lines.push(`- ${check}`);
  lines.push(
    "",
    "## Safety boundary",
    "",
    "Use redacted SQL or error text only. Do not include secrets, private connection strings, real user data, payment data, private screenshots, full names, private handles, or credential values."
  );
  return lines.join("\n");
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log(usage());
    return;
  }
  const failOn = parseFailOn(readOption(args, "--fail-on", ""));
  const raw = readInput(args);
  const label = readOption(args, "--label", "Supabase grants cutover");
  const report = buildReport({ label, raw, failOn });
  if (args.includes("--json")) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(markdown(report));
  }
  if (report.ci.wouldFail) process.exitCode = 2;
}

main().catch((error) => {
  console.error(`supabase-grants-cutover: ${error.message}`);
  process.exitCode = 1;
});

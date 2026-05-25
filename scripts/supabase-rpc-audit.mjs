#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";

const SECRET_PATTERNS = [
  /\b(?:postgres|postgresql):\/\/[^:\s]+:[^@\s]+@/i,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_]{12,}\b/,
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/,
  /\b(?:api[_-]?key|bearer|password|secret|service[_-]?role[_-]?key|token)\b\s*[:=]\s*["']?[^"',\s]{8,}/i,
];

function usage() {
  return [
    "Usage: supabase-rpc-audit [options]",
    "",
    "Reads redacted Supabase SQL/RPC/view/Security Advisor notes and prints an RLS bypass risk report.",
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

const SEVERITY_RANK = {
  low: 1,
  medium: 2,
  high: 3,
};

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

function reviewSql(raw) {
  validateRedacted(raw);
  const findings = [];
  const hasInput = raw.trim().length > 0;
  const sql = stripSqlComments(raw);
  const hasCreateFunction = /create(?:\s+or\s+replace)?\s+function\s+[\w".]+\s*\(/i.test(sql);
  const hasSecurityAdvisorSearchPath = /function\s+search\s+path\s+mutable|0011_function_search_path_mutable/i.test(raw);
  const hasSecurityDefiner = /security\s+definer/i.test(sql);
  const exposedSchemaFunction = /create(?:\s+or\s+replace)?\s+function\s+public\./i.test(sql);
  const exposedSchemaView = /create(?:\s+or\s+replace)?\s+view\s+public\./i.test(sql);
  const hasSecurityInvokerView = /security_invoker\s*=\s*(?:true|on)/i.test(sql);
  const hasSetSearchPath = /set\s+search_path\s*=/i.test(sql);
  const hasEmptySearchPath = /set\s+search_path\s*=\s*(?:''|""|\(\s*''\s*\))/i.test(sql);
  const hasSearchPathFromCurrent = /set\s+search_path\s+from\s+current/i.test(sql);
  const hasNonEmptySearchPath = /set\s+search_path\s*=\s*(?!\s*(?:''|""|\(\s*''\s*\)))/i.test(sql);
  const hasSqlLanguage = /language\s+sql\b/i.test(sql);
  const hasStableOrImmutable = /\b(?:stable|immutable)\b/i.test(sql);
  const returnsSet = /returns\s+(?:setof|table\b)/i.test(sql);
  const grantExecuteBroad = /grant\s+execute[\s\S]{0,220}\bto\s+(?:public|anon|authenticated)\b/i.test(sql);
  const grantSelectBroad = /grant\s+select[\s\S]{0,220}\bto\s+(?:public|anon|authenticated)\b/i.test(sql);
  const revokeExecute = /revoke\s+execute[\s\S]{0,220}\bfrom\s+(?:public|anon|authenticated)\b/i.test(sql);
  const defaultPrivilegesRevokeExecute = /alter\s+default\s+privileges[\s\S]{0,320}revoke\s+execute[\s\S]{0,220}\bfrom\s+(?:public|anon|authenticated|service_role)\b/i.test(sql);
  const publicExecuteAcl = /\bproacl\b[\s\S]{0,160}\{[^}]*=X\//i.test(raw) || /\{[^}]*=X\/[^}]*\}/i.test(raw);
  const browserRoleExecuteAcl = /\bproacl\b[\s\S]{0,180}\b(?:anon|authenticated)=X\//i.test(raw) || /\b(?:anon|authenticated)=X\//i.test(raw);
  const rpcRestSmoke = /\bPOST\s+\/rest\/v\d+\/rpc\/[A-Za-z0-9_".-]+/i.test(raw);
  const anonRpcSmokeSuccess = rpcRestSmoke && /\b(?:anon|anonymous|publishable)\b[\s\S]{0,220}\b(?:200|201|success|succeeds|executes|executed|callable)\b/i.test(raw);
  const executeUnexpectedLanguage = /\b(?:still|unexpectedly|even though|without explicit grant|no explicit grant)[\s\S]{0,180}\b(?:executable|execute|executes|callable|success|succeeds)\b/i.test(raw);
  const touchesSensitiveTables = /\b(?:profiles|users|sessions|team|teams|tenant|organization|memberships|invites|billing|payments|orders|customers|admin|roles)\b/i.test(sql);
  const hasIdentityCheck = /auth\.uid\s*\(|auth\.jwt\s*\(|current_setting\s*\(\s*'request\.jwt|request\.jwt|is_admin|membership/i.test(sql);
  const usingTrue = /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(sql);
  const serviceRole = /service_role|bypassrls|bypass\s+rls/i.test(sql);
  const rpcMention = /rpc\(|remote procedure|function\s+public\.|create\s+(?:or\s+replace\s+)?function/i.test(sql);
  const viewMention = /view\s+public\.|create\s+(?:or\s+replace\s+)?view/i.test(sql);

  if (!hasInput) {
    add(findings, "medium", "no_redacted_input", "No redacted SQL, RPC, or view notes provided", "Paste a redacted function, view, grant, or RPC note to review for SECURITY DEFINER, missing SECURITY INVOKER, and exposed execution risk.");
    return findings;
  }

  if (exposedSchemaView && !hasSecurityInvokerView) {
    add(findings, "high", "public_view_without_security_invoker", "Public view is missing visible security_invoker=true", "In Postgres 15+, public views that should obey underlying table RLS need WITH (security_invoker = true). Otherwise view execution can use owner privileges and bypass caller RLS expectations.");
  }

  if (exposedSchemaView && !hasSecurityInvokerView && touchesSensitiveTables) {
    add(findings, "high", "view_rls_bypass_regression", "View over sensitive tables may bypass caller RLS", "Treat missing security_invoker on views over user, profile, team, tenant, billing, admin, or membership data as a launch blocker until anon/authenticated regression calls prove expected row visibility.");
  }

  if (grantSelectBroad && exposedSchemaView) {
    add(findings, "high", "broad_view_select_grant", "Broad SELECT grant found on an exposed view", "Review whether anon/authenticated should reach this view at all. If the view stays exposed, verify security_invoker and underlying table RLS with real anon/authenticated calls.");
  }

  if (hasSecurityDefiner && exposedSchemaFunction) {
    add(findings, "high", "security_definer_in_exposed_schema", "SECURITY DEFINER function appears in the public schema", "Move privileged helper functions to a non-exposed schema or prove this public RPC is intentionally callable and has caller-bound authorization checks.");
  } else if (hasSecurityDefiner) {
    add(findings, "medium", "security_definer_review_required", "SECURITY DEFINER function found", "Review creator privileges, exposed schema placement, EXECUTE grants, search_path, and caller authorization before launch.");
  }

  if (hasSecurityDefiner && !hasSetSearchPath) {
    add(findings, "medium", "security_definer_search_path_missing", "SECURITY DEFINER function lacks visible search_path hardening", "Set a narrow search_path so the function does not resolve caller-controlled objects or unexpected public objects.");
  }

  if ((hasCreateFunction || hasSecurityAdvisorSearchPath) && !hasSetSearchPath) {
    add(findings, "medium", "function_search_path_mutable_lint", "Function Search Path Mutable warning likely applies", "Supabase Security Advisor flags functions without an explicit search_path. Add a review note before launch: either pin search_path and fully qualify object references, or document why this function needs a different remediation with tests.");
  }

  if (hasSqlLanguage && hasStableOrImmutable && returnsSet && hasEmptySearchPath) {
    add(findings, "medium", "search_path_empty_sql_inlining_review", "Empty search_path may need SQL-function inlining review", "For stable or immutable SQL functions that return sets, SET search_path can affect Postgres inlining and query plans. Keep the hardening decision, but require EXPLAIN evidence for the caller query and explicit schema-qualified references before treating the lint as fixed.");
  }

  if (hasSearchPathFromCurrent && (hasSecurityDefiner || hasSecurityAdvisorSearchPath)) {
    add(findings, "medium", "search_path_from_current_review", "SET search_path FROM CURRENT needs captured-path evidence", "This can be intentionally hard-coded at function creation time, but the review packet should record the migration-time search_path and the resulting pg_proc.proconfig value so self-hosted/local advisor warnings can be distinguished from truly mutable functions.");
  }

  if (hasNonEmptySearchPath && (hasSecurityDefiner || hasSecurityAdvisorSearchPath)) {
    add(findings, "medium", "non_empty_search_path_review", "Non-empty search_path needs explicit justification", "A non-empty or inherited search_path may be intentional for extension operators, but it should be reviewed against Supabase Security Advisor guidance, exposed schemas, and caller-controlled object resolution risk.");
  }

  if (grantExecuteBroad) {
    add(findings, "high", "broad_execute_grant", "Broad EXECUTE grant found", "Revoke broad function execution first, then grant only the exact role that should call the RPC. Treat anon execution as a launch blocker unless it is intentionally public.");
  } else if (defaultPrivilegesRevokeExecute && (publicExecuteAcl || browserRoleExecuteAcl || anonRpcSmokeSuccess || executeUnexpectedLanguage)) {
    add(findings, "high", "default_execute_revoke_not_enforced", "Default EXECUTE revoke appears contradicted by callable-function evidence", "The packet shows default EXECUTE revocation plus ACL, REST/RPC, or narrative evidence that the function is still callable. Add a function-specific REVOKE after creation and keep an anon/authenticated deny smoke test.");
  } else if (browserRoleExecuteAcl || anonRpcSmokeSuccess) {
    add(findings, "high", "browser_role_rpc_execute_evidence", "Browser-facing role can execute an RPC", "Treat anon/authenticated RPC execution as intentional only if the function is public by design. Otherwise add function-specific REVOKE lines and a deny regression test.");
  } else if (publicExecuteAcl && rpcMention) {
    add(findings, "medium", "public_execute_acl_review", "Function ACL includes public EXECUTE marker", "A proacl entry such as =X means PUBLIC has EXECUTE. Confirm whether this RPC should be callable by browser-facing roles and add explicit revoke/grant evidence.");
  } else if (rpcMention && !revokeExecute) {
    add(findings, "medium", "execute_privilege_evidence_missing", "EXECUTE privilege evidence missing", "Include revoke/grant lines in the review packet so callable roles are explicit.");
  }

  if (hasSecurityDefiner && touchesSensitiveTables && !hasIdentityCheck) {
    add(findings, "high", "rls_bypass_without_caller_check", "Privileged function touches sensitive tables without visible caller check", "A definer RPC can bypass table RLS. Add explicit caller identity, membership, tenant, or admin checks inside the function before returning data or mutating rows.");
  }

  if (usingTrue) {
    add(findings, "high", "permissive_policy_near_rpc", "Permissive policy appears near RPC code", "A permissive policy plus broad RPC access can turn a quick fix into broad data exposure. Replace true policies with ownership or tenant conditions.");
  }

  if (serviceRole) {
    add(findings, "medium", "service_role_or_bypassrls_review", "Service-role or BYPASSRLS language found", "Confirm privileged keys or bypass roles are never browser reachable and are not used as a workaround for client-side RLS failures.");
  }

  if (!hasSecurityDefiner && rpcMention) {
    add(findings, "low", "rpc_without_definer_marker", "RPC/function found without SECURITY DEFINER marker", "Still review EXECUTE grants and caller checks. Invoker functions can be safer, but callable roles and row access still matter.");
  }

  if (viewMention && hasSecurityInvokerView) {
    add(findings, "low", "security_invoker_view_present", "Security invoker view marker found", "Keep a regression test that the rendered or recreated view definition preserves WITH (security_invoker = true) and that anon/authenticated calls see only rows allowed by underlying table RLS.");
  }

  if (!findings.length) {
    add(findings, "low", "no_rpc_or_view_blocker_detected", "No obvious SECURITY DEFINER RPC or view blocker detected", "This is not a safety guarantee. Keep RLS tests, callable-role review, view-definition review, and redacted migration review in the launch checklist.");
  }

  return findings;
}

function summarize(findings) {
  if (findings.some((finding) => finding.severity === "high")) return "BLOCK";
  if (findings.some((finding) => finding.severity === "medium")) return "CAUTION";
  return "REVIEW";
}

function buildReport({ label, raw, failOn }) {
  const findings = reviewSql(raw);
  const failOnMatched = shouldFail(findings, failOn);
  return {
    ok: true,
    label,
    generatedBy: "ai-agent-launch-tools supabase-rpc-audit",
    inputDigest: shortDigest(raw),
    verdict: summarize(findings),
    ci: {
      failOn: failOn || null,
      wouldFail: failOnMatched,
      exitCode: failOnMatched ? 2 : 0,
    },
    findings,
    nextSteps: [
      "Review SECURITY DEFINER functions before launch; they can bypass table RLS.",
      "For Function Search Path Mutable warnings, document the chosen remediation and keep EXPLAIN evidence if performance or SQL-function inlining matters.",
      "For public views that should obey underlying table RLS, preserve WITH (security_invoker = true) and test anon/authenticated calls.",
      "Keep broad EXECUTE grants off public/anon roles unless the RPC is intentionally public.",
      "Add caller-bound auth.uid/auth.jwt/membership checks inside privileged functions that touch tenant, user, billing, admin, or profile data.",
      "Keep real database URLs, tokens, service-role keys, customer data, and private project details out of public reports.",
    ],
    links: {
      browserAudit: "https://ai-launch-risk-check-public.vercel.app/supabase-security-definer-rpc-audit.html",
      sampleReport: "https://ai-launch-risk-check-public.vercel.app/sample-supabase-grants-rls-report.md",
      paidReportOverview: "https://ai-launch-risk-check-public.vercel.app/supabase-launch-risk-report.html",
    },
  };
}

function printMarkdown(report) {
  console.log("# Supabase RPC/View RLS Audit");
  console.log("");
  console.log(`- Label: ${report.label}`);
  console.log(`- Verdict: ${report.verdict}`);
  console.log(`- Input digest: ${report.inputDigest}`);
  console.log(`- Generated by: ${report.generatedBy}`);
  console.log("");
  console.log("| Severity | Code | Finding | Review note |");
  console.log("| --- | --- | --- | --- |");
  for (const finding of report.findings) {
    console.log(`| ${finding.severity.toUpperCase()} | ${finding.code} | ${finding.title} | ${finding.detail} |`);
  }
  console.log("");
  console.log("## Next Steps");
  console.log("");
  for (const step of report.nextSteps) console.log(`- ${step}`);
  console.log("");
  console.log("## Links");
  console.log("");
  console.log(`- Browser audit: ${report.links.browserAudit}`);
  console.log(`- Sample report: ${report.links.sampleReport}`);
  console.log(`- Paid report overview: ${report.links.paidReportOverview}`);
  console.log("");
  console.log("## Safety");
  console.log("");
  console.log("This tool pattern-matches redacted local text only. It does not connect to Supabase, call RPCs, fetch URLs, start servers, or prove that a project is safe.");
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log(usage());
    return;
  }
  const raw = readInput(args);
  const label = readOption(args, "--label", "redacted Supabase SQL");
  const failOn = parseFailOn(readOption(args, "--fail-on", ""));
  const report = buildReport({ label, raw, failOn });
  if (args.includes("--json")) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printMarkdown(report);
  }
  if (report.ci.wouldFail) process.exitCode = report.ci.exitCode;
}

try {
  main();
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}

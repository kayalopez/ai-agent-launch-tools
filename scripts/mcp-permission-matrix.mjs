#!/usr/bin/env node

import fs from "node:fs";
import crypto from "node:crypto";

const GATES = {
  allow: {
    label: "allow",
    evidence: "Record source, purpose, data class, and untrusted-content handling.",
  },
  ask: {
    label: "ask",
    evidence: "Show action class, destination, data classes, arguments, approver, receipt, and rollback path.",
  },
  deny: {
    label: "deny",
    evidence: "Keep blocked unless a human-owned manual flow or sandboxed exception is documented.",
  },
};

const RULES = [
  {
    actionClass: "credential_or_permission",
    gate: "deny",
    patterns: [
      "api_key",
      "apikey",
      "bearer",
      "credential",
      "oauth",
      "password",
      "permission",
      "role",
      "scope",
      "secret",
      "token",
    ],
    reason: "Credential, identity, permission, or access-scope action.",
  },
  {
    actionClass: "financial_or_identity",
    gate: "deny",
    patterns: [
      "bank",
      "billing",
      "card",
      "charge",
      "checkout",
      "invoice",
      "payment",
      "payout",
      "purchase",
      "subscription",
      "tax",
      "transfer",
    ],
    reason: "Financial, tax, billing, payout, or identity-sensitive action.",
  },
  {
    actionClass: "execute_code",
    gate: "deny",
    patterns: [
      "bash",
      "command",
      "deploy",
      "exec",
      "execute",
      "install",
      "npm",
      "python",
      "run_code",
      "shell",
      "subprocess",
      "terminal",
    ],
    reason: "Code, shell, package, or deployment execution.",
  },
  {
    actionClass: "destructive_write",
    gate: "ask",
    patterns: [
      "archive",
      "cancel",
      "delete",
      "destroy",
      "drop",
      "erase",
      "purge",
      "remove",
      "revoke",
      "truncate",
    ],
    reason: "Destructive or hard-to-reverse state change.",
  },
  {
    actionClass: "external_send_or_publish",
    gate: "ask",
    patterns: [
      "comment",
      "dm",
      "email",
      "message",
      "notify",
      "post",
      "publish",
      "reply",
      "send",
      "share",
      "slack",
      "sms",
      "tweet",
    ],
    reason: "External or customer-visible communication.",
  },
  {
    actionClass: "write_record",
    gate: "ask",
    patterns: [
      "add",
      "append",
      "commit",
      "create",
      "edit",
      "insert",
      "merge",
      "patch",
      "save",
      "set",
      "submit",
      "update",
      "upload",
      "write",
    ],
    reason: "Mutates a record, file, repository, ticket, task, or system state.",
  },
  {
    actionClass: "read_private",
    gate: "ask",
    patterns: [
      "customer",
      "database",
      "drive",
      "file",
      "inbox",
      "issue",
      "private",
      "record",
      "repo",
      "sql",
      "ticket",
      "user",
      "workspace",
    ],
    reason: "May read private business context or tenant data.",
  },
  {
    actionClass: "read_public",
    gate: "allow",
    patterns: [
      "browse",
      "fetch",
      "find",
      "get",
      "list",
      "read",
      "search",
    ],
    reason: "Read-only action with no obvious private-data or mutation signal.",
  },
];

const SECRET_PATTERNS = [
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_]{12,}\b/,
  /\b(?:api[_ -]?key|oauth|bearer|password|secret|token)\b\s*[:=]\s*["']?[^"',\s]{8,}/i,
  /\b(?:\d[ -]*?){13,19}\b/,
];

const METADATA_INJECTION_PATTERNS = [
  {
    code: "instruction_override",
    severity: "high",
    terms: ["ignore previous", "ignore all previous", "developer message", "system prompt", "override instructions"],
    reason: "Tool metadata appears to contain instruction-override language.",
  },
  {
    code: "secret_exfiltration_pressure",
    severity: "high",
    terms: ["reveal secret", "exfiltrate", "ssh key", "id_rsa", "private key", "api key", "access token"],
    reason: "Tool metadata appears to pressure the agent toward secret access or exfiltration.",
  },
  {
    code: "concealment_instruction",
    severity: "high",
    terms: ["do not tell", "do not mention", "without telling", "silently", "hide this"],
    reason: "Tool metadata appears to tell the agent to conceal behavior from the user.",
  },
  {
    code: "tool_selection_bias",
    severity: "medium",
    terms: ["deprecated", "recommended version", "prefer this tool", "migrate to this", "supersedes", "legacy tool", "always use this"],
    reason: "Tool metadata appears to bias tool selection through credibility or replacement claims.",
  },
  {
    code: "network_or_file_exfil_hint",
    severity: "medium",
    terms: ["send to http", "send to https", "webhook", "callback url", "upload the file", "read the file first"],
    reason: "Tool metadata appears to hint at network or file-transfer behavior that needs review.",
  },
];

function schemaFinding(path, severity, code, reason) {
  return { path, severity, code, reason };
}

function outputSchemaFinding(path, severity, code, reason) {
  return { path, severity, code, reason };
}

function usage() {
  return [
    "Usage: mcp-permission-matrix [options]",
    "",
    "Reads an MCP tools/list JSON result and prints a non-sensitive permission matrix.",
    "",
    "Options:",
    "  --file <path>          Read JSON from a file instead of stdin.",
    "  --baseline <path>      Compare against a prior JSON matrix snapshot.",
    "  --server <label>       Server label for the report.",
    "  --codex-config         Print only a Codex config.toml review snippet.",
    "  --json                 Print structured JSON.",
    "  --markdown             Print Markdown. Default.",
    "  --help                 Show this help.",
    "",
    "Accepted input shapes:",
    "  { \"tools\": [...] }",
    "  { \"result\": { \"tools\": [...] } }",
    "  [ ...tools ]",
    "",
    "This tool never calls MCP tools. It only classifies metadata.",
  ].join("\n");
}

function readOption(args, name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value.`);
  }
  return value;
}

function readInput(args) {
  const file = readOption(args, "--file", "");
  if (file) return fs.readFileSync(file, "utf8");
  if (process.stdin.isTTY) {
    throw new Error("No input provided. Pass --file <path> or pipe tools/list JSON on stdin.");
  }
  return fs.readFileSync(0, "utf8");
}

function assertNoSensitiveInput(raw) {
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(raw)) {
      throw new Error("Input appears to contain sensitive data. Remove secrets before generating a matrix.");
    }
  }
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

function shortDigest(value) {
  return digest(value).slice(0, 12);
}

function extractTools(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed?.tools)) return parsed.tools;
  if (Array.isArray(parsed?.result?.tools)) return parsed.result.tools;
  if (Array.isArray(parsed?.data?.tools)) return parsed.data.tools;
  throw new Error("Could not find a tools array. Expected { tools: [...] }, { result: { tools: [...] } }, or an array.");
}

function collectStringFields(value, path = "$", output = []) {
  if (typeof value === "string") {
    output.push({ path, value });
    return output;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectStringFields(item, `${path}[${index}]`, output));
    return output;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      collectStringFields(child, `${path}.${key}`, output);
    }
  }
  return output;
}

function collectJsonRefs(value, path = "$", output = []) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectJsonRefs(item, `${path}[${index}]`, output));
    return output;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      if (key === "$ref" && typeof child === "string") {
        output.push({ path: childPath, value: child });
      }
      collectJsonRefs(child, childPath, output);
    }
  }
  return output;
}

function stringifySchemaKeys(schema) {
  return collectStringFields(schema ?? {}, "inputSchema").map((item) => item.value).join(" ");
}

function hasOwn(value, key) {
  return Boolean(value && Object.prototype.hasOwnProperty.call(value, key));
}

function findMetadataInjectionFindings(tool) {
  const fields = [
    { path: "name", value: typeof tool?.name === "string" ? tool.name : "" },
    { path: "description", value: typeof tool?.description === "string" ? tool.description : "" },
    ...collectStringFields(tool?.inputSchema ?? tool?.input_schema ?? {}, "inputSchema"),
  ].filter((item) => item.value.trim());

  const findings = [];
  for (const field of fields) {
    const lower = field.value.toLowerCase();
    for (const pattern of METADATA_INJECTION_PATTERNS) {
      const matched = pattern.terms.find((term) => lower.includes(term));
      if (matched) {
        findings.push({
          path: field.path,
          severity: pattern.severity,
          code: pattern.code,
          matched,
          reason: pattern.reason,
        });
      }
    }
  }
  return findings;
}

function findSchemaReviewFindings(tool) {
  const hasInputSchema = hasOwn(tool, "inputSchema");
  const hasSnakeInputSchema = hasOwn(tool, "input_schema");
  if (!hasInputSchema && !hasSnakeInputSchema) {
    return [
      schemaFinding(
        "inputSchema",
        "medium",
        "missing_input_schema",
        "Tool metadata is missing inputSchema, so clients cannot distinguish a no-argument tool from incomplete metadata."
      ),
    ];
  }

  const path = hasInputSchema ? "inputSchema" : "input_schema";
  const schema = hasInputSchema ? tool.inputSchema : tool.input_schema;
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    return [
      schemaFinding(
        path,
        "medium",
        "invalid_input_schema_shape",
        "Tool inputSchema is not an object. Verify the server is emitting JSON Schema-compatible metadata."
      ),
    ];
  }

  const keys = Object.keys(schema);
  if (keys.length === 0) {
    return [
      schemaFinding(
        path,
        "high",
        "empty_input_schema",
        "Tool inputSchema is an empty object. This often means wrapper schemas or generators dropped parameter metadata from tools/list."
      ),
    ];
  }

  const findings = [];
  for (const ref of collectJsonRefs(schema, path)) {
    const local = ref.value.startsWith("#/");
    findings.push(
      schemaFinding(
        ref.path,
        local ? "medium" : "high",
        local ? "input_schema_local_ref" : "input_schema_external_ref",
        local
          ? "Tool inputSchema contains a local JSON Schema $ref. Some MCP clients and LLM tool adapters do not dereference local refs before argument generation."
          : "Tool inputSchema contains an external JSON Schema $ref. Review whether clients can resolve it before relying on generated arguments."
      )
    );
  }
  const properties = schema.properties && typeof schema.properties === "object" && !Array.isArray(schema.properties) ? schema.properties : null;
  const propertyNames = properties ? Object.keys(properties) : [];
  if ((schema.type === "object" || propertyNames.length > 0) && propertyNames.length === 0) {
    findings.push(
      schemaFinding(
        `${path}.properties`,
        "medium",
        "object_schema_without_properties",
        "Object inputSchema has no properties. Verify this is an intentional no-argument tool, not lost schema metadata."
      )
    );
  }
  if (propertyNames.length > 0 && !Array.isArray(schema.required)) {
    findings.push(
      schemaFinding(
        `${path}.required`,
        "medium",
        "properties_without_required_array",
        "Input schema has properties but no required array. Clients may treat every argument as optional and send empty tool-call arguments; confirm required parameters are declared explicitly."
      )
    );
  }
  for (const [name, property] of Object.entries(properties ?? {})) {
    if (!property || typeof property !== "object" || Array.isArray(property)) {
      findings.push(
        schemaFinding(
          `${path}.properties.${name}`,
          "high",
          "invalid_property_schema_shape",
          "Input parameter schema is not an object. MCP tool inputSchema properties should map parameter names to schema objects; boolean, null, array, or primitive property entries can break client validation and argument generation."
        )
      );
      continue;
    }
    if (Array.isArray(property.type)) {
      findings.push(
        schemaFinding(
          `${path}.properties.${name}.type`,
          "medium",
          "property_union_type_compatibility",
          "Input parameter uses a JSON Schema union type array. This can be valid JSON Schema, but some MCP clients or LLM tool adapters may drop nullable/union detail before argument generation; add a regression test for the target client."
        )
      );
    }
    if (!("description" in property)) {
      findings.push(
        schemaFinding(
          `${path}.properties.${name}.description`,
          "low",
          "property_without_description",
          "Input parameter is missing a description, which can make client-side review and LLM argument generation less reliable."
        )
      );
    }
  }
  return findings;
}

function looksLikeStructuredOutputTool(normalized, classification) {
  const structuredTerms = [
    "data",
    "dataset",
    "evaluate",
    "export",
    "get",
    "json",
    "list",
    "metric",
    "metrics",
    "report",
    "result",
    "schema",
    "search",
    "stat",
    "statistics",
    "stats",
    "status",
    "summary",
  ];
  return (
    classification.actionClass === "read_public" ||
    classification.actionClass === "read_private" ||
    structuredTerms.some((term) => normalized.searchable.includes(term))
  );
}

function findOutputSchemaReviewFindings(tool, normalized, classification) {
  const hasOutputSchema = hasOwn(tool, "outputSchema");
  const hasSnakeOutputSchema = hasOwn(tool, "output_schema");
  if (!hasOutputSchema && !hasSnakeOutputSchema) {
    if (!looksLikeStructuredOutputTool(normalized, classification)) return [];
    return [
      outputSchemaFinding(
        "outputSchema",
        "low",
        "missing_output_schema_for_structured_tool",
        "Tool appears likely to return structured data, but tools/list does not declare outputSchema. Clients cannot validate structuredContent or know the result shape before calling."
      ),
    ];
  }

  const path = hasOutputSchema ? "outputSchema" : "output_schema";
  const schema = hasOutputSchema ? tool.outputSchema : tool.output_schema;
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    return [
      outputSchemaFinding(
        path,
        "medium",
        "invalid_output_schema_shape",
        "Tool outputSchema is not an object. Verify the server is emitting JSON Schema-compatible structured-output metadata."
      ),
    ];
  }
  if (Object.keys(schema).length === 0) {
    return [
      outputSchemaFinding(
        path,
        "medium",
        "empty_output_schema",
        "Tool outputSchema is an empty object. This gives clients no useful contract for validating structuredContent."
      ),
    ];
  }

  const findings = [];
  for (const ref of collectJsonRefs(schema, path)) {
    const local = ref.value.startsWith("#/");
    findings.push(
      outputSchemaFinding(
        ref.path,
        local ? "medium" : "high",
        local ? "output_schema_local_ref" : "output_schema_external_ref",
        local
          ? "Tool outputSchema contains a local JSON Schema $ref. Confirm target clients dereference it before relying on structuredContent validation."
          : "Tool outputSchema contains an external JSON Schema $ref. Review whether clients can resolve it before relying on structuredContent validation."
      )
    );
  }
  const properties = schema.properties && typeof schema.properties === "object" && !Array.isArray(schema.properties) ? schema.properties : null;
  const propertyNames = properties ? Object.keys(properties) : [];
  if ((schema.type === "object" || propertyNames.length > 0) && propertyNames.length === 0) {
    findings.push(
      outputSchemaFinding(
        `${path}.properties`,
        "medium",
        "output_schema_without_properties",
        "Object outputSchema has no properties. Verify this is an intentional empty structured result, not lost result metadata."
      )
    );
  }
  if (propertyNames.length > 0 && !Array.isArray(schema.required)) {
    findings.push(
      outputSchemaFinding(
        `${path}.required`,
        "low",
        "output_properties_without_required_array",
        "Output schema has properties but no required array. Confirm every structuredContent field is intentionally optional."
      )
    );
  }
  for (const [name, property] of Object.entries(properties ?? {})) {
    if (!property || typeof property !== "object" || Array.isArray(property)) {
      findings.push(
        outputSchemaFinding(
          `${path}.properties.${name}`,
          "high",
          "invalid_output_property_schema_shape",
          "Output property schema is not an object. MCP tool outputSchema properties should map result field names to schema objects."
        )
      );
      continue;
    }
    if (Array.isArray(property.type)) {
      findings.push(
        outputSchemaFinding(
          `${path}.properties.${name}.type`,
          "medium",
          "output_property_union_type_compatibility",
          "Output property uses a JSON Schema union type array. Add a client regression test before relying on structuredContent validation across clients."
        )
      );
    }
    if (!("description" in property)) {
      findings.push(
        outputSchemaFinding(
          `${path}.properties.${name}.description`,
          "low",
          "output_property_without_description",
          "Output property is missing a description, which can make client-side display and downstream result handling less reliable."
        )
      );
    }
  }
  return findings;
}

function annotationFinding(path, severity, code, reason) {
  return { path, severity, code, reason };
}

function findAnnotationReviewFindings(tool, classification) {
  const annotations = tool?.annotations;
  const hasAnnotations = Boolean(annotations && typeof annotations === "object" && !Array.isArray(annotations));
  const findings = [];
  if (!hasAnnotations || Object.keys(annotations).length === 0) {
    findings.push(
      annotationFinding(
        "annotations",
        "medium",
        "missing_tool_annotations",
        "Tool metadata does not include MCP annotations. Clients cannot use readOnlyHint, destructiveHint, idempotentHint, or openWorldHint to shape approval prompts."
      )
    );
    return findings;
  }

  const mutatingOrRisky = new Set([
    "credential_or_permission",
    "financial_or_identity",
    "execute_code",
    "destructive_write",
    "external_send_or_publish",
    "write_record",
  ]);
  if (mutatingOrRisky.has(classification.actionClass) && typeof annotations.destructiveHint !== "boolean") {
    findings.push(
      annotationFinding(
        "annotations.destructiveHint",
        "medium",
        "missing_destructive_hint",
        "Tool looks mutating or externally visible, but destructiveHint is not set. Clients may show weaker confirmation prompts than the tool deserves."
      )
    );
  }
  if (classification.actionClass === "read_public" && annotations.readOnlyHint !== true) {
    findings.push(
      annotationFinding(
        "annotations.readOnlyHint",
        "low",
        "missing_readonly_hint",
        "Tool looks read-only, but readOnlyHint is not true. Clients may not be able to distinguish safe reads from actions that need approval."
      )
    );
  }
  if (classification.gate === "ask" && typeof annotations.openWorldHint !== "boolean") {
    findings.push(
      annotationFinding(
        "annotations.openWorldHint",
        "low",
        "missing_open_world_hint",
        "Tool needs review, but openWorldHint is not set. Clients cannot tell whether the tool may interact with external systems."
      )
    );
  }
  return findings;
}

function normalizeTool(tool, index) {
  const name = typeof tool?.name === "string" && tool.name.trim() ? tool.name.trim() : `tool_${index + 1}`;
  const description = typeof tool?.description === "string" ? tool.description.trim() : "";
  const annotations = tool?.annotations && typeof tool.annotations === "object" ? tool.annotations : {};
  const schemaText = stringifySchemaKeys(tool?.inputSchema ?? tool?.input_schema ?? {});
  const metadataInjectionFindings = findMetadataInjectionFindings(tool);
  const schemaReviewFindings = findSchemaReviewFindings(tool);
  const metaText = [
    tool?._meta?.tool_configuration?.require_approval,
    tool?._meta?.tool_configuration?.server_label,
    tool?._meta?.tool_configuration?.type,
  ].filter(Boolean).join(" ");
  return {
    name,
    description,
    annotations,
    sourceDigest: shortDigest({
      name,
      description,
      inputSchema: tool?.inputSchema ?? tool?.input_schema ?? null,
      outputSchema: tool?.outputSchema ?? tool?.output_schema ?? null,
      annotations,
      toolConfiguration: tool?._meta?.tool_configuration ?? null,
    }),
    searchable: `${name} ${description} ${schemaText} ${metaText}`.toLowerCase(),
    metadataInjectionFindings,
    schemaReviewFindings,
  };
}

function hasPromptInjectionSignal(text) {
  return [
    "ignore previous",
    "ignore all previous",
    "do not tell",
    "developer message",
    "system prompt",
    "reveal secret",
    "exfiltrate",
    "override",
  ].some((term) => text.includes(term));
}

function classify(normalized) {
  if (normalized.metadataInjectionFindings.length || hasPromptInjectionSignal(normalized.searchable)) {
    return {
      actionClass: "metadata_injection_signal",
      gate: "deny",
      reason: "Tool name, description, or inputSchema contains instruction-like, tool-selection-bias, or exfiltration language.",
    };
  }

  if (normalized.schemaReviewFindings.some((finding) => finding.severity === "high" || finding.severity === "medium")) {
    return {
      actionClass: "schema_review_signal",
      gate: "ask",
      reason: "Tool inputSchema is missing, empty, underspecified, or contains refs that may be degraded by MCP clients. Review metadata completeness before first invocation.",
    };
  }

  // Annotation pre-pass: when the server declares the action shape via
  // MCP standard annotations, trust that declaration over keyword
  // matching against tool descriptions. The injection and schema-review
  // checks above are orthogonal (they assess metadata quality, not
  // action shape) and still fire; this layer specifically replaces the
  // substring-based action classification because the server's own
  // declaration is strictly stronger evidence than substring matches.
  const ann = normalized.annotations;
  if (ann.destructiveHint === true) {
    return {
      actionClass: "destructive_write",
      gate: "ask",
      reason: "Server declared destructiveHint=true. Destructive or hard-to-reverse state change.",
    };
  }
  if (ann.readOnlyHint === true) {
    // openWorldHint=true means the read may touch systems beyond the
    // local server's bounded context (e.g. a public web fetch). Route
    // those to read_public/allow. Default (false or unset) is the
    // safer read_private/ask classification.
    const isPublic = ann.openWorldHint === true;
    return {
      actionClass: isPublic ? "read_public" : "read_private",
      gate: isPublic ? "allow" : "ask",
      reason: isPublic
        ? "Server declared readOnlyHint=true with openWorldHint=true. Read-only action with no obvious private-data or mutation signal."
        : "Server declared readOnlyHint=true. May read private business context or tenant data.",
    };
  }

  for (const rule of RULES) {
    if (rule.patterns.some((pattern) => normalized.searchable.includes(pattern))) {
      return {
        actionClass: rule.actionClass,
        gate: rule.gate,
        reason: rule.reason,
      };
    }
  }

  return {
    actionClass: "unknown",
    gate: "ask",
    reason: "No confident classification. Review before first invocation.",
  };
}

function buildMatrix({ tools, server }) {
  const rows = tools.map((tool, index) => {
    const normalized = normalizeTool(tool, index);
    const classification = classify(normalized);
    const annotationReviewFindings = findAnnotationReviewFindings(tool, classification);
    const outputSchemaReviewFindings = findOutputSchemaReviewFindings(tool, normalized, classification);
    const policyKey = `${server}.${normalized.name}`.replace(/\s+/g, "_");
    return {
      tool: normalized.name,
      policyKey,
      metadataDigest: normalized.sourceDigest,
      description: normalized.description || "(no description)",
      annotationHints: {
        readOnlyHint: normalized.annotations.readOnlyHint ?? null,
        destructiveHint: normalized.annotations.destructiveHint ?? null,
        idempotentHint: normalized.annotations.idempotentHint ?? null,
        openWorldHint: normalized.annotations.openWorldHint ?? null,
      },
      actionClass: classification.actionClass,
      defaultGate: classification.gate,
      reason: classification.reason,
      evidence: GATES[classification.gate].evidence,
      metadataInjectionFindings: normalized.metadataInjectionFindings,
      schemaReviewFindings: normalized.schemaReviewFindings,
      annotationReviewFindings,
      outputSchemaReviewFindings,
    };
  });

  const totals = rows.reduce((acc, row) => {
    acc[row.defaultGate] = (acc[row.defaultGate] ?? 0) + 1;
    return acc;
  }, { allow: 0, ask: 0, deny: 0 });

  return {
    ok: true,
    server,
    generatedBy: "ai-agent-launch-tools mcp-permission-matrix",
    toolCount: rows.length,
    snapshotDigest: shortDigest({
      server,
      tools: rows.map((row) => ({
        policyKey: row.policyKey,
        metadataDigest: row.metadataDigest,
        defaultGate: row.defaultGate,
        actionClass: row.actionClass,
      })),
    }),
    totals,
    metadataInjectionFindingCount: rows.reduce((total, row) => total + row.metadataInjectionFindings.length, 0),
    schemaReviewFindingCount: rows.reduce((total, row) => total + row.schemaReviewFindings.length, 0),
    annotationReviewFindingCount: rows.reduce((total, row) => total + row.annotationReviewFindings.length, 0),
    outputSchemaReviewFindingCount: rows.reduce((total, row) => total + row.outputSchemaReviewFindings.length, 0),
    rows,
    launchRule: "New or changed MCP tools should default to ask or deny until their action class, data boundary, approval UI, receipt, and rollback path are reviewed.",
    safety: "Do not include secrets, customer records, private screenshots, payment data, OAuth tokens, cookies, API keys, card, bank, tax, payout, or full transaction identifiers in tools/list examples or reports.",
  };
}

function readBaseline(file) {
  if (!file) return null;
  const raw = fs.readFileSync(file, "utf8");
  assertNoSensitiveInput(raw);
  const parsed = JSON.parse(raw);
  const rows = Array.isArray(parsed?.rows) ? parsed.rows : Array.isArray(parsed) ? parsed : [];
  if (!rows.length) {
    throw new Error("Baseline file must be JSON output from this tool or an array of rows.");
  }
  return {
    source: file,
    snapshotDigest: parsed?.snapshotDigest ?? null,
    rows,
  };
}

function compareBaseline(matrix, baseline) {
  if (!baseline) return null;
  const before = new Map();
  for (const row of baseline.rows) {
    const key = row.policyKey || row.tool;
    if (key) before.set(key, row);
  }
  const after = new Map(matrix.rows.map((row) => [row.policyKey || row.tool, row]));
  const changes = [];

  for (const [key, row] of after.entries()) {
    const prior = before.get(key);
    if (!prior) {
      changes.push({ policyKey: key, change: "added", previousGate: null, currentGate: row.defaultGate, previousDigest: null, currentDigest: row.metadataDigest });
      continue;
    }
    if ((prior.metadataDigest ?? "") !== row.metadataDigest || (prior.defaultGate ?? "") !== row.defaultGate) {
      changes.push({
        policyKey: key,
        change: "changed",
        previousGate: prior.defaultGate ?? null,
        currentGate: row.defaultGate,
        previousDigest: prior.metadataDigest ?? null,
        currentDigest: row.metadataDigest,
      });
    }
  }

  for (const [key, row] of before.entries()) {
    if (!after.has(key)) {
      changes.push({ policyKey: key, change: "removed", previousGate: row.defaultGate ?? null, currentGate: null, previousDigest: row.metadataDigest ?? null, currentDigest: null });
    }
  }

  const totals = changes.reduce((acc, item) => {
    acc[item.change] = (acc[item.change] ?? 0) + 1;
    return acc;
  }, { added: 0, changed: 0, removed: 0 });

  return {
    baseline: baseline.source,
    previousSnapshotDigest: baseline.snapshotDigest,
    currentSnapshotDigest: matrix.snapshotDigest,
    unchanged: matrix.rows.length - totals.added - totals.changed,
    totals,
    reviewRequired: changes.length > 0,
    changes,
  };
}

function escapeCell(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();
}

function quoteTomlString(value) {
  return JSON.stringify(String(value));
}

function codexApprovalMode(gate) {
  if (gate === "allow") return "approve";
  return "prompt";
}

function buildCodexConfig(matrix) {
  const allowRows = matrix.rows.filter((row) => row.defaultGate === "allow");
  const askRows = matrix.rows.filter((row) => row.defaultGate === "ask");
  const denyRows = matrix.rows.filter((row) => row.defaultGate === "deny");
  const allTools = matrix.rows.map((row) => row.tool);

  const lines = [
    "# Codex MCP approval review snippet",
    `# Server label reviewed: ${matrix.server}`,
    `# Reviewed tools/list snapshot: ${matrix.snapshotDigest}`,
    "# Codex approval_mode values from the current schema: auto, prompt, approve.",
    "# Keep sandbox/read-only settings separate from MCP tool approval.",
    "",
    `[mcp_servers.${quoteTomlString(matrix.server)}]`,
    '# Add your reviewed transport here, for example command/args or url.',
    'default_tools_approval_mode = "prompt"',
  ];

  if (allTools.length) {
    lines.push(`enabled_tools = [${allTools.map(quoteTomlString).join(", ")}]`);
  }
  if (denyRows.length) {
    lines.push(`disabled_tools = [${denyRows.map((row) => quoteTomlString(row.tool)).join(", ")}]`);
  }

  for (const row of [...allowRows, ...askRows]) {
    lines.push("");
    lines.push(`[mcp_servers.${quoteTomlString(matrix.server)}.tools.${quoteTomlString(row.tool)}]`);
    lines.push(`approval_mode = ${quoteTomlString(codexApprovalMode(row.defaultGate))}`);
    lines.push(`# ${row.policyKey} digest ${row.metadataDigest}: ${row.reason}`);
  }

  const reviewNotes = [
    "Paste only after reviewing the transport, command/url, cwd, env boundary, and each tool's data boundary.",
    "Deny is represented with disabled_tools because Codex tool approval modes are auto, prompt, and approve.",
    "If the snapshot digest or any metadata digest changes, re-run review before inheriting prior approval.",
    "This snippet does not disable Codex sandboxing and does not call MCP tools.",
  ];

  return {
    server: matrix.server,
    snapshotDigest: matrix.snapshotDigest,
    allowTools: allowRows.map((row) => row.tool),
    askTools: askRows.map((row) => row.tool),
    disabledTools: denyRows.map((row) => row.tool),
    toml: lines.join("\n"),
    reviewNotes,
  };
}

function printMarkdown(matrix) {
  console.log("# MCP Permission Matrix");
  console.log("");
  console.log(`- Server: ${matrix.server}`);
  console.log(`- Tools reviewed: ${matrix.toolCount}`);
  console.log(`- Default gates: allow ${matrix.totals.allow}, ask ${matrix.totals.ask}, deny ${matrix.totals.deny}`);
  console.log(`- Snapshot digest: ${matrix.snapshotDigest}`);
  console.log(`- Metadata/schema injection findings: ${matrix.metadataInjectionFindingCount}`);
  console.log(`- Schema review findings: ${matrix.schemaReviewFindingCount}`);
  console.log(`- Output schema review findings: ${matrix.outputSchemaReviewFindingCount}`);
  console.log(`- Annotation review findings: ${matrix.annotationReviewFindingCount}`);
  console.log(`- Generated by: ${matrix.generatedBy}`);
  console.log("");
  console.log("| Tool | Policy key | Digest | Action class | Default gate | Reason | Evidence to keep |");
  console.log("| --- | --- | --- | --- | --- | --- | --- |");
  for (const row of matrix.rows) {
    console.log(`| ${escapeCell(row.tool)} | ${escapeCell(row.policyKey)} | ${escapeCell(row.metadataDigest)} | ${escapeCell(row.actionClass)} | ${escapeCell(row.defaultGate)} | ${escapeCell(row.reason)} | ${escapeCell(row.evidence)} |`);
  }
  if (matrix.metadataInjectionFindingCount) {
    console.log("");
    console.log("## Metadata And Schema Injection Findings");
    console.log("");
    console.log("These findings scan tool names, tool descriptions, and every string inside `inputSchema`, including nested parameter descriptions, titles, defaults, and enum values.");
    console.log("");
    console.log("| Tool | Path | Severity | Code | Matched term | Review note |");
    console.log("| --- | --- | --- | --- | --- | --- |");
    for (const row of matrix.rows) {
      for (const finding of row.metadataInjectionFindings) {
        console.log(`| ${escapeCell(row.tool)} | ${escapeCell(finding.path)} | ${escapeCell(finding.severity)} | ${escapeCell(finding.code)} | ${escapeCell(finding.matched)} | ${escapeCell(finding.reason)} |`);
      }
    }
  }
  if (matrix.schemaReviewFindingCount) {
    console.log("");
    console.log("## Schema Review Findings");
    console.log("");
    console.log("These findings flag missing, empty, underspecified, or `$ref`-based `inputSchema` metadata that can break client-side review, validation, or argument generation.");
    console.log("");
    console.log("| Tool | Path | Severity | Code | Review note |");
    console.log("| --- | --- | --- | --- | --- |");
    for (const row of matrix.rows) {
      for (const finding of row.schemaReviewFindings) {
        console.log(`| ${escapeCell(row.tool)} | ${escapeCell(finding.path)} | ${escapeCell(finding.severity)} | ${escapeCell(finding.code)} | ${escapeCell(finding.reason)} |`);
      }
    }
  }
  if (matrix.outputSchemaReviewFindingCount) {
    console.log("");
    console.log("## Output Schema Review Findings");
    console.log("");
    console.log("These findings flag missing or incomplete MCP `outputSchema` metadata for tools that appear to return structured data, plus output schemas that may not validate `structuredContent` reliably.");
    console.log("");
    console.log("| Tool | Path | Severity | Code | Review note |");
    console.log("| --- | --- | --- | --- | --- |");
    for (const row of matrix.rows) {
      for (const finding of row.outputSchemaReviewFindings) {
        console.log(`| ${escapeCell(row.tool)} | ${escapeCell(finding.path)} | ${escapeCell(finding.severity)} | ${escapeCell(finding.code)} | ${escapeCell(finding.reason)} |`);
      }
    }
  }
  if (matrix.annotationReviewFindingCount) {
    console.log("");
    console.log("## Annotation Review Findings");
    console.log("");
    console.log("These findings flag missing or incomplete MCP `annotations` hints that clients can use for read-only, destructive, idempotent, and open-world approval prompts.");
    console.log("");
    console.log("| Tool | Path | Severity | Code | Review note |");
    console.log("| --- | --- | --- | --- | --- |");
    for (const row of matrix.rows) {
      for (const finding of row.annotationReviewFindings) {
        console.log(`| ${escapeCell(row.tool)} | ${escapeCell(finding.path)} | ${escapeCell(finding.severity)} | ${escapeCell(finding.code)} | ${escapeCell(finding.reason)} |`);
      }
    }
  }
  if (matrix.baselineComparison) {
    console.log("");
    console.log("## Snapshot Comparison");
    console.log("");
    console.log(`- Baseline: ${matrix.baselineComparison.baseline}`);
    console.log(`- Previous snapshot: ${matrix.baselineComparison.previousSnapshotDigest ?? "(not recorded)"}`);
    console.log(`- Current snapshot: ${matrix.baselineComparison.currentSnapshotDigest}`);
    console.log(`- Changes: added ${matrix.baselineComparison.totals.added}, changed ${matrix.baselineComparison.totals.changed}, removed ${matrix.baselineComparison.totals.removed}`);
    console.log(`- Review required: ${matrix.baselineComparison.reviewRequired ? "yes" : "no"}`);
    if (matrix.baselineComparison.changes.length) {
      console.log("");
      console.log("| Policy key | Change | Previous gate | Current gate | Previous digest | Current digest |");
      console.log("| --- | --- | --- | --- | --- | --- |");
      for (const change of matrix.baselineComparison.changes) {
        console.log(`| ${escapeCell(change.policyKey)} | ${escapeCell(change.change)} | ${escapeCell(change.previousGate ?? "")} | ${escapeCell(change.currentGate ?? "")} | ${escapeCell(change.previousDigest ?? "")} | ${escapeCell(change.currentDigest ?? "")} |`);
      }
    }
  }
  console.log("");
  console.log("## Launch Rule");
  console.log("");
  console.log(matrix.launchRule);
  console.log("");
  console.log("## Codex Config Review Snippet");
  console.log("");
  console.log("For Codex, `allow` maps to `approval_mode = \"approve\"`, `ask` maps to `approval_mode = \"prompt\"`, and `deny` maps to `disabled_tools`.");
  console.log("");
  console.log("```toml");
  console.log(matrix.codexConfig.toml);
  console.log("```");
  console.log("");
  for (const note of matrix.codexConfig.reviewNotes) {
    console.log(`- ${note}`);
  }
  console.log("");
  console.log("## Safety");
  console.log("");
  console.log(matrix.safety);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log(usage());
    return 0;
  }

  const json = args.includes("--json");
  const markdown = args.includes("--markdown");
  const codexConfigOnly = args.includes("--codex-config");
  const outputModes = [json, markdown, codexConfigOnly].filter(Boolean).length;
  if (outputModes > 1) {
    console.error("Error: use only one output mode: --json, --markdown, or --codex-config.");
    return 1;
  }

  let raw;
  let parsed;
  let server;
  let baseline;
  try {
    raw = readInput(args);
    assertNoSensitiveInput(raw);
    parsed = JSON.parse(raw);
    server = readOption(args, "--server", parsed?.server_label ?? parsed?.serverLabel ?? "candidate MCP server");
    baseline = readBaseline(readOption(args, "--baseline", ""));
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  let matrix;
  try {
    matrix = buildMatrix({ tools: extractTools(parsed), server });
    matrix.baselineComparison = compareBaseline(matrix, baseline);
    matrix.codexConfig = buildCodexConfig(matrix);
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  if (json) console.log(JSON.stringify(matrix, null, 2));
  else if (codexConfigOnly) {
    console.log(matrix.codexConfig.toml);
    console.log("");
    for (const note of matrix.codexConfig.reviewNotes) {
      console.log(`# ${note}`);
    }
  }
  else printMarkdown(matrix);
  return 0;
}

process.exitCode = main();

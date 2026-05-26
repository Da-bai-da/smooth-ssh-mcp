import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { redactAndTruncate } from "./redaction.js";
import type { Redaction } from "./types.js";

export type AuditResultKind = "confirmation_required" | "policy_decision" | "exec_result" | "blocked" | "ok" | "error";

export type AuditToolCall = {
  tool: string;
  input: unknown;
  result: unknown;
  durationMs: number;
};

export type Auditor = {
  recordToolCall(call: AuditToolCall): void;
};

export type JsonlAuditorOptions = {
  path?: string;
  enabled?: boolean;
  now?: () => Date;
};

const SENSITIVE_KEYS = new Set(["confirmationToken", "env", "stdin", "input", "password", "passwordEnv", "secret", "token", "value"]);

export class JsonlAuditor implements Auditor {
  private readonly path: string;
  private readonly enabled: boolean;
  private readonly now: () => Date;

  constructor(options: JsonlAuditorOptions = {}) {
    this.path = expandHome(options.path ?? process.env.SMOOTH_SSH_MCP_AUDIT_LOG ?? "~/.config/smooth-ssh-mcp/audit.jsonl");
    this.enabled = options.enabled ?? process.env.SMOOTH_SSH_MCP_AUDIT !== "0";
    this.now = options.now ?? (() => new Date());
  }

  recordToolCall(call: AuditToolCall): void {
    if (!this.enabled) return;
    const entry = summarizeToolCall(call, this.now());
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    appendFileSync(this.path, JSON.stringify(entry) + "\n", { encoding: "utf8", mode: 0o600 });
  }
}

export function summarizeToolCall(call: AuditToolCall, timestamp: Date): Record<string, unknown> {
  const result = call.result;
  const redactions = collectRedactions(result);
  return {
    timestamp: timestamp.toISOString(),
    tool: call.tool,
    hostId: findString(call.input, "hostId") ?? findString(result, "hostId"),
    operation: inferOperation(call.tool, result),
    resultKind: resultKind(result),
    exitCode: findNumberOrNull(result, "exitCode"),
    durationMs: call.durationMs,
    remoteDurationMs: findNumber(result, "durationMs"),
    truncated: findBoolean(result, "truncated"),
    redactions,
    input: sanitizeValue(call.input)
  };
}

function resultKind(value: unknown): AuditResultKind {
  if (!value || typeof value !== "object") return "ok";
  const input = value as Record<string, unknown>;
  if (input.confirmationRequired === true) return "confirmation_required";
  if (input.blocked) return "blocked";
  if (typeof input.exitCode === "number" || input.exitCode === null) return "exec_result";
  if (typeof input.allowed === "boolean" && typeof input.confirmationRequired === "boolean") return "policy_decision";
  if (input.error) return "error";
  return "ok";
}

function inferOperation(tool: string, result: unknown): string {
  const resultOperation = findString(result, "operation");
  if (resultOperation) return resultOperation;
  if (tool.includes("upload")) return "upload";
  if (tool.includes("download")) return "download";
  if (tool.includes("forward")) return "forward";
  if (tool.includes("session")) return "pty";
  if (["host_add", "host_update", "host_remove", "secret_set"].some((name) => tool.includes(name))) return "config";
  if (tool.includes("permission")) return "permission";
  if (tool.includes("ssh") || tool.includes("task") || tool.includes("cleanup")) return "exec";
  return "local";
}

function sanitizeValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sanitizeValue);
  if (!value || typeof value !== "object") return sanitizeScalar(value);
  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    output[key] = isSensitiveKey(key) ? "[REDACTED]" : sanitizeValue(child);
  }
  return output;
}

function sanitizeScalar(value: unknown): unknown {
  if (typeof value !== "string") return value;
  return redactAndTruncate(value, 1024).text;
}

function isSensitiveKey(key: string): boolean {
  const lower = key.toLowerCase();
  return SENSITIVE_KEYS.has(key) || lower.includes("password") || lower.includes("secret") || lower.includes("token");
}

function collectRedactions(value: unknown): Redaction[] {
  const redactions = findValue(value, "redactions");
  return Array.isArray(redactions) ? (redactions as Redaction[]) : [];
}

function findString(value: unknown, key: string): string | undefined {
  const found = findValue(value, key);
  return typeof found === "string" ? found : undefined;
}

function findNumber(value: unknown, key: string): number | undefined {
  const found = findValue(value, key);
  return typeof found === "number" ? found : undefined;
}

function findNumberOrNull(value: unknown, key: string): number | null | undefined {
  const found = findValue(value, key);
  return typeof found === "number" || found === null ? found : undefined;
}

function findBoolean(value: unknown, key: string): boolean | undefined {
  const found = findValue(value, key);
  return typeof found === "boolean" ? found : undefined;
}

function findValue(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object") return undefined;
  const direct = (value as Record<string, unknown>)[key];
  if (direct !== undefined) return direct;
  const blocked = (value as Record<string, unknown>).blocked;
  if (blocked && typeof blocked === "object") {
    const blockedValue = findValue(blocked, key);
    if (blockedValue !== undefined) return blockedValue;
  }
  const result = (value as Record<string, unknown>).result;
  if (result && typeof result === "object") {
    const resultValue = findValue(result, key);
    if (resultValue !== undefined) return resultValue;
  }
  return undefined;
}

function expandHome(path: string): string {
  if (path === "~") return process.env.HOME ?? path;
  if (path.startsWith("~/")) return join(process.env.HOME ?? "", path.slice(2));
  return path;
}

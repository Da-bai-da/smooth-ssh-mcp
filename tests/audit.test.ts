import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JsonlAuditor } from "../src/audit.js";

describe("JsonlAuditor", () => {
  it("appends redacted JSONL tool call records", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-audit-"));
    const auditPath = join(dir, "audit.jsonl");
    const auditor = new JsonlAuditor({ path: auditPath, now: () => new Date("2026-01-01T00:00:00.000Z") });

    auditor.recordToolCall({
      tool: "ssh_exec",
      input: {
        hostId: "prod-api",
        command: "cat /etc/hostname",
        confirmationToken: "secret-token",
        env: { API_TOKEN: "secret" },
        stdin: "password=secret"
      },
      result: {
        exitCode: 0,
        durationMs: 12,
        truncated: false,
        redactions: [{ pattern: "token", count: 1 }]
      },
      durationMs: 15
    });

    const line = readFileSync(auditPath, "utf8").trim();
    const entry = JSON.parse(line);
    expect(entry).toMatchObject({
      timestamp: "2026-01-01T00:00:00.000Z",
      tool: "ssh_exec",
      hostId: "prod-api",
      operation: "exec",
      resultKind: "exec_result",
      exitCode: 0,
      durationMs: 15,
      remoteDurationMs: 12,
      truncated: false,
      redactions: [{ pattern: "token", count: 1 }]
    });
    expect(entry.input).toMatchObject({
      hostId: "prod-api",
      command: "cat /etc/hostname",
      confirmationToken: "[REDACTED]",
      env: "[REDACTED]",
      stdin: "[REDACTED]"
    });
    expect(line).not.toContain("secret-token");
    expect(line).not.toContain("password=secret");
  });
});

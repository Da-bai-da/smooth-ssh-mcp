import { describe, expect, it } from "vitest";
import { createMcpServer } from "../src/mcpServer.js";
import type { SshOperations } from "../src/operations.js";
import packageJson from "../package.json" with { type: "json" };

type RegisteredTool = {
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
};

function registeredTools(): Record<string, RegisteredTool> {
  const server = createMcpServer({} as SshOperations);
  return (server as unknown as { _registeredTools: Record<string, RegisteredTool> })._registeredTools;
}

describe("MCP tool metadata", () => {
  it("uses the package version in MCP server metadata", () => {
    const server = createMcpServer({} as SshOperations);
    const info = (server as unknown as { server: { _serverInfo: { version: string } } }).server._serverInfo;

    expect(info.version).toBe(packageJson.version);
  });

  it("marks connection and observation tools as low-friction read-only hints", () => {
    const tools = registeredTools();

    for (const name of [
      "host_list",
      "host_get",
      "host_recent",
      "capability_list",
      "host_connect",
      "ssh_probe",
      "host_health",
      "session_start",
      "session_read",
      "session_list",
      "session_stop",
      "forward_list",
      "forward_stop"
    ]) {
      expect(tools[name]?.annotations, name).toMatchObject({
        readOnlyHint: true,
        destructiveHint: false
      });
    }
  });

  it("keeps command, input, transfer, and forward-start tools outside read-only auto-approval", () => {
    const tools = registeredTools();

    for (const name of ["ssh_exec", "ssh_command", "task_batch", "cleanup_paths", "session_send", "file_upload", "file_download", "forward_start"]) {
      expect(tools[name]?.annotations, name).toMatchObject({
        readOnlyHint: false,
        destructiveHint: true
      });
    }
  });

  it("exposes host config tools as confirmed local state tools", () => {
    const tools = registeredTools();

    for (const name of ["host_add", "host_update", "host_remove", "secret_set"]) {
      expect(tools[name]?.annotations, name).toMatchObject({
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false
      });
    }
  });

  it("exposes only the numeric permission override tool", () => {
    const tools = registeredTools();

    expect(tools.host_permission_set).toBeDefined();
    expect(tools.host_safety_set).toBeUndefined();
  });

  it("uses form elicitation to confirm a blocked command when the client supports choices", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const operations = {
      sshCommand: async (input: Record<string, unknown>) => {
        calls.push(input);
        if (!input.confirmationToken) {
          return {
            confirmationRequired: true,
            token: "confirm-token",
            risk: "high",
            reason: "command appears to modify remote state",
            hostId: "prod-api",
            operation: "exec",
            preview: {
              command: "rm -rf /tmp/old-file"
            },
            expiresAt: "2026-01-01T00:05:00.000Z"
          };
        }
        return {
          hostId: "prod-api",
          commandId: "command-id",
          exitCode: 0,
          signal: null,
          stdout: "",
          stderr: "",
          startedAt: "2026-01-01T00:00:00.000Z",
          endedAt: "2026-01-01T00:00:00.010Z",
          durationMs: 10,
          truncated: false,
          redactions: []
        };
      }
    } as unknown as SshOperations;
    const server = createMcpServer(operations);
    const mcp = server as unknown as {
      server: {
        getClientCapabilities: () => unknown;
        elicitInput: (input: unknown) => Promise<unknown>;
      };
      _registeredTools: Record<string, { handler: (input: unknown) => Promise<unknown> }>;
    };
    mcp.server.getClientCapabilities = () => ({ elicitation: { form: {} } });
    mcp.server.elicitInput = async () => ({
      action: "accept",
      content: {
        decision: "confirm"
      }
    });

    const result = await mcp._registeredTools.ssh_command.handler({
      hostId: "prod-api",
      program: "rm",
      args: ["-rf", "/tmp/old-file"]
    });

    expect(JSON.parse((result as { content: Array<{ text: string }> }).content[0].text)).toMatchObject({
      exitCode: 0,
      commandId: "command-id"
    });
    expect(calls).toEqual([
      { hostId: "prod-api", program: "rm", args: ["-rf", "/tmp/old-file"] },
      { hostId: "prod-api", program: "rm", args: ["-rf", "/tmp/old-file"], confirmationToken: "confirm-token" }
    ]);
  });

  it("falls back to returning confirmationRequired when the client has no choice UI support", async () => {
    const operations = {
      sshCommand: async () => ({
        confirmationRequired: true,
        token: "confirm-token",
        risk: "high",
        reason: "command appears to modify remote state",
        hostId: "prod-api",
        operation: "exec",
        preview: {
          command: "rm -rf /tmp/old-file"
        },
        expiresAt: "2026-01-01T00:05:00.000Z"
      })
    } as unknown as SshOperations;
    const server = createMcpServer(operations);
    const mcp = server as unknown as {
      _registeredTools: Record<string, { handler: (input: unknown) => Promise<unknown> }>;
    };

    const result = await mcp._registeredTools.ssh_command.handler({
      hostId: "prod-api",
      program: "rm",
      args: ["-rf", "/tmp/old-file"]
    });

    expect(JSON.parse((result as { content: Array<{ text: string }> }).content[0].text)).toMatchObject({
      confirmationRequired: true,
      token: "confirm-token"
    });
  });

  it("uses blocked task resume metadata when confirming a task_batch through choice UI", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const operations = {
      taskBatch: async (input: Record<string, unknown>) => {
        calls.push(input);
        if (!input.confirmationToken) {
          return {
            hostId: "prod-api",
            completed: [{ id: "nginx", exitCode: 0 }],
            blocked: {
              id: "remove",
              index: 1,
              resumeFrom: 1,
              result: {
                confirmationRequired: true,
                token: "confirm-token",
                risk: "high",
                reason: "command appears to modify remote state",
                hostId: "prod-api",
                operation: "exec",
                preview: {
                  command: "rm -rf /tmp/old-file"
                },
                expiresAt: "2026-01-01T00:05:00.000Z"
              }
            }
          };
        }
        return {
          hostId: "prod-api",
          completed: [{ id: "remove", exitCode: 0 }]
        };
      }
    } as unknown as SshOperations;
    const server = createMcpServer(operations);
    const mcp = server as unknown as {
      server: {
        getClientCapabilities: () => unknown;
        elicitInput: (input: unknown) => Promise<unknown>;
      };
      _registeredTools: Record<string, { handler: (input: unknown) => Promise<unknown> }>;
    };
    mcp.server.getClientCapabilities = () => ({ elicitation: { form: {} } });
    mcp.server.elicitInput = async () => ({
      action: "accept",
      content: {
        decision: "confirm"
      }
    });

    const input = {
      hostId: "prod-api",
      tasks: [
        { id: "nginx", program: "systemctl", args: ["is-active", "nginx"] },
        { id: "remove", program: "rm", args: ["-rf", "/tmp/old-file"] }
      ]
    };
    const result = await mcp._registeredTools.task_batch.handler(input);

    expect(JSON.parse((result as { content: Array<{ text: string }> }).content[0].text)).toMatchObject({
      completed: [{ id: "remove", exitCode: 0 }]
    });
    expect(calls).toEqual([
      input,
      {
        ...input,
        confirmationToken: "confirm-token",
        startAt: 1
      }
    ]);
  });
  it("audits registered tool calls without changing tool output", async () => {
    const records: Array<Record<string, unknown>> = [];
    const operations = {
      hostList: () => [{ id: "prod-api", hasIdentityFile: false, hasPasswordEnv: false }]
    } as unknown as SshOperations;
    const server = createMcpServer(operations, {
      auditor: {
        recordToolCall: (call) => records.push(call as unknown as Record<string, unknown>)
      }
    });
    const mcp = server as unknown as {
      _registeredTools: Record<string, { handler: (input: unknown) => Promise<unknown> }>;
    };

    const result = await mcp._registeredTools.host_list.handler({});

    expect(JSON.parse((result as { content: Array<{ text: string }> }).content[0].text)).toMatchObject({
      hosts: [{ id: "prod-api" }]
    });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      tool: "host_list",
      input: {},
      result: { hosts: [{ id: "prod-api" }] }
    });
    expect(typeof records[0].durationMs).toBe("number");
  });

});

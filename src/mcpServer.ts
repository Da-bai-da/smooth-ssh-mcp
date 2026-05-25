import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type { SshOperations } from "./operations.js";
import type { Auditor } from "./audit.js";
import type { ConfirmationRequired } from "./types.js";

const LOCAL_READ_HINT: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};

const REMOTE_READ_HINT: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true
};

const CONNECTION_HINT: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true
};

const LOCAL_STATE_HINT: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};

const RISK_GATED_REMOTE_HINT: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true
};

type McpServerOptions = {
  auditor?: Auditor;
};

export function createMcpServer(operations: SshOperations, options: McpServerOptions = {}): McpServer {
  const server = new McpServer({
    name: "smooth-ssh-mcp",
    version: "0.1.0"
  });
  const toolHandler = createToolHandler(options.auditor);

  server.registerTool(
    "host_list",
    {
      title: "List SSH hosts",
      description: "List configured host aliases and non-secret metadata.",
      annotations: LOCAL_READ_HINT,
      inputSchema: {}
    },
    toolHandler("host_list", async () => ({ hosts: operations.hostList() }))
  );

  server.registerTool(
    "host_get",
    {
      title: "Get SSH host",
      description: "Get one configured host by alias, including non-secret connection metadata.",
      annotations: LOCAL_READ_HINT,
      inputSchema: {
        hostId: z.string().min(1)
      }
    },
    toolHandler("host_get", async ({ hostId }) => operations.hostGet(hostId))
  );

  server.registerTool(
    "host_select",
    {
      title: "Select default SSH host",
      description: "Persist the currently selected host id for future Codex sessions. Stores only non-secret host ids and timestamps.",
      annotations: LOCAL_STATE_HINT,
      inputSchema: {
        hostId: z.string().min(1)
      }
    },
    toolHandler("host_select", async (input) => operations.hostSelect(input))
  );

  server.registerTool(
    "host_recent",
    {
      title: "List recent SSH hosts",
      description: "List the selected host and recently used hosts. Does not include passwords, key paths, or session state.",
      annotations: LOCAL_READ_HINT,
      inputSchema: {}
    },
    toolHandler("host_recent", async () => operations.hostRecent())
  );

  server.registerTool(
    "host_permission_set",
    {
      title: "Set SSH host permission profile",
      description: "Persist a per-host numeric permission level override: 1 is highest, 2 is confirmed administration, 3 is restricted/read-only.",
      annotations: LOCAL_STATE_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        permissionLevel: z.union([z.literal(1), z.literal(2), z.literal(3)]),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("host_permission_set", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.hostPermissionSet(confirmedInput)))
  );

  server.registerTool(
    "capability_list",
    {
      title: "List Smooth SSH capabilities",
      description: "List preferred structured capabilities and the shell fallback policy so clients avoid building large shell commands.",
      annotations: LOCAL_READ_HINT,
      inputSchema: {}
    },
    toolHandler("capability_list", async () => operations.capabilityList())
  );

  server.registerTool(
    "host_connect",
    {
      title: "Connect to SSH host",
      description: "High-level connect flow: use a provided or selected host, probe it, and optionally start an interactive session.",
      annotations: CONNECTION_HINT,
      inputSchema: {
        hostId: z.string().min(1).optional(),
        timeoutMs: z.number().int().min(1000).max(120000).optional(),
        startSession: z.boolean().optional(),
        retryCount: z.number().int().min(0).max(5).optional(),
        retryDelayMs: z.number().int().min(0).max(30000).optional(),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("host_connect", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.hostConnect(confirmedInput)))
  );

  server.registerTool(
    "ssh_probe",
    {
      title: "Probe SSH host",
      description: "Run a bounded read-only SSH probe and classify basic connection failures.",
      annotations: REMOTE_READ_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        timeoutMs: z.number().int().min(1000).max(120000).optional()
      }
    },
    toolHandler("ssh_probe", async (input) => operations.sshProbe(input))
  );

  server.registerTool(
    "ssh_exec",
    {
      title: "Run SSH command",
      description: "Shell fallback for bounded remote commands. Prefer ssh_command, task_batch, or capability tools before using shell syntax.",
      annotations: RISK_GATED_REMOTE_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        command: z.string().min(1),
        cwd: z.string().optional(),
        env: z.record(z.string()).optional(),
        sudo: z.enum(["none", "nopasswd"]).optional(),
        timeoutMs: z.number().int().min(1000).max(600000).optional(),
        stdin: z.string().optional(),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("ssh_exec", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.sshExec(confirmedInput)))
  );

  server.registerTool(
    "ssh_command",
    {
      title: "Run SSH argv command",
      description: "Run one remote program with argv-style arguments. Avoids agent-built shell chains and uses semantic policy checks.",
      annotations: RISK_GATED_REMOTE_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        program: z.string().min(1),
        args: z.array(z.string()).optional(),
        cwd: z.string().optional(),
        env: z.record(z.string()).optional(),
        sudo: z.enum(["none", "nopasswd"]).optional(),
        timeoutMs: z.number().int().min(1000).max(600000).optional(),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("ssh_command", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.sshCommand(confirmedInput)))
  );

  server.registerTool(
    "task_batch",
    {
      title: "Run SSH task batch",
      description: "Run multiple structured argv tasks one by one. Defaults to compact stdout/stderr previews; use detail=full only when raw output is needed. Stops before tasks that need confirmation instead of building a composite shell command.",
      annotations: RISK_GATED_REMOTE_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        tasks: z.array(
          z.object({
            id: z.string().optional(),
            program: z.string().min(1),
            args: z.array(z.string()).optional(),
            timeoutMs: z.number().int().min(1000).max(600000).optional()
          })
        ),
        timeoutMs: z.number().int().min(1000).max(600000).optional(),
        detail: z.enum(["compact", "full"]).optional(),
        outputLimitBytes: z.number().int().min(1).max(4096).optional(),
        startAt: z.number().int().min(0).optional(),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("task_batch", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.taskBatch(confirmedInput)))
  );

  server.registerTool(
    "cleanup_paths",
    {
      title: "Clean remote paths",
      description: "Delete exact remote paths or empty exact remote directories after one path-list confirmation. Does not accept globs.",
      annotations: RISK_GATED_REMOTE_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        targets: z
          .array(
            z.object({
              path: z.string().min(1),
              mode: z.enum(["delete", "empty-dir"]).optional()
            })
          )
          .min(1),
        timeoutMs: z.number().int().min(1000).max(600000).optional(),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("cleanup_paths", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.cleanupPaths(confirmedInput)))
  );

  server.registerTool(
    "host_health",
    {
      title: "Read SSH host health",
      description: "Run a fixed read-only health inspection through structured argv tasks: host, load, memory, disk, services, ports, Docker, and critical logs.",
      annotations: REMOTE_READ_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        timeoutMs: z.number().int().min(1000).max(600000).optional(),
        services: z.array(z.string()).optional(),
        includeRaw: z.boolean().optional(),
        detail: z.enum(["compact", "full"]).optional()
      }
    },
    toolHandler("host_health", async (input) => operations.hostHealth(input))
  );

  server.registerTool(
    "session_start",
    {
      title: "Start SSH session",
      description: "Start a limited interactive ssh -tt session with TTL, idle timeout, and output ring buffer.",
      annotations: CONNECTION_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("session_start", async (input) => runWithOptionalChoiceConfirmation(server, input, async (confirmedInput) => operations.sessionStart(confirmedInput)))
  );

  server.registerTool(
    "session_send",
    {
      title: "Send SSH session input",
      description: "Write input to an active interactive SSH session.",
      annotations: RISK_GATED_REMOTE_HINT,
      inputSchema: {
        sessionId: z.string().min(1),
        input: z.string(),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("session_send", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.sessionSend(confirmedInput)))
  );

  server.registerTool(
    "session_read",
    {
      title: "Read SSH session output",
      description: "Read and clear buffered output from an active SSH session.",
      annotations: CONNECTION_HINT,
      inputSchema: {
        sessionId: z.string().min(1),
        maxBytes: z.number().int().min(1).max(1024 * 1024).optional()
      }
    },
    toolHandler("session_read", async (input) => operations.sessionRead(input))
  );

  server.registerTool(
    "session_stop",
    {
      title: "Stop SSH session",
      description: "Terminate an active interactive SSH session.",
      annotations: CONNECTION_HINT,
      inputSchema: {
        sessionId: z.string().min(1)
      }
    },
    toolHandler("session_stop", async (input) => operations.sessionStop(input))
  );

  server.registerTool(
    "session_list",
    {
      title: "List SSH sessions",
      description: "List active managed interactive SSH sessions.",
      annotations: CONNECTION_HINT,
      inputSchema: {}
    },
    toolHandler("session_list", async () => ({ sessions: operations.sessionList() }))
  );

  server.registerTool(
    "file_upload",
    {
      title: "Upload file over SCP",
      description: "Upload a local file to a remote host through scp. Requires host policy and confirmation.",
      annotations: RISK_GATED_REMOTE_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        localPath: z.string().min(1),
        remotePath: z.string().min(1),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("file_upload", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.fileUpload(confirmedInput)))
  );

  server.registerTool(
    "file_download",
    {
      title: "Download file over SCP",
      description: "Download a remote file through scp. Requires host policy and confirmation.",
      annotations: RISK_GATED_REMOTE_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        localPath: z.string().min(1),
        remotePath: z.string().min(1),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("file_download", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.fileDownload(confirmedInput)))
  );

  server.registerTool(
    "forward_start",
    {
      title: "Start local SSH port forward",
      description: "Start a managed ssh -N -L local port forward. Always policy checked and normally confirmation gated.",
      annotations: RISK_GATED_REMOTE_HINT,
      inputSchema: {
        hostId: z.string().min(1),
        localHost: z.string().default("127.0.0.1").optional(),
        localPort: z.number().int().min(1).max(65535),
        remoteHost: z.string().min(1),
        remotePort: z.number().int().min(1).max(65535),
        confirmationToken: z.string().optional()
      }
    },
    toolHandler("forward_start", async (input) => runWithOptionalChoiceConfirmation(server, input, (confirmedInput) => operations.forwardStart(confirmedInput)))
  );

  server.registerTool(
    "forward_stop",
    {
      title: "Stop SSH port forward",
      description: "Stop a managed SSH port forward by id.",
      annotations: CONNECTION_HINT,
      inputSchema: {
        forwardId: z.string().min(1)
      }
    },
    toolHandler("forward_stop", async (input) => operations.forwardStop(input))
  );

  server.registerTool(
    "forward_list",
    {
      title: "List SSH port forwards",
      description: "List active managed SSH port forwards.",
      annotations: CONNECTION_HINT,
      inputSchema: {}
    },
    toolHandler("forward_list", async () => ({ forwards: operations.forwardList() }))
  );

  return server;
}

type ToolInput = any;

function createToolHandler(auditor: Auditor | undefined) {
  return (tool: string, run: (input: ToolInput) => Promise<unknown> | unknown) =>
    async (input: ToolInput) => {
      const startedAt = Date.now();
      try {
        const result = await run(input);
        auditor?.recordToolCall({
          tool,
          input,
          result,
          durationMs: Date.now() - startedAt
        });
        return jsonResult(result);
      } catch (error) {
        auditor?.recordToolCall({
          tool,
          input,
          result: { error: error instanceof Error ? error.message : String(error) },
          durationMs: Date.now() - startedAt
        });
        throw error;
      }
    };
}

function jsonResult(data: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(data, null, 2)
      }
    ],
    structuredContent: data as Record<string, unknown>
  };
}

async function runWithOptionalChoiceConfirmation<TInput extends { confirmationToken?: string }, TResult>(
  server: McpServer,
  input: TInput,
  run: (input: TInput) => Promise<TResult> | TResult
): Promise<TResult | Record<string, unknown>> {
  const result = await run(input);
  const confirmation = confirmationFromResult(result);
  if (!confirmation || input.confirmationToken || !clientSupportsFormElicitation(server)) {
    return result as TResult;
  }

  try {
    const choice = await server.server.elicitInput({
      mode: "form",
      message: confirmationMessage(confirmation),
      requestedSchema: {
        type: "object",
        properties: {
          decision: {
            type: "string",
            title: "操作",
            oneOf: [
              { const: "confirm", title: "确认执行" },
              { const: "cancel", title: "取消" }
            ],
            default: "cancel"
          }
        },
        required: ["decision"]
      }
    });

    if (choice.action === "accept" && choice.content?.decision === "confirm") {
      const confirmedInput = {
        ...input,
        confirmationToken: confirmation.token
      };
      const resumeFrom = blockedResumeFrom(result);
      if (resumeFrom !== undefined) {
        (confirmedInput as Record<string, unknown>).startAt = resumeFrom;
      }
      return await run(confirmedInput);
    }

    return {
      cancelled: true,
      hostId: confirmation.hostId,
      operation: confirmation.operation,
      reason: "user cancelled confirmation",
      preview: confirmation.preview
    };
  } catch {
    return result;
  }
}

function clientSupportsFormElicitation(server: McpServer): boolean {
  return Boolean(server.server.getClientCapabilities()?.elicitation?.form);
}

function isConfirmationRequired(value: unknown): value is ConfirmationRequired {
  return Boolean(value && typeof value === "object" && (value as { confirmationRequired?: unknown }).confirmationRequired === true);
}

function confirmationFromResult(value: unknown): ConfirmationRequired | undefined {
  if (isConfirmationRequired(value)) return value;
  if (!value || typeof value !== "object") return undefined;
  const blocked = (value as { blocked?: unknown }).blocked;
  if (!blocked || typeof blocked !== "object") return undefined;
  const blockedResult = (blocked as { result?: unknown }).result;
  return isConfirmationRequired(blockedResult) ? blockedResult : undefined;
}

function blockedResumeFrom(value: unknown): number | undefined {
  if (!value || typeof value !== "object") return undefined;
  const blocked = (value as { blocked?: unknown }).blocked;
  if (!blocked || typeof blocked !== "object") return undefined;
  const resumeFrom = (blocked as { resumeFrom?: unknown }).resumeFrom;
  return typeof resumeFrom === "number" ? resumeFrom : undefined;
}

function confirmationMessage(confirmation: ConfirmationRequired): string {
  const preview = [
    confirmation.preview.command ? `command: ${confirmation.preview.command}` : undefined,
    confirmation.preview.localPath ? `localPath: ${confirmation.preview.localPath}` : undefined,
    confirmation.preview.remotePath ? `remotePath: ${confirmation.preview.remotePath}` : undefined,
    confirmation.preview.ports ? `ports: ${confirmation.preview.ports.join(", ")}` : undefined
  ]
    .filter(Boolean)
    .join("\n");

  return [
    `确认在 ${confirmation.hostId} 执行高风险操作？`,
    `风险：${confirmation.risk}`,
    `原因：${confirmation.reason}`,
    preview ? `预览：\n${preview}` : undefined
  ]
    .filter(Boolean)
    .join("\n");
}

import { createHash, randomUUID } from "node:crypto";
import { unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join, posix as pathPosix } from "node:path";
import { wrapWithPasswordAuth } from "./auth.js";
import { buildScpArgs, buildSshArgs, controlPathForHost } from "./sshArgs.js";
import { InventoryConfigStore, type HostAddInput, type HostRemoveInput, type HostUpdateInput, type SecretSetInput } from "./configStore.js";
import { ForwardManager } from "./forwardManager.js";
import { findHost } from "./inventory.js";
import { evaluateOperationPolicy, issueConfirmation, verifyConfirmation } from "./policy.js";
import { redactAndTruncate } from "./redaction.js";
import { nodeRunner, type Runner } from "./runner.js";
import { SessionManager } from "./sessionManager.js";
import { defaultStatePath, StateStore } from "./stateStore.js";
import type { CommandAccess, ConfirmationRequired, ExecResult, Host, Inventory, Operation, PermissionLevel, PolicyDecision } from "./types.js";

type OperationsOptions = {
  inventory: Inventory;
  runner?: Runner;
  controlDir?: string;
  sessionManager?: SessionManager;
  forwardManager?: ForwardManager;
  env?: NodeJS.ProcessEnv;
  stateStore?: StateStore;
  configPath?: string;
  secretsPath?: string;
};

type ExecInput = {
  hostId: string;
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  sudo?: "none" | "nopasswd";
  timeoutMs?: number;
  confirmationToken?: string;
  stdin?: string;
};

type CommandInput = {
  hostId: string;
  program: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  sudo?: "none" | "nopasswd";
  timeoutMs?: number;
  confirmationToken?: string;
};

type BatchTaskInput = {
  id?: string;
  program: string;
  args?: string[];
  timeoutMs?: number;
};

type BatchInput = {
  hostId: string;
  tasks: BatchTaskInput[];
  timeoutMs?: number;
  confirmationToken?: string;
  detail?: "compact" | "full";
  outputLimitBytes?: number;
  startAt?: number;
};

type CleanupMode = "delete" | "empty-dir";

type CleanupTargetInput = {
  path: string;
  mode?: CleanupMode;
};

type CleanupTarget = {
  path: string;
  mode: CleanupMode;
};

type CleanupInput = {
  hostId: string;
  targets: CleanupTargetInput[];
  timeoutMs?: number;
  confirmationToken?: string;
};

type HealthInput = {
  hostId: string;
  timeoutMs?: number;
  services?: string[];
  includeRaw?: boolean;
  detail?: "compact" | "full";
};

type FileInput = {
  hostId: string;
  localPath: string;
  remotePath: string;
  confirmationToken?: string;
};

type HostConnectInput = {
  hostId?: string;
  timeoutMs?: number;
  startSession?: boolean;
  retryCount?: number;
  retryDelayMs?: number;
  confirmationToken?: string;
};

const DANGEROUS_CLEANUP_PATHS = new Set([
  "/",
  "/bin",
  "/boot",
  "/dev",
  "/etc",
  "/home",
  "/lib",
  "/lib64",
  "/opt",
  "/proc",
  "/root",
  "/run",
  "/sbin",
  "/srv",
  "/sys",
  "/tmp",
  "/usr",
  "/var"
]);

const DEFAULT_BATCH_OUTPUT_LIMIT_BYTES = 2048;
const MAX_BATCH_OUTPUT_LIMIT_BYTES = 4096;

export class SshOperations {
  private readonly inventory: Inventory;
  private readonly runner: Runner;
  private readonly controlDir: string;
  private readonly sessions: SessionManager;
  private readonly forwards: ForwardManager;
  private readonly env: NodeJS.ProcessEnv;
  private readonly stateStore: StateStore;
  private readonly sessionInputBuffers = new Map<string, string>();
  private readonly configStore: InventoryConfigStore;

  constructor(options: OperationsOptions) {
    this.inventory = options.inventory;
    this.runner = options.runner ?? nodeRunner;
    this.env = options.env ?? process.env;
    this.controlDir = options.controlDir ?? join(homedir(), ".cache", "smooth-ssh-mcp", "control");
    this.sessions = options.sessionManager ?? new SessionManager({ controlDir: this.controlDir, env: this.env });
    this.forwards = options.forwardManager ?? new ForwardManager({ controlDir: this.controlDir, env: this.env });
    this.stateStore = options.stateStore ?? new StateStore(defaultStatePath());
    this.configStore = new InventoryConfigStore({ configPath: options.configPath, secretsPath: options.secretsPath, env: this.env });
  }

  dispose(): void {
    this.sessions.stopAll();
  }

  hostList(): Array<Omit<Host, "identityFile" | "passwordEnv"> & { hasIdentityFile: boolean; hasPasswordEnv: boolean }> {
    return this.inventory.hosts.map((rawHost) => {
      const effectiveHost = this.applyStatePolicy(rawHost);
      const { identityFile, passwordEnv, ...host } = effectiveHost;
      return {
        ...host,
        hasIdentityFile: Boolean(identityFile),
        hasPasswordEnv: Boolean(passwordEnv)
      };
    });
  }

  hostGet(hostId: string): Omit<Host, "identityFile" | "passwordEnv"> & { hasIdentityFile: boolean; hasPasswordEnv: boolean } {
    const { identityFile, passwordEnv, ...host } = this.findEffectiveHost(hostId);
    return { ...host, hasIdentityFile: Boolean(identityFile), hasPasswordEnv: Boolean(passwordEnv) };
  }

  hostAdd(input: HostAddInput & { confirmationToken?: string }): ReturnType<InventoryConfigStore["addHost"]> | ConfirmationRequired {
    const { confirmationToken, ...hostInput } = input;
    if (this.inventory.hosts.some((host) => host.id === hostInput.id)) {
      throw new Error(`Host already exists in inventory: ${hostInput.id}`);
    }
    const prepared = this.configStore.prepareHostAdd(hostInput);
    const stdinHash = hashOptionalInput(prepared.password);
    if (
      !verifyConfirmation(confirmationToken, {
        host: prepared.host,
        operation: "config",
        command: prepared.command,
        stdinHash
      })
    ) {
      return issueConfirmation({
        host: prepared.host,
        operation: "config",
        command: prepared.command,
        stdinHash,
        reasons: ["host_add writes local SSH inventory configuration"]
      });
    }

    const result = this.configStore.addHost(hostInput);
    this.refreshInventoryFromConfig();
    return result;
  }

  hostUpdate(input: HostUpdateInput & { confirmationToken?: string }): ReturnType<InventoryConfigStore["updateHost"]> | ConfirmationRequired {
    const { confirmationToken, ...hostInput } = input;
    findHost(this.inventory, hostInput.hostId);
    const prepared = this.configStore.prepareHostUpdate(hostInput);
    const stdinHash = hashOptionalInput(prepared.password);
    if (
      !verifyConfirmation(confirmationToken, {
        host: prepared.host,
        operation: "config",
        command: prepared.command,
        stdinHash
      })
    ) {
      return issueConfirmation({
        host: prepared.host,
        operation: "config",
        command: prepared.command,
        stdinHash,
        reasons: ["host_update writes local SSH inventory configuration"]
      });
    }

    const result = this.configStore.updateHost(hostInput);
    this.refreshInventoryFromConfig();
    return result;
  }

  hostRemove(input: HostRemoveInput & { confirmationToken?: string }): ReturnType<InventoryConfigStore["removeHost"]> | ConfirmationRequired {
    const { confirmationToken, ...removeInput } = input;
    const host = findHost(this.inventory, removeInput.hostId);
    const prepared = this.configStore.prepareHostRemove(removeInput);
    if (
      !verifyConfirmation(confirmationToken, {
        host,
        operation: "config",
        command: prepared.command
      })
    ) {
      return issueConfirmation({
        host,
        operation: "config",
        command: prepared.command,
        reasons: ["host_remove writes local SSH inventory configuration"]
      });
    }

    const result = this.configStore.removeHost(removeInput);
    this.refreshInventoryFromConfig();
    return result;
  }

  secretSet(input: SecretSetInput & { confirmationToken?: string }): ReturnType<InventoryConfigStore["setSecret"]> | ConfirmationRequired {
    const { confirmationToken, ...secretInput } = input;
    const prepared = this.configStore.prepareSecretSet(secretInput);
    const stdinHash = hashOptionalInput(prepared.value);
    if (
      !verifyConfirmation(confirmationToken, {
        host: prepared.host,
        operation: "config",
        command: prepared.command,
        stdinHash
      })
    ) {
      return issueConfirmation({
        host: prepared.host,
        operation: "config",
        command: prepared.command,
        stdinHash,
        reasons: ["secret_set writes local Smooth SSH secrets"]
      });
    }

    return this.configStore.setSecret(secretInput);
  }

  hostSelect(input: { hostId: string }): { selectedHostId?: string; recentHosts: unknown[] } {
    findHost(this.inventory, input.hostId);
    return this.stateStore.selectHost(input.hostId, "manual");
  }

  hostRecent(): { selectedHostId?: string; recentHosts: unknown[] } {
    const state = this.stateStore.getState();
    return {
      selectedHostId: state.selectedHostId,
      recentHosts: state.recentHosts
    };
  }

  hostPermissionSet(input: { hostId: string; permissionLevel: PermissionLevel; confirmationToken?: string }): { hostId: string; permissionLevel: PermissionLevel } | ConfirmationRequired {
    const host = findHost(this.inventory, input.hostId);
    const command = `host_permission_set ${input.hostId} ${input.permissionLevel}`;
    if (
      input.permissionLevel === 1 &&
      !verifyConfirmation(input.confirmationToken, {
        host,
        operation: "permission",
        command
      })
    ) {
      return issueConfirmation({
        host,
        operation: "permission",
        command,
        reasons: ["permission level 1 bypasses the smooth-ssh confirmation layer"]
      });
    }
    this.stateStore.setPermissionLevel(input.hostId, input.permissionLevel);
    return {
      hostId: input.hostId,
      permissionLevel: input.permissionLevel
    };
  }

  capabilityList(): Record<string, unknown> {
    return {
      capabilities: [
        {
          id: "host_add",
          preferredTool: "host_add",
          access: "confirmed-local-write",
          description: "Add a host to the local inventory after confirmation. Passwords are stored through passwordEnv in the secrets file."
        },
        {
          id: "host_update",
          preferredTool: "host_update",
          access: "confirmed-local-write",
          description: "Update a host in the local inventory after confirmation."
        },
        {
          id: "host_remove",
          preferredTool: "host_remove",
          access: "confirmed-local-write",
          description: "Remove a host from the local inventory after confirmation."
        },
        {
          id: "secret_set",
          preferredTool: "secret_set",
          access: "confirmed-local-write",
          description: "Write one secret to the Smooth SSH secrets file after confirmation."
        },
        {
          id: "host_health",
          preferredTool: "host_health",
          access: "read",
          description: "Fixed read-only host inspection for system, load, memory, disk, services, ports, Docker, and critical logs."
        },
        {
          id: "single_command",
          preferredTool: "ssh_command",
          access: "read-or-confirmed-write",
          description: "Run one remote program with argv arguments and semantic policy checks."
        },
        {
          id: "batch_tasks",
          preferredTool: "task_batch",
          access: "read-or-confirmed-write",
          description: "Run multiple argv tasks one by one without building a composite shell command. Defaults to compact per-task output; pass detail=full only when raw output is needed."
        },
        {
          id: "cleanup_paths",
          preferredTool: "cleanup_paths",
          access: "confirmed-write",
          description: "Delete exact remote paths or empty exact directories after a single path-list confirmation."
        },
        {
          id: "interactive_session",
          preferredTool: "host_connect",
          access: "pty",
          description: "Open a managed interactive SSH session only when the user asks for a shell-like workflow."
        }
      ],
      shellFallback: {
        tool: "ssh_exec",
        useWhen: "No structured capability or argv command fits; shell syntax and complex commands are policy-gated."
      }
    };
  }

  async hostConnect(input: HostConnectInput = {}): Promise<Record<string, unknown>> {
    const hostId = input.hostId ?? this.stateStore.getState().selectedHostId;
    if (!hostId) {
      throw new Error("No hostId provided and no selected host is saved");
    }
    const host = this.findEffectiveHost(hostId);
    const retryCount = input.retryCount ?? 2;
    const retryDelayMs = input.retryDelayMs ?? 2000;
    const probeTimeoutMs = hostConnectProbeTimeoutMs(input.timeoutMs, retryCount, retryDelayMs);
    let probe: Record<string, unknown> | undefined;
    let attempts = 0;
    for (let attempt = 0; attempt <= retryCount; attempt++) {
      attempts = attempt + 1;
      probe = await this.sshProbe({ hostId: host.id, timeoutMs: probeTimeoutMs });
      if (probe.ok || !isTransientProbeFailure(probe) || attempt === retryCount) break;
      await sleep(retryDelayMs);
    }
    if (!probe) throw new Error("SSH probe did not run");
    if (!probe.ok) {
      return {
        hostId: host.id,
        connected: false,
        probeConnected: false,
        target: hostTargetSummary(host),
        attempts,
        probe
      };
    }

    if (input.startSession !== true || !host.policy.allowPty) {
      const sessionBlockedReason = input.startSession === true && !host.policy.allowPty ? "pty is disabled by host policy" : undefined;
      return {
        hostId: host.id,
        connected: true,
        probeConnected: true,
        target: hostTargetSummary(host),
        attempts,
        probe,
        sessionStarted: false,
        ...(sessionBlockedReason ? { sessionBlockedReason } : {}),
        session: null
      };
    }

    const session = this.sessionStart({ hostId: host.id, confirmationToken: input.confirmationToken });
    const sessionStarted = hasSessionId(session);
    return {
      hostId: host.id,
      connected: true,
      probeConnected: true,
      target: hostTargetSummary(host),
      attempts,
      probe,
      sessionStarted,
      ...(!sessionStarted ? { sessionBlockedReason: policyReason(session) } : {}),
      session
    };
  }

  async sshProbe(input: { hostId: string; timeoutMs?: number }): Promise<Record<string, unknown>> {
    const host = this.findEffectiveHost(input.hostId);
    const timeoutMs = input.timeoutMs ?? 10_000;
    const command = [
      "printf 'smooth-ssh-ok\\n'",
      "uname -srm 2>/dev/null || true",
      "test -f /etc/openwrt_release && printf 'openwrt=true\\n' || true"
    ].join("; ");
    const argv = buildSshArgs(host, {
      controlDir: this.controlDir,
      command,
      timeoutSeconds: sshConnectTimeoutSeconds(timeoutMs)
    });
    const commandSpec = wrapWithPasswordAuth(host, "ssh", argv, this.env);
    const result = await this.runner.run(commandSpec.file, commandSpec.args, {
      timeoutMs,
      maxBufferBytes: host.policy.maxOutputBytes,
      env: commandSpec.env
    });
    if (result.exitCode === 0) this.stateStore.recordHostUse(host.id, "probe");
    return {
      hostId: host.id,
      ok: result.exitCode === 0,
      stages: {
        ssh: {
          ok: result.exitCode === 0,
          exitCode: result.exitCode,
          diagnostic: result.exitCode === 0 ? classifySshSuccess(result.stderr) : classifySshFailure(result.stderr, result.timedOut)
        }
      },
      stdout: redactAndTruncate(result.stdout, host.policy.maxOutputBytes).text,
      stderr: redactAndTruncate(result.stderr, host.policy.maxOutputBytes).text
    };
  }

  async sshExec(input: ExecInput): Promise<ExecResult | ConfirmationRequired | PolicyDecision> {
    const host = this.findEffectiveHost(input.hostId);
    const command = composeRemoteCommand(input);
    const stdinHash = hashOptionalInput(input.stdin);
    const policy = evaluateOperationPolicy({
      host,
      operation: "exec",
      command,
      stdin: input.stdin,
      stdinHash
    });
    const confirmationVerified =
      !policy.allowed && verifyConfirmation(input.confirmationToken, { host, operation: "exec", command, stdin: input.stdin, stdinHash });
    if (!policy.allowed && !confirmationVerified) {
      if (policy.confirmationRequired) {
        return issueConfirmation({
          host,
          operation: "exec",
          command,
          stdin: input.stdin,
          stdinHash,
          reasons: policy.reasons
        });
      }
      return policy;
    }

    return this.runRemoteCommand(host, command, {
      timeoutMs: input.timeoutMs,
      stdin: input.stdin,
      allowRetry: policy.allowed
    });
  }

  async sshCommand(input: CommandInput): Promise<ExecResult | ConfirmationRequired | PolicyDecision> {
    const host = this.findEffectiveHost(input.hostId);
    const args = input.args ?? [];
    validateArgvProgram(input.program);
    args.forEach((arg, index) => validateArgvArg(arg, index));

    const policyCommand = composeArgvPolicyCommand(input);
    const remoteCommand = composeArgvRemoteCommand(input);
    const access = classifyArgvAccess(input.program, args);
    const policy = evaluateOperationPolicy({
      host,
      operation: "exec",
      command: policyCommand,
      commandMode: "argv",
      access
    });
    const confirmationVerified =
      !policy.allowed &&
      verifyConfirmation(input.confirmationToken, {
        host,
        operation: "exec",
        command: policyCommand,
        commandMode: "argv",
        access
      });
    if (!policy.allowed && !confirmationVerified) {
      if (policy.confirmationRequired) {
        return issueConfirmation({
          host,
          operation: "exec",
          command: policyCommand,
          commandMode: "argv",
          access,
          reasons: policy.reasons
        });
      }
      return policy;
    }

    return this.runRemoteCommand(host, remoteCommand, {
      timeoutMs: input.timeoutMs,
      allowRetry: policy.allowed && access === "read"
    });
  }

  async taskBatch(input: BatchInput): Promise<Record<string, unknown>> {
    const completed: Array<Record<string, unknown>> = [];
    const detail = input.detail ?? "compact";
    const outputLimitBytes = normalizeBatchOutputLimit(input.outputLimitBytes);
    const startAt = normalizeBatchStartAt(input.startAt, input.tasks.length);
    for (const [index, task] of input.tasks.entries()) {
      if (index < startAt) continue;
      const id = task.id ?? `task-${index + 1}`;
      const result = await this.sshCommand({
        hostId: input.hostId,
        program: task.program,
        args: task.args,
        timeoutMs: task.timeoutMs ?? input.timeoutMs,
        confirmationToken: input.confirmationToken
      });
      if (!isExecResult(result)) {
        return {
          hostId: input.hostId,
          completed,
          blocked: {
            id,
            index,
            resumeFrom: index,
            result
          }
        };
      }
      completed.push({
        id,
        program: task.program,
        args: task.args ?? [],
        exitCode: result.exitCode,
        ...formatBatchOutput(result, detail, outputLimitBytes),
        diagnostic: result.diagnostic,
        durationMs: result.durationMs,
        redactions: result.redactions
      });
    }

    return {
      hostId: input.hostId,
      detail,
      startAt,
      ...(detail === "compact" ? { outputLimitBytes } : {}),
      completed
    };
  }

  async cleanupPaths(input: CleanupInput): Promise<Record<string, unknown> | ConfirmationRequired | PolicyDecision> {
    const host = this.findEffectiveHost(input.hostId);
    const targets = normalizeCleanupTargets(input.targets);
    const command = composeCleanupPolicyCommand(targets);
    const access: CommandAccess = "destructive";
    const policy = evaluateOperationPolicy({
      host,
      operation: "exec",
      command,
      commandMode: "argv",
      access
    });
    if (!policy.allowed && !policy.confirmationRequired) return policy;
    const confirmationVerified = verifyConfirmation(input.confirmationToken, {
      host,
      operation: "exec",
      command,
      commandMode: "argv",
      access
    });
    if (!confirmationVerified) {
      return issueConfirmation({
        host,
        operation: "exec",
        command,
        commandMode: "argv",
        access,
        reasons: policy.reasons.length > 0 ? policy.reasons : ["command appears to modify remote state"]
      });
    }

    const completed: Array<Record<string, unknown>> = [];
    for (const target of targets) {
      const remoteCommand = composeCleanupRemoteCommand(target);
      const result = await this.runRemoteCommand(host, remoteCommand, {
        timeoutMs: input.timeoutMs,
        allowRetry: false
      });
      const item = {
        path: target.path,
        mode: target.mode,
        command: remoteCommand,
        exitCode: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        diagnostic: result.diagnostic,
        durationMs: result.durationMs,
        truncated: result.truncated,
        redactions: result.redactions
      };
      completed.push(item);
      if (result.exitCode !== 0) {
        return {
          hostId: input.hostId,
          completed,
          failed: item
        };
      }
    }

    return {
      hostId: input.hostId,
      completed
    };
  }

  async hostHealth(input: HealthInput): Promise<Record<string, unknown>> {
    const services = input.services ?? ["ssh", "sshd", "nginx", "docker", "containerd", "ufw", "fail2ban"];
    const tasks: BatchTaskInput[] = [
      { id: "host", program: "hostnamectl" },
      { id: "kernel", program: "uname", args: ["-srm"] },
      { id: "uptime", program: "uptime" },
      { id: "memory", program: "free", args: ["-h"] },
      { id: "disk", program: "df", args: ["-hT", "-x", "tmpfs", "-x", "devtmpfs"] },
      { id: "inode", program: "df", args: ["-ih", "-x", "tmpfs", "-x", "devtmpfs"] },
      { id: "top-cpu", program: "ps", args: ["-eo", "pid,ppid,comm,%cpu,%mem", "--sort=-%cpu"] },
      { id: "failed-units", program: "systemctl", args: ["--failed", "--no-pager"] },
      ...services.map((service) => ({
        id: `service:${service}`,
        program: "systemctl",
        args: ["is-active", service]
      })),
      { id: "listening-ports", program: "ss", args: ["-ltnp"] },
      { id: "docker", program: "docker", args: ["ps", "--format", "table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}"] },
      { id: "critical-logs", program: "journalctl", args: ["-p", "0..3", "-n", "20", "--no-pager"] }
    ];
    const result = await this.taskBatch({
      hostId: input.hostId,
      timeoutMs: input.timeoutMs,
      tasks,
      detail: "full"
    });
    const checks = Array.isArray(result.completed) ? (result.completed as HealthCheck[]) : [];
    const blocked = result.blocked;
    const summary = summarizeHealth(checks, blocked);
    const failedChecks = Array.isArray(summary.failedChecks) ? summary.failedChecks : [];
    const includeRaw = input.detail === "compact" ? false : input.includeRaw === true || input.detail === "full";

    return {
      hostId: input.hostId,
      ok: failedChecks.length === 0 && !blocked,
      summary,
      ...(blocked ? { blocked } : {}),
      ...(includeRaw ? { checks } : {})
    };
  }

  private async runRemoteCommand(
    host: Host,
    command: string,
    options: { timeoutMs?: number; stdin?: string; allowRetry: boolean }
  ): Promise<ExecResult> {
    const timeoutMs = options.timeoutMs ?? host.policy.maxCommandSeconds * 1000;
    const runExec = async () => {
      const argv = buildSshArgs(host, {
        controlDir: this.controlDir,
        command,
        timeoutSeconds: Math.ceil(timeoutMs / 1000)
      });
      const commandSpec = wrapWithPasswordAuth(host, "ssh", argv, this.env);
      const result = await this.runner.run(commandSpec.file, commandSpec.args, {
        timeoutMs,
        input: options.stdin,
        maxBufferBytes: host.policy.maxOutputBytes,
        env: commandSpec.env
      });
      return { commandSpec, result };
    };
    let attempts = 1;
    let { commandSpec, result } = await runExec();
    if (options.allowRetry && shouldRetrySshExec(result)) {
      clearControlSocket(host, this.controlDir);
      attempts = 2;
      ({ commandSpec, result } = await runExec());
    }
    const stdout = redactAndTruncate(result.stdout, host.policy.maxOutputBytes);
    const stderr = redactAndTruncate(result.stderr, host.policy.maxOutputBytes);
    if (result.exitCode === 0) this.stateStore.recordHostUse(host.id, "exec");
    const diagnostic = result.exitCode === 0 ? classifySshSuccess(result.stderr) : classifySshFailure(result.stderr, result.timedOut);

    return {
      hostId: host.id,
      commandId: randomUUID(),
      exitCode: result.exitCode,
      signal: result.signal,
      stdout: stdout.text,
      stderr: stderr.text,
      startedAt: result.startedAt.toISOString(),
      endedAt: result.endedAt.toISOString(),
      durationMs: result.durationMs,
      truncated: stdout.truncated || stderr.truncated || Boolean(result.stdoutTruncated) || Boolean(result.stderrTruncated),
      redactions: [...stdout.redactions, ...stderr.redactions],
      diagnostic,
      attempts,
      ...debugArgv(commandSpec.args, this.env)
    };
  }

  async fileUpload(input: FileInput): Promise<ExecResult | ConfirmationRequired | PolicyDecision> {
    return this.fileTransfer("upload", input);
  }

  async fileDownload(input: FileInput): Promise<ExecResult | ConfirmationRequired | PolicyDecision> {
    return this.fileTransfer("download", input);
  }

  sessionStart(input: { hostId: string; confirmationToken?: string }): unknown {
    const host = this.findEffectiveHost(input.hostId);
    const policy = evaluateOperationPolicy({ host, operation: "pty" });
    if (!policy.allowed && !verifyConfirmation(input.confirmationToken, { host, operation: "pty" })) {
      if (policy.confirmationRequired) {
        return issueConfirmation({
          host,
          operation: "pty",
          reasons: policy.reasons
        });
      }
      return policy;
    }
    const session = this.sessions.start(host);
    this.stateStore.recordHostUse(host.id, "pty");
    return session;
  }

  sessionSend(input: { sessionId: string; input: string; confirmationToken?: string }): unknown {
    const bufferedInput = this.sessionInputBuffers.get(input.sessionId) ?? "";
    const candidateInput = bufferedInput + input.input;
    const completedInput = completedSessionInput(candidateInput);
    if (completedInput && completedInput.trim().length > 0) {
      const sessionHost = this.sessions.hostForSession(input.sessionId);
      const host = this.findEffectiveHost(sessionHost.id);
      const policy = evaluateOperationPolicy({
        host,
        operation: "pty-input",
        command: completedInput
      });
      const confirmationVerified =
        !policy.allowed &&
        verifyConfirmation(input.confirmationToken, {
          host,
          operation: "pty-input",
          command: completedInput
        });
      if (!policy.allowed && !confirmationVerified) {
        if (policy.confirmationRequired) {
          return issueConfirmation({
            host,
            operation: "pty-input",
            command: completedInput,
            reasons: policy.reasons
          });
        }
        return policy;
      }
    }
    const result = this.sessions.send(input.sessionId, input.input);
    this.updateSessionInputBuffer(input.sessionId, candidateInput);
    return result;
  }

  sessionRead(input: { sessionId: string; maxBytes?: number }): unknown {
    return this.sessions.read(input.sessionId, input.maxBytes);
  }

  sessionStop(input: { sessionId: string }): unknown {
    this.sessionInputBuffers.delete(input.sessionId);
    return this.sessions.stop(input.sessionId);
  }

  sessionList(): unknown {
    return this.sessions.list();
  }

  private updateSessionInputBuffer(sessionId: string, candidateInput: string): void {
    const lastNewline = lastSessionNewlineIndex(candidateInput);
    if (lastNewline < 0) {
      this.sessionInputBuffers.set(sessionId, candidateInput);
      return;
    }
    const remaining = candidateInput.slice(lastNewline + 1);
    if (remaining) {
      this.sessionInputBuffers.set(sessionId, remaining);
    } else {
      this.sessionInputBuffers.delete(sessionId);
    }
  }

  async forwardStart(input: {
    hostId: string;
    localHost?: string;
    localPort: number;
    remoteHost: string;
    remotePort: number;
    confirmationToken?: string;
  }): Promise<PolicyDecision | ConfirmationRequired | unknown> {
    const host = this.findEffectiveHost(input.hostId);
    const policy = evaluateOperationPolicy({
      host,
      operation: "forward",
      ports: [`${input.localHost ?? "127.0.0.1"}:${input.localPort}`, `${input.remoteHost}:${input.remotePort}`]
    });
    if (
      !policy.allowed &&
      !verifyConfirmation(input.confirmationToken, {
        host,
        operation: "forward",
        ports: [`${input.localHost ?? "127.0.0.1"}:${input.localPort}`, `${input.remoteHost}:${input.remotePort}`]
      })
    ) {
      if (policy.confirmationRequired) {
        return issueConfirmation({
          host,
          operation: "forward",
          ports: [`${input.localHost ?? "127.0.0.1"}:${input.localPort}`, `${input.remoteHost}:${input.remotePort}`],
          reasons: policy.reasons
        });
      }
      return policy;
    }
    const forward = this.forwards.start({
      host,
      localHost: input.localHost,
      localPort: input.localPort,
      remoteHost: input.remoteHost,
      remotePort: input.remotePort
    });
    this.stateStore.recordHostUse(host.id, "forward");
    return forward;
  }

  forwardStop(input: { forwardId: string }): unknown {
    return this.forwards.stop(input.forwardId);
  }

  forwardList(): unknown {
    return this.forwards.list();
  }

  private refreshInventoryFromConfig(): void {
    const refreshed = this.configStore.loadInventory();
    this.inventory.hosts.splice(0, this.inventory.hosts.length, ...refreshed.hosts);
  }

  private findEffectiveHost(hostId: string): Host {
    return this.applyStatePolicy(findHost(this.inventory, hostId));
  }

  private applyStatePolicy(host: Host): Host {
    const permissionLevel = this.stateStore.permissionLevelFor(host.id);
    if (!permissionLevel) return host;
    return {
      ...host,
      policy: {
        ...host.policy,
        permissionLevel
      }
    };
  }

  private async fileTransfer(
    operation: Extract<Operation, "upload" | "download">,
    input: FileInput
  ): Promise<ExecResult | ConfirmationRequired | PolicyDecision> {
    const host = this.findEffectiveHost(input.hostId);
    const policy = evaluateOperationPolicy({
      host,
      operation,
      localPath: input.localPath,
      remotePath: input.remotePath
    });
    if (!policy.allowed && !verifyConfirmation(input.confirmationToken, { host, operation, localPath: input.localPath, remotePath: input.remotePath })) {
      if (policy.confirmationRequired) {
        return issueConfirmation({
          host,
          operation,
          localPath: input.localPath,
          remotePath: input.remotePath,
          reasons: policy.reasons
        });
      }
      return policy;
    }

    const argv = buildScpArgs(host, {
      controlDir: this.controlDir,
      direction: operation,
      localPath: input.localPath,
      remotePath: input.remotePath
    });
    const commandSpec = wrapWithPasswordAuth(host, "scp", argv, this.env);
    const result = await this.runner.run(commandSpec.file, commandSpec.args, {
      timeoutMs: host.policy.maxCommandSeconds * 1000,
      maxBufferBytes: host.policy.maxOutputBytes,
      env: commandSpec.env
    });
    const stdout = redactAndTruncate(result.stdout, host.policy.maxOutputBytes);
    const stderr = redactAndTruncate(result.stderr, host.policy.maxOutputBytes);
    if (result.exitCode === 0) this.stateStore.recordHostUse(host.id, operation);
    return {
      hostId: host.id,
      commandId: randomUUID(),
      exitCode: result.exitCode,
      signal: result.signal,
      stdout: stdout.text,
      stderr: stderr.text,
      startedAt: result.startedAt.toISOString(),
      endedAt: result.endedAt.toISOString(),
      durationMs: result.durationMs,
      truncated: stdout.truncated || stderr.truncated || Boolean(result.stdoutTruncated) || Boolean(result.stderrTruncated),
      redactions: [...stdout.redactions, ...stderr.redactions],
      diagnostic: result.exitCode === 0 ? classifySshSuccess(result.stderr) : classifySshFailure(result.stderr, result.timedOut),
      attempts: 1,
      ...debugArgv(commandSpec.args, this.env)
    };
  }
}

function normalizeBatchOutputLimit(value: number | undefined): number {
  if (value === undefined) return DEFAULT_BATCH_OUTPUT_LIMIT_BYTES;
  if (!Number.isFinite(value) || value < 1) throw new Error("Invalid outputLimitBytes: expected a positive number");
  return Math.min(Math.floor(value), MAX_BATCH_OUTPUT_LIMIT_BYTES);
}

function normalizeBatchStartAt(value: number | undefined, taskCount: number): number {
  if (value === undefined) return 0;
  if (!Number.isInteger(value) || value < 0 || value > taskCount) {
    throw new Error(`Invalid startAt: expected an integer from 0 to ${taskCount}`);
  }
  return value;
}

function completedSessionInput(value: string): string | undefined {
  const lastNewline = lastSessionNewlineIndex(value);
  return lastNewline >= 0 ? value.slice(0, lastNewline + 1) : undefined;
}

function lastSessionNewlineIndex(value: string): number {
  return Math.max(value.lastIndexOf("\n"), value.lastIndexOf("\r"));
}

function formatBatchOutput(result: ExecResult, detail: "compact" | "full", outputLimitBytes: number): Record<string, unknown> {
  const stdout = detail === "full" ? fullOutput(result.stdout) : compactOutput(result.stdout, outputLimitBytes);
  const stderr = detail === "full" ? fullOutput(result.stderr) : compactOutput(result.stderr, outputLimitBytes);
  return {
    stdout: stdout.text,
    stderr: stderr.text,
    stdoutBytes: stdout.bytes,
    stderrBytes: stderr.bytes,
    stdoutTruncated: stdout.truncated,
    stderrTruncated: stderr.truncated,
    truncated: result.truncated || stdout.truncated || stderr.truncated
  };
}

function fullOutput(text: string): { text: string; bytes: number; truncated: boolean } {
  return {
    text,
    bytes: Buffer.byteLength(text, "utf8"),
    truncated: false
  };
}

function compactOutput(text: string, limitBytes: number): { text: string; bytes: number; truncated: boolean } {
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes <= limitBytes) {
    return {
      text,
      bytes,
      truncated: false
    };
  }
  return {
    text: Buffer.from(text, "utf8").subarray(0, limitBytes).toString("utf8"),
    bytes,
    truncated: true
  };
}

function composeRemoteCommand(input: ExecInput): string {
  let command = input.command;
  if (input.env) {
    const env = Object.entries(input.env)
      .map(([key, value]) => {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error(`Invalid env key: ${key}`);
        if (value.includes("\0")) throw new Error(`Invalid env value for ${key}: contains NUL`);
        return `${key}=${shellQuote(value)}`;
      })
      .join(" ");
    if (env) command = `${env} ${command}`;
  }
  if (input.cwd) {
    if (input.cwd.includes("\0") || input.cwd.includes("\n") || input.cwd.includes("\r")) {
      throw new Error("Invalid cwd: contains a control character");
    }
    command = `cd ${shellQuote(input.cwd)} && ${command}`;
  }
  if (input.sudo === "nopasswd") {
    command = `sudo -n sh -lc ${shellQuote(command)}`;
  }
  return command;
}

type HealthCheck = {
  id: string;
  program: string;
  args: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
  diagnostic?: string;
  durationMs: number;
  truncated: boolean;
  redactions: unknown[];
};

function summarizeHealth(checks: HealthCheck[], blocked: unknown): Record<string, unknown> {
  const byId = new Map(checks.map((check) => [check.id, check]));
  const services = summarizeServices(checks);
  const failedChecks = checks
    .filter((check) => check.exitCode !== 0 && !check.id.startsWith("service:"))
    .map((check) => ({
      id: check.id,
      exitCode: check.exitCode,
      diagnostic: check.diagnostic,
      message: firstNonEmptyLine(check.stderr)
    }));
  const notices = summarizeNotices({ services, checks, blocked, failedChecks });

  return {
    system: summarizeSystem(byId),
    uptime: summarizeUptime(byId.get("uptime")?.stdout ?? ""),
    memory: summarizeMemory(byId.get("memory")?.stdout ?? ""),
    disk: summarizeDisk(byId.get("disk")?.stdout ?? ""),
    inode: summarizeDisk(byId.get("inode")?.stdout ?? ""),
    services,
    docker: summarizeDocker(byId.get("docker")?.stdout ?? ""),
    ports: summarizePorts(byId.get("listening-ports")?.stdout ?? ""),
    failedChecks,
    notices
  };
}

function summarizeSystem(byId: Map<string, HealthCheck>): Record<string, string | undefined> {
  const host = byId.get("host")?.stdout ?? "";
  const kernel = byId.get("kernel")?.stdout.trim() || matchLineValue(host, "Kernel");
  return {
    hostname: matchLineValue(host, "Static hostname"),
    os: matchLineValue(host, "Operating System"),
    kernel: kernel ? kernel.replace(/\s+x86_64$/, "") : undefined
  };
}

function summarizeUptime(stdout: string): Record<string, unknown> {
  const load = stdout.match(/load averages?:\s*([0-9.]+),\s*([0-9.]+),\s*([0-9.]+)/i);
  const up = stdout.match(/\bup\s+(.+?),\s+\d+\s+users?/i);
  return {
    text: stdout.trim() || undefined,
    up: up?.[1]?.trim(),
    load: load ? [load[1], load[2], load[3]] : undefined
  };
}

function summarizeMemory(stdout: string): Record<string, string | undefined> {
  const memLine = stdout.split(/\r?\n/).find((line) => /^Mem:\s+/.test(line));
  const swapLine = stdout.split(/\r?\n/).find((line) => /^Swap:\s+/.test(line));
  const mem = memLine?.trim().split(/\s+/) ?? [];
  const swap = swapLine?.trim().split(/\s+/) ?? [];
  return {
    total: mem[1],
    used: mem[2],
    free: mem[3],
    available: mem[6],
    swapTotal: swap[1],
    swapUsed: swap[2],
    swapFree: swap[3]
  };
}

function summarizeDisk(stdout: string): Record<string, unknown> {
  const root = stdout.split(/\r?\n/).find((line) => /\s\/$/.test(line));
  if (!root) return {};
  const parts = root.trim().split(/\s+/);
  return {
    root: {
      filesystem: parts[0],
      type: parts.length >= 7 ? parts[1] : undefined,
      size: parts.length >= 7 ? parts[2] : parts[1],
      used: parts.length >= 7 ? parts[3] : parts[2],
      available: parts.length >= 7 ? parts[4] : parts[3],
      usePercent: parts.length >= 7 ? parts[5] : parts[4]
    }
  };
}

function summarizeServices(checks: HealthCheck[]): Record<string, string> {
  const services: Record<string, string> = {};
  for (const check of checks) {
    if (!check.id.startsWith("service:")) continue;
    const service = check.id.slice("service:".length);
    services[service] = check.stdout.trim() || (check.exitCode === 0 ? "active" : "inactive");
  }
  return services;
}

function summarizeDocker(stdout: string): Record<string, unknown> {
  const rows = stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).slice(1);
  return {
    running: rows.length,
    healthy: rows.filter((row) => /\(healthy\)/i.test(row)).length,
    names: rows.map((row) => row.split(/\s+/)[0]).filter(Boolean)
  };
}

function summarizePorts(stdout: string): Record<string, string[]> {
  const publicPorts = new Set<string>();
  const localPorts = new Set<string>();
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.includes("LISTEN")) continue;
    const match = line.match(/\s(\S+):(\d+)\s+\S+:\*/);
    if (!match) continue;
    const address = match[1];
    const port = match[2];
    if (address === "127.0.0.1" || address === "::1" || address === "[::1]") {
      localPorts.add(port);
    } else {
      publicPorts.add(port);
    }
  }
  return {
    public: [...publicPorts].sort(sortNumericStrings),
    local: [...localPorts].sort(sortNumericStrings)
  };
}

function summarizeNotices(input: {
  services: Record<string, string>;
  checks: HealthCheck[];
  blocked: unknown;
  failedChecks: Array<Record<string, unknown>>;
}): string[] {
  const notices: string[] = [];
  if (input.services.ufw && input.services.ufw !== "active") notices.push("ufw is inactive");
  if (input.services.fail2ban && input.services.fail2ban !== "active") notices.push("fail2ban is inactive");
  const criticalLogs = input.checks.find((check) => check.id === "critical-logs");
  if (criticalLogs?.stdout.trim()) notices.push("critical logs present");
  const failedUnits = input.checks.find((check) => check.id === "failed-units");
  if (failedUnits && failedUnits.exitCode !== 0) notices.push("systemd failed units present");
  if (input.failedChecks.length > 0) notices.push("one or more health checks failed");
  if (input.blocked) notices.push("health check blocked before completion");
  return notices;
}

function matchLineValue(text: string, label: string): string | undefined {
  const pattern = new RegExp(`${escapeRegExp(label)}:\\s*(.+)`, "i");
  return text.match(pattern)?.[1]?.trim();
}

function firstNonEmptyLine(text: string): string | undefined {
  return text.split(/\r?\n/).map((line) => line.trim()).find(Boolean);
}

function sortNumericStrings(a: string, b: string): number {
  return Number(a) - Number(b);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function composeArgvRemoteCommand(input: CommandInput): string {
  return composeRemoteCommand({
    hostId: input.hostId,
    command: [input.program, ...(input.args ?? [])].map(shellQuote).join(" "),
    cwd: input.cwd,
    env: input.env,
    sudo: input.sudo,
    timeoutMs: input.timeoutMs,
    confirmationToken: input.confirmationToken
  });
}

function composeArgvPolicyCommand(input: CommandInput): string {
  let command = [input.program, ...(input.args ?? [])].join(" ");
  if (input.sudo === "nopasswd") command = `sudo -n ${command}`;
  if (input.cwd) command = `cd ${input.cwd} && ${command}`;
  if (input.env) {
    const env = Object.keys(input.env).join(" ");
    if (env) command = `${env} ${command}`;
  }
  return command;
}

function validateArgvProgram(value: string): void {
  if (!value || value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error("Invalid program: contains a control character or is empty");
  }
  if (value.startsWith("-")) {
    throw new Error("Invalid program: leading dash is not allowed");
  }
  if (/[\s;|&`$<>]/.test(value)) {
    throw new Error("Invalid program: contains whitespace or shell metacharacters");
  }
}

function validateArgvArg(value: string, index: number): void {
  if (value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error(`Invalid args[${index}]: contains a control character`);
  }
}

function normalizeCleanupTargets(targets: CleanupTargetInput[]): CleanupTarget[] {
  if (targets.length === 0) throw new Error("cleanup_paths requires at least one target");
  return targets.map((target, index) => {
    const mode = target.mode ?? "delete";
    if (mode !== "delete" && mode !== "empty-dir") {
      throw new Error(`Invalid cleanup target mode at index ${index}: ${mode}`);
    }
    const path = normalizeCleanupPath(target.path, index);
    return { path, mode };
  });
}

function normalizeCleanupPath(value: string, index: number): string {
  if (!value || value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error(`Invalid cleanup target path at index ${index}: contains a control character or is empty`);
  }
  if (!value.startsWith("/")) {
    throw new Error(`Invalid cleanup target path at index ${index}: must be absolute`);
  }
  if (/[\s;|&`$<>'"*?[\]{}()]/.test(value)) {
    throw new Error(`Invalid cleanup target path at index ${index}: contains whitespace, glob, quote, or shell metacharacters`);
  }
  const normalized = pathPosix.normalize(value);
  if (DANGEROUS_CLEANUP_PATHS.has(normalized)) {
    throw new Error(`Invalid cleanup target path at index ${index}: path is too broad`);
  }
  return normalized;
}

function composeCleanupPolicyCommand(targets: CleanupTarget[]): string {
  return ["cleanup_paths", ...targets.flatMap((target) => [`--${target.mode}`, target.path])].join(" ");
}

function composeCleanupRemoteCommand(target: CleanupTarget): string {
  if (target.mode === "empty-dir") {
    return `find ${shellQuote(target.path)} -mindepth 1 -delete`;
  }
  return `rm -rf -- ${shellQuote(target.path)}`;
}

function classifyArgvAccess(program: string, args: string[]): CommandAccess {
  const rawTokens = [program, ...args].map(commandName);
  const tokens = unwrapArgvCommandTokens(rawTokens);
  const name = tokens[0] ?? commandName(program);
  const commandArgs = tokens.slice(1);
  const first = commandArgs[0];
  const joined = tokens.join(" ");

  if (/^(shutdown|reboot|halt|poweroff|mkfs|dd)$/.test(name)) return "destructive";
  if (argvHasInterpreterExecution(rawTokens)) return "write";
  if (name === "rm" || name === "rmdir" || name === "mv" || name === "cp" || name === "chmod" || name === "chown" || name === "tee") return "write";
  if (name === "sed" && commandArgs.includes("-i")) return "write";
  if (name === "find" && commandArgs.some((arg) => arg === "-exec" || arg === "-execdir" || arg === "-ok" || arg === "-okdir")) return "write";
  if (name === "xargs") return "write";
  if (name === "find" && commandArgs.includes("-delete")) return "write";
  if (argvActionAfter(tokens, "systemctl")?.match(/^(restart|reload|stop|disable|enable|daemon-reload)$/)) return "restart";
  if (name === "service" && commandArgs[1] && /^(restart|reload|stop)$/.test(commandName(commandArgs[1]))) return "restart";
  if (name === "ufw" && !ufwArgsAreReadOnly(commandArgs)) return "firewall";
  if (name === "iptables" && commandArgs.some((arg) => /^-(A|I|D|R|P|F|N|X|Z)$/.test(arg))) return "firewall";
  if (argvActionAfter(tokens, "nft")?.match(/^(add|delete|destroy|flush|insert|replace|reset)$/)) return "firewall";
  if (name === "docker" && /\bdocker\s+(rm|rmi|container rm|image rm|network rm|volume rm|image prune|builder prune|system prune)\b/i.test(joined)) {
    return "write";
  }

  if (
    [
      "cat",
      "crontab",
      "df",
      "du",
      "file",
      "free",
      "grep",
      "egrep",
      "fgrep",
      "head",
      "hostnamectl",
      "journalctl",
      "ls",
      "pgrep",
      "ps",
      "ss",
      "tail",
      "uname",
      "uptime",
      "which"
    ].includes(name)
  ) {
    return "read";
  }
  if (name === "systemctl" && first && /^(list-units|list-unit-files|cat|status|show|is-active|is-enabled|--failed)$/.test(first)) return "read";
  if (name === "ufw" && ufwArgsAreReadOnly(commandArgs)) return "read";
  if (name === "iptables" && commandArgs.every((arg) => /^(-L|-S|-n|-v|--list|--list-rules)$/.test(arg))) return "read";
  if (name === "nft" && first && /^(list|monitor)$/.test(first)) return "read";
  if (name === "docker" && first && /^(ps|images)$/.test(first)) return "read";

  return "unknown";
}

function unwrapArgvCommandTokens(tokens: string[]): string[] {
  let remaining = [...tokens];
  while (remaining.length > 0) {
    const head = remaining[0];
    if (head === "sudo") {
      remaining = remaining.slice(1);
      remaining = consumeWrapperOptions(remaining, new Set(["-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from", "-D", "--chdir"]));
      continue;
    }
    if (head === "env") {
      remaining = remaining.slice(1);
      remaining = consumeWrapperOptions(remaining, new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]));
      while (/^[A-Za-z_][A-Za-z0-9_]*=/.test(remaining[0] ?? "")) remaining = remaining.slice(1);
      continue;
    }
    if (head === "command") {
      remaining = remaining.slice(1);
      continue;
    }
    break;
  }
  return remaining;
}

function consumeWrapperOptions(tokens: string[], optionsWithValues: Set<string>): string[] {
  let remaining = [...tokens];
  while (remaining[0]?.startsWith("-")) {
    const option = remaining[0];
    remaining = remaining.slice(1);
    const optionName = option.includes("=") ? option.slice(0, option.indexOf("=")) : option;
    if (optionsWithValues.has(optionName) && !option.includes("=") && remaining.length > 0) {
      remaining = remaining.slice(1);
    }
  }
  return remaining;
}

function argvHasInterpreterExecution(tokens: string[]): boolean {
  const interpreters = new Set(["sh", "bash", "ash", "dash", "python", "python3", "perl", "ruby", "node"]);
  for (let index = 0; index < tokens.length; index++) {
    if (!interpreters.has(tokens[index])) continue;
    for (const option of tokens.slice(index + 1, index + 4)) {
      if (!option.startsWith("-")) break;
      if (option === "-c" || option === "-lc" || /^-[A-Za-z]*c[A-Za-z]*$/.test(option)) return true;
    }
  }
  return false;
}

function argvActionAfter(tokens: string[], command: string): string | undefined {
  const index = tokens.indexOf(command);
  if (index < 0) return undefined;
  return tokens.slice(index + 1).find((token) => !token.startsWith("-"));
}

function ufwArgsAreReadOnly(args: string[]): boolean {
  const action = args.find((arg) => !arg.startsWith("-"));
  return action === "status" || action === "show";
}

function commandName(value: string): string {
  return value.split("/").filter(Boolean).pop()?.toLowerCase() ?? value.toLowerCase();
}

function isExecResult(value: ExecResult | ConfirmationRequired | PolicyDecision): value is ExecResult {
  return Boolean(value && typeof value === "object" && "commandId" in value);
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function hashOptionalInput(value: string | undefined): string {
  if (value === undefined) return "";
  return createHash("sha256").update(value).digest("hex");
}

function hasSessionId(value: unknown): boolean {
  return Boolean(value && typeof value === "object" && "sessionId" in value);
}

function policyReason(value: unknown): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const reasons = (value as { reasons?: unknown }).reasons;
  if (Array.isArray(reasons) && typeof reasons[0] === "string") return reasons[0];
  const reason = (value as { reason?: unknown }).reason;
  return typeof reason === "string" ? reason : undefined;
}

function isTransientProbeFailure(probe: Record<string, unknown>): boolean {
  const diagnostic = probeDiagnostic(probe);
  return diagnostic === "tcp" || diagnostic === "timeout";
}

function probeDiagnostic(probe: Record<string, unknown>): string {
  const stages = probe.stages;
  if (!stages || typeof stages !== "object") return "";
  const ssh = (stages as Record<string, unknown>).ssh;
  if (!ssh || typeof ssh !== "object") return "";
  const diagnostic = (ssh as Record<string, unknown>).diagnostic;
  return typeof diagnostic === "string" ? diagnostic : "";
}

function hostTargetSummary(host: Host): string {
  return `${host.user ? `${host.user}@` : ""}${host.hostname}${host.port ? `:${host.port}` : ""}`;
}

function sleep(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function hostConnectProbeTimeoutMs(totalTimeoutMs: number | undefined, retryCount: number, retryDelayMs: number): number {
  if (retryCount <= 0) return totalTimeoutMs ?? 10_000;
  const totalBudgetMs = totalTimeoutMs ?? 30_000;
  const delayBudgetMs = Math.max(0, retryDelayMs) * retryCount;
  const attemptCount = retryCount + 1;
  return Math.max(1000, Math.floor((totalBudgetMs - delayBudgetMs) / attemptCount));
}

function shouldRetrySshExec(result: { exitCode: number | null; stderr: string; timedOut: boolean }): boolean {
  if (result.exitCode !== 255) return false;
  const diagnostic = classifySshFailure(result.stderr, result.timedOut);
  return diagnostic === "timeout" || diagnostic === "tcp" || !result.stderr.trim();
}

function clearControlSocket(host: Host, controlDir: string): void {
  try {
    unlinkSync(controlPathForHost(host, controlDir));
  } catch {
    // Missing or already removed sockets are expected during recovery.
  }
}

function sshConnectTimeoutSeconds(timeoutMs: number): number {
  const bufferedMs = Math.max(1000, timeoutMs - 2000);
  return Math.max(1, Math.ceil(bufferedMs / 1000));
}

function debugArgv(argv: string[], env: NodeJS.ProcessEnv): { argv?: string[] } {
  return env.SMOOTH_SSH_MCP_INCLUDE_ARGV === "1" ? { argv: sanitizeArgv(argv) } : {};
}

function sanitizeArgv(argv: string[]): string[] {
  return argv.map((arg, index) => {
    const previous = argv[index - 1];
    if (previous === "-i") return "[REDACTED_IDENTITY_FILE]";
    if (arg.startsWith("ControlPath=")) return "ControlPath=[REDACTED]";
    if (arg.includes("ControlPath=")) return arg.replace(/ControlPath=[^\s]+/g, "ControlPath=[REDACTED]");
    return redactAndTruncate(arg, 2048).text;
  });
}

function classifySshFailure(stderr: string, timedOut: boolean): string {
  if (/Could not resolve hostname/i.test(stderr)) return "dns";
  if (/Connection timed out|No route to host|Connection refused|Connection reset|kex_exchange_identification/i.test(stderr)) return "tcp";
  if (/REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed|authenticity of host|can't be established|fingerprint/i.test(stderr)) return "host-key";
  if (/Permission denied|publickey|authentication/i.test(stderr)) return "auth";
  if (/Pseudo-terminal|shell request failed/i.test(stderr)) return "shell";
  if (timedOut) return "timeout";
  return stderr.trim() ? "ssh-error" : "none";
}

function classifySshSuccess(stderr: string): string {
  if (/Permanently added .+ to the list of known hosts/i.test(stderr)) return "host-key-added";
  return "none";
}

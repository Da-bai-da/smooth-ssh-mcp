import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { loadInventory } from "../src/inventory.js";
import { SshOperations } from "../src/operations.js";
import { issueConfirmation } from "../src/policy.js";
import type { SessionManager } from "../src/sessionManager.js";
import { StateStore } from "../src/stateStore.js";
import type { Host, Inventory } from "../src/types.js";
import type { RunOptions, Runner, RunResult } from "../src/runner.js";

const host: Host = {
  id: "prod-api",
  hostname: "203.0.113.10",
  user: "root",
  port: 22,
  environment: "prod",
  riskLevel: "high",
  tags: ["api"],
  policy: {
    allowExec: true,
    allowPty: true,
    allowUpload: false,
    allowDownload: false,
    allowForward: false,
    acceptNewHostKey: false,
    requireConfirmForSudo: true,
    requireConfirmForWrite: true,
    requireConfirmForProd: true,
    permissionLevel: 2,
    deniedCommandPatterns: [],
    maxCommandSeconds: 30,
    maxOutputBytes: 32
  }
};

const inventory: Inventory = { hosts: [host] };

class FakeRunner implements Runner {
  calls: Array<{ file: string; args: string[]; options?: RunOptions }> = [];
  results: RunResult[] = [];
  result: RunResult = {
    exitCode: 0,
    signal: null,
    stdout: "ok",
    stderr: "",
    startedAt: new Date("2026-01-01T00:00:00.000Z"),
    endedAt: new Date("2026-01-01T00:00:00.010Z"),
    durationMs: 10,
    timedOut: false
  };

  async run(file: string, args: string[], options?: RunOptions): Promise<RunResult> {
    this.calls.push({ file, args, options });
    return this.results.shift() ?? this.result;
  }
}

describe("SshOperations", () => {
  const makeOperations = (runner: FakeRunner, selectedInventory: Inventory = inventory) =>
    new SshOperations({
      inventory: selectedInventory,
      runner,
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore()
    });

  it("returns a confirmation object before running prod exec", async () => {
    const runner = new FakeRunner();
    const operations = makeOperations(runner);

    const result = await operations.sshExec({
      hostId: "prod-api",
      command: "hostname"
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec"
    });
    expect(runner.calls).toHaveLength(0);
  });

  it("stops all managed sessions when disposed", () => {
    const stopAll = vi.fn();
    const operations = new SshOperations({
      inventory,
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        stopAll
      } as unknown as SessionManager
    });

    operations.dispose();

    expect(stopAll).toHaveBeenCalledOnce();
  });

  it("executes only when a confirmation token matches the exact command", async () => {
    const runner = new FakeRunner();
    runner.result.stdout = "Authorization: Bearer abcdef123456\n" + "x".repeat(80);
    const operations = makeOperations(runner);
    const confirmation = issueConfirmation({
      host,
      operation: "exec",
      command: "hostname",
      reasons: ["host environment is prod"]
    });

    const result = await operations.sshExec({
      hostId: "prod-api",
      command: "hostname",
      confirmationToken: confirmation.token
    });

    expect("exitCode" in result && result.exitCode).toBe(0);
    expect(runner.calls).toHaveLength(1);
    expect(runner.calls[0].file).toBe("ssh");
    expect(result).toMatchObject({
      hostId: "prod-api",
      truncated: true
    });
    if ("stdout" in result) {
      expect(result.stdout).toContain("Authorization: Bearer [REDACTED]");
      expect(result.stdout.length).toBeLessThanOrEqual(32);
    }
  });

  it("does not allow upload when host policy disables upload", async () => {
    const runner = new FakeRunner();
    const operations = makeOperations(runner);

    const result = await operations.fileUpload({
      hostId: "prod-api",
      localPath: "/tmp/a",
      remotePath: "/tmp/a"
    });

    expect(result).toMatchObject({
      allowed: false,
      confirmationRequired: false,
      risk: "critical"
    });
    expect(runner.calls).toHaveLength(0);
  });

  it("starts prod interactive sessions without confirmation when pty is allowed", () => {
    const runner = new FakeRunner();
    const operations = new SshOperations({
      inventory,
      runner,
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        start: (selectedHost: Host) => ({
          sessionId: "test-session",
          hostId: selectedHost.id,
          startedAt: "2026-01-01T00:00:00.000Z",
          lastActiveAt: "2026-01-01T00:00:00.000Z",
          state: "running",
          truncated: false,
          ttlSeconds: 1800,
          idleTimeoutSeconds: 300,
          outputBufferBytes: 65536
        })
      } as unknown as SessionManager
    });

    const result = operations.sessionStart({ hostId: "prod-api" });

    expect(result).toMatchObject({
      hostId: "prod-api",
      state: "running"
    });
  });

  it("requires confirmation before risky input is sent to an interactive session", () => {
    const send = vi.fn();
    const operations = new SshOperations({
      inventory,
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        hostForSession: () => host,
        send
      } as unknown as SessionManager
    });

    const result = operations.sessionSend({
      sessionId: "test-session",
      input: "rm -rf /tmp/old-file\n"
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "pty-input"
    });
    expect(send).not.toHaveBeenCalled();
  });

  it("allows whitespace-only interactive input without policy confirmation", () => {
    const send = vi.fn(() => ({ sessionId: "test-session", state: "running" }));
    const operations = new SshOperations({
      inventory,
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        hostForSession: () => {
          throw new Error("blank input should not need host policy lookup");
        },
        send
      } as unknown as SessionManager
    });

    const result = operations.sessionSend({
      sessionId: "test-session",
      input: "\n"
    });

    expect(result).toMatchObject({
      sessionId: "test-session",
      state: "running"
    });
    expect(send).toHaveBeenCalledWith("test-session", "\n");
  });

  it("evaluates split interactive input when the command is submitted", () => {
    const send = vi.fn(() => ({ sessionId: "test-session", state: "running" }));
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const operations = new SshOperations({
      inventory: { hosts: [lowRiskHost] },
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        hostForSession: () => lowRiskHost,
        send
      } as unknown as SessionManager
    });

    expect(operations.sessionSend({ sessionId: "test-session", input: "cat /etc" })).toMatchObject({
      state: "running"
    });

    const result = operations.sessionSend({ sessionId: "test-session", input: "/shadow\n" });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "pty-input"
    });
    expect(send).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledWith("test-session", "cat /etc");
  });

  it("applies current host permission overrides to existing interactive sessions", () => {
    const send = vi.fn(() => ({ sessionId: "test-session", state: "running" }));
    const operations = new SshOperations({
      inventory,
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        hostForSession: () => host,
        send
      } as unknown as SessionManager
    });
    operations.hostPermissionSet({ hostId: "prod-api", permissionLevel: 3 });

    const result = operations.sessionSend({ sessionId: "test-session", input: "ls\n" });

    expect(result).toMatchObject({
      allowed: false,
      confirmationRequired: false,
      risk: "critical"
    });
    expect(send).not.toHaveBeenCalled();
  });

  it("uses sshpass for passwordEnv hosts without putting the password in argv", async () => {
    const passwordHost: Host = {
      ...host,
      id: "password-host",
      hostname: "192.0.2.30",
      environment: "dev",
      riskLevel: "low",
      passwordEnv: "SMOOTH_SSH_PASSWORD_TEST",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const runner = new FakeRunner();
    const operations = new SshOperations({
      inventory: { hosts: [passwordHost] },
      runner,
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      env: {
        SMOOTH_SSH_PASSWORD_TEST: "secret"
      }
    });

    const result = await operations.sshExec({
      hostId: "password-host",
      command: "hostname"
    });

    expect("exitCode" in result && result.exitCode).toBe(0);
    expect(runner.calls[0].file).toBe("sshpass");
    expect(runner.calls[0].args.slice(0, 2)).toEqual(["-e", "ssh"]);
    expect(runner.calls[0].args.join(" ")).not.toContain("secret");
  });

  it("selects and reports recent hosts", () => {
    const operations = new SshOperations({
      inventory,
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore()
    });

    const selected = operations.hostSelect({ hostId: "prod-api" });
    const recent = operations.hostRecent();

    expect(selected).toMatchObject({
      selectedHostId: "prod-api"
    });
    expect(recent).toMatchObject({
      selectedHostId: "prod-api"
    });
    expect(recent.recentHosts[0]).toMatchObject({
      hostId: "prod-api"
    });
  });

  it("classifies tcp stderr before generic process timeout", async () => {
    const runner = new FakeRunner();
    runner.result = {
      ...runner.result,
      exitCode: 255,
      stderr: "ssh: connect to host 203.0.113.10 port 22: Connection refused\r\n",
      timedOut: true
    };
    const operations = makeOperations(runner);

    const result = await operations.sshProbe({
      hostId: "prod-api",
      timeoutMs: 10_000
    });

    expect(result).toMatchObject({
      ok: false,
      stages: {
        ssh: {
          diagnostic: "tcp"
        }
      }
    });
    expect(runner.calls[0].args).toContain("ConnectTimeout=8");
  });

  it("reports host-key-added for successful accept-new probes", async () => {
    const runner = new FakeRunner();
    runner.result = {
      ...runner.result,
      exitCode: 0,
      stdout: "smooth-ssh-ok\nLinux x86_64\n",
      stderr: "Warning: Permanently added '203.0.113.10' (ED25519) to the list of known hosts.\r\n"
    };
    const operations = makeOperations(runner);

    const result = await operations.sshProbe({
      hostId: "prod-api",
      timeoutMs: 10_000
    });

    expect(result).toMatchObject({
      ok: true,
      stages: {
        ssh: {
          diagnostic: "host-key-added"
        }
      }
    });
  });

  it("connects the selected host with one high level operation", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const runner = new FakeRunner();
    const operations = new SshOperations({
      inventory: { hosts: [lowRiskHost] },
      runner,
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        start: (selectedHost: Host) => ({
          sessionId: "test-session",
          hostId: selectedHost.id,
          startedAt: "2026-01-01T00:00:00.000Z",
          lastActiveAt: "2026-01-01T00:00:00.000Z",
          state: "running",
          truncated: false,
          ttlSeconds: 1800,
          idleTimeoutSeconds: 300,
          outputBufferBytes: 65536
        })
      } as unknown as SessionManager
    });
    operations.hostSelect({ hostId: "prod-api" });

    const result = await operations.hostConnect({
      timeoutMs: 10_000,
      startSession: true
    });

    expect(result).toMatchObject({
      hostId: "prod-api",
      connected: true,
      probe: {
        ok: true
      },
      session: {
        hostId: "prod-api",
        state: "running"
      }
    });
  });

  it("does not start an interactive session by default in high level connect", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const runner = new FakeRunner();
    const operations = new SshOperations({
      inventory: { hosts: [lowRiskHost] },
      runner,
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        start: () => {
          throw new Error("session should not start");
        }
      } as unknown as SessionManager
    });

    const result = await operations.hostConnect({
      hostId: "prod-api",
      timeoutMs: 10_000
    });

    expect(result).toMatchObject({
      connected: true,
      probeConnected: true,
      sessionStarted: false,
      session: null
    });
  });

  it("keeps host_connect connected when the probe succeeds but session start is blocked", async () => {
    const restrictedHost: Host = {
      ...host,
      policy: {
        ...host.policy,
        permissionLevel: 3
      }
    };
    const runner = new FakeRunner();
    const operations = new SshOperations({
      inventory: { hosts: [restrictedHost] },
      runner,
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      sessionManager: {
        start: () => {
          throw new Error("session should not start");
        }
      } as unknown as SessionManager
    });

    const result = await operations.hostConnect({
      hostId: "prod-api",
      timeoutMs: 10_000,
      startSession: true
    });

    expect(result).toMatchObject({
      connected: true,
      probeConnected: true,
      sessionStarted: false,
      sessionBlockedReason: "operation pty is denied by permission level 3",
      session: {
        allowed: false,
        confirmationRequired: false
      }
    });
  });

  it("retries transient tcp probe failures during high level connect", async () => {
    const runner = new FakeRunner();
    runner.results = [
      {
        ...runner.result,
        exitCode: 255,
        stderr: "ssh: connect to host 203.0.113.10 port 22: Connection refused\r\n",
        timedOut: false
      },
      {
        ...runner.result,
        exitCode: 0,
        stdout: "smooth-ssh-ok\nLinux x86_64\n",
        stderr: "",
        timedOut: false
      }
    ];
    const operations = makeOperations(runner);

    const result = await operations.hostConnect({
      hostId: "prod-api",
      timeoutMs: 10_000,
      retryDelayMs: 0
    });

    expect(result).toMatchObject({
      connected: true,
      attempts: 2,
      probe: {
        ok: true
      }
    });
    expect(runner.calls).toHaveLength(2);
    expect(runner.calls[0].options?.timeoutMs).toBeLessThan(10_000);
  });

  it("retries ssh exec once after an empty timeout-style ssh failure", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const runner = new FakeRunner();
    runner.results = [
      {
        ...runner.result,
        exitCode: 255,
        stdout: "",
        stderr: "",
        durationMs: 20_000,
        timedOut: true
      },
      {
        ...runner.result,
        exitCode: 0,
        stdout: "ok\n",
        stderr: "",
        timedOut: false
      }
    ];
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshExec({
      hostId: "prod-api",
      command: "df -h",
      timeoutMs: 20_000
    });

    expect("exitCode" in result && result.exitCode).toBe(0);
    expect(result).toMatchObject({
      attempts: 2,
      diagnostic: "none"
    });
    expect(runner.calls).toHaveLength(2);
  });

  it("adds a diagnostic to ssh exec failures", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const runner = new FakeRunner();
    runner.result = {
      ...runner.result,
      exitCode: 255,
      stdout: "",
      stderr: "",
      durationMs: 20_000,
      timedOut: true
    };
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshExec({
      hostId: "prod-api",
      command: "df -h",
      timeoutMs: 20_000
    });

    expect(result).toMatchObject({
      exitCode: 255,
      diagnostic: "timeout"
    });
  });

  it("does not auto-retry confirmed write commands", async () => {
    const runner = new FakeRunner();
    runner.result = {
      ...runner.result,
      exitCode: 255,
      stdout: "",
      stderr: "",
      durationMs: 20_000,
      timedOut: true
    };
    const operations = makeOperations(runner);
    const confirmation = issueConfirmation({
      host,
      operation: "exec",
      command: "rm -- /root/old-file",
      reasons: ["command appears to modify remote state"]
    });

    const result = await operations.sshExec({
      hostId: "prod-api",
      command: "rm -- /root/old-file",
      confirmationToken: confirmation.token,
      timeoutMs: 20_000
    });

    expect(result).toMatchObject({
      exitCode: 255,
      attempts: 1,
      diagnostic: "timeout"
    });
    expect(runner.calls).toHaveLength(1);
  });

  it("runs read-only argv commands on prod hosts without building a composite shell command", async () => {
    const runner = new FakeRunner();
    const operations = makeOperations(runner);

    const result = await operations.sshCommand({
      hostId: "prod-api",
      program: "systemctl",
      args: ["is-active", "nginx"]
    });

    expect("exitCode" in result && result.exitCode).toBe(0);
    expect(runner.calls).toHaveLength(1);
    const remoteCommand = runner.calls[0].args.at(-1) ?? "";
    expect(remoteCommand).toBe("'systemctl' 'is-active' 'nginx'");
    expect(remoteCommand).not.toMatch(/[;&|`$]/);
  });

  it("applies persisted numeric permission levels before executing commands", async () => {
    const runner = new FakeRunner();
    const operations = makeOperations(runner);

    const pending = operations.hostPermissionSet({ hostId: "prod-api", permissionLevel: 1 });
    expect(pending).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "permission",
      preview: {
        command: "host_permission_set prod-api 1"
      }
    });

    expect(operations.hostPermissionSet({ hostId: "prod-api", permissionLevel: 1, confirmationToken: (pending as { token: string }).token })).toMatchObject({
      hostId: "prod-api",
      permissionLevel: 1
    });

    const adminResult = await operations.sshCommand({
      hostId: "prod-api",
      program: "rm",
      args: ["-rf", "/tmp/old-file"]
    });

    expect("exitCode" in adminResult && adminResult.exitCode).toBe(0);
    expect(runner.calls).toHaveLength(1);

    expect(operations.hostPermissionSet({ hostId: "prod-api", permissionLevel: 3 })).toMatchObject({
      hostId: "prod-api",
      permissionLevel: 3
    });

    const restrictedResult = await operations.sshCommand({
      hostId: "prod-api",
      program: "rm",
      args: ["-rf", "/tmp/other-file"]
    });

    expect(restrictedResult).toMatchObject({
      allowed: false,
      confirmationRequired: false,
      risk: "critical"
    });
    expect(runner.calls).toHaveLength(1);
  });

  it("requires confirmation for unknown argv commands on high-risk hosts even when prod confirmation is disabled", async () => {
    const runner = new FakeRunner();
    const highRiskHost: Host = {
      ...host,
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const operations = makeOperations(runner, { hosts: [highRiskHost] });

    const result = await operations.sshCommand({
      hostId: "prod-api",
      program: "customctl",
      args: ["status"]
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec"
    });
    expect("reason" in result && result.reason).toMatch(/unknown argv/i);
    expect(runner.calls).toHaveLength(0);
  });

  it("requires confirmation before read commands print sensitive remote paths", async () => {
    const runner = new FakeRunner();
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshCommand({
      hostId: "prod-api",
      program: "cat",
      args: ["/srv/app/.env"]
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec"
    });
    expect("reason" in result && result.reason).toMatch(/sensitive remote path/i);
    expect(runner.calls).toHaveLength(0);
  });

  it("requires confirmation before shell read commands print exact sensitive files", async () => {
    const runner = new FakeRunner();
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshExec({
      hostId: "prod-api",
      command: "cat /etc/shadow"
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec"
    });
    expect("reason" in result && result.reason).toMatch(/sensitive remote path/i);
    expect(runner.calls).toHaveLength(0);
  });

  it("requires confirmation before argv read commands print key files", async () => {
    const runner = new FakeRunner();
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshCommand({
      hostId: "prod-api",
      program: "cat",
      args: ["/root/client.pem"]
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec"
    });
    expect("reason" in result && result.reason).toMatch(/sensitive remote path/i);
    expect(runner.calls).toHaveLength(0);
  });

  it.each([
    ["less shadow", { program: "less", args: ["/etc/shadow"] }],
    ["strings pem", { program: "strings", args: ["/root/client.pem"] }],
    ["absolute cat", { program: "/bin/cat", args: ["/etc/shadow"] }],
    ["relative pem", { program: "cat", args: ["client.pem"] }],
    ["relative private key", { program: "cat", args: ["id_rsa"] }]
  ])("requires confirmation for sensitive argv read variant: %s", async (_label, command) => {
    const runner = new FakeRunner();
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshCommand({
      hostId: "prod-api",
      program: command.program,
      args: command.args
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec"
    });
    expect("reason" in result && result.reason).toMatch(/sensitive remote path/i);
    expect(runner.calls).toHaveLength(0);
  });

  it("requires confirmation for sensitive shell reads behind sudo even when sudo confirmation is disabled", async () => {
    const runner = new FakeRunner();
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false,
        requireConfirmForSudo: false
      }
    };
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshExec({
      hostId: "prod-api",
      command: "sudo cat /etc/shadow"
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec"
    });
    expect("reason" in result && result.reason).toMatch(/sensitive remote path/i);
    expect(runner.calls).toHaveLength(0);
  });

  it.each([
    ["base64", "base64 /etc/shadow"],
    ["xxd", "xxd /etc/shadow"],
    ["od", "od -An /etc/shadow"]
  ])("requires confirmation when shell command references a sensitive path through %s", async (_label, command) => {
    const runner = new FakeRunner();
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false,
        requireConfirmForSudo: false
      }
    };
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshExec({
      hostId: "prod-api",
      command
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec"
    });
    expect("reason" in result && result.reason).toMatch(/sensitive remote path/i);
    expect(runner.calls).toHaveLength(0);
  });

  it("runs batch tasks as separate argv commands and stops before blocked writes", async () => {
    const runner = new FakeRunner();
    runner.results = [
      {
        ...runner.result,
        stdout: "active\n"
      }
    ];
    const operations = makeOperations(runner);

    const result = await operations.taskBatch({
      hostId: "prod-api",
      tasks: [
        { id: "nginx", program: "systemctl", args: ["is-active", "nginx"] },
        { id: "remove", program: "rm", args: ["--", "/tmp/old-file"] }
      ]
    });

    expect(result).toMatchObject({
      hostId: "prod-api",
      completed: [
        {
          id: "nginx",
          exitCode: 0
        }
      ],
      blocked: {
        id: "remove",
        result: {
          confirmationRequired: true
        }
      }
    });
    expect(runner.calls).toHaveLength(1);
  });

  it("passes confirmation tokens through batch tasks for the blocked command", async () => {
    const runner = new FakeRunner();
    const operations = makeOperations(runner);
    const blocked = await operations.taskBatch({
      hostId: "prod-api",
      tasks: [{ id: "remove", program: "rm", args: ["-rf", "/tmp/old-file"] }]
    });
    const token = (blocked as { blocked: { result: { token: string } } }).blocked.result.token;

    const result = await operations.taskBatch({
      hostId: "prod-api",
      confirmationToken: token,
      tasks: [{ id: "remove", program: "rm", args: ["-rf", "/tmp/old-file"] }]
    } as never);

    expect(result).toMatchObject({
      hostId: "prod-api",
      completed: [
        {
          id: "remove",
          exitCode: 0
        }
      ]
    });
    expect(runner.calls).toHaveLength(1);
  });

  it("can resume a blocked batch without rerunning completed tasks", async () => {
    const runner = new FakeRunner();
    runner.results = [
      {
        ...runner.result,
        stdout: "active\n"
      }
    ];
    const operations = makeOperations(runner);
    const tasks = [
      { id: "nginx", program: "systemctl", args: ["is-active", "nginx"] },
      { id: "remove", program: "rm", args: ["-rf", "/tmp/old-file"] }
    ];
    const blocked = await operations.taskBatch({
      hostId: "prod-api",
      tasks
    });
    const token = (blocked as { blocked: { result: { token: string } } }).blocked.result.token;
    const retryInput = {
      hostId: "prod-api",
      confirmationToken: token,
      startAt: 1,
      tasks
    };

    const result = await operations.taskBatch(retryInput);

    expect(blocked).toMatchObject({
      blocked: {
        id: "remove",
        index: 1,
        resumeFrom: 1
      }
    });
    expect(result).toMatchObject({
      completed: [
        {
          id: "remove",
          exitCode: 0
        }
      ]
    });
    expect(runner.calls.map((call) => call.args.at(-1))).toEqual([
      "'systemctl' 'is-active' 'nginx'",
      "'rm' '-rf' '/tmp/old-file'"
    ]);
  });

  it("compacts batch task output by default to keep MCP transcripts small", async () => {
    const runner = new FakeRunner();
    runner.result.stdout = "line-1\nline-2\nline-3\n";
    runner.result.stderr = "warning-1\nwarning-2\n";
    const operations = makeOperations(runner);

    const result = await operations.taskBatch({
      hostId: "prod-api",
      outputLimitBytes: 8,
      tasks: [{ id: "scan", program: "systemctl", args: ["is-active", "nginx"] }]
    } as never);

    expect(result).toMatchObject({
      completed: [
        {
          id: "scan",
          stdout: "line-1\nl",
          stderr: "warning-",
          stdoutBytes: 21,
          stderrBytes: 20,
          stdoutTruncated: true,
          stderrTruncated: true,
          truncated: true
        }
      ]
    });
  });

  it("returns full batch task output when requested", async () => {
    const runner = new FakeRunner();
    runner.result.stdout = "line-1\nline-2\nline-3\n";
    runner.result.stderr = "warning-1\nwarning-2\n";
    const operations = makeOperations(runner);

    const result = await operations.taskBatch({
      hostId: "prod-api",
      detail: "full",
      outputLimitBytes: 8,
      tasks: [{ id: "scan", program: "systemctl", args: ["is-active", "nginx"] }]
    } as never);

    expect(result).toMatchObject({
      completed: [
        {
          id: "scan",
          stdout: "line-1\nline-2\nline-3\n",
          stderr: "warning-1\nwarning-2\n",
          stdoutTruncated: false,
          stderrTruncated: false
        }
      ]
    });
  });

  it("caps compact batch output previews even when callers request a large limit", async () => {
    const runner = new FakeRunner();
    runner.result.stdout = "x".repeat(5000);
    const operations = makeOperations(runner, {
      hosts: [
        {
          ...host,
          policy: {
            ...host.policy,
            maxOutputBytes: 10000
          }
        }
      ]
    });

    const result = await operations.taskBatch({
      hostId: "prod-api",
      outputLimitBytes: 30000,
      tasks: [{ id: "scan", program: "systemctl", args: ["is-active", "nginx"] }]
    } as never);

    expect(result).toMatchObject({
      outputLimitBytes: 4096,
      completed: [
        {
          id: "scan",
          stdoutBytes: 5000,
          stdoutTruncated: true,
          truncated: true
        }
      ]
    });
    expect(((result.completed as Array<{ stdout: string }>)[0].stdout)).toHaveLength(4096);
  });

  it("confirms cleanup paths once and then runs exact cleanup commands", async () => {
    const runner = new FakeRunner();
    const operations = makeOperations(runner);
    const targets = [
      { path: "/srv/opkg/packages", mode: "empty-dir" as const },
      { path: "/srv/opkg/lab-20260421", mode: "delete" as const },
      { path: "/root/ipk-lab-src", mode: "delete" as const }
    ];

    const pending = await operations.cleanupPaths({
      hostId: "prod-api",
      targets
    });

    expect(pending).toMatchObject({
      confirmationRequired: true,
      hostId: "prod-api",
      operation: "exec",
      preview: {
        command: "cleanup_paths --empty-dir /srv/opkg/packages --delete /srv/opkg/lab-20260421 --delete /root/ipk-lab-src"
      }
    });
    expect(runner.calls).toHaveLength(0);

    const token = (pending as { token: string }).token;
    const result = await operations.cleanupPaths({
      hostId: "prod-api",
      targets,
      confirmationToken: token
    });

    expect(result).toMatchObject({
      hostId: "prod-api",
      completed: [
        { path: "/srv/opkg/packages", mode: "empty-dir", exitCode: 0 },
        { path: "/srv/opkg/lab-20260421", mode: "delete", exitCode: 0 },
        { path: "/root/ipk-lab-src", mode: "delete", exitCode: 0 }
      ]
    });
    expect(runner.calls.map((call) => call.args.at(-1))).toEqual([
      "find '/srv/opkg/packages' -mindepth 1 -delete",
      "rm -rf -- '/srv/opkg/lab-20260421'",
      "rm -rf -- '/root/ipk-lab-src'"
    ]);
  });

  it("requires confirmation for argv commands that invoke another command interpreter", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const runner = new FakeRunner();
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshCommand({
      hostId: "prod-api",
      program: "sh",
      args: ["-c", "printf ok"]
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      operation: "exec"
    });
    expect(runner.calls).toHaveLength(0);
  });

  it("requires confirmation for argv commands that hide interpreters behind wrappers", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false,
        requireConfirmForSudo: false
      }
    };
    const runner = new FakeRunner();
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    for (const input of [
      { program: "sudo", args: ["sh", "-c", "printf ok"] },
      { program: "env", args: ["FOO=bar", "bash", "-lc", "printf ok"] },
      { program: "command", args: ["python3", "-c", "print('ok')"] }
    ]) {
      const result = await operations.sshCommand({
        hostId: "prod-api",
        program: input.program,
        args: input.args
      });

      expect(result).toMatchObject({
        confirmationRequired: true,
        operation: "exec"
      });
    }
    expect(runner.calls).toHaveLength(0);
  });

  it("requires confirmation for argv find execution actions", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const runner = new FakeRunner();
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    for (const action of ["-execdir", "-ok", "-okdir"]) {
      const result = await operations.sshCommand({
        hostId: "prod-api",
        program: "find",
        args: ["/tmp", action, "sh", "-c", "printf ok", ";"]
      });

      expect(result).toMatchObject({
        confirmationRequired: true,
        operation: "exec"
      });
    }
    expect(runner.calls).toHaveLength(0);
  });

  it("requires confirmation for argv firewall mutations with global ufw options", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false
      }
    };
    const runner = new FakeRunner();
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    const result = await operations.sshCommand({
      hostId: "prod-api",
      program: "ufw",
      args: ["--force", "enable"]
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      operation: "exec"
    });
    expect(runner.calls).toHaveLength(0);
  });

  it("classifies dangerous argv commands behind wrapper options with values", async () => {
    const lowRiskHost: Host = {
      ...host,
      environment: "dev",
      riskLevel: "low",
      policy: {
        ...host.policy,
        requireConfirmForProd: false,
        requireConfirmForSudo: false
      }
    };
    const runner = new FakeRunner();
    const operations = makeOperations(runner, { hosts: [lowRiskHost] });

    for (const input of [
      { program: "sudo", args: ["-u", "root", "ufw", "--force", "enable"] },
      { program: "env", args: ["-u", "FOO", "systemctl", "restart", "nginx"] }
    ]) {
      const result = await operations.sshCommand({
        hostId: "prod-api",
        program: input.program,
        args: input.args
      });

      expect(result).toMatchObject({
        confirmationRequired: true,
        operation: "exec"
      });
    }
    expect(runner.calls).toHaveLength(0);
  });

  it("exposes a capability catalog so clients can prefer structured tools", () => {
    const operations = makeOperations(new FakeRunner());

    expect(operations.capabilityList()).toMatchObject({
      capabilities: expect.arrayContaining([
        expect.objectContaining({ id: "host_add", preferredTool: "host_add" }),
        expect.objectContaining({ id: "host_health", preferredTool: "host_health" }),
        expect.objectContaining({ id: "single_command", preferredTool: "ssh_command" }),
        expect.objectContaining({ id: "batch_tasks", preferredTool: "task_batch" })
      ]),
      shellFallback: expect.objectContaining({
        tool: "ssh_exec"
      })
    });
  });

  it("returns compact host health summary by default without raw checks", async () => {
    const runner = new FakeRunner();
    runner.results = healthResults();
    const operations = makeOperations(runner, healthInventory());

    const result = await operations.hostHealth({
      hostId: "prod-api"
    });

    expect(result).toMatchObject({
      hostId: "prod-api",
      ok: true,
      summary: {
        system: expect.objectContaining({
          hostname: "cxdabai",
          os: "Ubuntu 24.04.4 LTS",
          kernel: "Linux 6.8.0-110-generic"
        }),
        memory: expect.objectContaining({
          total: "955Mi",
          available: "418Mi"
        }),
        disk: expect.objectContaining({
          root: expect.objectContaining({
            usePercent: "45%"
          })
        }),
        services: expect.objectContaining({
          nginx: "active",
          ufw: "inactive"
        }),
        docker: expect.objectContaining({
          running: 2,
          healthy: 1
        }),
        ports: expect.objectContaining({
          public: expect.arrayContaining(["22", "80"]),
          local: expect.arrayContaining(["5173"])
        }),
        notices: expect.arrayContaining(["ufw is inactive", "fail2ban is inactive", "critical logs present"])
      }
    });
    expect(result).not.toHaveProperty("checks");
    expect(runner.calls.length).toBeGreaterThan(4);
    for (const call of runner.calls) {
      const remoteCommand = call.args.at(-1) ?? "";
      expect(remoteCommand).not.toMatch(/;|&&|\|\|/);
      expect(remoteCommand).not.toContain(" | ");
    }
  });

  it("includes raw host health checks only when requested", async () => {
    const runner = new FakeRunner();
    runner.results = healthResults();
    const operations = makeOperations(runner, healthInventory());

    const result = await operations.hostHealth({
      hostId: "prod-api",
      includeRaw: true
    });

    expect(result).toMatchObject({
      hostId: "prod-api",
      checks: expect.arrayContaining([
        expect.objectContaining({ id: "uptime" }),
        expect.objectContaining({ id: "memory" }),
        expect.objectContaining({ id: "disk" }),
        expect.objectContaining({ id: "listening-ports" })
      ])
    });
  });

  it("includes raw host health checks when full detail is requested", async () => {
    const runner = new FakeRunner();
    runner.results = healthResults();
    const operations = makeOperations(runner, healthInventory());

    const result = await operations.hostHealth({
      hostId: "prod-api",
      detail: "full"
    });

    expect(result).toMatchObject({
      checks: expect.arrayContaining([expect.objectContaining({ id: "critical-logs" })])
    });
  });

  it("keeps host health raw checks hidden for explicit compact detail", async () => {
    const runner = new FakeRunner();
    runner.results = healthResults();
    const operations = makeOperations(runner, healthInventory());

    const result = await operations.hostHealth({
      hostId: "prod-api",
      includeRaw: true,
      detail: "compact"
    });

    expect(result).toHaveProperty("summary");
    expect(result).not.toHaveProperty("checks");
  });

  it("keeps host health failures and blocked checks visible in compact summary", async () => {
    const runner = new FakeRunner();
    runner.results = healthResults({
      failedUnitsExitCode: 1,
      failedUnitsStdout: "1 loaded units listed.\nfailed.service loaded failed failed Example failure\n",
      failedUnitsStderr: "systemctl failed\n"
    });
    const partiallyBlockedHost: Host = {
      ...host,
      policy: {
        ...host.policy,
        maxOutputBytes: 64 * 1024,
        deniedCommandPatterns: ["journalctl"]
      }
    };
    const operations = makeOperations(runner, { hosts: [partiallyBlockedHost] });

    const result = await operations.hostHealth({
      hostId: "prod-api"
    });

    expect(result).toMatchObject({
      ok: false,
      summary: expect.objectContaining({
        failedChecks: expect.arrayContaining([expect.objectContaining({ id: "failed-units", exitCode: 1, message: "systemctl failed" })]),
        notices: expect.arrayContaining(["health check blocked before completion"])
      }),
      blocked: expect.objectContaining({
        id: expect.any(String),
        result: expect.objectContaining({
          allowed: false
        })
      })
    });
    expect(JSON.stringify(result)).not.toContain('"stderr"');
    expect(result).not.toHaveProperty("checks");
  });

  it("requires confirmation before adding a host to the local inventory", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-host-add-"));
    const configPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(configPath, "hosts: []\n", { mode: 0o600 });
    const operations = new SshOperations({
      inventory: { hosts: [] },
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      configPath,
      secretsPath
    });

    const result = operations.hostAdd({
      id: "lab",
      hostname: "192.0.2.10",
      user: "root",
      password: "secret-password"
    });

    expect(result).toMatchObject({
      confirmationRequired: true,
      hostId: "lab",
      operation: "config"
    });
    expect(readFileSync(configPath, "utf8")).toBe("hosts: []\n");
    expect(existsSync(secretsPath)).toBe(false);
  });

  it("adds a password host after confirmation without writing inline passwords", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-host-add-"));
    const configPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(configPath, "hosts: []\n", { mode: 0o600 });
    const operations = new SshOperations({
      inventory: { hosts: [] },
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      configPath,
      secretsPath
    });
    const input = {
      id: "lab",
      hostname: "192.0.2.10",
      user: "root",
      port: 2222,
      password: "secret-password",
      tags: ["test"],
      environment: "dev" as const
    };
    const confirmation = operations.hostAdd(input);
    if (!("confirmationRequired" in confirmation)) throw new Error("expected confirmation");

    const result = operations.hostAdd({ ...input, confirmationToken: confirmation.token });

    expect(result).toMatchObject({
      hostId: "lab",
      added: true,
      hasPasswordEnv: true,
      configPath,
      secretsPath
    });
    const configText = readFileSync(configPath, "utf8");
    expect(configText).toContain("id: lab");
    expect(configText).toContain("passwordEnv: SMOOTH_SSH_PASSWORD_LAB");
    expect(configText).not.toContain("secret-password");
    expect(readFileSync(secretsPath, "utf8")).toContain("SMOOTH_SSH_PASSWORD_LAB=secret-password\n");
    expect((statSync(configPath).mode & 0o777).toString(8)).toBe("600");
    expect((statSync(secretsPath).mode & 0o777).toString(8)).toBe("600");
    expect(loadInventory(configPath).hosts[0]).toMatchObject({
      id: "lab",
      hostname: "192.0.2.10",
      user: "root",
      port: 2222,
      passwordEnv: "SMOOTH_SSH_PASSWORD_LAB"
    });
    expect(operations.hostGet("lab")).toMatchObject({
      id: "lab",
      hasPasswordEnv: true
    });
  });

  it("updates a host after confirmation and keeps password out of hosts.yaml", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-host-update-"));
    const configPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(
      configPath,
      [
        "hosts:",
        "  - id: lab",
        "    hostname: 192.0.2.10",
        "    user: root",
        "    passwordEnv: SMOOTH_SSH_PASSWORD_LAB"
      ].join("\n") + "\n",
      { mode: 0o600 }
    );
    writeFileSync(secretsPath, "SMOOTH_SSH_PASSWORD_LAB=old-secret\n", { mode: 0o600 });
    const operations = new SshOperations({
      inventory: loadInventory(configPath),
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      configPath,
      secretsPath
    });
    const input = {
      hostId: "lab",
      hostname: "192.0.2.11",
      port: 2222,
      tags: ["updated"],
      password: "new-secret"
    };

    const confirmation = operations.hostUpdate(input);

    expect(confirmation).toMatchObject({
      confirmationRequired: true,
      hostId: "lab",
      operation: "config"
    });
    expect(readFileSync(configPath, "utf8")).toContain("hostname: 192.0.2.10");
    expect(readFileSync(secretsPath, "utf8")).toContain("old-secret");
    if (!("confirmationRequired" in confirmation)) throw new Error("expected confirmation");
    expect(confirmation.preview.command).toContain("passwordEnv=SMOOTH_SSH_PASSWORD_LAB");

    const result = operations.hostUpdate({ ...input, confirmationToken: confirmation.token });

    expect(result).toMatchObject({
      hostId: "lab",
      updated: true,
      hasPasswordEnv: true
    });
    const configText = readFileSync(configPath, "utf8");
    expect(configText).toContain("hostname: 192.0.2.11");
    expect(configText).toContain("port: 2222");
    expect(configText).toContain("passwordEnv: SMOOTH_SSH_PASSWORD_LAB");
    expect(configText).not.toContain("new-secret");
    expect(readFileSync(secretsPath, "utf8")).toContain("SMOOTH_SSH_PASSWORD_LAB=new-secret\n");
    expect(loadInventory(configPath).hosts[0]).toMatchObject({
      id: "lab",
      hostname: "192.0.2.11",
      port: 2222,
      passwordEnv: "SMOOTH_SSH_PASSWORD_LAB"
    });
    expect(operations.hostGet("lab")).toMatchObject({
      id: "lab",
      hostname: "192.0.2.11"
    });
  });

  it("removes a host and its password secret after confirmation", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-host-remove-"));
    const configPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(
      configPath,
      [
        "hosts:",
        "  - id: lab",
        "    hostname: 192.0.2.10",
        "    passwordEnv: SMOOTH_SSH_PASSWORD_LAB",
        "  - id: keep",
        "    hostname: 192.0.2.20"
      ].join("\n") + "\n",
      { mode: 0o600 }
    );
    writeFileSync(secretsPath, "SMOOTH_SSH_PASSWORD_LAB=secret\nOTHER=1\n", { mode: 0o600 });
    const operations = new SshOperations({
      inventory: loadInventory(configPath),
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      configPath,
      secretsPath
    });

    const confirmation = operations.hostRemove({ hostId: "lab", removeSecret: true });

    expect(confirmation).toMatchObject({
      confirmationRequired: true,
      hostId: "lab",
      operation: "config"
    });
    expect(readFileSync(configPath, "utf8")).toContain("id: lab");
    if (!("confirmationRequired" in confirmation)) throw new Error("expected confirmation");

    const result = operations.hostRemove({ hostId: "lab", removeSecret: true, confirmationToken: confirmation.token });

    expect(result).toMatchObject({
      hostId: "lab",
      removed: true,
      removedPasswordEnv: "SMOOTH_SSH_PASSWORD_LAB"
    });
    expect(readFileSync(configPath, "utf8")).not.toContain("id: lab");
    expect(readFileSync(configPath, "utf8")).toContain("id: keep");
    expect(readFileSync(secretsPath, "utf8")).not.toContain("SMOOTH_SSH_PASSWORD_LAB");
    expect(readFileSync(secretsPath, "utf8")).toContain("OTHER=1");
    expect(() => operations.hostGet("lab")).toThrow(/host not found/i);
  });

  it("sets a secret after confirmation without returning the secret value", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-secret-set-"));
    const configPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(configPath, "hosts: []\n", { mode: 0o600 });
    const operations = new SshOperations({
      inventory: { hosts: [] },
      runner: new FakeRunner(),
      controlDir: "/tmp/smooth-ssh-mcp-test",
      stateStore: new StateStore(),
      configPath,
      secretsPath
    });

    const confirmation = operations.secretSet({ key: "SMOOTH_SSH_PASSWORD_LAB", value: "secret-value" });

    expect(confirmation).toMatchObject({
      confirmationRequired: true,
      hostId: "local-config",
      operation: "config"
    });
    expect(existsSync(secretsPath)).toBe(false);
    if (!("confirmationRequired" in confirmation)) throw new Error("expected confirmation");

    const result = operations.secretSet({ key: "SMOOTH_SSH_PASSWORD_LAB", value: "secret-value", confirmationToken: confirmation.token });

    expect(result).toMatchObject({
      key: "SMOOTH_SSH_PASSWORD_LAB",
      updated: true,
      secretsPath
    });
    expect(JSON.stringify(result)).not.toContain("secret-value");
    expect(readFileSync(secretsPath, "utf8")).toBe("SMOOTH_SSH_PASSWORD_LAB=secret-value\n");
    expect((statSync(secretsPath).mode & 0o777).toString(8)).toBe("600");
  });
});

function healthInventory(): Inventory {
  return {
    hosts: [
      {
        ...host,
        policy: {
          ...host.policy,
          maxOutputBytes: 64 * 1024
        }
      }
    ]
  };
}

function healthResults(
  overrides: {
    failedUnitsExitCode?: number;
    failedUnitsStdout?: string;
    failedUnitsStderr?: string;
  } = {}
): RunResult[] {
  const base: RunResult = {
    exitCode: 0,
    signal: null,
    stdout: "",
    stderr: "",
    startedAt: new Date("2026-01-01T00:00:00.000Z"),
    endedAt: new Date("2026-01-01T00:00:00.010Z"),
    durationMs: 10,
    timedOut: false
  };
  const stdout = (value: string, exitCode = 0, stderr = ""): RunResult => ({
    ...base,
    exitCode,
    stdout: value,
    stderr
  });
  return [
    stdout(" Static hostname: cxdabai\nOperating System: Ubuntu 24.04.4 LTS\n          Kernel: Linux 6.8.0-110-generic\n"),
    stdout("Linux 6.8.0-110-generic x86_64\n"),
    stdout(" 10:09:09 up 3 days,  6:11,  2 users,  load average: 0.58, 0.31, 0.23\n"),
    stdout("               total        used        free      shared  buff/cache   available\nMem:           955Mi       537Mi        78Mi        35Mi       533Mi       418Mi\nSwap:          2.3Gi       283Mi       2.1Gi\n"),
    stdout("Filesystem     Type  Size  Used Avail Use% Mounted on\n/dev/vda2      ext4   23G  9.7G   13G  45% /\n"),
    stdout("Filesystem     Inodes IUsed IFree IUse% Mounted on\n/dev/vda2        1.5M   42K  1.4M    3% /\n"),
    stdout("PID PPID COMMAND %CPU %MEM\n1 0 systemd 0.1 1.0\n"),
    stdout(overrides.failedUnitsStdout ?? "0 loaded units listed.\n", overrides.failedUnitsExitCode ?? 0, overrides.failedUnitsStderr),
    stdout("active\n"),
    stdout("active\n"),
    stdout("active\n"),
    stdout("active\n"),
    stdout("active\n"),
    stdout("inactive\n", 3),
    stdout("inactive\n", 3),
    stdout("State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:5173 0.0.0.0:*\n"),
    stdout("NAMES IMAGE STATUS PORTS\nsub2api app Up 3 days (healthy) 127.0.0.1:8090->8090/tcp\nredis redis Up 3 days 6379/tcp\n"),
    stdout("Apr 26 sshd[1]: Failed password for invalid user\n")
  ];
}

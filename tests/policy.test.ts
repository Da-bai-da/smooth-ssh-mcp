import { describe, expect, it } from "vitest";
import { evaluateOperationPolicy, issueConfirmation, verifyConfirmation } from "../src/policy.js";
import type { Host } from "../src/types.js";

const baseHost: Host = {
  id: "prod-api",
  hostname: "203.0.113.10",
  user: "root",
  port: 22,
  environment: "prod",
  riskLevel: "high",
  tags: [],
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
    maxOutputBytes: 65536
  }
};

describe("operation policy", () => {
  it("requires confirmation for prod command execution", () => {
    const decision = evaluateOperationPolicy({
      host: baseHost,
      operation: "exec",
      command: "hostname"
    });

    expect(decision.allowed).toBe(false);
    expect(decision.confirmationRequired).toBe(true);
    expect(decision.reasons).toContain("host environment is prod");
  });

  it("blocks commands matching denied patterns without offering confirmation", () => {
    const decision = evaluateOperationPolicy({
      host: {
        ...baseHost,
        policy: {
          ...baseHost.policy,
          deniedCommandPatterns: ["rm\\s+-rf\\s+/"]
        }
      },
      operation: "exec",
      command: "rm -rf /"
    });

    expect(decision.allowed).toBe(false);
    expect(decision.confirmationRequired).toBe(false);
    expect(decision.risk).toBe("critical");
  });

  it("denies writes under permission level 3", () => {
    const decision = evaluateOperationPolicy({
      host: {
        ...baseHost,
        policy: {
          ...baseHost.policy,
          permissionLevel: 3
        }
      },
      operation: "exec",
      command: "rm -rf /tmp/old-file",
      commandMode: "argv",
      access: "write"
    });

    expect(decision).toMatchObject({
      allowed: false,
      confirmationRequired: false,
      risk: "critical"
    });
  });

  it("allows writes under permission level 1 without confirmation", () => {
    const decision = evaluateOperationPolicy({
      host: {
        ...baseHost,
        policy: {
          ...baseHost.policy,
          permissionLevel: 1
        }
      },
      operation: "exec",
      command: "rm -rf /tmp/old-file",
      commandMode: "argv",
      access: "write"
    });

    expect(decision).toMatchObject({
      allowed: true,
      confirmationRequired: false
    });
  });

  it("binds confirmation tokens to the exact operation fingerprint", () => {
    const first = issueConfirmation({
      host: baseHost,
      operation: "exec",
      command: "systemctl reload nginx",
      reasons: ["sudo or service control"]
    });

    expect(verifyConfirmation(first.token, {
      host: baseHost,
      operation: "exec",
      command: "systemctl reload nginx"
    })).toBe(true);

    expect(verifyConfirmation(first.token, {
      host: baseHost,
      operation: "exec",
      command: "systemctl restart nginx"
    })).toBe(false);
  });

  it("binds confirmation tokens to stdin hash and effective command details", () => {
    const first = issueConfirmation({
      host: baseHost,
      operation: "exec",
      command: "id",
      stdinHash: "empty",
      reasons: ["host environment is prod"]
    });

    expect(verifyConfirmation(first.token, {
      host: baseHost,
      operation: "exec",
      command: "sudo -n sh -lc 'id'",
      stdinHash: "empty"
    })).toBe(false);

    const second = issueConfirmation({
      host: baseHost,
      operation: "exec",
      command: "id",
      stdinHash: "empty",
      reasons: ["host environment is prod"]
    });

    expect(verifyConfirmation(second.token, {
      host: baseHost,
      operation: "exec",
      command: "id",
      stdinHash: "changed"
    })).toBe(false);
  });

  it("blocks denied commands delivered through stdin to a shell", () => {
    const decision = evaluateOperationPolicy({
      host: {
        ...baseHost,
        environment: "dev",
        riskLevel: "low",
        policy: {
          ...baseHost.policy,
          requireConfirmForProd: false
        }
      },
      operation: "exec",
      command: "sh",
      stdin: "rm -rf /\n"
    });

    expect(decision).toMatchObject({
      allowed: false,
      confirmationRequired: false,
      risk: "critical"
    });
  });

  it("allows common read-only shell pipelines without confirmation", () => {
    const host = {
      ...baseHost,
      policy: {
        ...baseHost.policy,
        requireConfirmForProd: false
      }
    };

    expect(
      evaluateOperationPolicy({
        host,
        operation: "exec",
        command: "ps -eo pid,ppid,user,etime,cmd --sort=-etime | head -n 80"
      })
    ).toMatchObject({
      allowed: true,
      confirmationRequired: false
    });

    expect(
      evaluateOperationPolicy({
        host,
        operation: "exec",
        command: 'grep -RInE "server_name|proxy_pass|root|listen" /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/nginx.conf'
      })
    ).toMatchObject({
      allowed: true,
      confirmationRequired: false
    });
  });

  it("allows read-only argv commands on level 2 prod hosts without prod confirmation", () => {
    const decision = evaluateOperationPolicy({
      host: baseHost,
      operation: "exec",
      command: "'systemctl' 'is-active' 'ufw'",
      commandMode: "argv",
      access: "read"
    });

    expect(decision).toMatchObject({
      allowed: true,
      confirmationRequired: false
    });
  });

  it("allows recognized read-only shell checks on level 2 prod hosts without prod confirmation", () => {
    const decision = evaluateOperationPolicy({
      host: baseHost,
      operation: "exec",
      command: "ps -eo pid,comm,%cpu --sort=-%cpu | head -n 10"
    });

    expect(decision).toMatchObject({
      allowed: true,
      confirmationRequired: false
    });
  });

  it("does not require confirmation for opening a managed pty session solely because the host is prod", () => {
    const decision = evaluateOperationPolicy({
      host: baseHost,
      operation: "pty"
    });

    expect(decision).toMatchObject({
      allowed: true,
      confirmationRequired: false
    });
  });

  it("allows read-only firewall status checks while requiring confirmation for firewall mutations", () => {
    const host = {
      ...baseHost,
      environment: "dev" as const,
      riskLevel: "low" as const,
      policy: {
        ...baseHost.policy,
        requireConfirmForProd: false
      }
    };

    expect(
      evaluateOperationPolicy({
        host,
        operation: "exec",
        command: "systemctl is-active ufw"
      })
    ).toMatchObject({
      allowed: true,
      confirmationRequired: false
    });

    expect(
      evaluateOperationPolicy({
        host,
        operation: "exec",
        command: "ufw allow 22"
      })
    ).toMatchObject({
      allowed: false,
      confirmationRequired: true,
      risk: "medium"
    });
  });

  it("does not classify stderr redirects to /dev/null as remote writes", () => {
    const host = {
      ...baseHost,
      environment: "dev" as const,
      riskLevel: "low" as const,
      policy: {
        ...baseHost.policy,
        requireConfirmForProd: false
      }
    };

    const decision = evaluateOperationPolicy({
      host,
      operation: "exec",
      command: "hostnamectl 2>/dev/null"
    });

    expect(decision.reasons).not.toContain("command appears to modify remote state");
  });

  it("requires confirmation for destructive cleanup commands", () => {
    const host = {
      ...baseHost,
      policy: {
        ...baseHost.policy,
        requireConfirmForProd: false
      }
    };

    for (const command of [
      "rm -r -- /root/old-dir",
      "rm -- /root/old-file",
      "rmdir -- /root/backups",
      "docker image rm old:latest",
      "docker network rm old_default",
      "docker image prune -f",
      "docker builder prune -af"
    ]) {
      expect(
        evaluateOperationPolicy({
          host,
          operation: "exec",
          command
        })
      ).toMatchObject({
        allowed: false,
        confirmationRequired: true
      });
    }
  });

  it("requires confirmation for firewall mutations with global ufw options", () => {
    const host = {
      ...baseHost,
      environment: "dev" as const,
      riskLevel: "low" as const,
      policy: {
        ...baseHost.policy,
        requireConfirmForProd: false
      }
    };

    expect(
      evaluateOperationPolicy({
        host,
        operation: "exec",
        command: "ufw --force enable"
      })
    ).toMatchObject({
      allowed: false,
      confirmationRequired: true
    });
  });

  it("requires confirmation for firewall mutations behind sudo options with values", () => {
    const host = {
      ...baseHost,
      environment: "dev" as const,
      riskLevel: "low" as const,
      policy: {
        ...baseHost.policy,
        requireConfirmForProd: false,
        requireConfirmForSudo: false
      }
    };

    expect(
      evaluateOperationPolicy({
        host,
        operation: "exec",
        command: "sudo -u root ufw --force enable"
      })
    ).toMatchObject({
      allowed: false,
      confirmationRequired: true
    });
  });

  it("does not treat executable pipelines as read-only", () => {
    const host = {
      ...baseHost,
      policy: {
        ...baseHost.policy,
        requireConfirmForProd: false
      }
    };

    for (const command of [
      "cat /tmp/script.sh | sh",
      "grep payload /tmp/input | bash",
      "find /tmp -type f -exec sh -c 'id' \\;"
    ]) {
      expect(
        evaluateOperationPolicy({
          host,
          operation: "exec",
          command
        })
      ).toMatchObject({
        allowed: false,
        confirmationRequired: true
      });
    }
  });
});

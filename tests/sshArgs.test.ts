import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildScpArgs, buildSshArgs, buildSshControlArgs, controlPathForHost } from "../src/sshArgs.js";
import { wrapWithPasswordAuth } from "../src/auth.js";
import type { Host } from "../src/types.js";

const host: Host = {
  id: "prod-api",
  hostname: "203.0.113.10",
  user: "root",
  port: 2222,
  identityFile: "/home/tester/.ssh/prod.pem",
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

describe("ssh argv builder", () => {
  it("builds OpenSSH argv without local shell wrapping", () => {
    const controlDir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-control-"));
    const argv = buildSshArgs(host, {
      controlDir,
      command: "printf '%s\\n' hello",
      timeoutSeconds: 20
    });

    expect(argv[0]).toBe("-o");
    expect(argv).toContain("ControlMaster=auto");
    expect(argv).toContain("ControlPersist=10m");
    expect(argv).toContain("-p");
    expect(argv).toContain("2222");
    expect(argv).toContain("-i");
    expect(argv).toContain("/home/tester/.ssh/prod.pem");
    expect(argv.at(-3)).toBe("--");
    expect(argv.at(-2)).toBe("root@203.0.113.10");
    expect(argv.at(-1)).toBe("printf '%s\\n' hello");
    expect(argv.join(" ")).not.toContain("sh -c");
  });

  it("uses a hashed private ControlPath under the configured directory", () => {
    const controlDir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-control-"));
    const path = controlPathForHost(host, controlDir);

    expect(path.startsWith(controlDir)).toBe(true);
    expect(path).toMatch(/prod-api-[a-f0-9]{16}\.sock$/);
    expect(path).not.toContain("203.0.113.10");
    expect(path.length).toBeLessThan(104);
  });

  it("builds scp argv with source and destination as separate argv entries", () => {
    const controlDir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-control-"));
    const argv = buildScpArgs(host, {
      controlDir,
      direction: "upload",
      localPath: "/tmp/build.tar.gz",
      remotePath: "/tmp/build.tar.gz"
    });

    expect(argv).toContain("-P");
    expect(argv).toContain("2222");
    expect(argv.at(-3)).toBe("--");
    expect(argv.at(-2)).toBe("/tmp/build.tar.gz");
    expect(argv.at(-1)).toBe("root@203.0.113.10:/tmp/build.tar.gz");
  });

  it("rejects remote scp paths with shell metacharacters", () => {
    const controlDir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-control-"));

    expect(() =>
      buildScpArgs(host, {
        controlDir,
        direction: "download",
        localPath: "/tmp/out",
        remotePath: "/tmp/out;touch-pwned"
      })
    ).toThrow(/remotePath/i);
  });

  it("wraps password hosts with sshpass and omits BatchMode", () => {
    const controlDir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-control-"));
    const passwordHost: Host = {
      ...host,
      identityFile: undefined,
      passwordEnv: "SMOOTH_SSH_PASSWORD_TEST"
    };
    const sshArgs = buildSshArgs(passwordHost, {
      controlDir,
      command: "hostname"
    });
    const command = wrapWithPasswordAuth(passwordHost, "ssh", sshArgs, {
      SMOOTH_SSH_PASSWORD_TEST: "secret"
    });

    expect(sshArgs).not.toContain("BatchMode=yes");
    expect(command.file).toBe("sshpass");
    expect(command.args.slice(0, 3)).toEqual(["-e", "ssh", "-o"]);
    expect(command.env?.SSHPASS).toBe("secret");
    expect(command.args.join(" ")).not.toContain("secret");
  });

  it("can accept new host keys while still relying on OpenSSH to reject changed keys", () => {
    const controlDir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-control-"));
    const argv = buildSshArgs(
      {
        ...host,
        policy: {
          ...host.policy,
          acceptNewHostKey: true
        }
      },
      {
        controlDir,
        command: "hostname"
      }
    );

    expect(argv).toContain("StrictHostKeyChecking=accept-new");
  });

  it("builds a non-interactive control-master exit command", () => {
    const controlDir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-control-"));
    const argv = buildSshControlArgs(host, {
      controlDir,
      controlCommand: "exit"
    });
    const controlPath = controlPathForHost(host, controlDir);

    expect(argv).toContain("-O");
    expect(argv).toContain("exit");
    expect(argv).toContain("-S");
    expect(argv).toContain(controlPath);
    expect(argv).toContain("BatchMode=yes");
    expect(argv).toContain("NumberOfPasswordPrompts=0");
    expect(argv).toContain("ConnectTimeout=1");
    expect(argv).toContain("-p");
    expect(argv).toContain("2222");
    expect(argv.at(-2)).toBe("--");
    expect(argv.at(-1)).toBe("root@203.0.113.10");
    expect(argv).not.toContain("ControlMaster=auto");
    expect(argv).not.toContain("ControlPersist=10m");
  });
});

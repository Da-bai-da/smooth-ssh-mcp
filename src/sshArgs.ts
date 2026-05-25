import { createHash } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Host } from "./types.js";

type SshArgOptions = {
  controlDir: string;
  command?: string;
  timeoutSeconds?: number;
  forceTty?: boolean;
  batchMode?: boolean;
};

type ScpArgOptions = {
  controlDir: string;
  direction: "upload" | "download";
  localPath: string;
  remotePath: string;
};

type SshControlOptions = {
  controlDir: string;
  controlCommand: "check" | "exit" | "stop";
};

export function buildSshArgs(host: Host, options: SshArgOptions): string[] {
  const args = [
    ...baseSshOptions(host, options.controlDir, options.timeoutSeconds ?? host.policy.maxCommandSeconds)
  ];

  if (options.batchMode !== false && !host.passwordEnv) {
    args.push("-o", "BatchMode=yes");
  }
  if (options.forceTty) {
    args.push("-tt");
  }

  args.push("--", targetForHost(host));
  if (options.command !== undefined) {
    args.push(options.command);
  }
  return args;
}

export function buildSshControlArgs(host: Host, options: SshControlOptions): string[] {
  const args = [
    "-O",
    options.controlCommand,
    "-S",
    controlPathForHost(host, options.controlDir),
    "-o",
    "BatchMode=yes",
    "-o",
    "NumberOfPasswordPrompts=0",
    "-o",
    "ConnectTimeout=1"
  ];

  if (host.port) args.push("-p", String(host.port));
  if (host.identityFile) args.push("-i", host.identityFile);
  if (host.proxyJump) args.push("-J", host.proxyJump);

  args.push("--", targetForHost(host));
  return args;
}

export function buildScpArgs(host: Host, options: ScpArgOptions): string[] {
  validatePathArg(options.localPath, "localPath");
  validateRemotePathArg(options.remotePath);

  const args = [
    "-o",
    "ControlMaster=auto",
    "-o",
    "ControlPersist=10m",
    "-o",
    `ControlPath=${controlPathForHost(host, options.controlDir)}`,
    "-o",
    "ServerAliveInterval=10",
    "-o",
    "ServerAliveCountMax=3"
  ];

  if (host.port) args.push("-P", String(host.port));
  if (host.identityFile) args.push("-i", host.identityFile);
  if (host.proxyJump) args.push("-J", host.proxyJump);

  const remote = `${targetForHost(host)}:${options.remotePath}`;
  if (options.direction === "upload") {
    args.push("--", options.localPath, remote);
  } else {
    args.push("--", remote, options.localPath);
  }
  return args;
}

export function controlPathForHost(host: Host, controlDir: string): string {
  mkdirSync(controlDir, { recursive: true, mode: 0o700 });
  chmodSync(controlDir, 0o700);

  const fingerprint = createHash("sha256")
    .update(
      JSON.stringify({
        id: host.id,
        hostname: host.hostname,
        sshConfigHost: host.sshConfigHost,
        user: host.user,
        port: host.port,
        identityFile: host.identityFile,
        passwordEnv: host.passwordEnv,
        proxyJump: host.proxyJump
      })
    )
    .digest("hex")
    .slice(0, 16);
  const safeId = host.id.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 24);
  return join(controlDir, `${safeId}-${fingerprint}.sock`);
}

export function targetForHost(host: Host): string {
  const targetHost = host.sshConfigHost ?? host.hostname;
  return host.user ? `${host.user}@${targetHost}` : targetHost;
}

function baseSshOptions(host: Host, controlDir: string, timeoutSeconds: number): string[] {
  const args = [
    "-o",
    `ConnectTimeout=${timeoutSeconds}`,
    "-o",
    "ServerAliveInterval=10",
    "-o",
    "ServerAliveCountMax=3",
    "-o",
    "ControlMaster=auto",
    "-o",
    "ControlPersist=10m",
    "-o",
    `ControlPath=${controlPathForHost(host, controlDir)}`
  ];
  if (host.policy.acceptNewHostKey) {
    args.push("-o", "StrictHostKeyChecking=accept-new");
  }

  if (host.port) args.push("-p", String(host.port));
  if (host.identityFile) args.push("-i", host.identityFile);
  if (host.proxyJump) args.push("-J", host.proxyJump);
  return args;
}

function validatePathArg(value: string, label: string): void {
  if (value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error(`Invalid ${label}: contains a control character`);
  }
  if (value.startsWith("-")) {
    throw new Error(`Invalid ${label}: leading dash is not allowed`);
  }
}

function validateRemotePathArg(value: string): void {
  validatePathArg(value, "remotePath");
  if (/[\s;|&`$<>]/.test(value)) {
    throw new Error("Invalid remotePath: contains whitespace or shell metacharacters");
  }
}

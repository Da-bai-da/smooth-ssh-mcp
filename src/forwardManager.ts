import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { wrapWithPasswordAuth } from "./auth.js";
import { buildSshArgs } from "./sshArgs.js";
import type { Host } from "./types.js";

export type SpawnedForwardProcess = {
  pid?: number;
  kill: (signal?: NodeJS.Signals) => unknown;
  on: (event: string, listener: (...args: unknown[]) => void) => unknown;
};

type ForwardManagerOptions = {
  controlDir: string;
  maxForwards?: number;
  ttlSeconds?: number;
  env?: NodeJS.ProcessEnv;
  spawnProcess?: (file: string, args: string[], env?: NodeJS.ProcessEnv) => SpawnedForwardProcess;
};

type ForwardRecord = {
  forwardId: string;
  hostId: string;
  pid?: number;
  localHost: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
  state: "starting" | "running" | "exited" | "error";
  startedAt: string;
  expiresAt: string;
  argv: string[];
  process: SpawnedForwardProcess;
  timer?: NodeJS.Timeout;
};

export type ForwardInfo = Omit<ForwardRecord, "process">;

export class ForwardManager {
  private readonly forwards = new Map<string, ForwardRecord>();
  private readonly maxForwards: number;
  private readonly env: NodeJS.ProcessEnv;
  private readonly spawnProcess: (file: string, args: string[], env?: NodeJS.ProcessEnv) => SpawnedForwardProcess;

  constructor(private readonly options: ForwardManagerOptions) {
    this.maxForwards = options.maxForwards ?? 8;
    this.env = options.env ?? process.env;
    this.spawnProcess =
      options.spawnProcess ??
      ((file, args, env) =>
        spawn(file, args, {
          env,
          shell: false,
          stdio: ["ignore", "ignore", "pipe"]
        }) as unknown as SpawnedForwardProcess);
  }

  start(input: { host: Host; localHost?: string; localPort: number; remoteHost: string; remotePort: number }): ForwardInfo {
    this.cleanupExpired();
    if (this.forwards.size >= this.maxForwards) {
      throw new Error(`Maximum active forwards reached: ${this.maxForwards}`);
    }
    validatePort(input.localPort, "localPort");
    validatePort(input.remotePort, "remotePort");
    validateForwardHost(input.localHost ?? "127.0.0.1", "localHost");
    validateForwardHost(input.remoteHost, "remoteHost");

    const base = buildSshArgs(input.host, {
      controlDir: this.options.controlDir,
      batchMode: true
    });
    const target = base.pop();
    const separator = base.pop();
    if (!target || separator !== "--") throw new Error("Unable to build ssh target for forward");
    const localHost = input.localHost ?? "127.0.0.1";
    const spec = `${localHost}:${input.localPort}:${input.remoteHost}:${input.remotePort}`;
    const argv = [...base, "-o", "ExitOnForwardFailure=yes", "-N", "-L", spec, "--", target];
    const commandSpec = wrapWithPasswordAuth(input.host, "ssh", argv, this.env);
    const child = this.spawnProcess(commandSpec.file, commandSpec.args, commandSpec.env);
    const ttlSeconds = this.options.ttlSeconds ?? 60 * 60;
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const record: ForwardRecord = {
      forwardId: randomUUID(),
      hostId: input.host.id,
      pid: child.pid,
      localHost,
      localPort: input.localPort,
      remoteHost: input.remoteHost,
      remotePort: input.remotePort,
      state: "starting",
      startedAt: new Date().toISOString(),
      expiresAt,
      argv: sanitizeForwardArgv(commandSpec.args),
      process: child
    };
    record.timer = setTimeout(() => {
      this.stop(record.forwardId);
    }, ttlSeconds * 1000);
    record.timer.unref();
    setTimeout(() => {
      if (record.state === "starting") record.state = "running";
    }, 500).unref();
    child.on("close", () => {
      record.state = "exited";
    });
    child.on("error", () => {
      record.state = "error";
    });
    this.forwards.set(record.forwardId, record);
    return this.toInfo(record);
  }

  stop(forwardId: string): ForwardInfo {
    const record = this.forwards.get(forwardId);
    if (!record) throw new Error(`Forward not found: ${forwardId}`);
    if (record.timer) clearTimeout(record.timer);
    record.process.kill("SIGTERM");
    forceKillLater(record.process);
    record.state = "exited";
    this.forwards.delete(forwardId);
    return this.toInfo(record);
  }

  list(): ForwardInfo[] {
    this.cleanupExpired();
    return [...this.forwards.values()].map((record) => this.toInfo(record));
  }

  private toInfo(record: ForwardRecord): ForwardInfo {
    const { process: _process, timer: _timer, ...info } = record;
    return info;
  }

  private cleanupExpired(): void {
    const now = Date.now();
    for (const [forwardId, record] of this.forwards) {
      if (Date.parse(record.expiresAt) <= now || record.state === "exited" || record.state === "error") {
        if (record.timer) clearTimeout(record.timer);
        record.process.kill("SIGTERM");
        forceKillLater(record.process);
        this.forwards.delete(forwardId);
      }
    }
  }
}

function forceKillLater(process: SpawnedForwardProcess): void {
  setTimeout(() => {
    process.kill("SIGKILL");
  }, 1000).unref();
}

function validatePort(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
}

function validateForwardHost(value: string, label: string): void {
  if (value.startsWith("-")) {
    throw new Error(`Invalid ${label}: leading dash is not allowed`);
  }
  if (!/^[A-Za-z0-9._:-]+$/.test(value)) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
}

function sanitizeForwardArgv(argv: string[]): string[] {
  return argv.map((arg, index) => {
    const previous = argv[index - 1];
    if (previous === "-i") return "[REDACTED_IDENTITY_FILE]";
    if (arg.startsWith("ControlPath=")) return "ControlPath=[REDACTED]";
    if (arg.includes("ControlPath=")) return arg.replace(/ControlPath=[^\s]+/g, "ControlPath=[REDACTED]");
    return arg;
  });
}

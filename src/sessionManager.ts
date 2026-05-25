import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { wrapWithPasswordAuth } from "./auth.js";
import { buildSshArgs, buildSshControlArgs } from "./sshArgs.js";
import { redactAndTruncate } from "./redaction.js";
import type { Host } from "./types.js";

type InputStreamLike = {
  write?: (chunk: string) => unknown;
  end?: () => unknown;
};

export type SpawnedSessionProcess = {
  pid?: number;
  stdout: EventEmitter;
  stderr: EventEmitter;
  stdin: InputStreamLike;
  kill: (signal?: NodeJS.Signals) => unknown;
  on: (event: string, listener: (...args: unknown[]) => void) => unknown;
  unref?: () => unknown;
};

type SessionManagerOptions = {
  controlDir: string;
  maxSessions?: number;
  outputBufferBytes?: number;
  ttlSeconds?: number;
  idleTimeoutSeconds?: number;
  env?: NodeJS.ProcessEnv;
  spawnProcess?: (file: string, args: string[], env?: NodeJS.ProcessEnv) => SpawnedSessionProcess;
  spawnControlProcess?: (file: string, args: string[], env?: NodeJS.ProcessEnv) => SpawnedSessionProcess;
};

type SessionRecord = {
  sessionId: string;
  hostId: string;
  host: Host;
  pid?: number;
  startedAt: number;
  lastActiveAt: number;
  state: "running" | "exited" | "error";
  buffer: string;
  truncated: boolean;
  finalized: boolean;
  process: SpawnedSessionProcess;
  ttlSeconds: number;
  idleTimeoutSeconds: number;
  outputBufferBytes: number;
};

export type SessionInfo = Omit<SessionRecord, "buffer" | "finalized" | "host" | "process" | "startedAt" | "lastActiveAt"> & {
  startedAt: string;
  lastActiveAt: string;
};

export class SessionManager {
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly maxSessions: number;
  private readonly outputBufferBytes: number;
  private readonly ttlSeconds: number;
  private readonly idleTimeoutSeconds: number;
  private readonly env: NodeJS.ProcessEnv;
  private readonly spawnProcess: (file: string, args: string[], env?: NodeJS.ProcessEnv) => SpawnedSessionProcess;
  private readonly spawnControlProcess: (file: string, args: string[], env?: NodeJS.ProcessEnv) => SpawnedSessionProcess;

  constructor(options: SessionManagerOptions) {
    this.maxSessions = options.maxSessions ?? 8;
    this.outputBufferBytes = options.outputBufferBytes ?? 64 * 1024;
    this.ttlSeconds = options.ttlSeconds ?? 30 * 60;
    this.idleTimeoutSeconds = options.idleTimeoutSeconds ?? 5 * 60;
    this.env = options.env ?? process.env;
    this.spawnProcess =
      options.spawnProcess ??
      ((file, args, env) =>
        spawn(file, args, {
          env,
          shell: false,
          stdio: ["pipe", "pipe", "pipe"]
        }) as unknown as SpawnedSessionProcess);
    this.spawnControlProcess =
      options.spawnControlProcess ??
      ((file, args, env) =>
        spawn(file, args, {
          detached: true,
          env,
          shell: false,
          stdio: "ignore"
        }) as unknown as SpawnedSessionProcess);
    this.controlDir = options.controlDir;
  }

  private readonly controlDir: string;

  start(host: Host): SessionInfo {
    this.cleanupExpired();
    if (this.sessions.size >= this.maxSessions) {
      throw new Error(`Maximum active sessions reached: ${this.maxSessions}`);
    }

    const args = buildSshArgs(host, {
      controlDir: this.controlDir,
      forceTty: true,
      batchMode: false
    });
    const commandSpec = wrapWithPasswordAuth(host, "ssh", args, this.env);
    const child = this.spawnProcess(commandSpec.file, commandSpec.args, commandSpec.env);
    const now = Date.now();
    const record: SessionRecord = {
      sessionId: randomUUID(),
      hostId: host.id,
      host,
      pid: child.pid,
      startedAt: now,
      lastActiveAt: now,
      state: "running",
      buffer: "",
      truncated: false,
      finalized: false,
      process: child,
      ttlSeconds: this.ttlSeconds,
      idleTimeoutSeconds: this.idleTimeoutSeconds,
      outputBufferBytes: this.outputBufferBytes
    };
    this.sessions.set(record.sessionId, record);

    child.stdout.on("data", (chunk) => this.appendOutput(record, chunk));
    child.stderr.on("data", (chunk) => this.appendOutput(record, chunk));
    child.on("close", () => {
      this.finalizeSession(record, { state: "exited", terminateProcess: false });
    });
    child.on("error", () => {
      this.finalizeSession(record, { state: "error", terminateProcess: false });
    });

    return this.toInfo(record);
  }

  send(sessionId: string, input: string): SessionInfo {
    const record = this.requireSession(sessionId);
    if (record.state !== "running") throw new Error(`Session is not running: ${sessionId}`);
    record.process.stdin.write?.(input);
    record.lastActiveAt = Date.now();
    return this.toInfo(record);
  }

  read(sessionId: string, maxBytes?: number): { sessionId: string; output: string; truncated: boolean; state: string } {
    const record = this.requireSession(sessionId);
    record.lastActiveAt = Date.now();
    const limit = maxBytes ?? record.outputBufferBytes;
    const redacted = redactAndTruncate(record.buffer, limit);
    const truncated = record.truncated || redacted.truncated;
    record.buffer = "";
    record.truncated = false;
    return {
      sessionId,
      output: redacted.text,
      truncated,
      state: record.state
    };
  }

  hostForSession(sessionId: string): Host {
    return this.requireSession(sessionId).host;
  }

  stop(sessionId: string): SessionInfo {
    const record = this.requireSession(sessionId);
    return this.finalizeSession(record, { state: "exited", terminateProcess: true });
  }

  list(): SessionInfo[] {
    this.cleanupExpired();
    return [...this.sessions.values()].map((record) => this.toInfo(record));
  }

  stopAll(): void {
    for (const record of [...this.sessions.values()]) {
      this.finalizeSession(record, { state: "exited", terminateProcess: true });
    }
  }

  getProcessForTest(sessionId: string): SpawnedSessionProcess {
    return this.requireSession(sessionId).process;
  }

  private appendOutput(record: SessionRecord, chunk: unknown): void {
    record.lastActiveAt = Date.now();
    record.buffer += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
    while (Buffer.byteLength(record.buffer, "utf8") > record.outputBufferBytes) {
      record.buffer = record.buffer.slice(1);
      record.truncated = true;
    }
  }

  private cleanupExpired(): void {
    const now = Date.now();
    for (const [sessionId, record] of this.sessions) {
      const ttlExpired = now - record.startedAt > record.ttlSeconds * 1000;
      const idleExpired = now - record.lastActiveAt > record.idleTimeoutSeconds * 1000;
      if (ttlExpired || idleExpired) {
        this.finalizeSession(record, { state: "exited", terminateProcess: true });
      }
    }
  }

  private finalizeSession(record: SessionRecord, options: { state: "exited" | "error"; terminateProcess: boolean }): SessionInfo {
    if (!record.finalized) {
      record.finalized = true;
      if (options.terminateProcess) {
        record.process.stdin.end?.();
        record.process.kill("SIGTERM");
        forceKillLater(record.process);
      }
      this.closeControlMaster(record.host);
    }
    record.state = options.state;
    record.lastActiveAt = Date.now();
    this.sessions.delete(record.sessionId);
    return this.toInfo(record);
  }

  private closeControlMaster(host: Host): void {
    const args = buildSshControlArgs(host, {
      controlDir: this.controlDir,
      controlCommand: "exit"
    });
    try {
      const child = this.spawnControlProcess("ssh", args, this.env);
      child.on("error", () => undefined);
      child.unref?.();
    } catch {
      // Best-effort cleanup only; a missing or already-closed control socket is fine.
    }
  }

  private requireSession(sessionId: string): SessionRecord {
    this.cleanupExpired();
    const record = this.sessions.get(sessionId);
    if (!record) throw new Error(`Session not found: ${sessionId}`);
    return record;
  }

  private toInfo(record: SessionRecord): SessionInfo {
    return {
      sessionId: record.sessionId,
      hostId: record.hostId,
      pid: record.pid,
      startedAt: new Date(record.startedAt).toISOString(),
      lastActiveAt: new Date(record.lastActiveAt).toISOString(),
      state: record.state,
      truncated: record.truncated,
      ttlSeconds: record.ttlSeconds,
      idleTimeoutSeconds: record.idleTimeoutSeconds,
      outputBufferBytes: record.outputBufferBytes
    };
  }
}

function forceKillLater(process: SpawnedSessionProcess): void {
  setTimeout(() => {
    process.kill("SIGKILL");
  }, 1000).unref();
}

import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { SessionManager, type SpawnedSessionProcess } from "../src/sessionManager.js";
import type { Host } from "../src/types.js";

const host: Host = {
  id: "lab",
  hostname: "192.0.2.10",
  environment: "dev",
  riskLevel: "low",
  tags: [],
  policy: {
    allowExec: true,
    allowPty: true,
    allowUpload: true,
    allowDownload: true,
    allowForward: true,
    acceptNewHostKey: false,
    requireConfirmForSudo: true,
    requireConfirmForWrite: true,
    requireConfirmForProd: true,
    permissionLevel: 2,
    deniedCommandPatterns: [],
    maxCommandSeconds: 30,
    maxOutputBytes: 128
  }
};

function fakeProcess(): SpawnedSessionProcess & { emitClose: () => void; killed: NodeJS.Signals[] } {
  const stdout = new EventEmitter();
  const stderr = new EventEmitter();
  const listeners = new Map<string, Array<(...args: unknown[]) => void>>();
  const killed: NodeJS.Signals[] = [];
  return {
    pid: 123,
    stdout,
    stderr,
    stdin: { write: vi.fn(), end: vi.fn() },
    kill: vi.fn((signal?: NodeJS.Signals) => {
      if (signal) killed.push(signal);
    }),
    on: vi.fn((event: string, listener: (...args: unknown[]) => void) => {
      const existing = listeners.get(event) ?? [];
      existing.push(listener);
      listeners.set(event, existing);
    }),
    unref: vi.fn(),
    emitClose: () => {
      for (const listener of listeners.get("close") ?? []) listener();
    },
    killed
  };
}

describe("SessionManager", () => {
  it("keeps only the configured ring buffer size and clears output after read", () => {
    const manager = new SessionManager({
      controlDir: "/tmp/smooth-ssh-mcp-test",
      maxSessions: 2,
      outputBufferBytes: 12,
      spawnProcess: () => {
        const stdout = new EventEmitter();
        const stderr = new EventEmitter();
        return {
          pid: 123,
          stdout,
          stderr,
          stdin: { write: vi.fn(), end: vi.fn() },
          kill: vi.fn(),
          on: vi.fn()
        };
      }
    });

    const session = manager.start(host);
    const process = manager.getProcessForTest(session.sessionId);
    process.stdout.emit("data", Buffer.from("hello "));
    process.stdout.emit("data", Buffer.from("world again"));

    const first = manager.read(session.sessionId);
    const second = manager.read(session.sessionId);

    expect(first.output).toBe(" world again");
    expect(first.truncated).toBe(true);
    expect(second.output).toBe("");
  });

  it("stops the ssh child and closes its control master when a session is stopped", () => {
    const spawned: Array<{ file: string; args: string[]; process: ReturnType<typeof fakeProcess> }> = [];
    const manager = new SessionManager({
      controlDir: "/tmp/smooth-ssh-mcp-test",
      spawnProcess: (file, args) => {
        const process = fakeProcess();
        spawned.push({ file, args, process });
        return process;
      },
      spawnControlProcess: (file, args) => {
        const process = fakeProcess();
        spawned.push({ file, args, process });
        return process;
      }
    });

    const session = manager.start(host);
    const stopped = manager.stop(session.sessionId);

    expect(stopped.state).toBe("exited");
    expect(spawned[0].process.stdin.end).toHaveBeenCalled();
    expect(spawned[0].process.kill).toHaveBeenCalledWith("SIGTERM");
    expect(spawned[1]).toMatchObject({
      file: "ssh"
    });
    expect(spawned[1].args).toContain("-O");
    expect(spawned[1].args).toContain("exit");
    expect(manager.list()).toEqual([]);
  });

  it("removes exited sessions and closes the control master when the ssh child exits", () => {
    const spawned: Array<{ file: string; args: string[]; process: ReturnType<typeof fakeProcess> }> = [];
    const manager = new SessionManager({
      controlDir: "/tmp/smooth-ssh-mcp-test",
      spawnProcess: (file, args) => {
        const process = fakeProcess();
        spawned.push({ file, args, process });
        return process;
      },
      spawnControlProcess: (file, args) => {
        const process = fakeProcess();
        spawned.push({ file, args, process });
        return process;
      }
    });

    const session = manager.start(host);
    spawned[0].process.emitClose();

    expect(manager.list()).toEqual([]);
    expect(spawned[1].file).toBe("ssh");
    expect(spawned[1].args).toContain("-O");
    expect(spawned[1].args).toContain("exit");
    expect(() => manager.read(session.sessionId)).toThrow(/Session not found/);
  });

  it("stops all active sessions for process shutdown cleanup", () => {
    const spawned: Array<{ file: string; args: string[]; process: ReturnType<typeof fakeProcess> }> = [];
    const manager = new SessionManager({
      controlDir: "/tmp/smooth-ssh-mcp-test",
      spawnProcess: (file, args) => {
        const process = fakeProcess();
        spawned.push({ file, args, process });
        return process;
      },
      spawnControlProcess: (file, args) => {
        const process = fakeProcess();
        spawned.push({ file, args, process });
        return process;
      }
    });

    manager.start({ ...host, id: "lab-a" });
    manager.start({ ...host, id: "lab-b" });

    manager.stopAll();

    expect(manager.list()).toEqual([]);
    expect(spawned.filter((call) => call.args.includes("-O") && call.args.includes("exit"))).toHaveLength(2);
    expect(spawned[0].process.kill).toHaveBeenCalledWith("SIGTERM");
    expect(spawned[1].process.kill).toHaveBeenCalledWith("SIGTERM");
  });
});

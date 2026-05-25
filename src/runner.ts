import { spawn } from "node:child_process";

export type RunOptions = {
  timeoutMs?: number;
  input?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  maxBufferBytes?: number;
};

export type RunResult = {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  startedAt: Date;
  endedAt: Date;
  durationMs: number;
  timedOut: boolean;
  stdoutTruncated?: boolean;
  stderrTruncated?: boolean;
};

export type Runner = {
  run(file: string, args: string[], options?: RunOptions): Promise<RunResult>;
};

export const nodeRunner: Runner = {
  run(file, args, options = {}) {
    return runProcess(file, args, options);
  }
};

export function runProcess(file: string, args: string[], options: RunOptions = {}): Promise<RunResult> {
  const startedAt = new Date();
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    let stdoutTruncated = false;
    let stderrTruncated = false;
    let timedOut = false;
    const maxBufferBytes = options.maxBufferBytes ?? 2 * 1024 * 1024;
    const timeout = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill("SIGTERM");
          setTimeout(() => {
            if (!child.killed) child.kill("SIGKILL");
          }, 1000).unref();
        }, options.timeoutMs)
      : undefined;
    timeout?.unref();

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      const next = appendBounded(stdout, chunk, maxBufferBytes);
      stdout = next.text;
      stdoutTruncated ||= next.truncated;
    });
    child.stderr.on("data", (chunk: string) => {
      const next = appendBounded(stderr, chunk, maxBufferBytes);
      stderr = next.text;
      stderrTruncated ||= next.truncated;
    });
    child.on("error", (error) => {
      if (timeout) clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (exitCode, signal) => {
      if (timeout) clearTimeout(timeout);
      const endedAt = new Date();
      resolve({
        exitCode,
        signal,
        stdout,
        stderr,
        startedAt,
        endedAt,
        durationMs: endedAt.getTime() - startedAt.getTime(),
        timedOut,
        stdoutTruncated,
        stderrTruncated
      });
    });

    if (options.input) child.stdin.write(options.input);
    child.stdin.end();
  });
}

function appendBounded(current: string, chunk: string, maxBytes: number): { text: string; truncated: boolean } {
  if (maxBytes <= 0) return { text: "", truncated: true };
  const combined = current + chunk;
  if (Buffer.byteLength(combined, "utf8") <= maxBytes) {
    return { text: combined, truncated: false };
  }
  let used = 0;
  let text = "";
  for (const char of combined) {
    const size = Buffer.byteLength(char, "utf8");
    if (used + size > maxBytes) break;
    text += char;
    used += size;
  }
  return { text, truncated: true };
}

import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("CLI smoke", () => {
  it("prints help without starting the MCP server", () => {
    const output = execFileSync(process.execPath, ["dist/server.js", "--help"], { encoding: "utf8", timeout: 2000 });

    expect(output).toContain("smooth-ssh-mcp 0.1.1");
    expect(output).toContain("Usage:");
    expect(output).toContain("smooth-ssh-mcp init");
    expect(output).toContain("smooth-ssh-mcp doctor");
  });

  it("prints the package version without starting the MCP server", () => {
    const output = execFileSync(process.execPath, ["dist/server.js", "--version"], { encoding: "utf8", timeout: 2000 });

    expect(output.trim()).toBe("0.1.1");
  });

  it("runs when invoked through an npm-style bin symlink", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-bin-"));
    const binPath = join(dir, "smooth-ssh-mcp");
    const serverPath = resolve("dist/server.js");
    chmodSync(serverPath, 0o755);
    symlinkSync(serverPath, binPath);

    const output = execFileSync(binPath, ["--version"], { encoding: "utf8", timeout: 2000 });

    expect(output.trim()).toBe("0.1.1");
  });
});

import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

describe("CLI smoke", () => {
  it("prints help without starting the MCP server", () => {
    const output = execFileSync(process.execPath, ["dist/server.js", "--help"], { encoding: "utf8", timeout: 2000 });

    expect(output).toContain("smooth-ssh-mcp 0.1.0");
    expect(output).toContain("Usage:");
    expect(output).toContain("smooth-ssh-mcp init");
    expect(output).toContain("smooth-ssh-mcp doctor");
  });

  it("prints the package version without starting the MCP server", () => {
    const output = execFileSync(process.execPath, ["dist/server.js", "--version"], { encoding: "utf8", timeout: 2000 });

    expect(output.trim()).toBe("0.1.0");
  });
});

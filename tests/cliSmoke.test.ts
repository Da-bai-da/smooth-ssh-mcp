import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, symlinkSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import packageJson from "../package.json" with { type: "json" };

describe("CLI smoke", () => {
  it("prints help without starting the MCP server", () => {
    const output = execFileSync(process.execPath, ["dist/server.js", "--help"], { encoding: "utf8", timeout: 2000 });

    expect(output).toContain(`smooth-ssh-mcp ${packageJson.version}`);
    expect(output).toContain("Usage:");
    expect(output).toContain("smooth-ssh-mcp init");
    expect(output).toContain("smooth-ssh-mcp doctor");
  });

  it("prints subcommand help without running init", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-help-"));
    const configPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");

    const output = execFileSync(process.execPath, ["dist/server.js", "init", "--help", "--config", configPath, "--secrets", secretsPath], {
      encoding: "utf8",
      timeout: 2000
    });

    expect(output).toContain(`smooth-ssh-mcp ${packageJson.version}`);
    expect(output).toContain("Usage:");
    expect(existsSync(configPath)).toBe(false);
    expect(existsSync(secretsPath)).toBe(false);
  });

  it("prints the package version without starting the MCP server", () => {
    const output = execFileSync(process.execPath, ["dist/server.js", "--version"], { encoding: "utf8", timeout: 2000 });

    expect(output.trim()).toBe(packageJson.version);
  });

  it("runs when invoked through an npm-style bin symlink", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-bin-"));
    const binPath = join(dir, "smooth-ssh-mcp");
    const serverPath = resolve("dist/server.js");
    chmodSync(serverPath, 0o755);
    symlinkSync(serverPath, binPath);

    const output = execFileSync(binPath, ["--version"], { encoding: "utf8", timeout: 2000 });

    expect(output.trim()).toBe(packageJson.version);
  });

  it("runs after installing the packed npm tarball", () => {
    const packOutput = execFileSync("npm", ["pack", "--json"], { encoding: "utf8", timeout: 20000 });
    const [{ filename }] = JSON.parse(packOutput) as Array<{ filename: string }>;
    const tarballPath = resolve(filename);

    try {
      const projectDir = mkdtempSync(join(tmpdir(), "smooth-ssh-packed-"));

      execFileSync("npm", ["install", "--prefix", projectDir, tarballPath], { encoding: "utf8", timeout: 20000 });

      const binPath = join(projectDir, "node_modules", ".bin", "smooth-ssh-mcp");
      const version = execFileSync(binPath, ["--version"], { encoding: "utf8", timeout: 2000 });

      expect(version.trim()).toBe(packageJson.version);

      const configPath = join(projectDir, "hosts.yaml");
      const secretsPath = join(projectDir, "secrets.env");
      const help = execFileSync(binPath, ["init", "--help", "--config", configPath, "--secrets", secretsPath], { encoding: "utf8", timeout: 2000 });

      expect(help).toContain(`smooth-ssh-mcp ${packageJson.version}`);
      expect(existsSync(configPath)).toBe(false);
      expect(existsSync(secretsPath)).toBe(false);
    } finally {
      unlinkSync(tarballPath);
    }
  }, 30000);
});

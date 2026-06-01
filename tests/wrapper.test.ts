import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

describe("local wrapper", () => {
  it("loads secrets as key-value data instead of sourcing executable shell", () => {
    const script = readFileSync(new URL("../bin/smooth-ssh-mcp-local", import.meta.url), "utf8");

    expect(script).not.toContain("source \"$SECRETS_FILE\"");
    expect(script).toContain("export \"$key=$value\"");
  });

  it("resolves the installed package directory when launched through an npm bin symlink", () => {
    const root = mkdtempSync(join(tmpdir(), "smooth-ssh-wrapper-"));
    try {
      const packageDir = join(root, "package");
      const packageBinDir = join(packageDir, "bin");
      const packageDistDir = join(packageDir, "dist");
      const globalBinDir = join(root, "global", "bin");

      mkdirSync(packageBinDir, { recursive: true });
      mkdirSync(packageDistDir, { recursive: true });
      mkdirSync(globalBinDir, { recursive: true });

      const wrapperPath = join(packageBinDir, "smooth-ssh-mcp-local");
      const serverPath = join(packageDistDir, "server.js");
      const linkPath = join(globalBinDir, "smooth-ssh-mcp-local");

      copyFileSync(new URL("../bin/smooth-ssh-mcp-local", import.meta.url), wrapperPath);
      writeFileSync(serverPath, "console.log(JSON.stringify(process.argv.slice(2)));");
      symlinkSync(wrapperPath, linkPath);

      const result = spawnSync("bash", [linkPath, "doctor", "--json"], {
        env: {
          ...process.env,
          HOME: join(root, "home"),
          SMOOTH_SSH_MCP_CONFIG: join(root, "hosts.yaml"),
          SMOOTH_SSH_MCP_SECRETS: join(root, "missing-secrets.env"),
        },
        encoding: "utf8",
      });

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout.trim())).toEqual(["doctor", "--json", "--config", join(root, "hosts.yaml")]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

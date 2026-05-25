import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadInventory } from "../src/inventory.js";
import { runInit } from "../src/init.js";

describe("init", () => {
  it("creates parseable config and secrets files with private permissions", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-init-"));
    const configPath = join(dir, "nested", "hosts.yaml");
    const secretsPath = join(dir, "nested", "secrets.env");

    const report = runInit({ configPath, secretsPath, env: { HOME: dir } });

    expect(report.ok).toBe(true);
    expect(report.actions.map((action) => [action.id, action.status])).toEqual([
      ["config-dir", "created"],
      ["hosts", "created"],
      ["secrets", "created"]
    ]);
    expect(existsSync(configPath)).toBe(true);
    expect(existsSync(secretsPath)).toBe(true);
    expect((statSync(join(dir, "nested")).mode & 0o777).toString(8)).toBe("700");
    expect((statSync(configPath).mode & 0o777).toString(8)).toBe("600");
    expect((statSync(secretsPath).mode & 0o777).toString(8)).toBe("600");
    expect(loadInventory(configPath).hosts).toHaveLength(1);
    expect(readFileSync(secretsPath, "utf8")).toContain("SMOOTH_SSH_PASSWORD_EXAMPLE_HOST=");
  });

  it("preserves existing files unless force is set", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-init-"));
    const configPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(configPath, "hosts: []\n", { mode: 0o600 });
    writeFileSync(secretsPath, "EXISTING=1\n", { mode: 0o600 });

    const first = runInit({ configPath, secretsPath, env: { HOME: dir } });

    expect(first.ok).toBe(true);
    expect(first.actions.map((action) => [action.id, action.status])).toEqual([
      ["config-dir", "exists"],
      ["hosts", "exists"],
      ["secrets", "exists"]
    ]);
    expect(readFileSync(configPath, "utf8")).toBe("hosts: []\n");
    expect(readFileSync(secretsPath, "utf8")).toBe("EXISTING=1\n");

    const forced = runInit({ configPath, secretsPath, force: true, env: { HOME: dir } });

    expect(forced.ok).toBe(true);
    expect(forced.actions.map((action) => [action.id, action.status])).toEqual([
      ["config-dir", "exists"],
      ["hosts", "created"],
      ["secrets", "created"]
    ]);
    expect(loadInventory(configPath).hosts).toHaveLength(1);
    expect(readFileSync(secretsPath, "utf8")).not.toBe("EXISTING=1\n");
  });

  it("tightens permissions when force overwrites existing files", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-init-"));
    const configPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(configPath, "hosts: []\n", { mode: 0o644 });
    writeFileSync(secretsPath, "EXISTING=1\n", { mode: 0o644 });

    runInit({ configPath, secretsPath, force: true, env: { HOME: dir } });

    expect((statSync(configPath).mode & 0o777).toString(8)).toBe("600");
    expect((statSync(secretsPath).mode & 0o777).toString(8)).toBe("600");
  });
});

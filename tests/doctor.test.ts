import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runDoctor } from "../src/doctor.js";

describe("doctor", () => {
  it("reports ok checks for dependencies, inventory, and secrets permissions", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-doctor-"));
    const inventoryPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(inventoryPath, "hosts: []\n", { mode: 0o600 });
    writeFileSync(secretsPath, "SMOOTH_SSH_PASSWORD_TEST=secret\n", { mode: 0o600 });
    chmodSync(inventoryPath, 0o600);
    chmodSync(secretsPath, 0o600);

    const report = runDoctor({
      configPath: inventoryPath,
      secretsPath,
      commandExists: (name) => ["node", "ssh", "scp", "sshpass"].includes(name),
      nodeVersion: "v24.11.1"
    });

    expect(report.ok).toBe(true);
    expect(report.summary).toMatchObject({ errors: 0 });
    expect(report.checks.map((check) => [check.id, check.status])).toEqual([
      ["node", "ok"],
      ["ssh", "ok"],
      ["scp", "ok"],
      ["sshpass", "ok"],
      ["inventory", "ok"],
      ["inventory-permissions", "ok"],
      ["secrets", "ok"],
      ["secrets-permissions", "ok"]
    ]);
  });

  it("reports actionable errors for missing commands and unsafe files", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-doctor-"));
    const inventoryPath = join(dir, "hosts.yaml");
    const secretsPath = join(dir, "secrets.env");
    writeFileSync(inventoryPath, "hosts: []\n", { mode: 0o644 });
    writeFileSync(secretsPath, "SMOOTH_SSH_PASSWORD_TEST=secret\n", { mode: 0o644 });
    chmodSync(inventoryPath, 0o644);
    chmodSync(secretsPath, 0o644);

    const report = runDoctor({
      configPath: inventoryPath,
      secretsPath,
      commandExists: (name) => name !== "ssh",
      nodeVersion: "v18.19.0"
    });

    expect(report.ok).toBe(false);
    expect(report.summary.errors).toBeGreaterThanOrEqual(3);
    expect(report.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "node", status: "error", fix: expect.stringContaining("Node.js >=20") }),
        expect.objectContaining({ id: "ssh", status: "error", fix: expect.stringContaining("OpenSSH") }),
        expect.objectContaining({ id: "inventory-permissions", status: "error", fix: "chmod 600 " + inventoryPath }),
        expect.objectContaining({ id: "secrets-permissions", status: "error", fix: "chmod 600 " + secretsPath })
      ])
    );
  });
});

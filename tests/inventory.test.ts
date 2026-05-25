import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadInventory } from "../src/inventory.js";

describe("loadInventory", () => {
  it("loads hosts from yaml and applies safe defaults", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: prod-api",
        "    hostname: 203.0.113.10",
        "    user: root",
        "    port: 2222",
        "    environment: prod",
        "    tags: [api, nginx]",
        "    policy:",
        "      maxCommandSeconds: 15"
      ].join("\n")
    );

    const inventory = loadInventory(file);

    expect(inventory.hosts).toHaveLength(1);
    expect(inventory.hosts[0]).toMatchObject({
      id: "prod-api",
      hostname: "203.0.113.10",
      user: "root",
      port: 2222,
      environment: "prod",
      riskLevel: "high"
    });
    expect(inventory.hosts[0].policy).toMatchObject({
      allowExec: true,
      allowPty: true,
      allowUpload: false,
      allowDownload: false,
      allowForward: false,
      acceptNewHostKey: false,
      requireConfirmForProd: true,
      requireConfirmForSudo: true,
      requireConfirmForWrite: true,
      permissionLevel: 2,
      maxCommandSeconds: 15
    });
    expect(inventory.hosts[0].policy).not.toHaveProperty("safetyProfile");
    expect(inventory.hosts[0].policy).not.toHaveProperty("permissionProfile");
  });

  it("rejects duplicate host ids", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: lab",
        "    hostname: 192.0.2.10",
        "  - id: lab",
        "    hostname: 192.0.2.11"
      ].join("\n")
    );

    expect(() => loadInventory(file)).toThrow(/duplicate host id/i);
  });

  it("rejects unsafe host ids and hostnames before they reach ssh argv", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: bad host",
        "    hostname: \"example.com; touch /tmp/pwned\""
      ].join("\n")
    );

    expect(() => loadInventory(file)).toThrow(/host id/i);
  });

  it("rejects leading dash host ids and ssh operands", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: -bad",
        "    hostname: -oProxyCommand=touch-pwned"
      ].join("\n")
    );

    expect(() => loadInventory(file)).toThrow(/leading dash/i);
  });

  it("rejects policy values with unsafe types instead of treating strings as booleans", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: lab",
        "    hostname: 192.0.2.10",
        "    policy:",
        "      allowUpload: \"false\""
      ].join("\n")
    );

    expect(() => loadInventory(file)).toThrow(/allowUpload/i);
  });

  it("loads passwordEnv for password auth without accepting inline passwords", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: password-host",
        "    hostname: 192.0.2.20",
        "    user: root",
        "    passwordEnv: SMOOTH_SSH_PASSWORD_PASSWORD_HOST"
      ].join("\n")
    );

    const inventory = loadInventory(file);

    expect(inventory.hosts[0]).toMatchObject({
      id: "password-host",
      passwordEnv: "SMOOTH_SSH_PASSWORD_PASSWORD_HOST"
    });
  });

  it("loads explicit accept-new host key policy", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: first-connect",
        "    hostname: 192.0.2.22",
        "    policy:",
        "      acceptNewHostKey: true"
      ].join("\n")
    );

    const inventory = loadInventory(file);

    expect(inventory.hosts[0].policy.acceptNewHostKey).toBe(true);
  });

  it("rejects removed safety profile policy", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: smooth-prod",
        "    hostname: 192.0.2.23",
        "    policy:",
        "      safetyProfile: smooth"
      ].join("\n")
    );

    expect(() => loadInventory(file)).toThrow(/policy\.safetyProfile/i);
  });

  it("loads explicit numeric permission level policy", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: admin-prod",
        "    hostname: 192.0.2.25",
        "    policy:",
        "      permissionLevel: 1"
      ].join("\n")
    );

    const inventory = loadInventory(file);

    expect(inventory.hosts[0].policy.permissionLevel).toBe(1);
  });

  it("rejects removed permission profile policy", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: old-profile",
        "    hostname: 192.0.2.24",
        "    policy:",
        "      permissionProfile: admin"
      ].join("\n")
    );

    expect(() => loadInventory(file)).toThrow(/policy\.permissionProfile/i);
  });

  it("rejects invalid permission level values", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: bad-profile",
        "    hostname: 192.0.2.26",
        "    policy:",
        "      permissionLevel: 4"
      ].join("\n")
    );

    expect(() => loadInventory(file)).toThrow(/permissionLevel/i);
  });

  it("rejects inline passwords in inventory files", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-mcp-"));
    const file = join(dir, "hosts.yaml");
    writeFileSync(
      file,
      [
        "hosts:",
        "  - id: bad-password-host",
        "    hostname: 192.0.2.21",
        "    user: root",
        "    password: hunter2"
      ].join("\n")
    );

    expect(() => loadInventory(file)).toThrow(/passwordEnv/i);
  });
});

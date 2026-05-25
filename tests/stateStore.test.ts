import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { StateStore } from "../src/stateStore.js";

describe("StateStore", () => {
  it("persists selected host and recent hosts without secrets", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-state-"));
    const statePath = join(dir, "state.json");
    const store = new StateStore(statePath);

    const selected = store.selectHost("vps-47-112-215-113", "manual");
    store.recordHostUse("vps-139-180-208-79", "exec");
    const reloaded = new StateStore(statePath);
    const recent = reloaded.recentHosts();

    expect(selected).toMatchObject({
      selectedHostId: "vps-47-112-215-113"
    });
    expect(reloaded.getState().selectedHostId).toBe("vps-47-112-215-113");
    expect(recent.map((entry) => entry.hostId)).toEqual(["vps-139-180-208-79", "vps-47-112-215-113"]);
    expect(readFileSync(statePath, "utf8")).not.toMatch(/password|secret|identityFile/i);
  });

  it("persists per-host numeric permission level overrides without secrets", () => {
    const dir = mkdtempSync(join(tmpdir(), "smooth-ssh-state-"));
    const statePath = join(dir, "state.json");
    const store = new StateStore(statePath);

    store.setPermissionLevel("vps-139-180-208-79", 1);
    const reloaded = new StateStore(statePath);

    expect(reloaded.permissionLevelFor("vps-139-180-208-79")).toBe(1);
    expect(readFileSync(statePath, "utf8")).toContain('"hostPermissionLevels"');
    expect(readFileSync(statePath, "utf8")).not.toMatch(/hostSafetyProfiles|hostPermissionProfiles/);
    expect(readFileSync(statePath, "utf8")).not.toMatch(/password|secret|identityFile/i);
  });
});

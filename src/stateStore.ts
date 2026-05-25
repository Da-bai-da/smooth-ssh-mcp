import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { PermissionLevel } from "./types.js";

export type HostUseReason = "manual" | "probe" | "exec" | "pty" | "upload" | "download" | "forward";

export type RecentHost = {
  hostId: string;
  lastUsedAt: string;
  useCount: number;
  reason: HostUseReason;
};

export type SmoothSshState = {
  selectedHostId?: string;
  recentHosts: RecentHost[];
  hostPermissionLevels: Record<string, PermissionLevel>;
};

export class StateStore {
  private state: SmoothSshState;

  constructor(private readonly path?: string) {
    this.state = this.load();
  }

  getState(): SmoothSshState {
    return {
      selectedHostId: this.state.selectedHostId,
      recentHosts: [...this.state.recentHosts],
      hostPermissionLevels: { ...this.state.hostPermissionLevels }
    };
  }

  selectHost(hostId: string, reason: HostUseReason = "manual"): SmoothSshState {
    this.state.selectedHostId = hostId;
    this.recordHostUse(hostId, reason);
    return this.getState();
  }

  recordHostUse(hostId: string, reason: HostUseReason): void {
    const now = new Date().toISOString();
    const existing = this.state.recentHosts.find((entry) => entry.hostId === hostId);
    const next: RecentHost = {
      hostId,
      lastUsedAt: now,
      useCount: (existing?.useCount ?? 0) + 1,
      reason
    };
    this.state.recentHosts = [next, ...this.state.recentHosts.filter((entry) => entry.hostId !== hostId)].slice(0, 20);
    this.save();
  }

  recentHosts(): RecentHost[] {
    return [...this.state.recentHosts];
  }

  setPermissionLevel(hostId: string, permissionLevel: PermissionLevel): SmoothSshState {
    this.state.hostPermissionLevels = {
      ...this.state.hostPermissionLevels,
      [hostId]: permissionLevel
    };
    this.save();
    return this.getState();
  }

  permissionLevelFor(hostId: string): PermissionLevel | undefined {
    return this.state.hostPermissionLevels[hostId];
  }

  private load(): SmoothSshState {
    if (!this.path || !existsSync(this.path)) return { recentHosts: [], hostPermissionLevels: {} };
    const parsed = JSON.parse(readFileSync(this.path, "utf8")) as Partial<SmoothSshState>;
    return {
      selectedHostId: typeof parsed.selectedHostId === "string" ? parsed.selectedHostId : undefined,
      recentHosts: Array.isArray(parsed.recentHosts)
        ? parsed.recentHosts
            .filter((entry): entry is RecentHost => Boolean(entry) && typeof entry.hostId === "string")
            .map((entry) => ({
              hostId: entry.hostId,
              lastUsedAt: typeof entry.lastUsedAt === "string" ? entry.lastUsedAt : new Date(0).toISOString(),
              useCount: typeof entry.useCount === "number" ? entry.useCount : 1,
              reason: isReason(entry.reason) ? entry.reason : "manual"
            }))
        : [],
      hostPermissionLevels: normalizePermissionLevels(parsed.hostPermissionLevels)
    };
  }

  private save(): void {
    if (!this.path) return;
    const resolved = resolve(this.path);
    mkdirSync(dirname(resolved), { recursive: true, mode: 0o700 });
    writeFileSync(resolved, JSON.stringify(this.state, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
    chmodSync(resolved, 0o600);
  }
}

export function defaultStatePath(): string {
  return process.env.SMOOTH_SSH_MCP_STATE ?? join(process.env.HOME ?? process.cwd(), ".config", "smooth-ssh-mcp", "state.json");
}

function isReason(value: unknown): value is HostUseReason {
  return (
    value === "manual" ||
    value === "probe" ||
    value === "exec" ||
    value === "pty" ||
    value === "upload" ||
    value === "download" ||
    value === "forward"
  );
}

function normalizePermissionLevels(value: unknown): Record<string, PermissionLevel> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const levels: Record<string, PermissionLevel> = {};
  for (const [hostId, level] of Object.entries(value)) {
    if (level === 1 || level === 2 || level === 3) {
      levels[hostId] = level;
    }
  }
  return levels;
}

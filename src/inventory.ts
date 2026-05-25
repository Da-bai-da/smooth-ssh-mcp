import { existsSync, readFileSync } from "node:fs";
import { extname, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Environment, Host, HostPolicy, Inventory, PermissionLevel } from "./types.js";

const HOST_ID_PATTERN = /^[A-Za-z0-9._-]+$/;
const SAFE_SSH_TOKEN_PATTERN = /^[^\s\0\r\n;|&`$<>]+$/;

const DEFAULT_POLICY: HostPolicy = {
  allowExec: true,
  allowPty: true,
  allowUpload: false,
  allowDownload: false,
  allowForward: false,
  acceptNewHostKey: false,
  requireConfirmForSudo: true,
  requireConfirmForWrite: true,
  requireConfirmForProd: true,
  permissionLevel: 2,
  deniedCommandPatterns: [],
  maxCommandSeconds: 30,
  maxOutputBytes: 64 * 1024
};

const POLICY_KEYS = new Set<keyof HostPolicy>([
  "allowExec",
  "allowPty",
  "allowUpload",
  "allowDownload",
  "allowForward",
  "acceptNewHostKey",
  "requireConfirmForSudo",
  "requireConfirmForWrite",
  "requireConfirmForProd",
  "permissionLevel",
  "deniedCommandPatterns",
  "maxCommandSeconds",
  "maxOutputBytes"
]);

type RawInventory = {
  hosts?: Array<Record<string, unknown>>;
};

export function loadInventory(path: string): Inventory {
  const resolved = resolve(expandHome(path));
  if (!existsSync(resolved)) {
    throw new Error(`Inventory file does not exist: ${resolved}`);
  }

  const text = readFileSync(resolved, "utf8");
  const raw = parseInventory(text, resolved);
  const hosts = (raw.hosts ?? []).map(normalizeHost);
  const ids = new Set<string>();

  for (const host of hosts) {
    if (ids.has(host.id)) {
      throw new Error(`Duplicate host id in inventory: ${host.id}`);
    }
    ids.add(host.id);
  }

  return { hosts };
}

export function findHost(inventory: Inventory, hostId: string): Host {
  const host = inventory.hosts.find((candidate) => candidate.id === hostId);
  if (!host) {
    throw new Error(`Host not found in inventory: ${hostId}`);
  }
  return host;
}

export function defaultInventoryPath(): string {
  return process.env.SMOOTH_SSH_MCP_CONFIG ?? "~/.config/smooth-ssh-mcp/hosts.yaml";
}

function parseInventory(text: string, path: string): RawInventory {
  if (extname(path).toLowerCase() === ".json") {
    return JSON.parse(text) as RawInventory;
  }
  return parseYaml(text) as RawInventory;
}

function normalizeHost(raw: Record<string, unknown>): Host {
  if (raw.password !== undefined) {
    throw new Error("Inline password is not allowed. Use passwordEnv to reference an environment variable.");
  }

  const id = requiredString(raw.id, "host id");
  if (!HOST_ID_PATTERN.test(id)) {
    throw new Error(`Invalid host id "${id}". Use letters, numbers, dots, underscores, and dashes only.`);
  }
  if (id.startsWith("-")) {
    throw new Error(`Invalid host id "${id}": leading dash is not allowed`);
  }

  const hostname = optionalString(raw.hostname) ?? optionalString(raw.host);
  const sshConfigHost = optionalString(raw.sshConfigHost);
  if (!hostname && !sshConfigHost) {
    throw new Error(`Host ${id} must define hostname or sshConfigHost`);
  }
  if (hostname) validateSshToken(hostname, `hostname for ${id}`);
  if (sshConfigHost) validateSshToken(sshConfigHost, `sshConfigHost for ${id}`);

  const port = optionalNumber(raw.port);
  if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new Error(`Invalid port for ${id}: ${port}`);
  }

  const user = optionalString(raw.user);
  if (user) validateSshToken(user, `user for ${id}`);

  const identityFile = optionalString(raw.identityFile) ?? optionalString(raw.keyPath);
  const passwordEnv = optionalString(raw.passwordEnv);
  if (passwordEnv) validateEnvName(passwordEnv, `passwordEnv for ${id}`);
  if (identityFile && passwordEnv) {
    throw new Error(`Host ${id} must not define both identityFile and passwordEnv`);
  }
  const proxyJump = optionalString(raw.proxyJump);
  if (proxyJump) validateSshToken(proxyJump, `proxyJump for ${id}`);

  const environment = normalizeEnvironment(optionalString(raw.environment));
  const policy = mergePolicy(raw.policy);

  return {
    id,
    hostname: hostname ?? sshConfigHost ?? id,
    port,
    user,
    identityFile: identityFile ? expandHome(identityFile) : undefined,
    passwordEnv,
    sshConfigHost,
    proxyJump,
    defaultCwd: optionalString(raw.defaultCwd),
    tags: normalizeStringArray(raw.tags),
    environment,
    riskLevel: normalizeRisk(optionalString(raw.riskLevel), environment),
    capabilities: normalizeCapabilities(raw.capabilities),
    policy
  };
}

function mergePolicy(raw: unknown): HostPolicy {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ...DEFAULT_POLICY };
  }

  const value = raw as Record<string, unknown>;
  validatePolicyKeys(value);
  return {
    allowExec: optionalPolicyBoolean(value, "allowExec", DEFAULT_POLICY.allowExec),
    allowPty: optionalPolicyBoolean(value, "allowPty", DEFAULT_POLICY.allowPty),
    allowUpload: optionalPolicyBoolean(value, "allowUpload", DEFAULT_POLICY.allowUpload),
    allowDownload: optionalPolicyBoolean(value, "allowDownload", DEFAULT_POLICY.allowDownload),
    allowForward: optionalPolicyBoolean(value, "allowForward", DEFAULT_POLICY.allowForward),
    acceptNewHostKey: optionalPolicyBoolean(value, "acceptNewHostKey", DEFAULT_POLICY.acceptNewHostKey),
    requireConfirmForSudo: optionalPolicyBoolean(
      value,
      "requireConfirmForSudo",
      DEFAULT_POLICY.requireConfirmForSudo
    ),
    requireConfirmForWrite: optionalPolicyBoolean(
      value,
      "requireConfirmForWrite",
      DEFAULT_POLICY.requireConfirmForWrite
    ),
    requireConfirmForProd: optionalPolicyBoolean(
      value,
      "requireConfirmForProd",
      DEFAULT_POLICY.requireConfirmForProd
    ),
    permissionLevel: optionalPolicyPermissionLevel(value, DEFAULT_POLICY.permissionLevel),
    deniedCommandPatterns: optionalPolicyStringArray(
      value,
      "deniedCommandPatterns",
      DEFAULT_POLICY.deniedCommandPatterns
    ),
    maxCommandSeconds: optionalPolicyNumber(value, "maxCommandSeconds", DEFAULT_POLICY.maxCommandSeconds),
    maxOutputBytes: optionalPolicyNumber(value, "maxOutputBytes", DEFAULT_POLICY.maxOutputBytes)
  };
}

function validatePolicyKeys(raw: Record<string, unknown>): void {
  for (const key of Object.keys(raw)) {
    if (!POLICY_KEYS.has(key as keyof HostPolicy)) {
      throw new Error(`Invalid policy.${key}: unsupported policy key`);
    }
  }
}

function normalizeEnvironment(value: string | undefined): Environment {
  if (value === "dev" || value === "staging" || value === "prod") return value;
  return "unknown";
}

function normalizeRisk(value: string | undefined, environment: Environment): Host["riskLevel"] {
  if (value === "low" || value === "medium" || value === "high") return value;
  if (environment === "prod") return "high";
  if (environment === "unknown") return "medium";
  return "low";
}

function normalizeCapabilities(raw: unknown): Host["capabilities"] | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const input = raw as Record<string, unknown>;
  return {
    sudo: optionalBoolean(input.sudo),
    docker: optionalBoolean(input.docker),
    nginx: optionalBoolean(input.nginx),
    systemd: optionalBoolean(input.systemd),
    openwrt: optionalBoolean(input.openwrt)
  };
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map(String).filter(Boolean);
}

function requiredString(value: unknown, label: string): string {
  const result = optionalString(value);
  if (!result) throw new Error(`Missing ${label}`);
  return result;
}

function optionalString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  if (typeof value === "number") return value;
  if (typeof value === "string" && value.trim() !== "") return Number(value);
  return undefined;
}

function optionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function validateSshToken(value: string, label: string): void {
  if (value.startsWith("-")) {
    throw new Error(`Invalid ${label}: leading dash is not allowed`);
  }
  if (!SAFE_SSH_TOKEN_PATTERN.test(value)) {
    throw new Error(`Invalid ${label}: contains whitespace or shell metacharacters`);
  }
}

function validateEnvName(value: string, label: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new Error(`Invalid ${label}: expected an environment variable name`);
  }
}

function optionalPolicyBoolean(raw: Record<string, unknown>, key: keyof HostPolicy, fallback: boolean): boolean {
  const value = raw[key];
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new Error(`Invalid policy.${key}: expected boolean`);
  return value;
}

function optionalPolicyNumber(raw: Record<string, unknown>, key: keyof HostPolicy, fallback: number): number {
  const value = raw[key];
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid policy.${key}: expected positive number`);
  }
  return value;
}

function optionalPolicyStringArray(raw: Record<string, unknown>, key: keyof HostPolicy, fallback: string[]): string[] {
  const value = raw[key];
  if (value === undefined) return fallback;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`Invalid policy.${key}: expected string array`);
  }
  return value;
}

function optionalPolicyPermissionLevel(raw: Record<string, unknown>, fallback: PermissionLevel): PermissionLevel {
  const value = raw.permissionLevel;
  if (value === 1 || value === 2 || value === 3) return value;
  if (value !== undefined) {
    throw new Error("Invalid policy.permissionLevel: expected 1, 2, or 3");
  }
  return fallback;
}

function expandHome(path: string): string {
  if (path === "~") return process.env.HOME ?? path;
  if (path.startsWith("~/")) return `${process.env.HOME ?? "~"}${path.slice(1)}`;
  return path;
}

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, extname, resolve } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { defaultInventoryPath, loadInventory, normalizeHostRecord } from "./inventory.js";
import type { Environment, Host, HostPolicy, Inventory } from "./types.js";

export type HostAddInput = {
  id: string;
  hostname?: string;
  sshConfigHost?: string;
  port?: number;
  user?: string;
  identityFile?: string;
  passwordEnv?: string;
  password?: string;
  proxyJump?: string;
  defaultCwd?: string;
  tags?: string[];
  environment?: Environment;
  capabilities?: Host["capabilities"];
  policy?: Partial<HostPolicy>;
};

export type PreparedHostAdd = {
  host: Host;
  rawHost: Record<string, unknown>;
  password?: string;
  passwordEnv?: string;
  configPath: string;
  secretsPath?: string;
  command: string;
};

export type HostAddResult = {
  hostId: string;
  added: true;
  configPath: string;
  secretsPath?: string;
  hasIdentityFile: boolean;
  hasPasswordEnv: boolean;
  host: Omit<Host, "identityFile" | "passwordEnv"> & { hasIdentityFile: boolean; hasPasswordEnv: boolean };
};

export type HostUpdateInput = Partial<HostAddInput> & {
  hostId: string;
};

export type PreparedHostUpdate = {
  host: Host;
  rawHost: Record<string, unknown>;
  password?: string;
  passwordEnv?: string;
  configPath: string;
  secretsPath?: string;
  command: string;
};

export type HostUpdateResult = {
  hostId: string;
  updated: true;
  configPath: string;
  secretsPath?: string;
  hasIdentityFile: boolean;
  hasPasswordEnv: boolean;
  host: Omit<Host, "identityFile" | "passwordEnv"> & { hasIdentityFile: boolean; hasPasswordEnv: boolean };
};

export type HostRemoveInput = {
  hostId: string;
  removeSecret?: boolean;
};

export type PreparedHostRemove = {
  host: Host;
  passwordEnv?: string;
  configPath: string;
  secretsPath?: string;
  command: string;
};

export type HostRemoveResult = {
  hostId: string;
  removed: true;
  configPath: string;
  secretsPath?: string;
  removedPasswordEnv?: string;
};

export type SecretSetInput = {
  key: string;
  value: string;
};

export type PreparedSecretSet = {
  host: Host;
  key: string;
  value: string;
  secretsPath: string;
  command: string;
};

export type SecretSetResult = {
  key: string;
  updated: true;
  secretsPath: string;
};

type InventoryConfigStoreOptions = {
  configPath?: string;
  secretsPath?: string;
  env?: NodeJS.ProcessEnv;
};

type RawInventory = {
  hosts?: Array<Record<string, unknown>>;
};

export class InventoryConfigStore {
  private readonly configPath: string;
  private readonly secretsPath?: string;
  private readonly env: NodeJS.ProcessEnv;

  constructor(options: InventoryConfigStoreOptions = {}) {
    this.env = options.env ?? process.env;
    this.configPath = resolve(expandHome(options.configPath ?? defaultInventoryPath(), this.env));
    this.secretsPath = options.secretsPath ? resolve(expandHome(options.secretsPath, this.env)) : defaultSecretsPath(this.env);
  }

  prepareHostAdd(input: HostAddInput): PreparedHostAdd {
    validateHostAddInput(input);
    const rawInventory = this.readRawInventory();
    const rawHosts = rawInventory.hosts ?? [];
    if (rawHosts.some((host) => host.id === input.id)) {
      throw new Error(`Host already exists in inventory: ${input.id}`);
    }

    const passwordEnv = input.password !== undefined ? input.passwordEnv ?? passwordEnvNameForHost(input.id) : input.passwordEnv;
    const rawHost = compactObject({
      id: input.id,
      hostname: input.hostname,
      sshConfigHost: input.sshConfigHost,
      port: input.port,
      user: input.user,
      identityFile: input.identityFile,
      passwordEnv,
      proxyJump: input.proxyJump,
      defaultCwd: input.defaultCwd,
      tags: input.tags,
      environment: input.environment,
      capabilities: compactObject(input.capabilities),
      policy: compactObject(input.policy)
    }) as Record<string, unknown>;
    const host = normalizeHostRecord(rawHost);
    return {
      host,
      rawHost,
      password: input.password,
      passwordEnv,
      configPath: this.configPath,
      secretsPath: input.password !== undefined ? this.secretsPath : undefined,
      command: hostAddCommand(host, passwordEnv, input.password !== undefined)
    };
  }

  addHost(input: HostAddInput): HostAddResult {
    const prepared = this.prepareHostAdd(input);
    const rawInventory = this.readRawInventory();
    const hosts = rawInventory.hosts ?? [];
    rawInventory.hosts = [...hosts, prepared.rawHost];
    this.writeRawInventory(rawInventory);
    if (prepared.password !== undefined) {
      if (!prepared.passwordEnv || !prepared.secretsPath) throw new Error("passwordEnv and secretsPath are required when password is provided");
      upsertEnvSecret(prepared.secretsPath, prepared.passwordEnv, prepared.password);
    }
    const inventory = loadInventory(this.configPath);
    const addedHost = inventory.hosts.find((host) => host.id === prepared.host.id);
    if (!addedHost) throw new Error(`Host was not written to inventory: ${prepared.host.id}`);
    const host = publicHost(addedHost);
    return {
      hostId: addedHost.id,
      added: true,
      configPath: this.configPath,
      secretsPath: prepared.password !== undefined ? prepared.secretsPath : undefined,
      hasIdentityFile: host.hasIdentityFile,
      hasPasswordEnv: host.hasPasswordEnv,
      host
    };
  }

  prepareHostUpdate(input: HostUpdateInput): PreparedHostUpdate {
    validateHostAddInput(input);
    const rawInventory = this.readRawInventory();
    const hosts = rawInventory.hosts ?? [];
    const index = hostIndex(hosts, input.hostId);
    const current = hosts[index];
    const existing = normalizeHostRecord(current);
    const passwordEnv = input.password !== undefined ? input.passwordEnv ?? existing.passwordEnv ?? passwordEnvNameForHost(input.hostId) : input.passwordEnv;
    const rawHost = mergeHostUpdate(current, input, passwordEnv);
    const host = normalizeHostRecord(rawHost);
    return {
      host,
      rawHost,
      password: input.password,
      passwordEnv,
      configPath: this.configPath,
      secretsPath: input.password !== undefined ? this.secretsPath : undefined,
      command: hostUpdateCommand(existing, host, passwordEnv, input.password !== undefined)
    };
  }

  updateHost(input: HostUpdateInput): HostUpdateResult {
    const prepared = this.prepareHostUpdate(input);
    const rawInventory = this.readRawInventory();
    const hosts = rawInventory.hosts ?? [];
    hosts[hostIndex(hosts, input.hostId)] = prepared.rawHost;
    rawInventory.hosts = hosts;
    this.writeRawInventory(rawInventory);
    if (prepared.password !== undefined) {
      if (!prepared.passwordEnv || !prepared.secretsPath) throw new Error("passwordEnv and secretsPath are required when password is provided");
      upsertEnvSecret(prepared.secretsPath, prepared.passwordEnv, prepared.password);
    }
    const inventory = loadInventory(this.configPath);
    const updatedHost = inventory.hosts.find((host) => host.id === input.hostId);
    if (!updatedHost) throw new Error(`Host was not written to inventory: ${input.hostId}`);
    const host = publicHost(updatedHost);
    return {
      hostId: updatedHost.id,
      updated: true,
      configPath: this.configPath,
      secretsPath: prepared.password !== undefined ? prepared.secretsPath : undefined,
      hasIdentityFile: host.hasIdentityFile,
      hasPasswordEnv: host.hasPasswordEnv,
      host
    };
  }

  prepareHostRemove(input: HostRemoveInput): PreparedHostRemove {
    const rawInventory = this.readRawInventory();
    const hosts = rawInventory.hosts ?? [];
    const host = normalizeHostRecord(hosts[hostIndex(hosts, input.hostId)]);
    return {
      host,
      passwordEnv: host.passwordEnv,
      configPath: this.configPath,
      secretsPath: input.removeSecret ? this.secretsPath : undefined,
      command: `host_remove ${host.id}${input.removeSecret ? " remove-secret" : ""}`
    };
  }

  removeHost(input: HostRemoveInput): HostRemoveResult {
    const prepared = this.prepareHostRemove(input);
    const rawInventory = this.readRawInventory();
    const hosts = rawInventory.hosts ?? [];
    hosts.splice(hostIndex(hosts, input.hostId), 1);
    rawInventory.hosts = hosts;
    this.writeRawInventory(rawInventory);
    if (input.removeSecret && prepared.passwordEnv && prepared.secretsPath) {
      deleteEnvSecret(prepared.secretsPath, prepared.passwordEnv);
    }
    return {
      hostId: prepared.host.id,
      removed: true,
      configPath: this.configPath,
      secretsPath: input.removeSecret ? prepared.secretsPath : undefined,
      removedPasswordEnv: input.removeSecret ? prepared.passwordEnv : undefined
    };
  }

  prepareSecretSet(input: SecretSetInput): PreparedSecretSet {
    validateEnvName(input.key, "secret key");
    validateSecretValue(input.value);
    if (!this.secretsPath) throw new Error("secretsPath is required");
    return {
      host: localConfigHost(),
      key: input.key,
      value: input.value,
      secretsPath: this.secretsPath,
      command: `secret_set ${input.key}`
    };
  }

  setSecret(input: SecretSetInput): SecretSetResult {
    const prepared = this.prepareSecretSet(input);
    upsertEnvSecret(prepared.secretsPath, prepared.key, prepared.value);
    return {
      key: prepared.key,
      updated: true,
      secretsPath: prepared.secretsPath
    };
  }

  loadInventory(): Inventory {
    return loadInventory(this.configPath);
  }

  private readRawInventory(): RawInventory {
    if (!existsSync(this.configPath)) return { hosts: [] };
    const text = readFileSync(this.configPath, "utf8");
    if (!text.trim()) return { hosts: [] };
    const raw = extname(this.configPath).toLowerCase() === ".json" ? (JSON.parse(text) as RawInventory) : (parseYaml(text) as RawInventory);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Inventory root must be an object");
    if (raw.hosts !== undefined && !Array.isArray(raw.hosts)) throw new Error("Inventory hosts must be an array");
    return raw;
  }

  private writeRawInventory(raw: RawInventory): void {
    mkdirSync(dirname(this.configPath), { recursive: true, mode: 0o700 });
    const text = extname(this.configPath).toLowerCase() === ".json" ? `${JSON.stringify(raw, null, 2)}\n` : stringifyYaml(raw);
    writeFileSync(this.configPath, text, { encoding: "utf8", mode: 0o600 });
    chmodSync(this.configPath, 0o600);
  }
}

export function publicHost(host: Host): Omit<Host, "identityFile" | "passwordEnv"> & { hasIdentityFile: boolean; hasPasswordEnv: boolean } {
  const { identityFile, passwordEnv, ...publicFields } = host;
  return {
    ...publicFields,
    hasIdentityFile: Boolean(identityFile),
    hasPasswordEnv: Boolean(passwordEnv)
  };
}

function validateHostAddInput(input: Pick<HostAddInput, "password" | "identityFile">): void {
  if (input.password !== undefined && input.password.length === 0) throw new Error("password must not be empty");
  if (input.password !== undefined && input.identityFile) throw new Error("Host must not define both identityFile and password");
  if (input.password !== undefined && /[\0\r\n]/.test(input.password)) throw new Error("password must not contain newlines or null bytes");
}

function validateEnvName(value: string, label: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new Error(`Invalid ${label}: expected an environment variable name`);
  }
}

function validateSecretValue(value: string): void {
  if (value.length === 0) throw new Error("secret value must not be empty");
  if (/[\0\r\n]/.test(value)) throw new Error("secret value must not contain newlines or null bytes");
}

function hostIndex(hosts: Array<Record<string, unknown>>, hostId: string): number {
  const index = hosts.findIndex((host) => host.id === hostId);
  if (index < 0) throw new Error(`Host not found in inventory: ${hostId}`);
  return index;
}

function mergeHostUpdate(current: Record<string, unknown>, input: HostUpdateInput, passwordEnv: string | undefined): Record<string, unknown> {
  const next: Record<string, unknown> = { ...current };
  setIfDefined(next, "hostname", input.hostname);
  setIfDefined(next, "sshConfigHost", input.sshConfigHost);
  setIfDefined(next, "port", input.port);
  setIfDefined(next, "user", input.user);
  setIfDefined(next, "proxyJump", input.proxyJump);
  setIfDefined(next, "defaultCwd", input.defaultCwd);
  setIfDefined(next, "tags", input.tags);
  setIfDefined(next, "environment", input.environment);
  if (input.capabilities !== undefined) next.capabilities = compactObject({ ...objectRecord(next.capabilities), ...input.capabilities });
  if (input.policy !== undefined) next.policy = compactObject({ ...objectRecord(next.policy), ...input.policy });
  if (input.identityFile !== undefined) {
    next.identityFile = input.identityFile;
    delete next.passwordEnv;
  }
  if (passwordEnv !== undefined) {
    next.passwordEnv = passwordEnv;
    delete next.identityFile;
  }
  return next;
}

function setIfDefined(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value !== undefined) target[key] = value;
}

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function hostUpdateCommand(previous: Host, next: Host, passwordEnv: string | undefined, writesPassword: boolean): string {
  const effectivePasswordEnv = passwordEnv ?? next.passwordEnv;
  const auth = next.identityFile ? "identityFile" : effectivePasswordEnv ? `passwordEnv=${effectivePasswordEnv}` : "agent-or-ssh-config";
  return `host_update ${previous.id} ${next.hostname}:${next.port ?? 22} ${auth}${writesPassword ? " with-secret" : ""}`;
}

function localConfigHost(): Host {
  return {
    id: "local-config",
    hostname: "local-config",
    tags: [],
    environment: "unknown",
    riskLevel: "medium",
    policy: {
      allowExec: false,
      allowPty: false,
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
    }
  };
}

function compactObject<T extends Record<string, unknown> | undefined>(value: T): T | undefined {
  if (!value) return undefined;
  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (child !== undefined) output[key] = child;
  }
  return Object.keys(output).length > 0 ? (output as T) : undefined;
}

function passwordEnvNameForHost(hostId: string): string {
  const suffix = hostId.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  return `SMOOTH_SSH_PASSWORD_${suffix || "HOST"}`;
}

function hostAddCommand(host: Host, passwordEnv: string | undefined, writesPassword: boolean): string {
  const auth = host.identityFile ? "identityFile" : passwordEnv ? `passwordEnv=${passwordEnv}` : "agent-or-ssh-config";
  return `host_add ${host.id} ${host.hostname}:${host.port ?? 22} ${auth}${writesPassword ? " with-secret" : ""}`;
}

function upsertEnvSecret(path: string, key: string, value: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const lines = existsSync(path) ? readFileSync(path, "utf8").split(/\n/) : [];
  const assignment = `${key}=${value}`;
  let updated = false;
  const output = lines.map((line) => {
    if (envLineKey(line) !== key) return line;
    updated = true;
    return assignment;
  });
  if (!updated) {
    if (output.length > 0 && output[output.length - 1] !== "") output.push("");
    output.push(assignment);
  }
  const text = output.join("\n").replace(/\n*$/, "\n");
  writeFileSync(path, text, { encoding: "utf8", mode: 0o600 });
  chmodSync(path, 0o600);
}

function deleteEnvSecret(path: string, key: string): void {
  if (!existsSync(path)) return;
  const lines = readFileSync(path, "utf8").split(/\n/);
  const output = lines.filter((line) => envLineKey(line) !== key);
  const text = output.join("\n").replace(/\n*$/, "\n");
  writeFileSync(path, text, { encoding: "utf8", mode: 0o600 });
  chmodSync(path, 0o600);
}

function envLineKey(line: string): string | undefined {
  const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=/.exec(line);
  return match?.[1];
}

function defaultSecretsPath(env: NodeJS.ProcessEnv): string {
  return resolve(expandHome(env.SMOOTH_SSH_MCP_SECRETS ?? "~/.config/smooth-ssh-mcp/secrets.env", env));
}

function expandHome(path: string, env: NodeJS.ProcessEnv): string {
  if (path === "~") return env.HOME ?? homedir();
  if (path.startsWith("~/")) return `${env.HOME ?? homedir()}${path.slice(1)}`;
  return path;
}

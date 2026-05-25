import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { defaultInventoryPath } from "./inventory.js";

export type InitActionStatus = "created" | "exists";

export type InitAction = {
  id: string;
  label: string;
  path: string;
  status: InitActionStatus;
};

export type InitReport = {
  ok: boolean;
  actions: InitAction[];
  nextSteps: string[];
};

type InitOptions = {
  configPath?: string;
  secretsPath?: string;
  force?: boolean;
  env?: NodeJS.ProcessEnv;
};

const HOSTS_TEMPLATE = `hosts:
  - id: example-host
    hostname: 192.0.2.10
    user: ubuntu
    port: 22
    identityFile: ~/.ssh/id_ed25519
    environment: dev
    tags: [example]
    capabilities:
      sudo: true
      systemd: true
    policy:
      allowExec: true
      allowPty: true
      allowUpload: false
      allowDownload: false
      allowForward: false
      acceptNewHostKey: false
      permissionLevel: 2
      maxCommandSeconds: 30
      maxOutputBytes: 65536
`;

const SECRETS_TEMPLATE = `# Optional password-based host secrets. Prefer SSH keys when possible.
# Example inventory value: passwordEnv: SMOOTH_SSH_PASSWORD_EXAMPLE_HOST
SMOOTH_SSH_PASSWORD_EXAMPLE_HOST=change-me
`;

export function runInit(options: InitOptions = {}): InitReport {
  const env = options.env ?? process.env;
  const configPath = expandHome(options.configPath ?? defaultInventoryPath(), env);
  const secretsPath = expandHome(options.secretsPath ?? env.SMOOTH_SSH_MCP_SECRETS ?? "~/.config/smooth-ssh-mcp/secrets.env", env);
  const configDir = dirname(configPath);
  const actions: InitAction[] = [];

  if (existsSync(configDir)) {
    actions.push({ id: "config-dir", label: "Config directory", path: configDir, status: "exists" });
  } else {
    mkdirSync(configDir, { recursive: true, mode: 0o700 });
    actions.push({ id: "config-dir", label: "Config directory", path: configDir, status: "created" });
  }

  actions.push(writeTemplate("hosts", "Hosts inventory", configPath, HOSTS_TEMPLATE, options.force));
  actions.push(writeTemplate("secrets", "Secrets file", secretsPath, SECRETS_TEMPLATE, options.force));

  return {
    ok: true,
    actions,
    nextSteps: [
      `Edit ${configPath} with your real hosts.`,
      `Run: smooth-ssh-mcp doctor --config ${configPath} --secrets ${secretsPath}`,
      "Add smooth-ssh-mcp to your MCP client configuration."
    ]
  };
}

export function formatInitReport(report: InitReport): string {
  const lines = [
    "smooth-ssh-mcp init: ok",
    ...report.actions.map((action) => `[${action.status}] ${action.label}: ${action.path}`),
    "next steps:",
    ...report.nextSteps.map((step) => `- ${step}`)
  ];
  return lines.join("\n");
}

function writeTemplate(id: string, label: string, path: string, text: string, force = false): InitAction {
  if (existsSync(path) && !force) {
    return { id, label, path, status: "exists" };
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, text, { encoding: "utf8", mode: 0o600 });
  chmodSync(path, 0o600);
  return { id, label, path, status: "created" };
}

function expandHome(path: string, env: NodeJS.ProcessEnv): string {
  if (path === "~") return env.HOME ?? path;
  if (path.startsWith("~/")) return `${env.HOME ?? ""}${path.slice(1)}`;
  return path;
}

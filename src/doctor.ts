import { existsSync, statSync } from "node:fs";
import { delimiter } from "node:path";
import { env as processEnv, version as processVersion } from "node:process";
import { defaultInventoryPath, loadInventory } from "./inventory.js";

export type DoctorStatus = "ok" | "warning" | "error";

export type DoctorCheck = {
  id: string;
  label: string;
  status: DoctorStatus;
  message: string;
  fix?: string;
};

export type DoctorReport = {
  ok: boolean;
  summary: {
    ok: number;
    warnings: number;
    errors: number;
  };
  checks: DoctorCheck[];
};

type DoctorOptions = {
  configPath?: string;
  secretsPath?: string;
  nodeVersion?: string;
  commandExists?: (name: string) => boolean;
  env?: NodeJS.ProcessEnv;
};

export function runDoctor(options: DoctorOptions = {}): DoctorReport {
  const env = options.env ?? processEnv;
  const configPath = expandHome(options.configPath ?? defaultInventoryPath(), env);
  const secretsPath = expandHome(options.secretsPath ?? env.SMOOTH_SSH_MCP_SECRETS ?? "~/.config/smooth-ssh-mcp/secrets.env", env);
  const commandExists = options.commandExists ?? ((name) => commandExistsOnPath(name, env));
  const checks: DoctorCheck[] = [
    checkNodeVersion(options.nodeVersion ?? processVersion),
    checkCommand("ssh", commandExists, "Install OpenSSH client so smooth-ssh can connect to remote hosts."),
    checkCommand("scp", commandExists, "Install OpenSSH scp so file transfer tools can work."),
    checkCommand("sshpass", commandExists, "Install sshpass only if you use passwordEnv hosts; key-based hosts do not need it.", true),
    checkInventory(configPath),
    checkFilePermissions("inventory-permissions", "Inventory permissions", configPath, "chmod 600 " + configPath, false),
    checkSecrets(secretsPath),
    checkFilePermissions("secrets-permissions", "Secrets permissions", secretsPath, "chmod 600 " + secretsPath, true)
  ];
  const summary = {
    ok: checks.filter((check) => check.status === "ok").length,
    warnings: checks.filter((check) => check.status === "warning").length,
    errors: checks.filter((check) => check.status === "error").length
  };
  return {
    ok: summary.errors === 0,
    summary,
    checks
  };
}

export function formatDoctorReport(report: DoctorReport): string {
  const icon = (status: DoctorStatus) => (status === "ok" ? "OK" : status === "warning" ? "WARN" : "ERROR");
  const lines = [
    `smooth-ssh-mcp doctor: ${report.ok ? "ok" : "issues found"}`,
    `summary: ${report.summary.ok} ok, ${report.summary.warnings} warnings, ${report.summary.errors} errors`,
    ...report.checks.map((check) => {
      const fix = check.fix ? ` fix: ${check.fix}` : "";
      return `[${icon(check.status)}] ${check.label}: ${check.message}${fix}`;
    })
  ];
  return lines.join("\n");
}

function checkNodeVersion(nodeVersion: string): DoctorCheck {
  const major = Number(nodeVersion.replace(/^v/, "").split(".")[0]);
  if (Number.isFinite(major) && major >= 20) {
    return {
      id: "node",
      label: "Node.js",
      status: "ok",
      message: nodeVersion
    };
  }
  return {
    id: "node",
    label: "Node.js",
    status: "error",
    message: `${nodeVersion} is not supported`,
    fix: "Install Node.js >=20"
  };
}

function checkCommand(name: string, commandExists: (name: string) => boolean, fix: string, optional = false): DoctorCheck {
  if (commandExists(name)) {
    return {
      id: name,
      label: name,
      status: "ok",
      message: "found on PATH"
    };
  }
  return {
    id: name,
    label: name,
    status: optional ? "warning" : "error",
    message: "not found on PATH",
    fix
  };
}

function checkInventory(path: string): DoctorCheck {
  if (!existsSync(path)) {
    return {
      id: "inventory",
      label: "Inventory",
      status: "error",
      message: `not found at ${path}`,
      fix: `Create ${path} or pass --config /path/to/hosts.yaml`
    };
  }
  try {
    const inventory = loadInventory(path);
    return {
      id: "inventory",
      label: "Inventory",
      status: "ok",
      message: `${inventory.hosts.length} hosts loaded from ${path}`
    };
  } catch (error) {
    return {
      id: "inventory",
      label: "Inventory",
      status: "error",
      message: error instanceof Error ? error.message : String(error)
    };
  }
}

function checkSecrets(path: string): DoctorCheck {
  if (!existsSync(path)) {
    return {
      id: "secrets",
      label: "Secrets file",
      status: "warning",
      message: `not found at ${path}; this is fine for key-based hosts`
    };
  }
  return {
    id: "secrets",
    label: "Secrets file",
    status: "ok",
    message: `found at ${path}`
  };
}

function checkFilePermissions(id: string, label: string, path: string, fix: string, optional: boolean): DoctorCheck {
  if (!existsSync(path)) {
    return {
      id,
      label,
      status: optional ? "warning" : "error",
      message: `cannot check permissions; file does not exist`,
      fix: optional ? undefined : fix
    };
  }
  const mode = statSync(path).mode & 0o777;
  if (mode === 0o600 || mode === 0o400) {
    return {
      id,
      label,
      status: "ok",
      message: mode.toString(8)
    };
  }
  return {
    id,
    label,
    status: "error",
    message: `mode ${mode.toString(8)} is too permissive`,
    fix
  };
}

function commandExistsOnPath(name: string, env: NodeJS.ProcessEnv): boolean {
  const path = env.PATH ?? "";
  const extensions = process.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""];
  for (const dir of path.split(delimiter)) {
    if (!dir) continue;
    for (const extension of extensions) {
      if (existsSync(`${dir}/${name}${extension}`)) return true;
    }
  }
  return false;
}

function expandHome(path: string, env: NodeJS.ProcessEnv): string {
  if (path === "~") return env.HOME ?? path;
  if (path.startsWith("~/")) return `${env.HOME ?? ""}${path.slice(1)}`;
  return path;
}

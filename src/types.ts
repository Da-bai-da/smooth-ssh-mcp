export type Environment = "dev" | "staging" | "prod" | "unknown";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type Operation = "exec" | "pty" | "pty-input" | "upload" | "download" | "forward" | "permission";
export type PermissionLevel = 1 | 2 | 3;
export type CommandMode = "shell" | "argv";
export type CommandAccess = "read" | "write" | "restart" | "firewall" | "destructive" | "unknown";

export type HostPolicy = {
  allowExec: boolean;
  allowPty: boolean;
  allowUpload: boolean;
  allowDownload: boolean;
  allowForward: boolean;
  acceptNewHostKey: boolean;
  requireConfirmForSudo: boolean;
  requireConfirmForWrite: boolean;
  requireConfirmForProd: boolean;
  permissionLevel: PermissionLevel;
  deniedCommandPatterns: string[];
  maxCommandSeconds: number;
  maxOutputBytes: number;
};

export type Host = {
  id: string;
  hostname: string;
  port?: number;
  user?: string;
  identityFile?: string;
  passwordEnv?: string;
  sshConfigHost?: string;
  proxyJump?: string;
  defaultCwd?: string;
  tags: string[];
  environment: Environment;
  riskLevel: Exclude<RiskLevel, "critical">;
  capabilities?: {
    sudo?: boolean;
    docker?: boolean;
    nginx?: boolean;
    systemd?: boolean;
    openwrt?: boolean;
  };
  policy: HostPolicy;
};

export type Inventory = {
  hosts: Host[];
};

export type PolicyDecision = {
  allowed: boolean;
  confirmationRequired: boolean;
  risk: RiskLevel;
  reasons: string[];
};

export type ConfirmationRequired = {
  confirmationRequired: true;
  token: string;
  risk: RiskLevel;
  reason: string;
  hostId: string;
  operation: Operation;
  preview: {
    command?: string;
    stdinHash?: string;
    stdinBytes?: number;
    localPath?: string;
    remotePath?: string;
    ports?: string[];
  };
  expiresAt: string;
};

export type Redaction = {
  pattern: string;
  count: number;
};

export type RedactedText = {
  text: string;
  redactions: Redaction[];
  truncated: boolean;
  originalBytes: number;
};

export type ExecResult = {
  hostId: string;
  commandId: string;
  exitCode: number | null;
  signal?: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  truncated: boolean;
  redactions: Redaction[];
  diagnostic?: string;
  attempts?: number;
  argv?: string[];
};

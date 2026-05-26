import { createHash, randomUUID } from "node:crypto";
import type { CommandAccess, CommandMode, ConfirmationRequired, Host, Operation, PolicyDecision, RiskLevel } from "./types.js";

type PolicyInput = {
  host: Host;
  operation: Operation;
  command?: string;
  commandMode?: CommandMode;
  access?: CommandAccess;
  stdin?: string;
  stdinHash?: string;
  localPath?: string;
  remotePath?: string;
  ports?: string[];
};

type IssueConfirmationInput = PolicyInput & {
  reasons: string[];
};

type StoredConfirmation = {
  fingerprint: string;
  expiresAt: number;
};

const confirmations = new Map<string, StoredConfirmation>();

const BUILT_IN_CRITICAL_PATTERNS = [
  "\\brm\\s+-r?f\\s+(?:--no-preserve-root\\s+)?/\\s*(?:$|[;&|])",
  "\\bmkfs(?:\\.|\\s)",
  "\\bdd\\s+[^\\n]*(?:of=|if=)",
  "\\b(shutdown|reboot|halt|poweroff)\\b",
  "\\bopkg\\s+remove\\b"
];

const WRITE_HINT_PATTERNS = [
  "\\brm\\b",
  "\\brmdir\\b",
  "\\btee\\b",
  "\\bsed\\s+-i\\b",
  "\\bmv\\b",
  "\\bcp\\b",
  "\\bchmod\\b",
  "\\bchown\\b",
  "\\bfind\\b[^\\n]*\\s-delete\\b",
  "\\bsystemctl\\s+(?:restart|reload|stop|disable|enable|daemon-reload)\\b",
  "\\bservice\\s+\\S+\\s+(?:restart|reload|stop)\\b",
  "\\bufw\\s+(?:allow|deny|delete|enable|disable|reload|reset|default|limit|route|insert|prepend)\\b",
  "\\biptables\\s+(?:-[AIDRPFNXZ]|--append|--insert|--delete|--replace|--flush|--policy|--new-chain|--delete-chain|--zero)\\b",
  "\\bnft\\s+(?:add|delete|destroy|flush|insert|replace|reset)\\b",
  "\\bdocker\\s+(?:rm|rmi|container\\s+rm|image\\s+rm|network\\s+rm|volume\\s+rm|image\\s+prune|builder\\s+prune|system\\s+prune)\\b",
  "\\bdocker\\s+compose\\s+(?:down|rm)\\b"
];

const COMPLEX_SHELL_PATTERNS = ["\\n", ";", "\\|", "&&", "\\|\\|", "`", "\\$\\(", "<<"];

const READ_ONLY_COMMAND_PATTERNS = [
  "^\\s*(?:ps|grep|egrep|fgrep|find|ls|cat|du|df|ss|pgrep|file|which|hostnamectl|uname|uptime|free|journalctl|crontab\\s+-l|loginctl\\s+show-user|nginx\\s+-t)\\b",
  "^\\s*systemctl\\s+(?:list-units|list-unit-files|cat|status|show|is-active|is-enabled|--failed)\\b",
  "^\\s*ufw\\s+(?:status|show)\\b",
  "^\\s*iptables\\s+(?:-L|-S|-n|-v|--list|--list-rules)\\b",
  "^\\s*nft\\s+(?:list|monitor)\\b",
  "^\\s*docker\\s+(?:ps|images|image\\s+ls|network\\s+ls|volume\\s+ls|volume\\s+inspect|system\\s+df|compose\\s+ls)\\b"
];

const EXECUTION_HINT_PATTERNS = [
  "\\|\\s*(?:sudo\\s+)?(?:sh|bash|ash|dash|python|python3|perl|ruby|node)\\b",
  "\\b(?:sh|bash|ash|dash|python|python3|perl|ruby|node)\\s+-c\\b",
  "\\bfind\\b[^\\n]*\\s-(?:exec|execdir|ok|okdir)\\b",
  "\\bxargs\\b",
  "\\bparallel\\b"
];

const SAFE_PIPE_STAGE_PATTERNS = [
  "^\\s*(?:head|tail)(?:\\s+-n\\s+\\d+)?\\s*$",
  "^\\s*sort(?:\\s+[-\\w]+)*\\s*$",
  "^\\s*uniq(?:\\s+[-\\w]+)*\\s*$",
  "^\\s*wc(?:\\s+[-\\w]+)*\\s*$",
  "^\\s*cut\\s+[-\\w\\s=,.:]+$",
  "^\\s*sed\\s+-n\\s+[^;|&`$]+$"
];

const SENSITIVE_REMOTE_PATH_PATTERNS = [
  "^/etc/shadow$",
  "(^|/)id_(rsa|ed25519|ecdsa)$",
  "(^|/)\\.ssh/",
  "(^|/)\\.env(\\.|$)?",
  "(^|/).+\\.pem$",
  "(^|/).+\\.key$"
];

const SENSITIVE_REMOTE_COMMAND_PATH_PATTERNS = [
  "(^|[\\s'\"`])\\/etc\\/shadow(?=$|[\\s'\";|&<>])",
  "(^|[\\s'\"`])(?:[^\\s'\";|&<>]*\\/)?id_(rsa|ed25519|ecdsa)(?=$|[\\s'\";|&<>])",
  "(^|[\\s'\"`])(?:[^\\s'\";|&<>]*\\/)?\\.ssh(?:\\/|(?=$|[\\s'\";|&<>]))",
  "(^|[\\s'\"`])(?:[^\\s'\";|&<>]*\\/)?\\.env(?:\\.[^\\s'\";|&<>]*)?(?=$|[\\s'\";|&<>])",
  "(^|[\\s'\"`])(?:[^\\s'\";|&<>]*\\/)?[^\\s'\";|&<>]+\\.(?:pem|key)(?=$|[\\s'\";|&<>])"
];

const SENSITIVE_LOCAL_DOWNLOAD_PATH_PATTERNS = [
  "(^|/)\\.ssh/",
  "(^|/)authorized_keys$",
  "(^|/)\\.bashrc$",
  "(^|/)\\.profile$",
  "(^|/)\\.zshrc$",
  "(^|/).+\\.pem$",
  "(^|/).+\\.key$"
];

export function evaluateOperationPolicy(input: PolicyInput): PolicyDecision {
  const reasons: string[] = [];
  const command = input.command ?? "";
  const commandMode = input.commandMode ?? "shell";
  const access = input.access ?? inferCommandAccess(commandMode, command);
  const stdin = input.stdin ?? "";
  const policyText = stdin ? `${command}\n${stdin}` : command;
  const permissionLevel = input.host.policy.permissionLevel;

  if (!operationAllowed(input.host, input.operation)) {
    return {
      allowed: false,
      confirmationRequired: false,
      risk: "critical",
      reasons: [`operation ${input.operation} is disabled by host policy`]
    };
  }

  const deniedPattern = [...BUILT_IN_CRITICAL_PATTERNS, ...input.host.policy.deniedCommandPatterns]
    .map((pattern) => new RegExp(pattern, "i"))
    .find((pattern) => pattern.test(policyText));
  if (deniedPattern) {
    return {
      allowed: false,
      confirmationRequired: false,
      risk: "critical",
      reasons: [`command matches denied pattern: ${deniedPattern.source}`]
    };
  }

  if (
    input.operation === "download" &&
    input.remotePath &&
    SENSITIVE_REMOTE_PATH_PATTERNS.some((pattern) => new RegExp(pattern, "i").test(input.remotePath ?? ""))
  ) {
    return {
      allowed: false,
      confirmationRequired: false,
      risk: "critical",
      reasons: ["remote path appears to contain secrets and is denied by default"]
    };
  }
  if (
    input.operation === "download" &&
    input.localPath &&
    SENSITIVE_LOCAL_DOWNLOAD_PATH_PATTERNS.some((pattern) => new RegExp(pattern, "i").test(input.localPath ?? ""))
  ) {
    return {
      allowed: false,
      confirmationRequired: false,
      risk: "critical",
      reasons: ["local download path targets sensitive SSH or shell configuration and is denied by default"]
    };
  }

  if (commandReferencesSensitiveRemotePath(input.operation, command)) {
    reasons.push("command references a sensitive remote path");
  }

  if (permissionLevel === 3 && !operationIsReadOnly(input.operation, commandMode, access, command)) {
    return {
      allowed: false,
      confirmationRequired: false,
      risk: "critical",
      reasons: [`operation ${input.operation} is denied by permission level 3`]
    };
  }

  if (permissionLevel !== 1) {
    if (
      input.host.environment === "prod" &&
      input.host.policy.requireConfirmForProd &&
      shouldConfirmForProd(input.operation, access)
    ) {
      reasons.push("host environment is prod");
    }
    if (
      operationUsesCommandPolicy(input.operation) &&
      commandMode === "argv" &&
      access === "unknown" &&
      (input.host.environment === "prod" || input.host.riskLevel === "high")
    ) {
      reasons.push("unknown argv command on high-risk host");
    }
    if (
      operationUsesCommandPolicy(input.operation) &&
      commandMode === "shell" &&
      input.host.riskLevel !== "low" &&
      COMPLEX_SHELL_PATTERNS.some((pattern) => new RegExp(pattern).test(command)) &&
      !commandLooksReadOnly(command)
    ) {
      reasons.push("command uses complex shell syntax");
    }
    if (input.operation === "exec" && stdin) {
      const stdinTargetRunsCode = /\b(?:sh|bash|ash|dash|python|perl|ruby|node)\b/i.test(command);
      const stdinLooksComplex = COMPLEX_SHELL_PATTERNS.some((pattern) => new RegExp(pattern).test(stdin));
      const stdinLooksLikeWrite = commandLooksLikeWrite(stdin);
      if (stdinTargetRunsCode || stdinLooksComplex || stdinLooksLikeWrite) {
        reasons.push("stdin may change remote execution semantics");
      }
    }
    if (operationUsesCommandPolicy(input.operation) && input.host.policy.requireConfirmForSudo && /\bsudo\b/i.test(command)) {
      reasons.push("command uses sudo");
    }
    if (operationUsesCommandPolicy(input.operation) && input.host.policy.requireConfirmForWrite && commandAccessMayWrite(access, command)) {
      reasons.push("command appears to modify remote state");
    }
    if (input.operation === "upload") {
      reasons.push("upload writes a local file to the remote host");
    }
    if (input.operation === "download") {
      reasons.push("download copies remote data to the local machine");
    }
    if (input.operation === "forward") {
      reasons.push("port forward exposes network access through this machine");
    }
  }

  if (reasons.length > 0) {
    return {
      allowed: false,
      confirmationRequired: true,
      risk: riskForReasons(input.host, reasons),
      reasons
    };
  }

  return {
    allowed: true,
    confirmationRequired: false,
    risk: input.host.riskLevel,
    reasons: []
  };
}

export function issueConfirmation(input: IssueConfirmationInput): ConfirmationRequired {
  cleanupExpiredConfirmations();
  const token = randomUUID();
  const expiresAt = Date.now() + 5 * 60 * 1000;
  confirmations.set(token, {
    fingerprint: operationFingerprint(input),
    expiresAt
  });

  return {
    confirmationRequired: true,
    token,
    risk: riskForReasons(input.host, input.reasons),
    reason: input.reasons.join("; "),
    hostId: input.host.id,
    operation: input.operation,
    preview: {
      command: input.command,
      stdinHash: input.stdinHash,
      stdinBytes: input.stdin ? Buffer.byteLength(input.stdin, "utf8") : undefined,
      localPath: input.localPath,
      remotePath: input.remotePath,
      ports: input.ports
    },
    expiresAt: new Date(expiresAt).toISOString()
  };
}

export function verifyConfirmation(token: string | undefined, input: PolicyInput): boolean {
  cleanupExpiredConfirmations();
  if (!token) return false;
  const stored = confirmations.get(token);
  if (!stored) return false;
  if (stored.expiresAt < Date.now()) {
    confirmations.delete(token);
    return false;
  }
  const ok = stored.fingerprint === operationFingerprint(input);
  if (ok) confirmations.delete(token);
  return ok;
}

function cleanupExpiredConfirmations(): void {
  const now = Date.now();
  for (const [token, confirmation] of confirmations) {
    if (confirmation.expiresAt < now) confirmations.delete(token);
  }
}

export function operationFingerprint(input: PolicyInput): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        hostId: input.host.id,
        environment: input.host.environment,
        operation: input.operation,
        commandMode: input.commandMode ?? "shell",
        access: input.access ?? "unknown",
        command: input.command ?? "",
        stdinHash: input.stdinHash ?? "",
        localPath: input.localPath ?? "",
        remotePath: input.remotePath ?? "",
        ports: input.ports ?? []
      })
    )
    .digest("hex");
}

function operationAllowed(host: Host, operation: Operation): boolean {
  if (operation === "exec") return host.policy.allowExec;
  if (operation === "pty") return host.policy.allowPty;
  if (operation === "pty-input") return host.policy.allowPty;
  if (operation === "upload") return host.policy.allowUpload;
  if (operation === "download") return host.policy.allowDownload;
  if (operation === "permission" || operation === "config") return true;
  return host.policy.allowForward;
}

function operationUsesCommandPolicy(operation: Operation): boolean {
  return operation === "exec" || operation === "pty-input";
}

function commandLooksLikeWrite(command: string): boolean {
  return (
    hasStateChangingRedirect(command) ||
    shellCommandHasFirewallMutation(command) ||
    WRITE_HINT_PATTERNS.some((pattern) => new RegExp(pattern, "i").test(command))
  );
}

function commandLooksReadOnly(command: string): boolean {
  if (commandLooksLikeWrite(command)) return false;
  if (EXECUTION_HINT_PATTERNS.some((pattern) => new RegExp(pattern, "i").test(command))) return false;
  if (/[;&`]|&&|\|\||\$\(|<</.test(command)) return false;
  const pipeline = splitUnquotedPipes(command);
  if (pipeline.length > 1) {
    return (
      READ_ONLY_COMMAND_PATTERNS.some((pattern) => new RegExp(pattern, "i").test(pipeline[0] ?? "")) &&
      pipeline.slice(1).every((stage) => SAFE_PIPE_STAGE_PATTERNS.some((pattern) => new RegExp(pattern, "i").test(stage)))
    );
  }
  return READ_ONLY_COMMAND_PATTERNS.some((pattern) => new RegExp(pattern, "i").test(command));
}

function commandAccessMayWrite(access: CommandAccess, command: string): boolean {
  if (access === "read") return false;
  if (access === "write" || access === "restart" || access === "firewall" || access === "destructive") return true;
  return commandLooksLikeWrite(command);
}

function shouldConfirmForProd(operation: Operation, access: CommandAccess): boolean {
  if (operation === "pty") return false;
  if (operation === "permission" || operation === "config") return false;
  if (operationUsesCommandPolicy(operation) && access === "read") return false;
  return true;
}

function operationIsReadOnly(operation: Operation, commandMode: CommandMode, access: CommandAccess, command: string): boolean {
  if (operation !== "exec") return false;
  if (access === "read") return true;
  if (access !== "unknown") return false;
  return commandMode === "shell" && commandLooksReadOnly(command);
}

function inferCommandAccess(commandMode: CommandMode, command: string): CommandAccess {
  if (commandMode !== "shell") return "unknown";
  if (commandLooksReadOnly(command)) return "read";
  if (commandLooksLikeWrite(command)) return "write";
  return "unknown";
}

function commandReferencesSensitiveRemotePath(operation: Operation, command: string): boolean {
  if (!operationUsesCommandPolicy(operation)) return false;
  return SENSITIVE_REMOTE_COMMAND_PATH_PATTERNS.some((pattern) => new RegExp(pattern, "i").test(command));
}

function hasStateChangingRedirect(command: string): boolean {
  const withoutBenignRedirects = command
    .replace(/\b[0-9]?>&[0-9]\b/g, " ")
    .replace(/\b[0-9]?>>?\s*\/dev\/null\b/g, " ");
  return /(^|[^<>])>>?\s*(?!&)[^\s]/.test(withoutBenignRedirects);
}

function shellCommandHasFirewallMutation(command: string): boolean {
  const segments = command.split(/[;&|]/);
  return segments.some((segment) => {
    const tokens = unwrapShellCommandTokens(tokenizeShellLike(segment));
    if (tokens[0] !== "ufw") return false;
    return !ufwArgsAreReadOnly(tokens.slice(1));
  });
}

function tokenizeShellLike(segment: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (const char of segment) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if ((char === "'" || char === '"') && !quote) {
      quote = char;
      continue;
    }
    if (char === quote) {
      quote = undefined;
      continue;
    }
    if (/\s/.test(char) && !quote) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }
  if (current) tokens.push(current);
  return tokens.map((token) => commandName(token));
}

function unwrapShellCommandTokens(tokens: string[]): string[] {
  let remaining = [...tokens];
  while (remaining.length > 0) {
    const head = remaining[0];
    if (head === "sudo") {
      remaining = remaining.slice(1);
      remaining = consumeWrapperOptions(remaining, new Set(["-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from", "-D", "--chdir"]));
      continue;
    }
    if (head === "env") {
      remaining = remaining.slice(1);
      remaining = consumeWrapperOptions(remaining, new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]));
      while (/^[A-Za-z_][A-Za-z0-9_]*=/.test(remaining[0] ?? "")) remaining = remaining.slice(1);
      continue;
    }
    if (head === "command") {
      remaining = remaining.slice(1);
      continue;
    }
    break;
  }
  return remaining;
}

function consumeWrapperOptions(tokens: string[], optionsWithValues: Set<string>): string[] {
  let remaining = [...tokens];
  while (remaining[0]?.startsWith("-")) {
    const option = remaining[0];
    remaining = remaining.slice(1);
    const optionName = option.includes("=") ? option.slice(0, option.indexOf("=")) : option;
    if (optionsWithValues.has(optionName) && !option.includes("=") && remaining.length > 0) {
      remaining = remaining.slice(1);
    }
  }
  return remaining;
}

function ufwArgsAreReadOnly(args: string[]): boolean {
  const action = args.find((arg) => !arg.startsWith("-"));
  return action === "status" || action === "show";
}

function commandName(value: string): string {
  return value.split("/").filter(Boolean).pop()?.toLowerCase() ?? value.toLowerCase();
}

function splitUnquotedPipes(command: string): string[] {
  const parts: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (const char of command) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      current += char;
      escaped = true;
      continue;
    }
    if ((char === "'" || char === '"') && !quote) {
      quote = char;
      current += char;
      continue;
    }
    if (char === quote) {
      quote = undefined;
      current += char;
      continue;
    }
    if (char === "|" && !quote) {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  parts.push(current.trim());
  return parts;
}

function riskForReasons(host: Host, reasons: string[]): RiskLevel {
  if (reasons.some((reason) => reason.includes("prod"))) return "high";
  if (host.riskLevel === "high") return "high";
  return "medium";
}

#!/usr/bin/env node
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { defaultInventoryPath, loadInventory } from "./inventory.js";
import { createMcpServer } from "./mcpServer.js";
import { formatDoctorReport, runDoctor } from "./doctor.js";
import { formatInitReport, runInit } from "./init.js";
import { JsonlAuditor } from "./audit.js";
import { SshOperations } from "./operations.js";
import type { Inventory } from "./types.js";

const VERSION = "0.1.0";

export function parseArgs(argv: string[]): { mode: "serve" | "doctor" | "init" | "help" | "version"; configPath: string; secretsPath?: string; json: boolean; force: boolean } {
  const mode = argv[0] === "--help" || argv[0] === "-h" ? "help" : argv[0] === "--version" || argv[0] === "-v" ? "version" : argv[0] === "doctor" ? "doctor" : argv[0] === "init" ? "init" : "serve";
  const args = mode === "serve" ? argv : argv.slice(1);
  const configIndex = args.findIndex((arg) => arg === "--config" || arg === "-c");
  if (configIndex >= 0) {
    const value = args[configIndex + 1];
    if (!value) throw new Error("--config requires a file path");
    return { mode, configPath: value, secretsPath: parseOptionalValue(args, "--secrets"), json: args.includes("--json"), force: args.includes("--force") };
  }
  return { mode, configPath: defaultInventoryPath(), secretsPath: parseOptionalValue(args, "--secrets"), json: args.includes("--json"), force: args.includes("--force") };
}

function parseOptionalValue(argv: string[], flag: string): string | undefined {
  const index = argv.findIndex((arg) => arg === flag);
  if (index < 0) return undefined;
  const value = argv[index + 1];
  if (!value) throw new Error(`${flag} requires a file path`);
  return value;
}


function formatHelp(): string {
  return [
    "smooth-ssh-mcp 0.1.0",
    "",
    "Usage:",
    "  smooth-ssh-mcp [--config <hosts.yaml>]",
    "  smooth-ssh-mcp init [--config <hosts.yaml>] [--secrets <secrets.env>] [--force] [--json]",
    "  smooth-ssh-mcp doctor [--config <hosts.yaml>] [--secrets <secrets.env>] [--json]",
    "",
    "Options:",
    "  -c, --config <path>  Host inventory path",
    "  --secrets <path>     Secrets env file path for init and doctor",
    "  --force              Regenerate init files even when they already exist",
    "  --json               Print JSON for init and doctor",
    "  -h, --help           Show this help",
    "  -v, --version        Show version"
  ].join("\n");
}

function loadInventoryForServer(configPath: string): Inventory {
  const expanded = configPath.startsWith("~/")
    ? `${process.env.HOME ?? ""}${configPath.slice(1)}`
    : configPath;
  if (!existsSync(expanded)) {
    console.error(
      `[smooth-ssh-mcp] Inventory not found at ${configPath}. Starting with no hosts. ` +
        "Create hosts.yaml or pass --config /path/to/hosts.yaml."
    );
    return { hosts: [] };
  }
  return loadInventory(configPath);
}

export async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.mode === "help") {
    console.log(formatHelp());
    process.exit(0);
  }
  if (args.mode === "version") {
    console.log(VERSION);
    process.exit(0);
  }
  if (args.mode === "doctor") {
    const report = runDoctor({ configPath: args.configPath, secretsPath: args.secretsPath });
    console.log(args.json ? JSON.stringify(report, null, 2) : formatDoctorReport(report));
    process.exit(report.ok ? 0 : 1);
  }
  if (args.mode === "init") {
    const report = runInit({ configPath: args.configPath, secretsPath: args.secretsPath, force: args.force });
    console.log(args.json ? JSON.stringify(report, null, 2) : formatInitReport(report));
    process.exit(report.ok ? 0 : 1);
  }
  const { configPath } = args;
  const inventory = loadInventoryForServer(configPath);
  const operations = new SshOperations({ inventory });
  installShutdownCleanup(operations);
  const server = createMcpServer(operations, { auditor: new JsonlAuditor() });
  process.stdin.resume();
  await server.connect(new StdioServerTransport());
  console.error(`[smooth-ssh-mcp] Running on stdio with ${inventory.hosts.length} configured hosts.`);
  await keepStdioServerAlive();
}

function installShutdownCleanup(operations: SshOperations): void {
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    operations.dispose();
  };

  process.once("beforeExit", cleanup);
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => {
      cleanup();
      process.exit(0);
    });
  }
}

function keepStdioServerAlive(): Promise<void> {
  setInterval(() => undefined, 60_000);
  return new Promise(() => undefined);
}

if (isDirectExecution()) {
  main().catch((error) => {
    console.error("[smooth-ssh-mcp] Fatal error:", error);
    process.exit(1);
  });
}

function isDirectExecution(): boolean {
  return process.argv[1] === fileURLToPath(import.meta.url);
}

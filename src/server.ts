#!/usr/bin/env node
import { existsSync } from "node:fs";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { defaultInventoryPath, loadInventory } from "./inventory.js";
import { createMcpServer } from "./mcpServer.js";
import { SshOperations } from "./operations.js";
import type { Inventory } from "./types.js";

function parseArgs(argv: string[]): { configPath: string } {
  const configIndex = argv.findIndex((arg) => arg === "--config" || arg === "-c");
  if (configIndex >= 0) {
    const value = argv[configIndex + 1];
    if (!value) throw new Error("--config requires a file path");
    return { configPath: value };
  }
  return { configPath: defaultInventoryPath() };
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

async function main(): Promise<void> {
  const { configPath } = parseArgs(process.argv.slice(2));
  const inventory = loadInventoryForServer(configPath);
  const operations = new SshOperations({ inventory });
  installShutdownCleanup(operations);
  const server = createMcpServer(operations);
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

main().catch((error) => {
  console.error("[smooth-ssh-mcp] Fatal error:", error);
  process.exit(1);
});

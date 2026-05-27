#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));

function fail(message) {
  throw new Error(message);
}

function readJson(path) {
  return JSON.parse(readFileSync(join(rootDir, path), "utf8"));
}

function requireFile(path) {
  const fullPath = join(rootDir, path);
  if (!existsSync(fullPath)) fail(`Missing required file: ${path}`);
  return fullPath;
}

function run(command, args, options = {}) {
  console.log(`\n> ${[command, ...args].join(" ")}`);
  return execFileSync(command, args, {
    cwd: rootDir,
    encoding: options.encoding,
    stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit"
  });
}

function assertPackageMetadata(packageJson) {
  if (packageJson.name !== "smooth-ssh-mcp") fail("package.json name must be smooth-ssh-mcp");
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(packageJson.version)) {
    fail(`package.json version is not valid semver: ${packageJson.version}`);
  }
  if (packageJson.type !== "module") fail("package.json type must be module");
  if (packageJson.bin?.["smooth-ssh-mcp"] !== "dist/server.js") {
    fail("package.json bin.smooth-ssh-mcp must point to dist/server.js");
  }
  for (const expected of ["dist", "bin", "README.md", "README.en.md", "README.zh-CN.md", "LICENSE", "examples", "docs"]) {
    if (!packageJson.files?.includes(expected)) fail(`package.json files is missing ${expected}`);
  }
}

function assertRequiredFiles() {
  const requiredFiles = [
    "LICENSE",
    "README.md",
    "README.en.md",
    "README.zh-CN.md",
    "bin/smooth-ssh-mcp-codex",
    "dist/server.js",
    "dist/version.js",
    "docs/mcp-client.example.json",
    "examples/hosts.example.yaml",
    "package-lock.json"
  ];

  for (const path of requiredFiles) requireFile(path);

  const wrapper = requireFile("bin/smooth-ssh-mcp-codex");
  const wrapperMode = statSync(wrapper).mode & 0o111;
  if (wrapperMode === 0) fail("bin/smooth-ssh-mcp-codex must be executable");
  if (!readFileSync(wrapper, "utf8").startsWith("#!/usr/bin/env bash")) {
    fail("bin/smooth-ssh-mcp-codex must keep its bash shebang");
  }

  if (!readFileSync(requireFile("dist/server.js"), "utf8").startsWith("#!/usr/bin/env node")) {
    fail("dist/server.js must keep its node shebang");
  }
}

function assertVersionMatches(packageJson) {
  const cliVersion = run("node", ["dist/server.js", "--version"], { capture: true, encoding: "utf8" }).trim();
  if (cliVersion !== packageJson.version) {
    fail(`CLI version ${cliVersion} does not match package.json version ${packageJson.version}`);
  }
}

function assertPackContents() {
  const output = run("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    capture: true,
    encoding: "utf8"
  });
  const packResult = JSON.parse(output);
  const [artifact] = packResult;
  if (!artifact || packResult.length !== 1) fail("npm pack dry run did not return exactly one artifact");

  const files = new Set(artifact.files.map((file) => file.path));
  const requiredPackFiles = [
    "LICENSE",
    "README.md",
    "README.en.md",
    "README.zh-CN.md",
    "bin/smooth-ssh-mcp-codex",
    "dist/server.js",
    "dist/version.js",
    "docs/mcp-client.example.json",
    "examples/hosts.example.yaml",
    "package.json"
  ];

  for (const path of requiredPackFiles) {
    if (!files.has(path)) fail(`npm package is missing ${path}`);
  }

  const forbiddenPrefixes = [".github/", "node_modules/", "scripts/", "src/", "tests/"];
  for (const file of files) {
    if (forbiddenPrefixes.some((prefix) => file.startsWith(prefix))) {
      fail(`npm package should not include ${file}`);
    }
  }

  console.log(`\nPackage dry run: ${artifact.filename}, ${artifact.entryCount} files, ${artifact.size} bytes`);
}

const packageJson = readJson("package.json");

run("npm", ["run", "typecheck"]);
run("npm", ["test"]);
run("npm", ["run", "build"]);
run("npm", ["run", "test:cli"]);

assertPackageMetadata(packageJson);
assertRequiredFiles();
assertVersionMatches(packageJson);
assertPackContents();

console.log("\nRelease check passed.");

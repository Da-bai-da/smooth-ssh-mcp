import { describe, expect, it } from "vitest";
import { parseArgs } from "../src/server.js";

describe("server args", () => {
  it("parses serve mode defaults and config", () => {
    expect(parseArgs([])).toMatchObject({ mode: "serve", json: false });
    expect(parseArgs(["--config", "/tmp/hosts.yaml"])).toEqual({
      mode: "serve",
      configPath: "/tmp/hosts.yaml",
      secretsPath: undefined,
      json: false,
      force: false
    });
  });

  it("parses doctor mode config, secrets, and json", () => {
    expect(parseArgs(["doctor", "--config", "/tmp/hosts.yaml", "--secrets", "/tmp/secrets.env", "--json"])).toEqual({
      mode: "doctor",
      configPath: "/tmp/hosts.yaml",
      secretsPath: "/tmp/secrets.env",
      json: true,
      force: false
    });
  });

  it("parses init mode force and output flags", () => {
    expect(parseArgs(["init", "--config", "/tmp/hosts.yaml", "--secrets", "/tmp/secrets.env", "--force", "--json"])).toEqual({
      mode: "init",
      configPath: "/tmp/hosts.yaml",
      secretsPath: "/tmp/secrets.env",
      json: true,
      force: true
    });
  });
});

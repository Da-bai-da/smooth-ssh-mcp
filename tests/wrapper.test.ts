import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("local wrapper", () => {
  it("loads secrets as key-value data instead of sourcing executable shell", () => {
    const script = readFileSync(new URL("../bin/smooth-ssh-mcp-local", import.meta.url), "utf8");

    expect(script).not.toContain("source \"$SECRETS_FILE\"");
    expect(script).toContain("export \"$key=$value\"");
  });
});

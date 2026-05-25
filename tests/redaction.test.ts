import { describe, expect, it } from "vitest";
import { redactAndTruncate } from "../src/redaction.js";

describe("redactAndTruncate", () => {
  it("redacts common secrets before returning output", () => {
    const result = redactAndTruncate(
      "Authorization: Bearer abcdef123456\npassword = hunter2\nnormal line",
      1000
    );

    expect(result.text).toContain("Authorization: Bearer [REDACTED]");
    expect(result.text).toContain("password=[REDACTED]");
    expect(result.text).toContain("normal line");
    expect(result.redactions.length).toBeGreaterThanOrEqual(2);
  });

  it("truncates long output and reports original size", () => {
    const result = redactAndTruncate("a".repeat(120), 40);

    expect(result.truncated).toBe(true);
    expect(result.originalBytes).toBe(120);
    expect(result.text.length).toBeLessThanOrEqual(40);
  });

  it("redacts incomplete private key blocks after bounded buffering", () => {
    const result = redactAndTruncate("-----BEGIN OPENSSH PRIVATE KEY-----\nabc123", 1000);

    expect(result.text).toBe("[REDACTED PRIVATE KEY]");
    expect(result.redactions.some((entry) => entry.pattern.includes("private-key"))).toBe(true);
  });
});

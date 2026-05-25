import type { RedactedText, Redaction } from "./types.js";

type Pattern = {
  name: string;
  regex: RegExp;
  replace: string | ((substring: string, ...args: string[]) => string);
};

const PATTERNS: Pattern[] = [
  {
    name: "authorization-bearer",
    regex: /\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
    replace: "Authorization: Bearer [REDACTED]"
  },
  {
    name: "password-assignment",
    regex: /\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*("[^"]*"|'[^']*'|\S+)/gi,
    replace: (_match, key: string) => `${key}=[REDACTED]`
  },
  {
    name: "private-key-block",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    replace: "[REDACTED PRIVATE KEY]"
  },
  {
    name: "private-key-incomplete",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/g,
    replace: "[REDACTED PRIVATE KEY]"
  }
];

export function redactAndTruncate(text: string, maxBytes: number): RedactedText {
  const redactions: Redaction[] = [];
  let output = text;

  for (const pattern of PATTERNS) {
    let count = 0;
    output = output.replace(pattern.regex, (...args) => {
      count += 1;
      if (typeof pattern.replace === "function") {
        return pattern.replace(args[0], ...args.slice(1));
      }
      return pattern.replace;
    });
    if (count > 0) {
      redactions.push({ pattern: pattern.name, count });
    }
  }

  const originalBytes = Buffer.byteLength(output, "utf8");
  if (originalBytes <= maxBytes) {
    return { text: output, redactions, truncated: false, originalBytes };
  }

  return {
    text: truncateUtf8(output, maxBytes),
    redactions,
    truncated: true,
    originalBytes
  };
}

function truncateUtf8(text: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  let used = 0;
  let result = "";
  for (const char of text) {
    const size = Buffer.byteLength(char, "utf8");
    if (used + size > maxBytes) break;
    result += char;
    used += size;
  }
  return result;
}

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/cliSmoke.test.ts"],
    globals: false,
    restoreMocks: true
  }
});

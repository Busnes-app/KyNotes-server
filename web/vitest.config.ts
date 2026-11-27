import { defineConfig } from "vitest/config";
export default defineConfig({ test: { maxWorkers: 2, setupFiles: ["./pq-test-setup.mjs"], exclude: ["e2e/**", "node_modules/**"] } });

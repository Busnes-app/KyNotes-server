import { defineConfig } from "@playwright/test";

// Real-browser checks against a throwaway server (e2e/server.sh). Never point this at real data.
const url = process.env.KYNOTES_E2E_URL ?? "http://127.0.0.1:18080";
// The checks create and delete accounts: only ever a loopback server.
if (!["127.0.0.1", "localhost", "[::1]"].includes(new URL(url).hostname)) throw new Error(`KYNOTES_E2E_URL must be a loopback server, not ${url}`);
export default defineConfig({
  testDir: "e2e",
  testMatch: "*.e2e.ts",
  timeout: 180_000,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  use: { baseURL: url, browserName: "chromium", trace: "retain-on-failure", screenshot: "only-on-failure" },
  webServer: process.env.KYNOTES_E2E_URL ? undefined : { command: "bash e2e/server.sh", url: `${url}/readyz`, timeout: 180_000, reuseExistingServer: false, gracefulShutdown: { signal: "SIGTERM", timeout: 10_000 } },
});

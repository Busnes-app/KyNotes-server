import { expect, test } from "@playwright/test";
import { adminConsole, person } from "./people";

// UI-only multi-mode fixture over the throwaway single-mode server. Real PG isolation,
// authorization and audit tests live in internal/httpapi; this never enables hosted startup.
const org = (id: string) => ({ id, status: "active", homeRegion: "eu", enabled: true, revision: 5, lastPoll: "2026-11-23T12:00:00Z", notesUsedBytes: 26, poolBytes: 1024, orgUsedBytes: 33, ceilingBytes: 100, grantExpiresAt: "2099-01-01T00:00:00Z" });
const account = (id: string) => ({ id: `usr_${id}`, username: `${id}-account`, role: "user", accountKind: "user", status: "active", quotaBytes: 1024, createdAt: "2026-11-23T12:00:00Z", usedBytes: 26 });

test("staff console selects an org, ignores late replies and exposes no customer mutations", async ({ browser }, info) => {
  const staff = await person(browser, { viewport: { width: 1280, height: 900 }, colorScheme: "light" });
  const page = staff.page;
  let releaseA = () => {};
  let holdA = false;
  let aArrived = () => {};
  let aFinished = () => {};
  const pendingA = new Promise<void>((resolve) => { releaseA = resolve; });
  const arrivedA = new Promise<void>((resolve) => { aArrived = resolve; });
  const finishedA = new Promise<void>((resolve) => { aFinished = resolve; });
  const writes: string[] = [];
  try {
    await adminConsole(page);
    await page.route("**/api/v1/auth/session", async (route) => {
      const response = await route.fetch();
      const body: unknown = await response.json();
      if (typeof body !== "object" || body === null || !("user" in body) || typeof body.user !== "object" || body.user === null) throw new Error("missing real administrator session");
      await route.fulfill({ response, json: { ...body, user: { ...body.user, tenancy: "multi" } } });
    });
    await page.route("**/api/v1/admin/orgs", (route) => route.fulfill({ json: [org("org_a"), org("org_b")] }));
    await page.route("**/api/v1/admin/users?org=**", async (route) => {
      const id = new URL(route.request().url()).searchParams.get("org");
      if (id === "org_a" && holdA) { aArrived(); await pendingA; }
      await route.fulfill({ json: [account(id ?? "missing")] }).catch(() => undefined);
      if (id === "org_a" && holdA) aFinished();
    });
    await page.route("**/api/v1/admin/audit**", (route) => route.fulfill({ json: [{ event: new URL(route.request().url()).searchParams.has("org") ? "customer.event" : "platform.event", outcome: "success", at: "2026-11-23T12:00:00Z" }] }));
    page.on("request", (request) => { if (request.url().includes("/admin/") && request.method() !== "GET") writes.push(request.url()); });
    await page.goto("/#orgs");
    await page.reload(); // A hash-only navigation does not re-fetch the session marker.
    await expect(page.getByRole("heading", { name: "Organizations", exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Organization directory" })).toContainText("org_a");
    await expect(page.getByRole("link", { name: "Teams", exact: true })).toHaveCount(0);
    await page.screenshot({ path: info.outputPath("staff-orgs-desktop-light.png"), fullPage: true });
    await page.getByRole("button", { name: "org_b", exact: true }).click();
    await expect(page.getByText("org_b-account", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Create user", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Actions for/ })).toHaveCount(0);
    holdA = true;
    await page.getByRole("combobox", { name: "Organization", exact: true }).selectOption("org_a");
    await arrivedA;
    await expect(page.getByText("org_b-account", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("status").filter({ hasText: "Loading metadata" })).toBeVisible();
    await page.getByRole("combobox", { name: "Organization", exact: true }).selectOption("org_b");
    await expect(page.getByText("org_b-account", { exact: true })).toBeVisible();
    releaseA(); await finishedA;
    await expect(page.getByText("org_a-account", { exact: true })).toHaveCount(0);
    await page.getByRole("link", { name: "Single sign-on", exact: true }).click();
    await expect(page.getByText("Shared sign-in configuration is managed by the deployment.", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: /Save|Pair|Connect/ })).toHaveCount(0);
    await page.getByRole("link", { name: "Audit log", exact: true }).click();
    await expect(page.getByText("platform.event", { exact: true })).toBeVisible();
    await page.getByRole("combobox", { name: "Audit scope", exact: true }).selectOption("org_b");
    await expect(page.getByText("customer.event", { exact: true })).toBeVisible();
    await expect(page.getByText("platform.event", { exact: true })).toHaveCount(0);
    expect(writes).toEqual([]);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto("/#orgs");
    await expect(page.getByRole("heading", { name: "Organizations", exact: true })).toBeVisible();
    const region = page.getByRole("region", { name: "Organization directory" });
    await expect(region).toContainText("org_b");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("staff-orgs-phone-dark.png"), fullPage: true });
  } finally {
    releaseA();
    expect(staff.unexpected).toEqual([]);
    await page.context().close();
  }
});

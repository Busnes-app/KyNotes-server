import { expect, test, type Page } from "@playwright/test";
import { adminConsole, OWNER, person, signIn } from "./people";

// The list KyIdentity would give an SSO user, served in place of /api/v1/suite/apps: the throwaway
// server has no KyIdentity. The server side is covered by internal/httpapi/suite_routes_test.go.
const APPS = [
  { id: "kypost", name: "KyPost", url: "https://mail.example.com/api/auth/oidc/login" },
  { id: "kycalendar", name: "KyCalendar", url: "https://calendar.example.com/sso/login" },
  { id: "kynotes", name: "KyNotes", url: "https://notes.example.com/api/v1/auth/oidc/login" },
  { id: "kydrive", name: "KyDrive", url: "https://drive.example.com/sso/login" },
];

async function serveApps(page: Page, apps: typeof APPS) {
  await page.context().route("**/api/v1/suite/apps", (route) => route.fulfill({ json: { apps } }));
}

/** KYNOTES_E2E_SHOTS=<dir>: Busnes Light and Dark at 1440x900 and 390x844; KYNOTES_RAIL_STAGE names the set. */
async function shots(page: Page) {
  const dir = process.env.KYNOTES_E2E_SHOTS;
  if (!dir) return;
  for (const scheme of ["light", "dark"] as const) {
    for (const [width, height, form] of [[1440, 900, "desktop"], [390, 844, "phone"]] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width, height });
      if (form === "phone") await page.locator(".ky-content-foot").scrollIntoViewIfNeeded();
      await page.evaluate(() => document.fonts.ready);
      await page.screenshot({ path: `${dir}/app-rail-${process.env.KYNOTES_RAIL_STAGE ?? "after"}-${scheme}-${form}.png` });
    }
  }
  await page.emulateMedia({ colorScheme: null });
}

test("the app rail links the suite from the sidebar foot, and the page end on phones", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser, { viewport: { width: 1440, height: 900 } });
  try {
    await adminConsole(admin.page);
    const { page } = owner;
    await serveApps(page, APPS);
    await signIn(page, OWNER.username, OWNER.password);
    if (process.env.KYNOTES_RAIL_STAGE === "before") return await shots(page);

    const side = page.locator(".ky-sidebar-foot > .ky-app-rail:first-child");
    const rail = page.getByRole("navigation", { name: "Apps" });
    await expect(side).toBeVisible();
    await expect(rail).toHaveCount(1); // the phone copy is hidden, so out of the accessibility tree
    const links = rail.getByRole("link");
    await expect(links).toHaveCount(APPS.length);
    for (const [i, app] of APPS.entries()) {
      await expect(links.nth(i)).toHaveAttribute("href", app.url);
      await expect(links.nth(i)).toHaveAccessibleName(app.name);
    }
    await expect(rail.getByRole("link", { name: "KyNotes" })).toHaveAttribute("aria-current", "page");
    await expect(rail.locator('a[aria-current="page"]')).toHaveCount(1);
    // The marks are data: URIs: they only paint if the CSP allows them.
    expect(await side.locator("img").evaluateAll((images) => images.map((img) => (img as HTMLImageElement).naturalWidth > 0))).toEqual(APPS.map(() => true));

    await page.setViewportSize({ width: 390, height: 844 });
    await expect(side).toBeHidden();
    const foot = page.locator(".ky-content-foot > .ky-app-rail:first-child");
    await foot.scrollIntoViewIfNeeded();
    await expect(foot).toBeVisible();
    await expect(rail).toHaveCount(1);
    await page.setViewportSize({ width: 1440, height: 900 });
    await shots(page);

    // An empty list, as for a password account or a server without SSO: no nav at all.
    await page.context().unroute("**/api/v1/suite/apps");
    await serveApps(page, []);
    const answered = page.waitForResponse((res) => new URL(res.url()).pathname === "/api/v1/suite/apps");
    await page.reload();
    await answered;
    await expect(page.locator("#notebook-navigation")).toBeAttached();
    await expect(page.locator(".ky-app-rail")).toHaveCount(0);
  } finally {
    expect(owner.unexpected).toEqual([]);
    expect(admin.unexpected).toEqual([]);
  }
});

import { expect, test } from "@playwright/test";
import { adminConsole, openNotebooks, OWNER, person, signIn, withDialog } from "./people";

const TABS = ["Account", "Phones & apps", "Appearance", "Reminders", "Colleague keys", "Share links", "Unsent edits"];

// ky-ui's Settings menu: the gear opens a menu of the Settings tabs (README "Settings menu").
test("the Settings gear opens a menu of the Settings tabs, by mouse and by keyboard", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const page = owner.page;
    const foot = page.locator(".ky-sidebar-foot .ky-user-actions");
    const gear = foot.getByRole("button", { name: "Settings", exact: true });
    const menu = foot.getByRole("menu", { name: "Settings" });
    await expect(gear).toHaveAttribute("aria-haspopup", "menu");
    await expect(gear).toHaveAttribute("aria-expanded", "false");
    await expect(menu).toBeHidden();
    // The phone header's menu is a separate one.
    const phoneMenu = await page.locator(".ky-mobile-actions .ky-icon-button[aria-haspopup]").getAttribute("aria-controls");
    expect(phoneMenu).not.toBe(await gear.getAttribute("aria-controls"));

    // Enter opens on the first item; arrows wrap, Home and End jump, Escape returns to the gear.
    await gear.focus();
    await page.keyboard.press("Enter");
    await expect(gear).toHaveAttribute("aria-expanded", "true");
    await expect(menu.getByRole("menuitem")).toHaveText(TABS);
    await expect(menu.locator('[aria-current="page"]')).toHaveCount(0);
    await expect(menu.getByRole("menuitem", { name: "Account" })).toBeFocused();
    await page.keyboard.press("ArrowUp");
    await expect(menu.getByRole("menuitem", { name: "Unsent edits" })).toBeFocused();
    await page.keyboard.press("Home");
    await expect(menu.getByRole("menuitem", { name: "Account" })).toBeFocused();
    await page.keyboard.press("End");
    await expect(menu.getByRole("menuitem", { name: "Unsent edits" })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(menu).toBeHidden();
    await expect(gear).toBeFocused();
    // ArrowDown opens it too; Tab closes it.
    await page.keyboard.press("ArrowDown");
    await expect(menu.getByRole("menuitem", { name: "Account" })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(menu).toBeHidden();
    // A click outside closes it.
    await gear.click();
    await expect(menu).toBeVisible();
    await page.locator(".ky-content").click({ position: { x: 5, y: 5 } });
    await expect(menu).toBeHidden();

    // Choosing an item (Space here) opens its tab; the gear and that item become current.
    await gear.focus();
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await expect(menu.getByRole("menuitem", { name: "Appearance" })).toBeFocused();
    await page.keyboard.press(" ");
    await expect(page).toHaveURL(/#\/settings\/appearance$/);
    await expect(menu).toBeHidden();
    await expect(gear).toBeFocused();
    await expect(gear).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("navigation", { name: "Settings sections" }).getByRole("link", { name: "Appearance" })).toHaveAttribute("aria-current", "page");
    await gear.click();
    await expect(menu.locator('[aria-current="page"]')).toHaveText("Appearance");
    await menu.getByRole("menuitem", { name: "Reminders" }).click();
    await expect(page).toHaveURL(/#\/settings\/reminders$/);

    // The administrator's console: Account (no single sign-on here) and Appearance only.
    const adminGear = admin.page.locator(".ky-sidebar-foot").getByRole("button", { name: "Settings", exact: true });
    await adminGear.click();
    const adminMenu = admin.page.locator(".ky-sidebar-foot").getByRole("menu", { name: "Settings" });
    await expect(adminMenu.getByRole("menuitem")).toHaveText(["Account", "Appearance"]);
    await adminMenu.getByRole("menuitem", { name: "Appearance" }).click();
    await expect(admin.page).toHaveURL(/#appearance$/);
    await expect(adminGear).toHaveAttribute("aria-current", "page");
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

test("a Settings tab chosen as the first notebook finishes loading stays open", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const { page } = owner;
    // A notebook for the fresh load to open.
    await openNotebooks(page);
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: "Settings race" }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".workspace-title")).toHaveText("Settings race");
    // Hold the first notebook's object list after a fresh load.
    let arrived!: () => void, release!: () => void;
    const fetching = new Promise<void>((resolve) => { arrived = resolve; });
    const held = new Promise<void>((resolve) => { release = resolve; });
    let first = true;
    await page.route((url) => /^\/api\/v1\/containers\/[^/]+\/changes$/.test(url.pathname), async (route) => {
      if (!first) return route.fallback();
      first = false;
      arrived();
      await held;
      await route.continue();
    });
    await page.goto("about:blank");
    await page.goto("/");
    await fetching;
    // A menu click sets the hash; its hashchange is still queued when the load finishes.
    await page.evaluate(() => history.replaceState(null, "", "#/settings/reminders"));
    const loaded = page.waitForResponse((response) => /\/api\/v1\/containers\/[^/]+\/changes/.test(response.url()));
    release();
    await loaded;
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    await page.evaluate(() => window.dispatchEvent(new HashChangeEvent("hashchange")));
    await expect(page).toHaveURL(/#\/settings\/reminders$/);
    await expect(page.getByRole("navigation", { name: "Settings sections" }).getByRole("link", { name: "Reminders", exact: true })).toHaveAttribute("aria-current", "page");
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

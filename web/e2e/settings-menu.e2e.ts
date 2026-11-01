import { expect, test } from "@playwright/test";
import { adminConsole, OWNER, person, signIn } from "./people";

const TABS = ["Account", "Phones & apps", "Appearance", "Reminders", "Colleague keys", "Unsent edits"];

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

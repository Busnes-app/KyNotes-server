import { expect, test } from "@playwright/test";
import { adminConsole, OWNER, person, signIn } from "./people";

test("one navigation region on desktop; on phones the same destinations sit behind a Menu drawer", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser, { viewport: { width: 390, height: 844 } });
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const menu = owner.page.getByRole("button", { name: "Menu", exact: true });
    const notebooks = owner.page.locator("#notebook-navigation");
    await expect(menu).toHaveAttribute("aria-expanded", "false");
    await expect(notebooks).toBeHidden();
    await menu.click();
    await expect(notebooks).toBeVisible();
    for (const name of ["Notes", "Work queue", "Appearance", "Settings", "Sign out"]) await expect(owner.page.getByRole("button", { name, exact: true })).toBeVisible();
    await expect(notebooks.getByRole("button", { name: /New notebook/ })).toBeVisible();
    await owner.page.keyboard.press("Escape");
    await expect(notebooks).toBeHidden();
    await menu.click();
    await owner.page.getByRole("button", { name: "Appearance", exact: true }).click();
    await expect(notebooks).toBeHidden();
    await expect(owner.page.getByRole("heading", { level: 1, name: "Appearance" })).toBeVisible();

    // Desktop: no Menu button. The shared 240px column holds every destination beside the page.
    await owner.page.setViewportSize({ width: 1280, height: 900 });
    await expect(owner.page.locator(".nav-menu-toggle")).toBeHidden();
    await expect(notebooks).toBeVisible();
    const nav = await owner.page.locator(".app-nav").boundingBox();
    const main = await owner.page.locator(".app-main").boundingBox();
    expect(nav!.x).toBe(0);
    expect(nav!.width).toBe(240);
    expect(main!.x).toBe(240);
    for (const name of ["Notes", "Appearance", "Settings", "Sign out"]) await expect(owner.page.getByRole("button", { name, exact: true })).toBeInViewport();
    await expect(owner.page.getByRole("button", { name: /MIT License/ })).toBeInViewport();
    // Only the current destination is marked as the page.
    await expect(owner.page.locator('.app-nav [aria-current="page"]')).toHaveText(["Appearance"]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

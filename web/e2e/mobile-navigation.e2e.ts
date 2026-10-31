import { expect, test } from "@playwright/test";
import { adminConsole, OWNER, person, signIn } from "./people";

test("one navigation region on desktop; on phones it folds away without covering the editor", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser, { viewport: { width: 390, height: 844 } });
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const toggle = owner.page.getByRole("button", { name: "Notebooks and account" });
    const notebooks = owner.page.locator("#notebook-navigation");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(notebooks).toBeHidden();
    await toggle.click();
    await expect(notebooks).toBeVisible();
    await expect(notebooks.getByRole("button", { name: /New notebook/ })).toBeVisible();
    await expect(owner.page.getByRole("button", { name: "Sign out", exact: true })).toBeVisible();
    await toggle.click();
    await expect(notebooks).toBeHidden();

    // Desktop: no disclosure. Notebooks, account and the licence line share one left column beside the page.
    await owner.page.setViewportSize({ width: 1280, height: 900 });
    await expect(toggle).toBeHidden();
    await expect(notebooks).toBeVisible();
    const nav = await owner.page.locator(".app-nav").boundingBox();
    const main = await owner.page.locator(".app-main").boundingBox();
    expect(nav!.x).toBe(0);
    expect(nav!.width).toBe(288);
    expect(main!.x).toBe(288);
    for (const name of ["Appearance", "Settings", "Sign out"]) await expect(owner.page.getByRole("button", { name, exact: true })).toBeInViewport();
    await expect(owner.page.getByRole("button", { name: /MIT License/ })).toBeInViewport();
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

import { expect, test } from "@playwright/test";
import { adminConsole, OWNER, person, signIn } from "./people";

test("phone notebook navigation stays reachable without covering the editor", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser, { viewport: { width: 390, height: 844 } });
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const toggle = owner.page.getByRole("button", { name: "Notebooks and account" });
    const sidebar = owner.page.locator("#notebook-navigation");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(sidebar).toBeHidden();
    await toggle.click();
    await expect(sidebar).toBeVisible();
    await expect(sidebar.getByRole("button", { name: /New notebook/ })).toBeVisible();
    await toggle.click();
    await expect(sidebar).toBeHidden();
    await owner.page.setViewportSize({ width: 1280, height: 900 });
    await expect(sidebar).toBeHidden();
    await expect(toggle).toBeVisible();
    const list = owner.page.locator("#page-navigation");
    const editor = owner.page.locator(".editor");
    await expect(list).toBeVisible();
    const before = await list.boundingBox();
    const pageBox = await editor.boundingBox();
    expect(before!.x).toBe(0);
    expect(before!.width).toBe(240);
    expect(pageBox!.x).toBe(240);
    await toggle.click();
    await expect(sidebar).toBeVisible();
    await expect(list).toBeHidden();
    const notebooks = await sidebar.boundingBox();
    expect(notebooks!.x).toBe(before!.x);
    expect(notebooks!.width).toBe(before!.width);
    await toggle.click();
    await expect(list).toBeVisible();
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

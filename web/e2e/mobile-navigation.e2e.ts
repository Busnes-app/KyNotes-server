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
    await expect(sidebar).toBeVisible();
    await expect(toggle).toBeHidden();
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

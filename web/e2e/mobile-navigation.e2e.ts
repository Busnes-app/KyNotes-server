import { expect, test } from "@playwright/test";
import { adminConsole, OWNER, person, signIn } from "./people";

test("one frame on desktop; on phones the shared header and tabs, with the notebook tree under Notes", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser, { viewport: { width: 390, height: 844 } });
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const page = owner.page;
    const tabs = page.getByRole("navigation", { name: "Primary" });
    const notes = tabs.getByRole("button", { name: "Notes", exact: true });
    const tree = page.locator("#notebook-tree");
    // Phones: the brand and an icon-only Sign out, then one row of tabs. No hamburger, no name or role.
    await expect(page.getByRole("button", { name: "Menu", exact: true })).toHaveCount(0);
    await expect(page.locator(".ky-mobile-head").getByRole("button", { name: "Sign out", exact: true })).toBeVisible();
    await expect(page.locator(".ky-user-name")).toBeHidden();
    const tops = await tabs.locator(".ky-nav-item").evaluateAll((items) => items.map((item) => Math.round(item.getBoundingClientRect().top)));
    expect(new Set(tops).size).toBe(1);
    for (const name of ["Notes", "Work queue", "Appearance", "Settings"]) await expect(tabs.getByRole("button", { name, exact: true })).toBeAttached();
    // The current Notes tab opens and closes the notebook tree.
    await expect(notes).toHaveAttribute("aria-expanded", "false");
    await expect(tree).toBeHidden();
    await notes.click();
    await expect(notes).toHaveAttribute("aria-expanded", "true");
    await expect(tree.getByRole("button", { name: /New notebook/ })).toBeVisible();
    await notes.click();
    await expect(tree).toBeHidden();
    await tabs.getByRole("button", { name: "Appearance", exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Appearance" })).toBeVisible();
    await expect(notes).not.toHaveAttribute("aria-expanded");
    // The licence line closes the page, never under the tabs.
    await expect(page.locator(".ky-content-foot").getByRole("button", { name: /MIT License/ })).toBeVisible();

    // Desktop: the 240px sidebar holds every destination and the tree; the page starts at x=272.
    await page.setViewportSize({ width: 1280, height: 900 });
    await expect(tree).toBeVisible();
    const side = await page.locator(".ky-sidebar").boundingBox();
    expect(side!.x).toBe(0);
    expect(side!.width).toBe(240);
    expect((await page.getByRole("heading", { level: 1, name: "Appearance" }).boundingBox())!.x).toBe(272);
    await expect(notes).not.toHaveAttribute("aria-expanded");
    for (const name of ["Notes", "Appearance", "Settings", "Sign out"]) await expect(page.getByRole("button", { name, exact: true })).toBeInViewport();
    await expect(page.locator(".ky-sidebar-foot").getByRole("button", { name: /MIT License/ })).toBeInViewport();
    // Only the current destination is marked as the page.
    await expect(page.locator('.ky-nav [aria-current="page"]')).toHaveText(["Appearance"]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

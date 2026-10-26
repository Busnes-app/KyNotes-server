import { expect, test } from "@playwright/test";
import { THEME_STORAGE_KEY } from "../src/theme";
import { adminConsole, OWNER, person, signIn } from "./people";

test("Appearance follows a theme chosen in another tab", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    await owner.page.getByRole("button", { name: "Settings" }).click();
    const card = (id: string) => owner.page.locator(`.ky-appearance-radio[value="${id}"]`);
    await expect(card("system")).toBeChecked();
    await expect(owner.page.locator(".ky-appearance-option", { has: card("system") })).toContainText("Follows device");
    // Another tab on the same origin saves Sun by name, as the picker does.
    const other = await owner.page.context().newPage();
    await other.goto("/readyz");
    await other.evaluate(([key, value]) => localStorage.setItem(key, value), [THEME_STORAGE_KEY, "Sun"]);
    await expect(card("sun")).toBeChecked();
    await expect(card("system")).not.toBeChecked();
    await other.close();
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

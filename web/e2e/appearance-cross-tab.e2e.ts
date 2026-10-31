import { expect, test } from "@playwright/test";
import { THEME_STORAGE_KEY } from "../src/theme";
import { adminConsole, OWNER, openSettings, person, signIn } from "./people";

test("Appearance follows a theme chosen in another tab", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    await openSettings(owner.page, "Appearance");
    const choice = (value: string) => owner.page.locator(`input[name="kynotes-theme"][value="${value}"]`);
    await expect(choice("system")).toBeChecked();
    await expect(owner.page.getByRole("group", { name: "Busnes" }).locator("label", { has: choice("system") })).toContainText("Match system");
    // Another tab on the same origin saves Ocean by the name earlier versions wrote; it selects Ocean Dark.
    const other = await owner.page.context().newPage();
    await other.goto("/readyz");
    await other.evaluate(([key, value]) => localStorage.setItem(key, value), [THEME_STORAGE_KEY, "Ocean"]);
    await expect(choice("ocean")).toBeChecked();
    await expect(choice("system")).not.toBeChecked();
    // A choice here is saved as the half's ID.
    await owner.page.getByRole("group", { name: "Forest" }).getByRole("radio", { name: "Light", exact: true }).check();
    await expect(choice("forest-light")).toBeChecked();
    expect(await other.evaluate((key) => localStorage.getItem(key), THEME_STORAGE_KEY)).toBe("forest-light");
    await other.close();
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

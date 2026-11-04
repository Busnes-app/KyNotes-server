import { expect, test, type Page } from "@playwright/test";
import { adminConsole, OWNER, person, signIn, withDialog, openNotebooks } from "./people";

// Regression checks for the hostile-review pass 3 client fixes.
const objectSave = (page: Page, url?: string) => page.waitForResponse((response) => response.request().method() === "PUT" && (url ? response.url() === url : /\/api\/v1\/objects\/obj_/.test(response.url())) && response.ok(), { timeout: 15_000 });

test("New page first sends the open page's last edit", async ({ browser }) => {
  const admin = await person(browser, { viewport: { width: 1440, height: 900 } });
  const owner = await person(browser, { viewport: { width: 1440, height: 900 } });
  const { page } = owner;
  try {
    await adminConsole(admin.page);
    await signIn(page, OWNER.username, OWNER.password);
    await openNotebooks(page);
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: "Council pass 3" }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    const created = objectSave(page);
    await page.getByRole("button", { name: "New page", exact: true }).click();
    await created;
    const titled = objectSave(page);
    await page.locator(".title-input").fill("First page");
    const firstURL = (await titled).url();

    // Typed, then New page before the autosave fires: the first page's edit still reaches the server.
    await page.getByRole("toolbar", { name: "Page tools" }).getByRole("button", { name: "Heading 2" }).click();
    await page.keyboard.type("Kept words");
    const flushed = objectSave(page, firstURL);
    await page.getByRole("button", { name: "New page", exact: true }).click();
    const sent = await flushed;
    expect(sent.request().postDataBuffer()?.length ?? 0).toBeGreaterThan(0);
    await expect(page.locator(".title-input")).toHaveValue("Untitled page");
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

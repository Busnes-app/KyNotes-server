import { expect, test, type Page } from "@playwright/test";
import { adminConsole, backToNotes, OWNER, person, signIn, withDialog, openNotebooks, openSettings } from "./people";

// Owner answers Q10 (Delete notebook) and Q11 (share links name their page in the browser that made them).
const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok(), { timeout: 15_000 });
const tree = (page: Page) => page.locator("#notebook-tree");
const prompted = (name: string) => `Delete "${name}"? This deletes its pages, comments and attachments for every member. It cannot be undone.\n\nType the notebook's name to confirm.`;
const REAUTH = "Deleting a notebook needs a sign-in from the last 5 minutes. Sign out now, sign in again, then delete it?";

test("Share links name their page, and an owner deletes a notebook by typing its name", async ({ browser }) => {
  const admin = await person(browser, { viewport: { width: 1440, height: 900 } });
  const owner = await person(browser, { viewport: { width: 1440, height: 900 }, permissions: ["clipboard-read", "clipboard-write"] });
  const { page } = owner;
  try {
    await adminConsole(admin.page);
    await signIn(page, OWNER.username, OWNER.password);
    await openNotebooks(page);
    for (const name of ["Pass 4 kept", "Pass 4 removed"]) {
      await withDialog(owner, { type: "prompt", text: "Notebook name", answer: name }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
      await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    }
    const created = objectSave(page);
    await page.getByRole("button", { name: "New page", exact: true }).click();
    await created;
    const titled = objectSave(page);
    await page.locator(".title-input").fill("Shared plan");
    await titled;
    const texted = objectSave(page);
    await page.getByRole("toolbar", { name: "Page tools" }).getByRole("button", { name: "Heading 2" }).click();
    await page.keyboard.type("Words to share");
    await texted;

    // Q11: the link this browser made names its page.
    await page.locator(".title-input").focus();
    await page.keyboard.press("Control+Shift+L");
    await expect(page.getByText("Encrypted share link copied.", { exact: false })).toBeVisible();
    await openSettings(page, "Share links");
    const row = page.locator("#share-links .pin-row");
    await expect(row).toHaveCount(1);
    await expect(row).toContainText('"Shared plan" in Pass 4 removed: made ');
    await backToNotes(page);
    await openNotebooks(page);

    const clickDelete = async () => {
      await page.getByRole("button", { name: "Notebook options" }).click();
      await page.getByRole("button", { name: "Delete notebook", exact: true }).click();
    };
    const remove = (answer: string) => withDialog(owner, { type: "prompt", text: prompted("Pass 4 removed"), answer }, clickDelete);
    // A wrong name deletes nothing.
    await remove("Pass 4");
    await expect(page.getByText("The name did not match, so nothing was deleted.")).toBeVisible();
    await expect(tree(page).getByRole("button", { name: "Pass 4 removed" })).toBeVisible();
    // An old sign-in is asked to sign in again; declining keeps everything.
    await page.route("**/api/v1/containers/*", (route) => route.request().method() === "DELETE"
      ? route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: { code: "forbidden", message: "re-authentication required" } }) })
      : route.fallback());
    owner.expected.push({ type: "prompt", text: prompted("Pass 4 removed"), answer: "Pass 4 removed" });
    await withDialog(owner, { type: "confirm", text: REAUTH, decline: true }, clickDelete);
    await page.unroute("**/api/v1/containers/*");
    await expect(tree(page).getByRole("button", { name: "Pass 4 removed" })).toBeVisible();

    // The real delete: gone from the tree, and another notebook opens.
    const deleted = page.waitForResponse((response) => response.request().method() === "DELETE" && /\/api\/v1\/containers\/cnt_/.test(response.url()));
    await remove("Pass 4 removed");
    expect((await deleted).status()).toBe(204);
    await expect(tree(page).getByRole("button", { name: "Pass 4 removed" })).toHaveCount(0);
    await expect(tree(page).locator('[aria-current="true"]').first()).toBeVisible();
    await expect(page.getByRole("listitem").filter({ hasText: "Shared plan" })).toHaveCount(0);

    // The link outlives its notebook; this browser can no longer read which page it was.
    await openSettings(page, "Share links");
    await expect(row).toContainText("Made in this browser, page no longer readable");
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

import { expect, test, type Page } from "@playwright/test";
import { OWNER, adminConsole, openNotebooks, person, signIn, withDialog } from "./people";

// Regression checks for the hostile-review pass 1 client fixes.

const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());

async function newPage(page: Page, title: string) {
  const created = objectSave(page);
  await page.getByRole("button", { name: "New page" }).click();
  await created;
  const titled = objectSave(page);
  await page.locator(".title-input").fill(title);
  await titled;
}

test("client fixes: comment drafts stay with their page, a stale tab survives a missing chunk", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const { page } = owner;
    await openNotebooks(page);
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: "Council pass 1" }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");

    // A comment draft stays with its page.
    await newPage(page, "First page");
    const panel = page.locator("details.comments");
    if (await panel.getAttribute("open") === null) await panel.locator("summary").click();
    await page.getByPlaceholder("Add a comment…").fill("private draft");
    await newPage(page, "Second page");
    if (await panel.getAttribute("open") === null) await panel.locator("summary").click();
    await expect(page.getByPlaceholder("Add a comment…")).toHaveValue("");

    // A tab older than the server finds its page chunk gone: it reloads once and opens the page,
    // and does so again on a later upgrade.
    for (let round = 0; round < 3; round++) {
      // The chunk is gone for the whole first document; the tab's own reload is the second.
      let documents = 0;
      let refused = 0;
      const count = (request: { resourceType: () => string }) => { if (request.resourceType() === "document") documents += 1; };
      page.on("request", count);
      await page.route((url) => /\/assets\/CanvasPage-[^/]+\.js$/.test(url.pathname), (route) => {
        if (documents > 1) return route.fallback();
        refused += 1;
        return route.fulfill({ status: 404, body: "404 page not found" });
      });
      await page.reload();
      await expect(page.getByRole("toolbar", { name: "Page tools" })).toBeVisible({ timeout: 30_000 });
      expect(refused).toBeGreaterThan(0);
      expect(documents).toBe(2);
      page.off("request", count);
      await page.unrouteAll({ behavior: "ignoreErrors" });
    }

    for (const who of [admin, owner]) expect(who.unexpected).toEqual([]);
  } finally {
    for (const who of [admin, owner]) await who.page.context().close();
  }
});

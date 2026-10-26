import { expect, test } from "@playwright/test";
import { adminConsole, OWNER, person, signIn, withDialog } from "./people";

const EARLIER = "Load race earlier";
const FRESH = "Load race fresh";

test("a notebook created while the notebook list loads stays open", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const { page } = owner;
    const title = page.locator(".workspace-title");
    // Another notebook, so the list load has something else to pick.
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: EARLIER }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(title).toHaveText(EARLIER);
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    const earlier = /#\/(cnt_[0-9a-z]+)/.exec(page.url())![1];

    // After a fresh load, this tab's first list is read from the server at once but delivered late,
    // so the creation lands mid-load and the list predates it.
    let arrived!: () => void, release!: () => void;
    const fetching = new Promise<void>((resolve) => { arrived = resolve; });
    const held = new Promise<void>((resolve) => { release = resolve; });
    let first = true;
    await page.route((url) => url.pathname === "/api/v1/containers", async (route) => {
      if (route.request().method() !== "GET" || !first) return route.fallback();
      first = false;
      const response = await route.fetch();
      arrived();
      await held;
      await route.fulfill({ response });
    });
    await page.goto("about:blank");
    await page.goto("/");
    await fetching;
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: FRESH }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(title).toHaveText(FRESH);

    // The list load finishes after the creation; it must not switch back to its own pick.
    const picked = page.waitForRequest((request) => request.url().includes(`/api/v1/containers/${earlier}/changes`), { timeout: 3_000 }).then(() => true, () => false);
    release();
    await expect(page.getByRole("button", { name: EARLIER })).toBeVisible();
    expect(await picked).toBe(false);
    await expect(title).toHaveText(FRESH);
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

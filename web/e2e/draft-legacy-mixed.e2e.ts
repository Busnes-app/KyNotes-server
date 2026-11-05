import { expect, test, type Page } from "@playwright/test";
import { adminConsole, OWNER, person, signIn, withDialog, openNotebooks } from "./people";

const saved = (page: Page) => page.waitForResponse(r => r.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(r.url()) && r.ok());
async function row(page: Page, id: string) {
  return page.evaluate(async id => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open("kynotes-web", 7); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    try { return await new Promise<{ owner: string; id: string; payload: Uint8Array; version: number; updatedAt: string }>((resolve, reject) => { const r = db.transaction("notes").objectStore("notes").getAll(); r.onsuccess = () => resolve(r.result.find((n: { id: string }) => n.id === id)); r.onerror = () => reject(r.error); }); }
    finally { db.close(); }
  }, id);
}
for (const variant of ["same-base", "lower-base", "equal-time", "held-conflict"] as const) {
  test(`mixed legacy cache wins over older pending: ${variant}`, async ({ browser }) => {
    const admin = await person(browser), owner = await person(browser); let page = owner.page;
    try {
      await adminConsole(admin.page); await signIn(page, OWNER.username, OWNER.password); await openNotebooks(page);
      await withDialog(owner, { type: "prompt", text: "Notebook name", answer: `Mixed ${variant}` }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
      await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
      const created = saved(page); await page.getByRole("button", { name: "New page", exact: true }).click();
      const first = await created, url = first.url(), id = new URL(url).pathname.split("/").at(-1)!;
      const hash = await page.evaluate(() => location.hash);
      // Obtain both encrypted copies by real typing; no production crypto/test hooks.
      await page.route(url, async route => { if (route.request().method() === "PUT") await new Promise<void>(() => {}); else await route.fallback(); });
      const baseline = await row(page, id);
      await page.locator(".title-input").fill("Older pending text");
      await expect.poll(async () => Array.from((await row(page, id)).payload).join(",")).not.toBe(Array.from(baseline.payload).join(","));
      const older = await row(page, id);
      await page.locator(".title-input").fill("LATEST unmarked legacy text");
      await expect.poll(async () => Array.from((await row(page, id)).payload).join(",")).not.toBe(Array.from(older.payload).join(","));
      const latest = await row(page, id), bytes = Array.from(latest.payload).join(",");
      const context = page.context(); await page.close(); page = await context.newPage(); await page.goto("/healthz");
      await page.evaluate(async ({ older, id, variant }) => {
        const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open("kynotes-web", 7); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
        try { await new Promise<void>((resolve, reject) => {
          const tx = db.transaction(["notes", "pending"], "readwrite"), read = tx.objectStore("notes").get([older.owner, id]);
          read.onsuccess = () => {
            const latest = read.result; delete latest.unsent; tx.objectStore("notes").put(latest);
            tx.objectStore("pending").put({ ...older, payload: new Uint8Array(older.payload), version: variant === "lower-base" ? 0 : latest.version,
              updatedAt: variant === "equal-time" ? latest.updatedAt : older.updatedAt, ...(variant === "held-conflict" ? { conflicted: true } : {}) });
          };
          tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
        }); } finally { db.close(); }
      }, { older: { ...older, payload: Array.from(older.payload) }, id, variant });
      let release = () => {}; const held = new Promise<void>(resolve => { release = resolve; });
      await page.route(url, async route => {
        if (route.request().method() !== "PUT") return route.fallback();
        // The startup drain can already hold the older failed entry before the
        // notebook reader runs. Keep that failure, and observe the recovered copy.
        if (Array.from(route.request().postDataBuffer()!).join(",") !== bytes) return route.abort();
        await held; await route.continue();
      });
      const latestRequest = (r: import("@playwright/test").Request) => r.method() === "PUT" && r.url() === url && Array.from(r.postDataBuffer()!).join(",") === bytes;
      const request = page.waitForRequest(latestRequest, { timeout: 25_000 });
      const response = page.waitForResponse(r => latestRequest(r.request()), { timeout: 25_000 });
      // Handle a failed expected assertion without leaving event promises unobserved.
      void request.catch(() => {}); void response.catch(() => {});
      await page.goto("/" + hash);
      await expect(page.locator(".title-input")).toHaveValue("LATEST unmarked legacy text");
      await page.getByRole("button", { name: "Save", exact: true }).click();
      expect(Array.from((await request).postDataBuffer()!).join(",")).toBe(bytes);
      release(); expect((await response).status()).toBe(200);
      await expect.poll(async () => Array.from((await row(page, id)).payload).join(",")).toBe(bytes);
      await page.reload(); await expect(page.locator(".title-input")).toHaveValue("LATEST unmarked legacy text");
    } finally { await admin.page.context().close(); await page.context().close(); }
  });
}

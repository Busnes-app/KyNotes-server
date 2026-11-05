import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";
import { adminConsole, OWNER, person, signIn, withDialog, openNotebooks } from "./people";

const objectSave = (page: Page) => page.waitForResponse(r => r.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(r.url()) && r.ok());
async function queued(page: Page, id: string): Promise<boolean> {
  return page.evaluate(async id => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open("kynotes-web", 7); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    try { return await new Promise<boolean>((resolve, reject) => {
      const r = db.transaction("pending").objectStore("pending").getAll();
      r.onsuccess = () => resolve(r.result.some((row: { id: string }) => row.id === id)); r.onerror = () => reject(r.error);
    }); } finally { db.close(); }
  }, id);
}
async function failLocalStore(page: Page) {
  await page.evaluate(() => Object.defineProperty(window, "indexedDB", { configurable: true, get() { throw new DOMException("Storage unavailable", "SecurityError"); } }));
}
async function createNotebook(owner: Awaited<ReturnType<typeof person>>, name: string) {
  await openNotebooks(owner.page);
  await withDialog(owner, { type: "prompt", text: "Notebook name", answer: name }, () => owner.page.getByRole("button", { name: "＋ New notebook" }).click());
  await expect(owner.page.locator(".workspace-title")).toHaveText(name);
  await expect(owner.page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
  await expect(owner.page.getByRole("button", { name: "New page", exact: true })).toBeEnabled();
}
for (const kind of ["section", "group"] as const) {
  test(`unchanged ${kind} retry reuses a committed write after its response is lost`, async ({ browser }) => {
    const admin = await person(browser), owner = await person(browser), page = owner.page;
    try {
      await adminConsole(admin.page); await signIn(page, OWNER.username, OWNER.password);
      await createNotebook(owner, `Retry ${kind}`);
      const created = objectSave(page);
      await page.getByRole("button", { name: "Notebook options" }).click();
      await page.getByRole("button", { name: kind === "section" ? "New section" : "New section group", exact: true }).click();
      const first = await created, url = first.url();
      let lost = false;
      const sent: Array<{ body: Buffer | null; key: string | undefined }> = [];
      let lostDone = () => {};
      const dropped = new Promise<void>(resolve => { lostDone = resolve; });
      await page.route(url, async route => {
        if (route.request().method() !== "PUT") return route.fallback();
        sent.push({ body: route.request().postDataBuffer(), key: route.request().headers()["idempotency-key"] });
        if (!lost) { lost = true; const result = await route.fetch(); expect(result.status()).toBe(200); await route.abort(); lostDone(); }
        else await route.fallback();
      });
      const title = `Retried ${kind}`;
      const rename = async (old: string, next: string) => {
        await page.getByRole("button", { name: `${kind === "section" ? "Section" : "Group"} options for ${old}`, exact: true }).click();
        await withDialog(owner, { type: "prompt", text: kind === "section" ? "Section name" : "Group name", answer: next }, () => page.getByRole("button", { name: "Rename", exact: true }).click());
      };
      await rename(kind === "section" ? "New section" : "New group", title);
      await dropped;
      const retried = page.waitForResponse(r => r.url() === url && r.request().method() === "PUT");
      await rename(title, title);
      expect((await retried).status()).toBe(200);
      expect(sent).toHaveLength(2);
      expect(sent[1].body).toEqual(sent[0].body);
      expect(sent[1].key).toBe(sent[0].key);
      // Response headers precede local settlement and its UI update. Finish
      // that retry before opening a menu for the next distinct edit.
      await expect.poll(() => queued(page, new URL(url).pathname.split("/").at(-1)!)).toBe(false);
      const changed = page.waitForResponse(r => r.url() === url && r.request().method() === "PUT");
      await rename(title, "Actually changed");
      expect((await changed).status()).toBe(200);
      expect(sent[2].key).not.toBe(sent[1].key);
      const conflicts = await page.evaluate(async url => (await fetch(url + "/conflicts")).json(), url);
      expect(conflicts).toEqual([]);
    } finally { await admin.page.context().close(); await page.context().close(); }
  });
}
for (const failure of ["before-save", "after-conflict"] as const) {
  test(`a real conflict remains actionable when local storage fails ${failure}`, async ({ browser }) => {
    const admin = await person(browser), owner = await person(browser), page = owner.page;
    try {
      await adminConsole(admin.page); await signIn(page, OWNER.username, OWNER.password);
      await createNotebook(owner, `Conflict ${failure}`);
      const created = objectSave(page); await page.getByRole("button", { name: "New page", exact: true }).click();
      const first = await created, url = first.url();
      const advance = await page.request.put(url, { data: first.request().postDataBuffer()!, headers: { ...first.request().headers(), "idempotency-key": "advance-" + failure, "x-kynotes-base-version": "1" } });
      expect(advance.status()).toBe(200);
      if (failure === "before-save") await failLocalStore(page);
      else await page.route(url, async route => {
        if (route.request().method() !== "PUT") return route.fallback();
        const result = await route.fetch();
        if (result.status() === 409) await failLocalStore(page);
        await route.fulfill({ response: result });
      });
      let writes = 0;
      page.on("request", request => { if (request.url() === url && request.method() === "PUT") writes++; });
      const rejected = page.waitForResponse(r => r.url() === url && r.request().method() === "PUT");
      await page.locator(".title-input").fill("Kept in memory");
      expect((await rejected).status()).toBe(409);
      await expect(page.getByRole("button", { name: /Keep the other version/ })).toBeVisible();
      await expect(page.locator(".toast.error")).toContainText(failure === "before-save" ? "could not keep a local copy" : "preserved locally");
      await expect(page.locator(".title-input")).toHaveValue("Kept in memory");
      await page.waitForTimeout(16_000); // Observe the real periodic drain, without altering time.
      expect(writes).toBe(1);
    } finally { await admin.page.context().close(); await page.context().close(); }
  });
}

for (const mixed of [false, true]) {
test(`export reads another tab's ${mixed ? "mixed legacy" : "unqueued unsent"} text without activating an upload`, async ({ browser }) => {
  const admin = await person(browser), owner = await person(browser), page = owner.page;
  let second: Page | undefined;
  try {
    await adminConsole(admin.page); await signIn(page, OWNER.username, OWNER.password);
    const name = "Read-only export";
    await createNotebook(owner, name);
    const created = objectSave(page); await page.getByRole("button", { name: "New page", exact: true }).click();
    const first = await created, url = first.url(), id = new URL(url).pathname.split("/").at(-1)!;
    const hash = await page.evaluate(() => location.hash);
    second = await page.context().newPage(); await second.goto("/" + hash);
    await expect(second.locator(".title-input")).toBeVisible();
    await second.route(url, async route => { if (route.request().method() === "PUT") await new Promise<void>(() => {}); else await route.fallback(); });
    await second.locator(".title-input").fill("Unqueued export draft");
    await expect.poll(() => second!.evaluate(async id => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open("kynotes-web", 7); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
      try { return await new Promise<boolean>(resolve => { const r = db.transaction("notes").objectStore("notes").getAll(); r.onsuccess = () => resolve(r.result.some((v: { id: string; unsent?: boolean }) => v.id === id && v.unsent)); }); }
      finally { db.close(); }
    }, id)).toBe(true);
    await second.close();
    // A cache-only edit is the valid window between persistDraft and the autosave queue write.
    const queued = async (remove = false) => page.evaluate(async ({ id, remove }) => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open("kynotes-web", 7); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
      try { return await new Promise<number>((resolve, reject) => {
        const tx = db.transaction("pending", remove ? "readwrite" : "readonly"), store = tx.objectStore("pending");
        const r = store.getAll(); let count = 0;
        r.onsuccess = () => { for (const row of r.result) if (row.id === id) { count++; if (remove) store.delete([row.owner, row.id]); } };
        tx.oncomplete = () => resolve(count); tx.onerror = () => reject(tx.error);
      }); } finally { db.close(); }
    }, { id, remove });
    await queued(true);
    if (mixed) await page.evaluate(async ({ id, payload }) => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open("kynotes-web", 7); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
      try { await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(["notes", "pending"], "readwrite"), all = tx.objectStore("notes").getAll();
        all.onsuccess = () => { for (const row of all.result) if (row.id === id) {
          delete row.unsent; tx.objectStore("notes").put(row);
          tx.objectStore("pending").put({ ...row, payload: new Uint8Array(payload), updatedAt: "", conflicted: true });
        } };
        tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
      }); } finally { db.close(); }
    }, { id, payload: Array.from(first.request().postDataBuffer()!) });
    let writes = 0;
    page.on("request", request => { if (request.url() === url && request.method() === "PUT") writes++; });
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Notebook options" }).click();
    await withDialog(owner, { type: "confirm", text: `The export is not encrypted: anyone who gets the file can read these notes and attachments.\n\nExport "${name}"?` }, () => page.getByRole("button", { name: "Export notebook", exact: true }).click());
    const file = await download, path = await file.path();
    if (!path) throw new Error("missing export");
    expect((await readFile(path)).includes(Buffer.from("Unqueued export draft"))).toBe(true);
    expect.soft(await queued()).toBe(mixed ? 1 : 0);
    await page.waitForTimeout(16_000); // Cover an actual periodic drain after export.
    expect(writes).toBe(0);
    expect(await queued()).toBe(mixed ? 1 : 0);
  } finally { if (second && !second.isClosed()) await second.close(); await admin.page.context().close(); await page.context().close(); }
});

}

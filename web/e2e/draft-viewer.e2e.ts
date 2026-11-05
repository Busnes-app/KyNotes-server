import { expect, test } from "@playwright/test";
import { adminConsole, adminSection, approve, createTeamFor, createUser, nameTeam, OWNER, person, signIn, signInAndChoose, withDialog } from "./people";

test("a viewer can read the latest mixed legacy cache without uploading it", async ({ browser }) => {
  const admin = await person(browser), owner = await person(browser), reader = await person(browser);
  try {
    await adminConsole(admin.page); await signIn(owner.page, OWNER.username, OWNER.password);
    const username = "mixed-cache-viewer", temporary = "temporary horse battery staple";
    await createUser(admin, username, temporary); await signInAndChoose(reader.page, username, temporary, OWNER.password);
    const teamID = await createTeamFor(admin, OWNER.username); await nameTeam(owner, teamID, "Viewer mixed drafts");
    await adminSection(admin.page, "Teams"); await admin.page.getByRole("combobox", { name: "Team", exact: true }).selectOption(teamID);
    const who = admin.page.getByRole("combobox", { name: "Person", exact: true });
    await who.selectOption((await who.locator("option", { hasText: new RegExp(`^${username}$`) }).getAttribute("value"))!);
    await admin.page.getByRole("combobox", { name: "Role", exact: true }).selectOption("viewer");
    await withDialog(admin, { type: "alert", text: "Person added. They get the team's keys once one of its owners approves them." }, () => admin.page.getByRole("button", { name: "Add to team" }).click());
    await owner.page.reload(); await approve(owner, username);
    await expect(owner.page.getByRole("button", { name: "New page", exact: true })).toBeEnabled();
    const created = owner.page.waitForResponse(r => r.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(r.url()) && r.ok());
    await owner.page.getByRole("button", { name: "New page", exact: true }).click(); const first = await created;
    const url = first.url(), id = new URL(url).pathname.split("/").at(-1)!;
    await owner.page.route(url, async route => { if (route.request().method() === "PUT") await new Promise<void>(() => {}); else await route.fallback(); });
    const cached = () => owner.page.evaluate(async id => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open("kynotes-web", 7); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
      try { return await new Promise<{ id: string; containerID: string; version: number; keyGeneration: number; payload: number[]; updatedAt: string; unsent?: boolean }>(resolve => {
        const r = db.transaction("notes").objectStore("notes").getAll(); r.onsuccess = () => { const row = r.result.find((n: { id: string }) => n.id === id); resolve({ ...row, payload: Array.from(row.payload) }); };
      }); } finally { db.close(); }
    }, id);
    const old = await cached(); await owner.page.locator(".title-input").fill("Latest viewer local text");
    await expect.poll(async () => (await cached()).payload.join(",")).not.toBe(old.payload.join(","));
    const latest = await cached(); await owner.page.close();
    await reader.page.goto(`/#/${teamID}`);
    await expect(reader.page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    const readerID: string = await reader.page.evaluate(async () => (await (await fetch("/api/v1/auth/session")).json()).user.id);
    await reader.page.goto("/healthz");
    await reader.page.evaluate(async ({ latest, old, readerID }) => {
      const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open("kynotes-web", 7); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
      try { await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(["notes", "pending"], "readwrite");
        const copy = { ...latest, owner: readerID, payload: new Uint8Array(latest.payload) }; delete copy.unsent;
        tx.objectStore("notes").put(copy);
        tx.objectStore("pending").put({ ...copy, payload: new Uint8Array(old.payload), updatedAt: "" });
        tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
      }); } finally { db.close(); }
    }, { latest, old, readerID });
    let writes = 0; reader.page.on("request", r => { if (r.method() === "PUT" && r.url() === url) writes++; });
    await reader.page.goto(`/#/${teamID}/quick/${id}`);
    await expect(reader.page.locator(".title-input")).toHaveValue("Latest viewer local text");
    await expect(reader.page.locator(".title-input")).toHaveAttribute("readonly", "");
    await reader.page.waitForTimeout(16_000); // Actual periodic drain; no fake time.
    expect(writes).toBe(0);
    await reader.page.reload(); await expect(reader.page.locator(".title-input")).toHaveValue("Latest viewer local text");
    expect(writes).toBe(0);
  } finally { for (const who of [admin, owner, reader]) await who.page.context().close(); }
});

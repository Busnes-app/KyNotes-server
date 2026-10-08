import { readFileSync } from "node:fs";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { decryptObject, fromBase64, legacyKeyRef, type KeyRef } from "../src/crypto";
import { envelopeSender, unwrapEnvelope } from "../src/teamKeys";

// Three people in three isolated browser contexts (cookies and IndexedDB apart).
const TEMPORARY = "temporary horse battery staple";
const OWN = "my own horse battery staple";
const TEAM = "Team Keys E2E";
const WAITING = "Waiting for a team owner to share this notebook's keys. It is read-only until then.";

type Dialog = { type: string; text: string; answer?: string };
type Person = { page: Page; expected: Dialog[]; unexpected: string[] };

/** Every dialog must be announced with expectDialog; anything else (a fingerprint change included) fails the run. */
async function person(browser: Browser): Promise<Person> {
  const page = await (await browser.newContext()).newPage();
  const who: Person = { page, expected: [], unexpected: [] };
  page.on("dialog", (dialog) => {
    const next = who.expected[0];
    if (next && dialog.type() === next.type && dialog.message() === next.text) {
      who.expected.shift();
      void dialog.accept(next.answer);
      return;
    }
    who.unexpected.push(`${dialog.type()}: ${dialog.message()}`);
    void dialog.dismiss();
  });
  return who;
}

async function withDialog(who: Person, dialog: Dialog, action: () => Promise<unknown>) {
  who.expected.push(dialog);
  await action();
  await expect.poll(() => who.expected.length, { message: `dialog not shown: ${dialog.text}` }).toBe(0);
}

async function signIn(page: Page, username: string, password: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Unlock KyNotes" }).click();
  await expect(page.getByRole("button", { name: "Settings" })).toBeVisible();
}

/** An administrator-set password blocks the identity; the user's own change creates it. */
async function takeOverPassword(page: Page) {
  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByLabel("Current password").fill(TEMPORARY);
  await page.getByLabel("New password", { exact: true }).fill(OWN);
  await page.getByLabel("Confirm new password").fill(OWN);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Change password" }).click();
  await expect.poll(() => vaultOf(page), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });
  await page.getByRole("button", { name: "← Workspace" }).click();
}

type Vault = { authSecret: string; identity?: { deviceId: string; publicKey: number[]; privateKey: number[] } };

/** This browser's keys vault record (P1 stores the identity unwrapped). Never creates the database. */
function vaultOf(page: Page) {
  return page.evaluate(() => new Promise<Vault | null>((resolve) => {
    const open = indexedDB.open("kynotes-web");
    open.onupgradeneeded = () => open.transaction!.abort(); // not created yet: leave it to the app
    open.onerror = () => resolve(null);
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("keys")) { db.close(); resolve(null); return; }
      const all = db.transaction("keys").objectStore("keys").getAll();
      all.onsuccess = () => {
        db.close();
        const row = (all.result as Array<{ authSecret: string; identity?: { deviceId: string; publicKey: Uint8Array; privateKey: Uint8Array } }>)[0];
        if (!row) { resolve(null); return; }
        const identity = row.identity && { deviceId: row.identity.deviceId, publicKey: [...row.identity.publicKey], privateKey: [...row.identity.privateKey] };
        resolve({ authSecret: row.authSecret, identity });
      };
    };
  }));
}

/**
 * The team is each person's only notebook, so a fresh load opens it. Waiting for the route
 * the load writes on completion keeps a click from starting a second, overlapping load.
 */
async function openTeam(page: Page, name = TEAM) {
  await page.goto("/");
  await page.waitForURL(/#\/cnt_/);
  await expect(page.getByRole("button", { name })).toBeVisible();
  await expect(page.locator(".workspace-title")).toHaveText(name);
}

const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());

async function writePage(page: Page, title: string, comment: string) {
  const created = objectSave(page);
  await page.getByRole("button", { name: "New page" }).click();
  await created;
  const titled = objectSave(page);
  await page.locator(".title-input").fill(title);
  await titled;
  await page.getByPlaceholder("Add a comment…").fill(comment);
  await page.getByRole("button", { name: "Comment", exact: true }).click();
  await expect(page.getByText(comment)).toBeVisible();
}

async function readPage(page: Page, title: string, comments: string[]) {
  await page.locator(".note-row", { hasText: title }).click();
  await expect(page.locator(".title-input")).toHaveValue(title);
  for (const comment of comments) await expect(page.getByText(comment)).toBeVisible();
}

async function addToTeam(owner: Person, username: string) {
  const { page } = owner;
  await page.getByRole("button", { name: "Admin" }).click();
  const team = page.getByRole("combobox", { name: "Team", exact: true });
  await team.selectOption({ index: 1 });
  const person = page.getByRole("combobox", { name: "Person", exact: true });
  await person.selectOption((await person.locator("option", { hasText: username }).first().getAttribute("value"))!);
  await withDialog(owner, { type: "alert", text: "Person added to team." }, () => page.getByRole("button", { name: "Add to team" }).click());
  await page.getByRole("button", { name: "← Workspace" }).click();
}

const containerOf = (page: Page) => /#\/(cnt_[0-9a-z]+)/.exec(page.url())![1];

/** The server's bytes and generation for a page, read through page's session. */
async function serverCopy(page: Page, title: string) {
  const id = await page.locator(".note-row", { hasText: title }).getAttribute("data-page-id");
  return page.evaluate(async (oid) => {
    const response = await fetch(`/api/v1/objects/${oid}`);
    return { id: oid, version: Number(response.headers.get("X-Kynotes-Version")), generation: Number(response.headers.get("X-Kynotes-Key-Generation")), bytes: [...new Uint8Array(await response.arrayBuffer())] };
  }, id!);
}

/**
 * The container keys page's own envelopes open to, by generation. The sender key comes from the
 * identities the three browsers hold, never from the server, so a substituted sender fails here.
 */
async function heldKeys(page: Page, cid: string, senders: Map<string, Uint8Array>): Promise<Map<number, KeyRef>> {
  const own = (await vaultOf(page))!.identity!;
  const rows = await page.evaluate(async (id) => (await fetch(`/api/v1/containers/${id}/envelopes`)).json(), cid) as Array<{ deviceId: string; keyGeneration: number; envelope: string }>;
  return new Map(rows.filter((row) => row.deviceId === own.deviceId).map((row) => {
    const envelope = fromBase64(row.envelope);
    const sender = senders.get(envelopeSender(envelope));
    if (!sender) throw new Error(`envelope from an unknown sender ${envelopeSender(envelope)}`);
    return [row.keyGeneration, unwrapEnvelope(envelope, Uint8Array.from(own.privateKey), cid, row.keyGeneration, own.deviceId, sender)];
  }));
}

const titleOf = (key: KeyRef, cid: string, bytes: number[]) => decryptObject(key, cid, Uint8Array.from(bytes)).then((payload) => payload?.title);

test("team keys: three people share, a removed member loses new content", async ({ browser }) => {
  const owner = await person(browser);
  const editor = await person(browser);
  const newcomer = await person(browser);
  try {
    await scenario(owner, editor, newcomer);
  } finally {
    // An unexpected dialog (a fingerprint change, an error alert) is the root cause of whatever failed after it.
    for (const who of [owner, editor, newcomer]) expect(who.unexpected).toEqual([]);
  }
});

async function scenario(owner: Person, editor: Person, newcomer: Person) {
  // Owner: first-run setup (its own password, so its identity exists at once), then accounts.
  await owner.page.goto("/");
  await owner.page.getByLabel("Administrator Username").fill("owner");
  await owner.page.getByLabel("Master Password").fill(OWN);
  await owner.page.getByLabel("Confirm Password").fill(OWN);
  await owner.page.getByRole("button", { name: "Initialize KyNotes" }).click();
  await expect.poll(() => vaultOf(owner.page), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });
  await owner.page.getByRole("button", { name: "Admin" }).click();
  for (const name of ["editor", "newcomer"]) {
    await owner.page.getByPlaceholder("Username").fill(name);
    await owner.page.getByPlaceholder("Temporary password").fill(TEMPORARY);
    await owner.page.getByRole("button", { name: "Create user" }).click();
    await expect(owner.page.getByRole("combobox", { name: "Person", exact: true })).toContainText(name);
  }
  await withDialog(owner, { type: "prompt", text: "Team name", answer: TEAM }, () => owner.page.getByRole("button", { name: "Create team" }).click());
  await expect(owner.page.getByRole("combobox", { name: "Team", exact: true })).toContainText(TEAM);
  await owner.page.getByRole("button", { name: "← Workspace" }).click();

  for (const [who, name] of [[editor, "editor"], [newcomer, "newcomer"]] as const) {
    await signIn(who.page, name, TEMPORARY);
    await takeOverPassword(who.page);
  }
  // Envelope senders are checked against the identities these browsers hold.
  const senders = new Map<string, Uint8Array>();
  for (const who of [owner, editor, newcomer]) {
    const identity = (await vaultOf(who.page))!.identity!;
    senders.set(identity.deviceId, Uint8Array.from(identity.publicKey));
  }

  // Owner opens the team with every member keyed: the first key is minted and the name re-sealed.
  await addToTeam(owner, "editor");
  await openTeam(owner.page);
  await expect(owner.page.getByText(/not end-to-end shared yet/)).toHaveCount(0);
  await expect(owner.page.getByText(WAITING)).toHaveCount(0);
  await writePage(owner.page, "Owner page", "owner comment");
  await owner.page.locator('input[type="file"]').setInputFiles({ name: "evidence.txt", mimeType: "text/plain", buffer: Buffer.from("shared attachment bytes") });
  await expect(owner.page.getByRole("button", { name: /evidence\.txt/ })).toBeVisible();
  const cid = containerOf(owner.page);

  // The server holds the owner's row under the container key, not the owner's login-derived key.
  const ownerKeys = await heldKeys(owner.page, cid, senders);
  const ownerCopy = await serverCopy(owner.page, "Owner page");
  expect(ownerCopy.generation).toBeGreaterThan(0);
  await expect(titleOf(legacyKeyRef((await vaultOf(owner.page))!.authSecret), cid, ownerCopy.bytes)).rejects.toThrow();
  await expect(titleOf(ownerKeys.get(ownerCopy.generation)!, cid, ownerCopy.bytes)).resolves.toBe("Owner page");

  // Editor reads the owner's page, comment and attachment, and writes back.
  await openTeam(editor.page);
  await readPage(editor.page, "Owner page", ["owner comment"]);
  const download = editor.page.waitForEvent("download");
  await editor.page.getByRole("button", { name: /evidence\.txt/ }).click();
  expect(readFileSync(await (await download).path()).toString()).toBe("shared attachment bytes");
  await writePage(editor.page, "Editor page", "editor comment");

  // The editor's row too: its container key opens it, the editor's login-derived key does not.
  const editorKeys = await heldKeys(editor.page, cid, senders);
  const editorCopy = await serverCopy(editor.page, "Editor page");
  expect(editorCopy.generation).toBe(ownerCopy.generation);
  await expect(titleOf(legacyKeyRef((await vaultOf(editor.page))!.authSecret), cid, editorCopy.bytes)).rejects.toThrow();
  await expect(titleOf(editorKeys.get(editorCopy.generation)!, cid, editorCopy.bytes)).resolves.toBe("Editor page");
  await expect(titleOf(ownerKeys.get(editorCopy.generation)!, cid, editorCopy.bytes)).resolves.toBe("Editor page");

  // A tab from before shared keys (no key-scheme header) cannot write a shared row.
  const ownerPage = await serverCopy(editor.page, "Owner page");
  const stale = await editor.page.evaluate(async (copy) => {
    const csrf = document.cookie.split("; ").find((value) => value.startsWith("csrf_token="))?.slice(11) ?? "";
    const response = await fetch(`/api/v1/objects/${copy.id}`, {
      method: "PUT",
      body: new Uint8Array(copy.bytes),
      headers: { "Content-Type": "application/octet-stream", "X-CSRF-Token": csrf, "X-Kynotes-Base-Version": String(copy.version), "X-Kynotes-Key-Generation": String(copy.generation) },
    });
    return { status: response.status, body: await response.text() };
  }, ownerPage);
  expect(stale.status).toBe(409);
  expect(stale.body).toContain("this notebook uses shared keys");

  // Newcomer joins after content exists. Until a steward opens the team it waits, read-only.
  await addToTeam(owner, "newcomer");
  await owner.page.goto("about:blank"); // no owner tab runs the 90-second key refresh meanwhile
  // Its name is sealed with a key the newcomer does not hold yet: the fallback label shows.
  await openTeam(newcomer.page, `Notebook ${cid.slice(4, 10)}`);
  await expect(newcomer.page.getByText(WAITING)).toBeVisible();
  await expect(newcomer.page.getByRole("button", { name: "New page" })).toBeDisabled();
  await expect(newcomer.page.getByRole("button", { name: "New section or group" })).toBeDisabled();
  // The owner's next open wraps every held generation for the newcomer: history included.
  await openTeam(owner.page);
  await openTeam(newcomer.page);
  await expect(newcomer.page.getByText(WAITING)).toHaveCount(0);
  await readPage(newcomer.page, "Owner page", ["owner comment"]);
  await readPage(newcomer.page, "Editor page", ["editor comment"]);
  const newcomerKeys = await heldKeys(newcomer.page, cid, senders);
  const before = await serverCopy(owner.page, "Owner page");
  await expect(titleOf(newcomerKeys.get(before.generation)!, cid, before.bytes)).resolves.toBe("Owner page");

  // Remove the newcomer; the owner's browser re-mints at once, before anyone writes.
  const newcomerDevice = (await vaultOf(newcomer.page))!.identity!.deviceId;
  await withDialog(owner, { type: "confirm", text: "Remove this person from the team?" }, () =>
    owner.page.locator(".member-row", { hasText: "newcomer" }).getByRole("button", { name: "Remove" }).click());
  await expect(owner.page.locator(".member-row", { hasText: "newcomer" })).toHaveCount(0);
  // Removal retires generation N (N+1 stays empty); the re-mint fills N+2 for the remaining members only.
  const reminted = await owner.page.evaluate(async (id) => {
    const listed = await (await fetch("/api/v1/containers")).json() as Array<{ id: string; keyGeneration: number }>;
    const rows = await (await fetch(`/api/v1/containers/${id}/envelopes`)).json() as Array<{ deviceId: string; keyGeneration: number }>;
    return { generation: listed.find((entry) => entry.id === id)!.keyGeneration, rows };
  }, cid);
  expect(reminted.generation).toBe(before.generation + 2);
  const atNew = reminted.rows.filter((row) => row.keyGeneration === reminted.generation).map((row) => row.deviceId);
  expect(atNew.sort()).toEqual([...senders.keys()].filter((device) => device !== newcomerDevice).sort());
  await writePage(owner.page, "After removal", "after comment");
  const after = await serverCopy(owner.page, "After removal");
  expect(after.generation).toBeGreaterThan(before.generation);
  await expect(titleOf((await heldKeys(owner.page, cid, senders)).get(after.generation)!, cid, after.bytes)).resolves.toBe("After removal");
  // Forward secrecy: none of the newcomer's keys opens content written after the removal.
  expect(newcomerKeys.has(after.generation)).toBe(false);
  for (const key of newcomerKeys.values()) await expect(titleOf(key, cid, after.bytes)).rejects.toThrow();

  // The newcomer no longer sees the team; the editor reads the new content with the new key.
  expect(await newcomer.page.evaluate(async (id) => (await fetch(`/api/v1/containers/${id}/envelopes`)).status, cid)).toBe(404);
  const listed = newcomer.page.waitForResponse((response) => response.url().endsWith("/api/v1/containers") && response.ok());
  await newcomer.page.goto("/");
  expect(await (await listed).text()).not.toContain(cid);
  await expect(newcomer.page.getByText("Select a notebook")).toBeVisible();
  await expect(newcomer.page.getByRole("button", { name: /Team Keys E2E|Notebook / })).toHaveCount(0);
  await openTeam(editor.page);
  await readPage(editor.page, "After removal", ["after comment"]);
  await readPage(editor.page, "Owner page", ["owner comment"]);
}

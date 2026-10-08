import { readFileSync } from "node:fs";
import { expect, test, type Browser, type Locator, type Page } from "@playwright/test";
import { decryptObject, encryptNote, fromBase64, legacyKeyRef, type KeyRef } from "../src/crypto";
import { envelopeSender, unwrapEnvelope } from "../src/teamKeys";

// Three people in three isolated browser contexts (cookies and IndexedDB apart).
const TEMPORARY = "temporary horse battery staple";
const OWN = "my own horse battery staple";
const TEAM = "Team Keys E2E";
const WAITING = "This notebook is read-only until its keys reach this browser.";

/** decline: dismiss it (a confirm answered Cancel); otherwise it is accepted with answer. */
type Dialog = { type: string; text: string | RegExp; answer?: string; decline?: boolean; seen?: (defaultValue: string, message: string) => void };
type Person = { page: Page; expected: Dialog[]; unexpected: string[] };

/** Every dialog must be announced with expectDialog; anything else (a fingerprint change included) fails the run. */
async function person(browser: Browser): Promise<Person> {
  const page = await (await browser.newContext()).newPage();
  const who: Person = { page, expected: [], unexpected: [] };
  page.on("dialog", (dialog) => {
    const next = who.expected[0];
    const matches = next && dialog.type() === next.type && (typeof next.text === "string" ? dialog.message() === next.text : next.text.test(dialog.message()));
    if (matches) {
      who.expected.shift();
      next.seen?.(dialog.defaultValue(), dialog.message());
      void (next.decline ? dialog.dismiss() : dialog.accept(next.answer));
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
/** On Settings: the acknowledgement appears only while a notebook may still hold login-key items. */
async function changeOwnPassword(page: Page, current: string, next: string) {
  await page.getByLabel("Current password").fill(current);
  await page.getByLabel("New password", { exact: true }).fill(next);
  await page.getByLabel("Confirm new password").fill(next);
  const ack = page.getByRole("checkbox");
  if (await ack.isVisible()) await ack.check();
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByText("Password changed.")).toBeVisible();
}

async function takeOverPassword(page: Page) {
  await page.getByRole("button", { name: "Settings" }).click();
  await changeOwnPassword(page, TEMPORARY, OWN);
  await expect.poll(() => vaultOf(page), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });
  await page.getByRole("button", { name: "← Workspace" }).click();
}

type Vault = { authSecret: string; sealed: boolean; extractable?: boolean; identity?: { deviceId: string; publicKey: number[]; privateKey: number[] } };

/** This browser's keys vault record; a sealed identity is opened in the page with its device key. Never creates the database. */
function vaultOf(page: Page) {
  return page.evaluate(() => new Promise<Vault | null>((resolve, reject) => {
    const open = indexedDB.open("kynotes-web");
    open.onupgradeneeded = () => open.transaction!.abort(); // not created yet: leave it to the app
    open.onerror = () => resolve(null);
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("keys")) { db.close(); resolve(null); return; }
      const all = db.transaction("keys").objectStore("keys").getAll();
      all.onsuccess = async () => {
        db.close();
        type Stored = { userID: string; deviceId: string; publicKey: Uint8Array; privateKey?: Uint8Array; sealed?: Uint8Array; deviceKey?: CryptoKey };
        const row = (all.result as Array<{ authSecret: string; identity?: Stored }>)[0];
        if (!row) { resolve(null); return; }
        const stored = row.identity;
        if (!stored) { resolve({ authSecret: row.authSecret, sealed: false }); return; }
        try {
          const privateKey = stored.sealed && stored.deviceKey
            ? new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: stored.sealed.slice(0, 12), additionalData: new TextEncoder().encode(`kynotes/device-identity/v1|${stored.userID}|${stored.deviceId}`) }, stored.deviceKey, stored.sealed.slice(12)))
            : stored.privateKey!;
          resolve({ authSecret: row.authSecret, sealed: Boolean(stored.sealed), extractable: stored.deviceKey?.extractable, identity: { deviceId: stored.deviceId, publicKey: [...stored.publicKey], privateKey: [...privateKey] } });
        } catch (error) { reject(error); }
      };
    };
  }));
}

/** Removes the identity from this browser's vault, as on a browser that never held it. */
const dropVaultIdentity = (page: Page) => page.evaluate(() => new Promise<void>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const tx = open.result.transaction("keys", "readwrite");
    const store = tx.objectStore("keys");
    const all = store.getAll();
    all.onsuccess = () => { for (const row of all.result as Array<Record<string, unknown>>) { delete row.identity; store.put(row); } };
    tx.oncomplete = () => { open.result.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  };
}));

/** Reloads the app on cid (default: the first notebook) and waits until that load has finished. */
async function openTeam(page: Page, name = TEAM, cid?: string) {
  await page.goto("about:blank");
  await page.goto(cid ? `/#/${cid}` : "/");
  await expect(page.locator(".workspace-title")).toHaveText(name);
  await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
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

async function addToTeam(owner: Person, username: string, teamID?: string) {
  const { page } = owner;
  await page.getByRole("button", { name: "Admin" }).click();
  const team = page.getByRole("combobox", { name: "Team", exact: true });
  // Options read "<name> · <id>": select by value.
  await team.selectOption(teamID ?? { index: 1 });
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

const SECOND = "Second Team E2E";
const listed = (page: Page) => page.evaluate(async () => ((await (await fetch("/api/v1/containers")).json()) as Array<{ id: string }>).map((entry) => entry.id));

/** This person's own user ID and fingerprint, as their Settings shows them. */
async function ownSettings(page: Page) {
  await page.getByRole("button", { name: "Settings" }).click();
  const code = async (label: RegExp) => (await page.locator("p", { hasText: label }).locator("code").first().textContent())!.trim();
  const values = { userId: await code(/Your user ID/), fingerprint: await code(/Your encryption key fingerprint/) };
  await page.getByRole("button", { name: "← Workspace" }).click();
  return values;
}

/** From the open team, invites userId; returns the link and the message of the link dialog. */
async function inviteFrom(owner: Person, userId: string, carries: RegExp) {
  const shown = { link: "", message: "" };
  owner.expected.push({ type: "prompt", text: /^User ID to invite/, answer: userId });
  await withDialog(owner, { type: "prompt", text: new RegExp(`${carries.source}.*Send this link to the person you invited`, "s"), seen: (value, message) => Object.assign(shown, { link: value, message }) }, () =>
    owner.page.getByRole("button", { name: /Add person/ }).click());
  return shown;
}

/** Opens an invitation link in a fresh load and joins; the token must leave the address bar. */
async function join(who: Person, link: string) {
  await who.page.goto("about:blank");
  await who.page.goto(link);
  await expect(who.page).not.toHaveURL(/invite/);
  await who.page.getByRole("button", { name: "Join team" }).click();
  await expect(who.page.getByText("You joined the team.")).toBeVisible();
}

const REFUSED = "This invitation is no longer valid: it expired, was already used, is for another account, or its sender can no longer invite.";
const stashed = (page: Page) => page.evaluate(() => sessionStorage.getItem("kynotes-invitation"));

const titleOf = (key: KeyRef, cid: string, bytes: number[]) => decryptObject(key, cid, Uint8Array.from(bytes)).then((payload) => payload?.title);

test("team keys: three people share, a removed member loses new content", async ({ browser }) => {
  const owner = await person(browser);
  const editor = await person(browser);
  const newcomer = await person(browser);
  // A fourth browser where an invitation link is opened and then another account signs in.
  const shared = await person(browser);
  // A second browser of the editor's account, linked from the editor's browser.
  const second = await person(browser);
  try {
    await scenario(owner, editor, newcomer, shared, second);
  } finally {
    // An unexpected dialog (a fingerprint change, an error alert) is the root cause of whatever failed after it.
    for (const who of [owner, editor, newcomer, shared, second]) expect(who.unexpected).toEqual([]);
  }
});

async function scenario(owner: Person, editor: Person, newcomer: Person, shared: Person, second: Person) {
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
  await p3b(owner, editor, newcomer, shared, cid, senders);
  await p3c(editor, second, cid, senders);
  await p4(owner, editor, second, senders);
}

async function p3b(owner: Person, editor: Person, newcomer: Person, shared: Person, cid: string, senders: Map<string, Uint8Array>) {
  const ownerOwn = await ownSettings(owner.page);
  const editorOwn = await ownSettings(editor.page);
  const newcomerOwn = await ownSettings(newcomer.page);
  const ownerDevice = (await vaultOf(owner.page))!.identity!.deviceId;

  // 1. A second team whose invitation carries its key: the editor reads it before any owner reopens it.
  const before = await listed(owner.page);
  await owner.page.getByRole("button", { name: "Admin" }).click();
  await withDialog(owner, { type: "prompt", text: "Team name", answer: SECOND }, () => owner.page.getByRole("button", { name: "Create team" }).click());
  await expect(owner.page.getByRole("combobox", { name: "Team", exact: true })).toContainText(SECOND);
  await owner.page.getByRole("button", { name: "← Workspace" }).click();
  const second = (await listed(owner.page)).find((id) => !before.includes(id))!;
  await openTeam(owner.page, SECOND, second); // the only member: the first key is minted here
  await writePage(owner.page, "Second page", "second comment");
  const sealed = await inviteFrom(owner, editorOwn.userId, /The invitation carries this team's keys, sealed for the key with fingerprint/);
  expect(sealed.message).toContain(editorOwn.fingerprint);
  await owner.page.goto("about:blank"); // no owner tab can sweep meanwhile

  // Another account signs in where the link was opened: it is refused, the banner goes, and it gains nothing.
  await shared.page.goto(sealed.link);
  await expect(shared.page).not.toHaveURL(/invite/);
  await signIn(shared.page, "newcomer", OWN);
  await shared.page.getByRole("button", { name: "Join team" }).click();
  await expect(shared.page.getByText(REFUSED)).toBeVisible();
  await expect(shared.page.getByRole("button", { name: "Join team" })).toHaveCount(0);
  expect(await stashed(shared.page)).toBeNull();
  expect(await listed(shared.page)).not.toContain(second);
  await shared.page.reload();
  await expect(shared.page.getByRole("button", { name: "Settings" })).toBeVisible();
  await expect(shared.page.getByRole("button", { name: "Join team" })).toHaveCount(0);
  await shared.page.context().close();

  // The refusal did not use the invitation up: the invitee still joins with it.
  await join(editor, sealed.link);
  await openTeam(editor.page, SECOND, second);
  await expect(editor.page.getByText(WAITING)).toHaveCount(0);
  await readPage(editor.page, "Second page", ["second comment"]);
  const fromInvitation = await editor.page.evaluate(async (id) => (await fetch(`/api/v1/containers/${id}/envelopes`)).json(), second) as Array<{ deviceId: string; envelope: string }>;
  const editorDevice = (await vaultOf(editor.page))!.identity!.deviceId;
  expect(fromInvitation.filter((row) => row.deviceId === editorDevice).map((row) => envelopeSender(fromBase64(row.envelope)))).toEqual([ownerDevice]);
  expect((await heldKeys(editor.page, second, senders)).size).toBe(1);
  await openTeam(owner.page, SECOND, second);
  await expect(owner.page.locator(".member-row", { hasText: "editor" })).toContainText("has key");

  // An invitation issued before a removal cannot undo it.
  const stale = await inviteFrom(owner, editorOwn.userId, /The invitation carries/);
  await withDialog(owner, { type: "confirm", text: "Remove this person from the team?" }, () =>
    owner.page.locator(".member-row", { hasText: "editor" }).getByRole("button", { name: "Remove" }).click());
  await expect(owner.page.locator(".member-row", { hasText: "editor" })).toHaveCount(0);
  await owner.page.goto("about:blank");
  await editor.page.goto("about:blank");
  await editor.page.goto(stale.link);
  await editor.page.getByRole("button", { name: "Join team" }).click();
  await expect(editor.page.getByText(REFUSED)).toBeVisible();
  expect(await listed(editor.page)).not.toContain(second);

  // 2. The removed newcomer is invited back (reactivated, not 409), waits, asks, and gets keys from the sweep.
  await openTeam(owner.page, TEAM, cid);
  const back = await inviteFrom(owner, newcomerOwn.userId, /The invitation carries no keys: you cannot see this person's encryption key yet/);
  await owner.page.goto("about:blank");
  // Pasted into the tab already running KyNotes: no reload, the token leaves the address bar, the banner offers it.
  await expect(newcomer.page.locator(".workspace-title")).toBeVisible();
  await newcomer.page.evaluate(() => { (window as unknown as { sameTab: boolean }).sameTab = true; });
  await newcomer.page.evaluate((link) => { location.href = link; }, back.link);
  await expect(newcomer.page).not.toHaveURL(/invite/);
  await newcomer.page.getByRole("button", { name: "Join team" }).click();
  await expect(newcomer.page.getByText("You joined the team.")).toBeVisible();
  expect(await newcomer.page.evaluate(() => (window as unknown as { sameTab?: boolean }).sameTab)).toBe(true);
  await openTeam(newcomer.page, `Notebook ${cid.slice(4, 10)}`, cid);
  await expect(newcomer.page.getByText(WAITING)).toBeVisible();
  let request = "";
  await withDialog(newcomer, { type: "prompt", text: new RegExp(`^Send this to ${ownerOwn.userId} · owner\\.`), seen: (value) => { request = value; } }, () =>
    newcomer.page.getByRole("button", { name: "Ask an owner" }).click());
  expect(request).toContain(newcomerOwn.fingerprint);
  expect(request).toContain(`#/${cid}`);
  await openTeam(editor.page, TEAM, cid);
  await expect(editor.page.locator(".member-row", { hasText: "newcomer" })).toContainText("waiting for key");
  await openTeam(owner.page, TEAM, cid); // the sweep wraps the current key and history
  await expect(owner.page.locator(".member-row", { hasText: "newcomer" })).toContainText("has key");
  await openTeam(newcomer.page, TEAM, cid);
  await readPage(newcomer.page, "After removal", ["after comment"]);

  // 3. A reset deletes the newcomer's identity: members see it has none.
  await owner.page.getByRole("button", { name: "Admin" }).click();
  const users = owner.page.locator("#users");
  await users.getByLabel("Confirm your password").fill(OWN);
  await users.getByRole("button", { name: "Authorize user creation and password resets" }).click();
  await expect(users.getByText("Password confirmed for ten minutes.")).toBeVisible();
  owner.expected.push({ type: "prompt", text: "New temporary password for newcomer", answer: TEMPORARY });
  await withDialog(owner, { type: "alert", text: /^Password reset\./ }, () =>
    owner.page.locator(".admin-user", { hasText: "newcomer" }).getByRole("button", { name: "Reset password" }).click());
  await owner.page.goto("about:blank");
  await openTeam(editor.page, TEAM, cid);
  await expect(editor.page.locator(".member-row", { hasText: "newcomer" })).toContainText("no encryption key yet");
  const oldDevice = (await vaultOf(newcomer.page))!.identity!.deviceId;
  await signIn(newcomer.page, "newcomer", TEMPORARY);
  await takeOverPassword(newcomer.page);
  // The vault keeps the old identity until the new one is stored: wait for the new device.
  await expect.poll(async () => (await vaultOf(newcomer.page))?.identity?.deviceId, { timeout: 30_000 }).not.toBe(oldDevice);
  const renewed = await ownSettings(newcomer.page);
  expect(renewed.fingerprint).not.toBe(newcomerOwn.fingerprint);

  // An invitation never seals to a changed key the owner declined: it carries no keys.
  await openTeam(owner.page, SECOND, second);
  owner.expected.push({ type: "prompt", text: /^User ID to invite/, answer: newcomerOwn.userId });
  owner.expected.push({ type: "confirm", text: new RegExp(`^The encryption key of ${newcomerOwn.userId} · newcomer changed since this browser last saw it\\.[\\s\\S]*${renewed.fingerprint} \\(was ${newcomerOwn.fingerprint}\\)`), decline: true });
  await withDialog(owner, { type: "prompt", text: /^The invitation carries no keys: you did not confirm this person's new encryption key\. Send this link/ }, () =>
    owner.page.getByRole("button", { name: /Add person/ }).click());

  // 4. The owner re-trusts the new key in Settings, outside any wrap prompt (opened on the second team, where no wrap targets the newcomer).
  await openTeam(owner.page, SECOND, second);
  await owner.page.getByRole("button", { name: "Settings" }).click();
  const pin = owner.page.locator(".pin-row", { hasText: "newcomer" });
  await expect(pin).toContainText(newcomerOwn.fingerprint);
  await expect(pin).toContainText(renewed.fingerprint);
  await expect(owner.page.locator(".pin-row", { hasText: "editor" })).toContainText(editorOwn.fingerprint);
  await withDialog(owner, { type: "confirm", text: new RegExp(`^Trust the new encryption key of ${newcomerOwn.userId} · newcomer\\?`) }, () => pin.getByRole("button", { name: "Trust new key" }).click());
  await expect(pin).toContainText("matches the server");
  // No fingerprint dialog may appear now (unexpected dialogs fail the run): the sweep wraps for the new key.
  await openTeam(owner.page, TEAM, cid);
  await expect(owner.page.locator(".member-row", { hasText: "newcomer" })).toContainText("has key");
  await openTeam(newcomer.page, TEAM, cid);
  await readPage(newcomer.page, "Owner page", ["owner comment"]);

  // 5. An edit stranded on the device for a notebook this account cannot open: exported, then discarded.
  const lost = `cnt_${"z".repeat(26)}`;
  const stranded = await encryptNote(legacyKeyRef((await vaultOf(newcomer.page))!.authSecret), lost, { type: "page", title: "Stranded edit", body: "[]" });
  // Stamped with its account, as the app queues every edit: only those may be discarded.
  await newcomer.page.evaluate(({ container, bytes, owner }) => new Promise<void>((resolve, reject) => {
    const open = indexedDB.open("kynotes-web");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction("pending", "readwrite");
      tx.objectStore("pending").put({ id: `obj_${"z".repeat(26)}`, containerID: container, version: 1, payload: new Uint8Array(bytes), updatedAt: new Date().toISOString(), keyGeneration: 0, owner });
      tx.oncomplete = () => { open.result.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
  }), { container: lost, bytes: [...stranded], owner: newcomerOwn.userId });
  await newcomer.page.getByRole("button", { name: "Settings" }).click();
  const card = newcomer.page.locator("#unsent-edits");
  await expect(card).toContainText("1 edit(s)");
  const download = newcomer.page.waitForEvent("download");
  await card.getByRole("button", { name: "Export unsent edits" }).click();
  expect(JSON.parse(readFileSync(await (await download).path()).toString())).toEqual([expect.objectContaining({ notebook: lost, content: expect.objectContaining({ title: "Stranded edit" }) })]);
  await withDialog(newcomer, { type: "confirm", text: /^Delete 1 unsent edit/ }, () => card.getByRole("button", { name: "Discard unsent edits" }).click());
  await expect(card).toHaveCount(0);
  await newcomer.page.getByRole("button", { name: "← Workspace" }).click();

  // 6. A click on the notebook the app is still opening on its own leaves it loaded (one load wins).
  // The automatic load's last request (members, after its page list is in) is held until the click has started a second load.
  let release = () => {};
  const held = new Promise<void>((resolve) => {
    let reads = false;
    let holding = true;
    void editor.page.route(`**/api/v1/containers/${cid}/**`, async (route) => {
      const url = route.request().url();
      if (url.includes("/changes")) reads = true;
      if (holding && reads && url.endsWith("/members")) {
        holding = false;
        resolve();
        await new Promise<void>((done) => { release = done; });
      }
      await route.continue();
    });
  });
  await editor.page.goto("about:blank");
  await editor.page.goto(`/#/${cid}`);
  await held;
  await expect(editor.page.locator(".note-list")).toHaveAttribute("aria-busy", "true");
  // The pages listed at the moment the list stops being busy: "not busy" must already mean loaded.
  type Settled = { settled: Promise<string[]> };
  await editor.page.evaluate(() => {
    const list = document.querySelector(".note-list")!;
    (window as unknown as Settled).settled = new Promise((resolve) => new MutationObserver((_, observer) => {
      if (list.getAttribute("aria-busy") !== "false") return;
      observer.disconnect();
      resolve([...document.querySelectorAll(".note-row")].map((row) => row.textContent ?? ""));
    }).observe(list, { attributes: true, attributeFilter: ["aria-busy"] }));
  });
  await editor.page.getByRole("button", { name: TEAM }).click();
  release();
  expect(await editor.page.evaluate(() => (window as unknown as Settled).settled)).toContainEqual(expect.stringContaining("Owner page"));
  await expect(editor.page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
  await expect(editor.page.locator(".note-row", { hasText: "Owner page" })).toBeVisible();
}

const LINK_BANNER = /This browser does not hold your encryption key/;
const LINK_ENDED = "This link request ended: it was cancelled on the other browser or expired. Start again.";
const UNCACHED = "Saved to the server, but this browser could not keep its local copy (site storage may be full or blocked).";
const FORGET = "Forget this device and sign out? This browser's copy of your encryption key, its saved sign-in and your colleague key pins are removed. If no other browser holds a key you created with single sign-on, that key is lost. Unsent edits stay on this browser until they are sent, or until you discard them under Unsent edits.";
const linkCode = (id: string) => id.slice(-6).toUpperCase();

/** Starts a link on the newcomer's Settings card; returns the request ID the server issued. */
async function startLink(page: Page) {
  const created = page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/api/v1/me/link-requests" && response.ok());
  await page.locator("#link-this-browser").getByRole("button", { name: "Link this browser" }).click();
  const { id } = await (await created).json() as { id: string };
  await expect(page.locator("#link-this-browser .link-code")).toHaveText(linkCode(id));
  return id;
}

/**
 * The newcomer session's collect of a request, as the app polls it: 404 once the server holds no
 * such request. Only called while no bundle waits (a collect delivers and deletes one).
 */
const collectStatus = (page: Page, id: string) => page.evaluate(async (rid) => {
  const csrf = document.cookie.split("; ").find((value) => value.startsWith("csrf_token="))?.slice(11) ?? "";
  return (await fetch(`/api/v1/me/link-requests/${rid}/collect`, { method: "POST", headers: { "X-CSRF-Token": csrf } })).status;
}, id);

/** Request IDs the approver's session can still see (unclaimed, or claimed by it). */
const openRequests = (page: Page) => page.evaluate(async () => ((await (await fetch("/api/v1/me/link-requests")).json()) as Array<{ id: string }>).map((row) => row.id));

const approveButton = (page: Page) => page.locator("#link-devices").getByRole("button", { name: "Approve — send key" });
const typedCode = (page: Page) => page.locator("#link-devices").getByLabel("Check code shown on the other browser");

async function p3c(editor: Person, second: Person, cid: string, senders: Map<string, Uint8Array>) {
  const newcomer = second.page;
  const approver = editor.page;
  // A second browser of the editor's account that does not hold the key (as a single sign-on browser would not).
  await signIn(newcomer, "editor", OWN);
  await expect.poll(() => vaultOf(newcomer), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });
  await dropVaultIdentity(newcomer);
  await newcomer.goto("about:blank");
  await newcomer.goto(`/#/${cid}`);
  await expect(newcomer.getByText(LINK_BANNER)).toBeVisible();
  await expect(newcomer.locator(".workspace-title")).toHaveText(`Notebook ${cid.slice(4, 10)}`);
  await newcomer.locator(".conflict-banner").getByRole("button", { name: "Link this browser" }).click();

  // Every bundle the newcomer collects, and every key the approver sends.
  const collected: string[] = [];
  newcomer.on("response", async (response) => {
    if (!/\/api\/v1\/me\/link-requests\/[^/]+\/collect$/.test(response.url()) || !response.ok()) return;
    const body = await response.json().catch(() => ({})) as { bundle?: string };
    if (body.bundle) collected.push(response.url());
  });
  const sent: string[] = [];
  approver.on("request", (request) => { if (/\/api\/v1\/me\/link-requests\/lnk_[0-9a-z]+\/approve$/.test(request.url())) sent.push(request.url()); });
  await approver.getByRole("button", { name: "Settings" }).click();
  await expect(approver.locator("#link-devices")).toContainText("No browser is asking to be linked.");

  // 1. Cancel on the newcomer: the request leaves the server and the approver's list.
  let id = await startLink(newcomer);
  await expect(approver.locator("#link-devices .pin-row", { hasText: linkCode(id) })).toBeVisible();
  await newcomer.locator("#link-this-browser").getByRole("button", { name: "Cancel" }).click();
  await expect(newcomer.getByText("Request cancelled.")).toBeVisible();
  await expect.poll(() => collectStatus(newcomer, id)).toBe(404);
  await expect(approver.locator("#link-devices .pin-row")).toHaveCount(0);

  // 2. Leaving the newcomer's screen mid-attempt (unmount) cancels it too.
  id = await startLink(newcomer);
  await newcomer.getByRole("button", { name: "← Workspace" }).click();
  await expect.poll(() => collectStatus(newcomer, id)).toBe(404);
  expect(await openRequests(approver)).toEqual([]);
  await newcomer.locator(".conflict-banner").getByRole("button", { name: "Link this browser" }).click();

  // 3. A reload mid-attempt ends it: pagehide sends a keepalive cancel, so the server drops the request too.
  id = await startLink(newcomer);
  await expect(approver.locator("#link-devices .pin-row", { hasText: linkCode(id) })).toBeVisible();
  await newcomer.reload();
  await expect.poll(() => collectStatus(newcomer, id)).toBe(404);
  await expect(approver.locator("#link-devices .pin-row", { hasText: linkCode(id) })).toHaveCount(0);
  await expect(newcomer.getByText(LINK_BANNER)).toBeVisible();
  await newcomer.locator(".conflict-banner").getByRole("button", { name: "Link this browser" }).click();
  await expect(newcomer.locator("#link-this-browser .link-code")).toHaveCount(0);

  // 4. The approver leaving its screen after the claim (unmount) cancels the request; the newcomer sees it end.
  id = await startLink(newcomer);
  await approver.locator("#link-devices .pin-row", { hasText: linkCode(id) }).getByRole("button", { name: "Approve…" }).click();
  await expect(newcomer.locator(".check-code")).toBeVisible({ timeout: 30_000 });
  await expect(typedCode(approver)).toBeVisible({ timeout: 30_000 });
  await approver.getByRole("button", { name: "← Workspace" }).click();
  await expect(newcomer.getByText(LINK_ENDED)).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => collectStatus(newcomer, id)).toBe(404);
  await approver.getByRole("button", { name: "Settings" }).click();

  // 5. A relay that swaps the approver's one-time key on its way to the newcomer: the codes differ,
  // the approver's Approve stays disabled with the newcomer's code typed, and no key leaves.
  const swapped = Buffer.alloc(32, 9).toString("base64");
  await newcomer.route("**/api/v1/me/link-requests/*/collect", async (route) => {
    const response = await route.fetch();
    if (!response.ok()) { await route.fulfill({ response }); return; }
    const body = await response.json() as { approverKey?: string };
    if (body.approverKey) body.approverKey = swapped;
    await route.fulfill({ response, json: body });
  });
  id = await startLink(newcomer);
  await approver.locator("#link-devices .pin-row", { hasText: linkCode(id) }).getByRole("button", { name: "Approve…" }).click();
  const forged = (await newcomer.locator(".check-code").textContent({ timeout: 30_000 }))!.trim();
  await typedCode(approver).fill(forged);
  await expect(approveButton(approver)).toBeDisabled();
  await approver.locator("#link-devices").getByRole("button", { name: "Codes differ" }).click();
  await expect(approver.getByText(/^Linking cancelled: the codes differed\./)).toBeVisible();
  await expect(newcomer.getByText(LINK_ENDED)).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => collectStatus(newcomer, id)).toBe(404);
  expect(sent).toEqual([]);
  expect(collected).toEqual([]);
  expect((await vaultOf(newcomer))!.identity).toBeUndefined();
  await newcomer.unroute("**/api/v1/me/link-requests/*/collect");

  // 6. The honest link. The approver accepts only the newcomer's code, typed; the newcomer keeps the
  // collected key unopened until its own user confirms the code it shows.
  id = await startLink(newcomer);
  await approver.locator("#link-devices .pin-row", { hasText: linkCode(id) }).getByRole("button", { name: "Approve…" }).click();
  const code = (await newcomer.locator(".check-code").textContent({ timeout: 30_000 }))!.trim();
  const wrong = code.replace(/\d/, (digit) => String((Number(digit) + 1) % 10));
  await typedCode(approver).fill(wrong);
  await expect(approveButton(approver)).toBeDisabled();
  await typedCode(approver).fill(code);
  await expect(approveButton(approver)).toBeEnabled();
  await approveButton(approver).click();
  await expect(approver.getByText("Key sent. Finish on the other browser.")).toBeVisible({ timeout: 30_000 });
  expect(sent).toHaveLength(1);
  await expect.poll(() => collected.length, { timeout: 30_000 }).toBe(1);
  expect((await vaultOf(newcomer))!.identity).toBeUndefined();
  await expect(newcomer.locator(".check-code")).toHaveText(code);
  await newcomer.getByRole("button", { name: "Codes match", exact: true }).click();
  await expect(newcomer.getByText("Linked. This browser now holds your encryption key.")).toBeVisible({ timeout: 30_000 });
  const linked = (await vaultOf(newcomer))!;
  expect(linked).toMatchObject({ sealed: true, extractable: false });
  const original = (await vaultOf(approver))!.identity!;
  expect(linked.identity).toEqual(original);
  // Collect delivered the bundle once and deleted the request: a second collect is refused.
  expect(await collectStatus(newcomer, id)).toBe(404);
  expect(await openRequests(approver)).toEqual([]);
  await approver.getByRole("button", { name: "← Workspace" }).click();

  // 7. The linked browser opens the team's keys: it reads what the owner wrote; both show one fingerprint.
  await openTeam(newcomer, TEAM, cid);
  await expect(newcomer.getByText(LINK_BANNER)).toHaveCount(0);
  await readPage(newcomer, "Owner page", ["owner comment"]);
  expect((await ownSettings(newcomer)).fingerprint).toBe((await ownSettings(approver)).fingerprint);

  // 8. A local cache that refuses every write: the edit still reaches the server, and the page says it has no local copy.
  await newcomer.evaluate(() => {
    const put = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (this: IDBObjectStore, ...args: Parameters<IDBObjectStore["put"]>) {
      if (this.name === "notes") throw new DOMException("The quota has been exceeded.", "QuotaExceededError");
      return put.apply(this, args);
    };
  });
  await writePage(newcomer, "Linked page", "linked comment");
  await expect(newcomer.getByText(UNCACHED)).toBeVisible();
  const uncached = await serverCopy(newcomer, "Linked page");
  await expect(titleOf((await heldKeys(newcomer, cid, senders)).get(uncached.generation)!, cid, uncached.bytes)).resolves.toBe("Linked page");

  // 9. Forget this device asks first, names what it removes and keeps, then deletes the sealed key and its device key together.
  await newcomer.getByRole("button", { name: "Settings" }).click();
  await withDialog(second, { type: "confirm", text: FORGET }, () => newcomer.getByRole("button", { name: "Forget this device & sign out" }).click());
  await expect.poll(() => vaultOf(newcomer)).toBeNull();
}

const LEGACY_TEAM = "Legacy Team E2E";
const LEGACY_CLOSED = "This browser no longer opens items written before this notebook was shared.";
const LEGACY_CHECKING = "Checking the items written before this notebook was shared…";
const LEGACY_UNCHECKED = "This browser could not list the items written before this notebook was shared.";
const LEGACY_STILL_OPEN = "This browser still opens items written before this notebook was shared; they are not end-to-end verified.";
const LEGACY_LABEL = "Written before sharing; not end-to-end verified";
const LEGACY_BLOCKED = "These pages use attachments you're sharing; tick them too, or keep the notebook open:";
const LEAVE_ONE = "1 item you did not tick will stay on the server, and this browser will stop opening them. Share the ticked items and stop opening the rest?";
const STOP_LEGACY = "Stop opening items written before this notebook was shared? This browser will no longer open any of them, including your own that you have not shared. They stay on the server.";
const REOPEN_CONFIRM = "Show items written before this notebook was shared again? They are not end-to-end verified: the server could have written or changed any of them. This browser opens them with your login key until you stop again.";
const STOP = "Stop opening pre-sharing items";
const REOPEN = "Show pre-sharing items again";
const FORGED = `obj_${"f".repeat(26)}`;
// Long, so the dialog's wrapping is exercised too.
const FORGED_TITLE = "Forged page the server wrote with your login key to look like one of your own notes from before this notebook was shared";

/** This browser's legacy closure for cid (0: still open), read from its vault's key memory. */
const closedIn = (page: Page, cid: string) => page.evaluate((id) => new Promise<number>((resolve) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => resolve(0);
  open.onsuccess = () => {
    const all = open.result.transaction("keys").objectStore("keys").getAll();
    all.onsuccess = () => {
      open.result.close();
      const row = (all.result as Array<{ keyStates?: { byContainer: Record<string, { closed?: number }> } }>)[0];
      resolve(row?.keyStates?.byContainer[id]?.closed ?? 0);
    };
  };
}), cid);

const legacyPath = (cid: string) => (url: URL) => url.pathname === `/api/v1/containers/${cid}/legacy`;
const legacyListed = (page: Page, cid: string) => page.waitForResponse((response) => legacyPath(cid)(new URL(response.url())));

/**
 * A malicious server: it seals a page with this account's login key (derivable from what the server
 * sees at sign-in), labels it below sharing and slips it into the change feed of cid. While listed, it
 * is in the legacy list too, which also claims it uses every pre-sharing attachment, and the server
 * accepts a new copy's attach to it.
 */
async function forgeLegacyPage(page: Page, cid: string) {
  const forgery = { listed: true };
  const bytes = await encryptNote(legacyKeyRef((await vaultOf(page))!.authSecret), cid, { type: "page", title: FORGED_TITLE, body: "" });
  await page.route((url) => url.pathname === `/api/v1/objects/${FORGED}`, (route) => route.fulfill({ status: 200, contentType: "application/octet-stream", headers: { "X-Kynotes-Version": "1", "X-Kynotes-Key-Generation": "1" }, body: Buffer.from(bytes) }));
  await page.route((url) => url.pathname === `/api/v1/objects/${FORGED}/attachments`, (route) => route.request().method() === "POST" ? route.fulfill({ status: 204 }) : route.fulfill({ json: [] }));
  await page.route((url) => url.pathname === `/api/v1/containers/${cid}/changes`, async (route) => {
    const response = await route.fetch();
    const json = await response.json() as { changes: Array<Record<string, unknown>> };
    if (new URL(route.request().url()).searchParams.get("since") === "0") json.changes.push({ id: FORGED, kind: "object", changeSeq: 1, deleted: false });
    await route.fulfill({ response, json });
  });
  await page.route(legacyPath(cid), async (route) => {
    if (!forgery.listed) { await route.continue(); return; }
    const response = await route.fetch();
    const json = await response.json() as { objects: Array<Record<string, unknown>>; attachments: Array<{ objectIds: string[] }> };
    json.objects.push({ id: FORGED, version: 1, keyGeneration: 1 });
    for (const attachment of json.attachments) attachment.objectIds.push(FORGED);
    await route.fulfill({ response, json });
  });
  return forgery;
}
const pageRow = (page: Page, title: string) => page.locator(".note-row", { hasText: title });

/** KYNOTES_E2E_SHOTS=<dir>: each P4 state in Busnes Light and Dark at 1280x900 and 390x844 (UI-VERIFICATION.md). */
async function shoot(page: Page, state: string, focus: Locator) {
  const dir = process.env.KYNOTES_E2E_SHOTS;
  if (!dir) return;
  const size = page.viewportSize()!;
  for (const scheme of ["light", "dark"] as const) {
    for (const [width, height, form] of [[1280, 900, "desktop"], [390, 844, "mobile"]] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width, height });
      await focus.scrollIntoViewIfNeeded();
      await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      const measured = await page.evaluate(() => {
        const dialog = document.querySelector("dialog[open]");
        return { scrollWidth: document.documentElement.scrollWidth, dialog: dialog && { overflowY: getComputedStyle(dialog).overflowY, scrolls: dialog.scrollHeight > dialog.clientHeight, right: dialog.getBoundingClientRect().right } };
      });
      console.log(`shot ${state}-${scheme}-${form}: ${JSON.stringify(measured)}`);
      expect(measured.scrollWidth).toBeLessThanOrEqual(width);
      await page.screenshot({ path: `${dir}/team-keys-p4-${state}-${scheme}-${form}.png` });
    }
  }
  await page.emulateMedia({ colorScheme: null });
  await page.setViewportSize(size);
}

async function p4(owner: Person, editor: Person, second: Person, senders: Map<string, Uint8Array>) {
  // 1. A team the editor writes in before its owner first opens it: those rows use the editor's login key.
  const before = await listed(owner.page);
  await owner.page.getByRole("button", { name: "Admin" }).click();
  await withDialog(owner, { type: "prompt", text: "Team name", answer: LEGACY_TEAM }, () => owner.page.getByRole("button", { name: "Create team" }).click());
  await expect(owner.page.getByRole("combobox", { name: "Team", exact: true })).toContainText(LEGACY_TEAM);
  await owner.page.getByRole("button", { name: "← Workspace" }).click();
  const lid = (await listed(owner.page)).find((id) => !before.includes(id))!;
  await addToTeam(owner, "editor", lid);
  await owner.page.goto("about:blank"); // no owner tab mints meanwhile
  await openTeam(editor.page, `Notebook ${lid.slice(4, 10)}`, lid);
  await writePage(editor.page, "Pre-sharing page", "pre-sharing comment");
  await editor.page.locator('input[type="file"]').setInputFiles({ name: "legacy.txt", mimeType: "text/plain", buffer: Buffer.from("legacy attachment bytes") });
  await expect(editor.page.getByRole("button", { name: /legacy\.txt/ })).toBeVisible();
  const editorLogin = legacyKeyRef((await vaultOf(editor.page))!.authSecret);
  const pre = await serverCopy(editor.page, "Pre-sharing page");
  await expect(titleOf(editorLogin, lid, pre.bytes)).resolves.toBe("Pre-sharing page");

  // 2. The owner opens it: the first key is minted. Nothing listed is the owner's, so its browser
  // stops opening pre-sharing rows by itself, and counts the editor's.
  await openTeam(owner.page, LEGACY_TEAM, lid);
  await expect(owner.page.getByText(/^3 items written before this notebook was shared can be opened only by their authors\./)).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => closedIn(owner.page, lid)).toBeGreaterThan(0);
  await expect(owner.page.getByRole("button", { name: "Review and share…" })).toHaveCount(0);
  await expect(owner.page.getByRole("button", { name: REOPEN })).toBeVisible();
  await shoot(owner.page, "others", owner.page.getByText(/can be opened only by their authors/));

  // 3. The editor's browser is still open: its rows read with the login key, labelled. The forged page does too.
  const forgery = await forgeLegacyPage(editor.page, lid);
  await openTeam(editor.page, LEGACY_TEAM, lid);
  await expect(pageRow(editor.page, "Pre-sharing page")).toContainText("Not verified");
  await expect(pageRow(editor.page, FORGED_TITLE)).toContainText("Not verified");
  await expect(editor.page.getByText(/^4 items you wrote before this notebook was shared are not end-to-end verified yet\./)).toBeVisible({ timeout: 30_000 });
  await expect(editor.page.getByRole("button", { name: STOP })).toBeVisible();
  expect(await closedIn(editor.page, lid)).toBe(0);
  await shoot(editor.page, "banner", editor.page.locator(".legacy-banner"));

  // 4. Review: every item is labelled, nothing is ticked and Share is off until something is. The editor
  // ticks only its own three; sharing asks before the unticked forged page is hidden.
  await editor.page.getByRole("button", { name: "Review and share…" }).click();
  const dialog = editor.page.locator("dialog.legacy-review");
  const items = ["Page: Pre-sharing page", `Page: ${FORGED_TITLE}`, "Comment: pre-sharing comment", /Attachment: legacy\.txt \(1 KB\)/];
  for (const label of items) {
    await expect(dialog.getByLabel(label)).not.toBeChecked();
    await expect(dialog.locator("li", { has: editor.page.getByLabel(label) })).toContainText(LEGACY_LABEL);
  }
  const share = dialog.getByRole("button", { name: "Share ticked items" });
  await expect(share).toBeDisabled();
  await shoot(editor.page, "dialog", dialog.getByRole("heading"));
  for (const label of [items[0], items[2], items[3]]) await dialog.getByLabel(label).check();
  await expect(share).toBeEnabled();
  // The server swaps the page's bytes after the review: what is sealed must be what the dialog showed.
  const swapped = await encryptNote(editorLogin, lid, { type: "page", title: "Swapped by the server", body: "[]" });
  const reviewed = await serverCopy(editor.page, "Pre-sharing page");
  const swap = (url: URL) => url.pathname === `/api/v1/objects/${reviewed.id}`;
  await editor.page.route(swap, (route) => route.request().method() !== "GET" ? route.continue() : route.fulfill({ status: 200, contentType: "application/octet-stream", headers: { "X-Kynotes-Version": String(reviewed.version), "X-Kynotes-Key-Generation": String(reviewed.generation) }, body: Buffer.from(swapped) }));
  await withDialog(editor, { type: "confirm", text: LEAVE_ONE }, () => share.click());
  await expect(editor.page.getByText(`Shared 3 items. ${LEGACY_CLOSED}`)).toBeVisible({ timeout: 60_000 });
  await editor.page.unroute(swap);
  expect(await closedIn(editor.page, lid)).toBeGreaterThan(0);
  // The server's claim that the forged page uses the shared attachment blocked nothing: its own text does not.
  await expect(editor.page.getByText(LEGACY_BLOCKED)).toHaveCount(0);
  await expect(editor.page.getByRole("button", { name: "Tick these too" })).toHaveCount(0);

  // 5. Closed: the forged page is gone although the server still offers it; the shared rows read without a label.
  await openTeam(editor.page, LEGACY_TEAM, lid);
  await expect(pageRow(editor.page, "Pre-sharing page")).toBeVisible();
  await expect(pageRow(editor.page, FORGED_TITLE)).toHaveCount(0);
  await expect(pageRow(editor.page, "Pre-sharing page")).not.toContainText("Not verified");
  await readPage(editor.page, "Pre-sharing page", ["pre-sharing comment"]);
  await expect(editor.page.getByRole("button", { name: "Review and share…" })).toHaveCount(0);
  await expect(editor.page.getByRole("button", { name: REOPEN })).toBeVisible();
  await shoot(editor.page, "closed", editor.page.getByRole("button", { name: REOPEN }));

  // 6. The server holds every migrated row under the container key, as reviewed, none under the login key.
  const keys = await heldKeys(editor.page, lid, senders);
  const migrated = await serverCopy(editor.page, "Pre-sharing page");
  expect(migrated.generation).toBeGreaterThan(pre.generation);
  await expect(titleOf(keys.get(migrated.generation)!, lid, migrated.bytes)).resolves.toBe("Pre-sharing page");
  await expect(titleOf(editorLogin, lid, migrated.bytes)).rejects.toThrow();
  const rows = await editor.page.evaluate(async (oid) => ({
    comments: await (await fetch(`/api/v1/objects/${oid}/comments`)).json() as Array<{ keyGeneration: number }>,
    attachments: await (await fetch(`/api/v1/objects/${oid}/attachments`)).json() as Array<{ keyGeneration: number }>,
  }), migrated.id);
  expect(rows.comments.map((row) => row.keyGeneration)).toEqual([migrated.generation]);
  expect(rows.attachments.map((row) => row.keyGeneration)).toEqual([migrated.generation]);

  // 7. The owner reads all of it: page, comment and attachment.
  await openTeam(owner.page, LEGACY_TEAM, lid);
  await readPage(owner.page, "Pre-sharing page", ["pre-sharing comment"]);
  const download = owner.page.waitForEvent("download");
  await owner.page.getByRole("button", { name: /legacy\.txt/ }).click();
  expect(readFileSync(await (await download).path()).toString()).toBe("legacy attachment bytes");
  await expect(owner.page.getByText(/can be opened only by/)).toHaveCount(0);

  // 8. Reopening changes nothing: no object is written on load.
  const writes: string[] = [];
  editor.page.on("request", (request) => { if (request.method() === "PUT" && /\/api\/v1\/(objects|comments)\//.test(request.url())) writes.push(request.url()); });
  await openTeam(editor.page, LEGACY_TEAM, lid);
  expect(writes).toEqual([]);

  // 9. "Show pre-sharing items again" warns first; then the forged page is back, labelled.
  await withDialog(editor, { type: "confirm", text: REOPEN_CONFIRM }, () => editor.page.getByRole("button", { name: REOPEN }).click());
  await expect(pageRow(editor.page, FORGED_TITLE)).toContainText("Not verified", { timeout: 30_000 });
  await expect(editor.page.getByText(/^1 item you wrote before this notebook was shared is not end-to-end verified yet\./)).toBeVisible({ timeout: 30_000 });
  expect(await closedIn(editor.page, lid)).toBe(0);
  // It survives a reload where the server lists nothing of this user's, which alone would close it again.
  forgery.listed = false;
  const answered = legacyListed(editor.page, lid);
  await openTeam(editor.page, LEGACY_TEAM, lid);
  await answered;
  await expect(editor.page.getByText(LEGACY_CHECKING)).toHaveCount(0);
  await expect(pageRow(editor.page, FORGED_TITLE)).toContainText("Not verified");
  expect(await closedIn(editor.page, lid)).toBe(0);
  await expect(editor.page.getByRole("button", { name: REOPEN })).toHaveCount(0);
  // Stop stays on screen with nothing of this user's listed, and closes it again.
  await expect(editor.page.locator(".legacy-banner")).toContainText(LEGACY_STILL_OPEN);
  await withDialog(editor, { type: "confirm", text: STOP_LEGACY }, () => editor.page.getByRole("button", { name: STOP }).click());
  await expect(editor.page.getByRole("button", { name: REOPEN })).toBeVisible({ timeout: 30_000 });
  await expect(pageRow(editor.page, FORGED_TITLE)).toHaveCount(0);
  expect(await closedIn(editor.page, lid)).toBeGreaterThan(0);

  // 10. A second browser of the editor's account (signed in again after P3c's "Forget this device"),
  // with nothing of its own listed.
  await signIn(second.page, "editor", OWN);
  let answer: "fail" | "empty" = "fail";
  await second.page.route(legacyPath(lid), (route) => answer === "fail"
    ? route.fulfill({ status: 500, json: { error: { code: "internal", message: "internal server error" } } })
    : route.fulfill({ json: { complete: true, objects: [], comments: [], attachments: [], conflicts: [] } }));
  // A failed list is not an empty one: the banner says why, Stop shows, and nothing closes.
  await openTeam(second.page, LEGACY_TEAM, lid);
  const banner = second.page.locator(".legacy-banner");
  await expect(banner).toContainText(`${LEGACY_UNCHECKED} The server could not list them (500).`, { timeout: 30_000 });
  await expect(banner.getByRole("button", { name: STOP })).toBeVisible();
  expect(await closedIn(second.page, lid)).toBe(0);
  await shoot(second.page, "unchecked", banner);
  // A complete, empty list: it stops opening them by itself.
  answer = "empty";
  await openTeam(second.page, LEGACY_TEAM, lid);
  await expect(second.page.getByRole("button", { name: REOPEN })).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => closedIn(second.page, lid)).toBeGreaterThan(0);
  // Reopened, then with the list failing again: Stop still closes it with one click.
  answer = "fail";
  await withDialog(second, { type: "confirm", text: REOPEN_CONFIRM }, () => second.page.getByRole("button", { name: REOPEN }).click());
  await expect(banner).toContainText(LEGACY_UNCHECKED, { timeout: 30_000 });
  expect(await closedIn(second.page, lid)).toBe(0);
  await withDialog(second, { type: "confirm", text: STOP_LEGACY }, () => banner.getByRole("button", { name: STOP }).click());
  await expect(second.page.getByRole("button", { name: REOPEN })).toBeVisible({ timeout: 30_000 });
  expect(await closedIn(second.page, lid)).toBeGreaterThan(0);
}

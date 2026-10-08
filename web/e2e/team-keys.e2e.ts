import { readFileSync } from "node:fs";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { decryptObject, encryptNote, fromBase64, legacyKeyRef, type KeyRef } from "../src/crypto";
import { envelopeSender, unwrapEnvelope } from "../src/teamKeys";

// Three people in three isolated browser contexts (cookies and IndexedDB apart).
const TEMPORARY = "temporary horse battery staple";
const OWN = "my own horse battery staple";
const TEAM = "Team Keys E2E";
const WAITING = "Waiting for a team owner to share this notebook's keys. It is read-only until then.";

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
  try {
    await scenario(owner, editor, newcomer, shared);
  } finally {
    // An unexpected dialog (a fingerprint change, an error alert) is the root cause of whatever failed after it.
    for (const who of [owner, editor, newcomer, shared]) expect(who.unexpected).toEqual([]);
  }
});

async function scenario(owner: Person, editor: Person, newcomer: Person, shared: Person) {
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

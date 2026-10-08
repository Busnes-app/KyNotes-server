import { readFileSync } from "node:fs";
import { expect, test, type Browser, type Locator, type Page, type Request } from "@playwright/test";
import { asContentKey, decryptComment, decryptContainerMeta, decryptObject, encryptNote, fromBase64, type KeyRef } from "../src/crypto";
import { waitingKey } from "../src/keyring";
import { newRecoveryCode } from "../src/recovery";
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

/** On Settings. An administrator-set password blocks the identity; the user's own change creates it. */
async function changeOwnPassword(page: Page, current: string, next: string) {
  await page.getByLabel("Current password").fill(current);
  await page.getByLabel("New password", { exact: true }).fill(next);
  await page.getByLabel("Confirm new password").fill(next);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByText("Password changed.")).toBeVisible();
}

async function takeOverPassword(page: Page) {
  await page.getByRole("button", { name: "Settings" }).click();
  await changeOwnPassword(page, TEMPORARY, OWN);
  await expect.poll(() => vaultOf(page), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });
  await page.getByRole("button", { name: "← Workspace" }).click();
}

// Copied from components/RecoveryCode.tsx, recovery.ts and main.tsx: a changed string fails the run.
const RECOVERY_SAVED = "Recovery code saved. Keep it somewhere safe.";
const LINKED = "Linked. This browser now holds your encryption key.";
const RECOVERY_TYPO = "Check the recovery code: a character is wrong or missing.";
const RECOVERY_WRONG = "This recovery code does not open your key. Check it and try again.";
const RECOVERY_STALE = "The server's recovery copy is not for your account's current key. Reload and try again.";
const RESET_HELD = "This browser holds your encryption key, so you do not need a reset to get it back: save a recovery code instead. Reset only if a browser that holds your key was lost or stolen.";
const RESET_CONFIRM = "Reset your encryption key? Your personal notebooks become unreadable for good, on every browser, and so does any team notebook whose keys no other owner or admin holds. Unsent edits waiting for a notebook's keys are never sent afterwards: export them first. Team owners must share each team's keys with you again, and colleagues are asked to trust your new key. Type RESET to continue.";
const RESET_WRONG_PASSWORD = "That password is not right. Nothing was reset.";
const RESET_DONE = "Your encryption key was reset. Team owners share their notebooks' keys with you again when they next open them.";
const ADMIN_RESET = "Password reset. All existing sessions and paired device credentials were revoked. The account keeps its encryption key: after changing the temporary password, the user gets it back from a browser that holds it or with their recovery code (an account linked to KySignOn gets no password copy back). With neither, they can reset it themselves, and their personal notebooks are lost. If a browser holding the key was lost or stolen, ask the user to reset their encryption key in Settings: this reset does not cut that browser off.";
const CODE_FORMAT = /^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{4}$/;

const typeBackLabel = (scope: Locator) => scope.locator("label.field span").filter({ hasText: /^Type group [1-7] of 7 from your saved copy$/ });

/**
 * On a shown code: reads it, hides it, shows it again (the asked group must change, so the group just read
 * is never the one asked), then types back the asked group and saves. Returns the code.
 */
async function saveShownCode(scope: Locator, shots?: { page: Page; phase: string; state: string }) {
  const shown = scope.locator(".recovery-code");
  const code = (await shown.textContent())!.trim();
  expect(code).toMatch(CODE_FORMAT);
  if (shots) await shoot(shots.page, shots.phase, `${shots.state}-code`, scope);
  await scope.getByRole("button", { name: "I saved it" }).click();
  await expect(shown).toHaveCount(0);
  const first = (await typeBackLabel(scope).textContent())!;
  if (shots) await shoot(shots.page, shots.phase, `${shots.state}-type-back`, scope);
  await scope.getByRole("button", { name: "Show the code again" }).click();
  await expect(shown).toHaveText(code);
  await scope.getByRole("button", { name: "I saved it" }).click();
  const label = (await typeBackLabel(scope).textContent())!;
  expect(label).not.toBe(first);
  const group = Number(/group ([1-7])/.exec(label)![1]);
  await scope.getByLabel(label).fill(code.split("-")[group - 1].toLowerCase());
  await scope.getByRole("button", { name: "Save recovery code" }).click();
  return code;
}

/**
 * The user's own reset in Settings, from a browser that holds the key; returns the new recovery code.
 * It needs RESET typed and a password step-up before any code is shown. The reset's response is lost
 * after the server committed it: the browser finishes from the identity the server then lists.
 */
async function resetOwnKey(who: Person, password: string) {
  const { page } = who;
  await page.getByRole("button", { name: "Settings" }).click();
  const card = page.locator("#identity-reset");
  await expect(card.getByText(RESET_HELD)).toBeVisible();
  const steps: string[] = [];
  const track = (request: { method: () => string; url: () => string }) => {
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/step-up" || path === "/api/v1/me/identity" && request.method() !== "GET") steps.push(`${request.method()} ${path}`);
  };
  page.on("request", track);
  await card.getByRole("button", { name: "Reset encryption key…" }).click();
  await expect(card.getByRole("alert")).toHaveText(RESET_CONFIRM);
  await shoot(page, "p5", "reset-dialog", card);
  const go = card.getByRole("button", { name: "Continue" });
  await card.getByLabel("Your password").fill(password);
  for (const typed of ["", "reset", "RESETX"]) {
    await card.getByLabel("Type RESET to confirm").fill(typed);
    await expect(go).toBeDisabled();
  }
  await card.getByLabel("Type RESET to confirm").fill("RESET");
  await card.getByLabel("Your password").fill(`${password} wrong`);
  await go.click();
  await expect(card.getByText(RESET_WRONG_PASSWORD)).toBeVisible();
  await expect(card.locator(".recovery-code")).toHaveCount(0);
  expect(steps).toEqual(["POST /api/v1/auth/step-up"]);
  await card.getByLabel("Your password").fill(password);
  await go.click();
  await expect(card.locator(".recovery-code")).toBeVisible();
  await shoot(page, "p5", "reset-code", card);
  // The server commits the reset, then the connection drops before its answer arrives.
  const committed: number[] = [];
  await page.route((url) => url.pathname === "/api/v1/me/identity", async (route) => {
    if (route.request().method() !== "PUT") { await route.continue(); return; }
    committed.push((await route.fetch()).status());
    await route.abort("connectionreset");
  });
  const code = await saveShownCode(card);
  await expect(card.getByText(RESET_DONE)).toBeVisible({ timeout: 30_000 });
  await page.unroute((url) => url.pathname === "/api/v1/me/identity");
  page.off("request", track);
  expect(committed).toEqual([200]);
  // Every write was behind a step-up, and the one reset request followed the last of them.
  expect(steps.slice(-2)).toEqual(["POST /api/v1/auth/step-up", "PUT /api/v1/me/identity"]);
  expect(steps.filter((step) => step.startsWith("PUT"))).toHaveLength(1);
  await expect(page.locator("#recovery")).toContainText("You saved a recovery code on");
  await page.getByRole("button", { name: "← Workspace" }).click();
  return code;
}

/** True when any storage this page can see (IndexedDB, localStorage, sessionStorage, the URL) holds needle. */
const storageHolds = (page: Page, needle: string) => page.evaluate(async (text) => {
  const dumps: string[] = [location.href, JSON.stringify({ ...localStorage }), JSON.stringify({ ...sessionStorage })];
  for (const info of await indexedDB.databases()) {
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const open = indexedDB.open(info.name!); open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error); });
    for (const name of [...db.objectStoreNames]) {
      const rows = await new Promise<unknown[]>((resolve) => { const all = db.transaction(name).objectStore(name).getAll(); all.onsuccess = () => resolve(all.result); });
      dumps.push(JSON.stringify(rows, (_, value) => (ArrayBuffer.isView(value) ? new TextDecoder().decode(value as Uint8Array) : value)));
    }
    db.close();
  }
  const forms = [text, text.replaceAll("-", "")].map((form) => form.toLowerCase());
  return dumps.some((dump) => forms.some((form) => dump.toLowerCase().includes(form)));
}, needle);

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
    return [row.keyGeneration, asContentKey(unwrapEnvelope(envelope, Uint8Array.from(own.privateKey), cid, row.keyGeneration, own.deviceId, sender))];
  }));
}

type Queued = { id: string; containerID: string; version: number; payload: number[]; keyGeneration: number; owner: string };

/** Puts an entry in this browser's queue of unsent edits, shaped as the app's saveNow queues one. */
const queueEdit = (page: Page, entry: Queued) => page.evaluate((item) => new Promise<void>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const tx = open.result.transaction("pending", "readwrite");
    tx.objectStore("pending").put({ ...item, payload: new Uint8Array(item.payload), updatedAt: new Date().toISOString() });
    tx.oncomplete = () => { open.result.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  };
}), entry);

/** Every row of one store of this browser's local database, byte arrays as numbers; null when the store is missing. */
const storeRows = (page: Page, store: string) => page.evaluate((name) => new Promise<Array<Record<string, unknown>> | null>((resolve, reject) => {
  const open = indexedDB.open("kynotes-web");
  open.onerror = () => reject(open.error);
  open.onsuccess = () => {
    const db = open.result;
    if (!db.objectStoreNames.contains(name)) { db.close(); resolve(null); return; }
    const all = db.transaction(name).objectStore(name).getAll();
    all.onsuccess = () => {
      db.close();
      resolve((all.result as Array<Record<string, unknown>>).map((row) => Object.fromEntries(Object.entries(row).map(([key, value]) => [key, value instanceof Uint8Array ? [...value] : value]))));
    };
  };
}), store);

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

/** The key the server could derive from what it sees at sign-in. Test-only: content must never open with it. */
const loginKey = (authSecret: string) => asContentKey(Uint8Array.from(Buffer.from(authSecret, "hex")));

test("team keys: three people share, a removed member loses new content", async ({ browser }) => {
  const owner = await person(browser);
  const editor = await person(browser);
  const newcomer = await person(browser);
  // A fourth browser where an invitation link is opened and then another account signs in.
  const shared = await person(browser);
  // A second browser of the editor's account, linked from the editor's browser.
  const second = await person(browser);
  // The legacy review route is gone: no browser may ever ask for it.
  const legacyCalls: string[] = [];
  const watch = (who: Person) => who.page.on("request", (request) => { if (/\/legacy(\?|$)/.test(new URL(request.url()).pathname)) legacyCalls.push(request.url()); });
  for (const who of [owner, editor, newcomer, shared, second]) watch(who);
  // Browsers the later scenarios open; each is watched and checked the same way.
  const extra: Person[] = [];
  const another = async () => {
    const who = await person(browser);
    watch(who);
    extra.push(who);
    return who;
  };
  try {
    await scenario(owner, editor, newcomer, shared, second, another);
  } finally {
    // An unexpected dialog (a fingerprint change, an error alert) is the root cause of whatever failed after it.
    for (const who of [owner, editor, newcomer, shared, second, ...extra]) expect(who.unexpected).toEqual([]);
    expect(legacyCalls).toEqual([]);
  }
});

async function scenario(owner: Person, editor: Person, newcomer: Person, shared: Person, second: Person, another: () => Promise<Person>) {
  // Owner: first-run setup (its own password, so its identity exists at once), then accounts.
  await owner.page.goto("/");
  await owner.page.getByLabel("Administrator Username").fill("owner");
  await owner.page.getByLabel("Password", { exact: true }).fill(OWN);
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
  await expect(titleOf(loginKey((await vaultOf(owner.page))!.authSecret), cid, ownerCopy.bytes)).rejects.toThrow();
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
  await expect(titleOf(loginKey((await vaultOf(editor.page))!.authSecret), cid, editorCopy.bytes)).rejects.toThrow();
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
  await p5(owner, editor, cid, another);
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

  // 3. An administrator reset keeps the newcomer's key (members still see it); only the newcomer's own reset replaces it.
  await owner.page.getByRole("button", { name: "Admin" }).click();
  const users = owner.page.locator("#users");
  await users.getByLabel("Confirm your password").fill(OWN);
  await users.getByRole("button", { name: "Authorize user creation and password resets" }).click();
  await expect(users.getByText("Password confirmed for ten minutes.")).toBeVisible();
  owner.expected.push({ type: "prompt", text: "New temporary password for newcomer", answer: TEMPORARY });
  await withDialog(owner, { type: "alert", text: ADMIN_RESET }, () =>
    owner.page.locator(".admin-user", { hasText: "newcomer" }).getByRole("button", { name: "Reset password" }).click());
  await owner.page.goto("about:blank");
  await openTeam(editor.page, TEAM, cid);
  await expect(editor.page.locator(".member-row", { hasText: "newcomer" })).toContainText("has key");
  const oldIdentity = (await vaultOf(newcomer.page))!.identity!;
  await signIn(newcomer.page, "newcomer", TEMPORARY);
  await takeOverPassword(newcomer.page);
  expect((await vaultOf(newcomer.page))!.identity!.deviceId).toBe(oldIdentity.deviceId);
  // Every content key the old identity opens: a stolen browser would keep these after the reset.
  const preReset = await heldKeys(newcomer.page, cid, senders);
  expect(preReset.size).toBeGreaterThan(0);
  const newCode = await resetOwnKey(newcomer, OWN);
  await expect.poll(async () => (await vaultOf(newcomer.page))?.identity?.deviceId, { timeout: 30_000 }).not.toBe(oldIdentity.deviceId);
  expect(await storageHolds(newcomer.page, newCode)).toBe(false);
  // The reset retired the team's generation: until a steward mints the next one, a member sees the
  // waiting state (its name is sealed with the current key only) and cannot write.
  await openTeam(editor.page, `Notebook ${cid.slice(4, 10)}`, cid);
  await expect(editor.page.getByText(WAITING)).toBeVisible();
  await expect(editor.page.locator(".member-row", { hasText: "newcomer" })).toContainText("waiting for key");
  // Only owners and admins are told who reset: an editor's list does not say.
  await expect(editor.page.locator(".member-row", { hasText: "newcomer" })).not.toContainText("reset their key");
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
  await expect(owner.page.locator(".member-row", { hasText: "newcomer" })).toContainText("reset their key");
  // That one pass minted the generation the reset retired and wrapped the team's history for the new key.
  await openTeam(newcomer.page, TEAM, cid);
  await readPage(newcomer.page, "Owner page", ["owner comment"]);
  // The steward re-shared for the new key only: the old key is gone from the server and opens none of it.
  const newIdentity = (await vaultOf(newcomer.page))!.identity!;
  const rows = await newcomer.page.evaluate(async (id) => (await fetch(`/api/v1/containers/${id}/envelopes`)).json(), cid) as Array<{ deviceId: string; keyGeneration: number; envelope: string }>;
  expect(rows.filter((row) => row.deviceId === oldIdentity.deviceId)).toEqual([]);
  const reshared = rows.filter((row) => row.deviceId === newIdentity.deviceId);
  expect(reshared.length).toBeGreaterThan(0);
  for (const row of reshared) {
    const envelope = fromBase64(row.envelope);
    const sender = senders.get(envelopeSender(envelope))!;
    expect(() => unwrapEnvelope(envelope, Uint8Array.from(oldIdentity.privateKey), cid, row.keyGeneration, newIdentity.deviceId, sender)).toThrow();
    expect(() => unwrapEnvelope(envelope, Uint8Array.from(oldIdentity.privateKey), cid, row.keyGeneration, oldIdentity.deviceId, sender)).toThrow();
    expect(unwrapEnvelope(envelope, Uint8Array.from(newIdentity.privateKey), cid, row.keyGeneration, newIdentity.deviceId, sender)).toHaveLength(32);
  }
  // The reset retired the old key's generations: the steward minted a new one, so content written
  // afterwards sits above them all and no retained pre-reset key opens the server's bytes.
  await writePage(owner.page, "After reset", "after reset comment");
  const afterReset = await serverCopy(owner.page, "After reset");
  expect(afterReset.generation).toBeGreaterThan(Math.max(...preReset.keys()));
  for (const key of preReset.values()) await expect(titleOf(key, cid, afterReset.bytes)).rejects.toThrow();
  await expect(titleOf((await heldKeys(newcomer.page, cid, senders)).get(afterReset.generation)!, cid, afterReset.bytes)).resolves.toBe("After reset");

  // 5. An edit stranded on the device for a notebook this account cannot open: exported, then discarded.
  const lost = `cnt_${"z".repeat(26)}`;
  // Sealed as the app seals an edit made while the key is missing: generation 0, the identity's waiting key.
  const stranded = await encryptNote(waitingKey({ privateKey: Uint8Array.from(newIdentity.privateKey) }), lost, { type: "page", title: "Stranded edit", body: "[]" });
  // Stamped with its account, as the app queues every edit: only those may be discarded.
  await queueEdit(newcomer.page, { id: `obj_${"z".repeat(26)}`, containerID: lost, version: 1, payload: [...stranded], keyGeneration: 0, owner: newcomerOwn.userId });
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
const FORGET = "Forget this device and sign out? This browser's copy of your encryption key, its saved sign-in and your colleague key pins are removed. To get the key back here, link this browser from another one or enter your recovery code (or sign in with your password, if it still unlocks your key; accounts that use KySignOn have no password copy). Unsent edits stay on this browser until they are sent, or until you discard them under Unsent edits.";
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
  await expect(newcomer.getByText(LINKED)).toBeVisible({ timeout: 30_000 });
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

const pageRow = (page: Page, title: string) => page.locator(".note-row", { hasText: title });

/** KYNOTES_E2E_SHOTS=<dir>: a state in Busnes Light and Dark at 1280x900 and 390x844 (UI-VERIFICATION.md). */
async function shoot(page: Page, phase: string, state: string, focus: Locator) {
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
      console.log(`shot ${phase}-${state}-${scheme}-${form}: ${JSON.stringify(measured)}`);
      expect(measured.scrollWidth).toBeLessThanOrEqual(width);
      await page.screenshot({ path: `${dir}/team-keys-${phase}-${state}-${scheme}-${form}.png` });
    }
  }
  await page.emulateMedia({ colorScheme: null });
  await page.setViewportSize(size);
}

const KEYED = "Keyed Notebook";
const WAITED = "Keyed page, edited while waiting";
const NEW_OWN = "newer horse battery staple";
const RESET_TEMPORARY = "reset horse battery staple";
const FORGED = `obj_${"f".repeat(26)}`;
const FORGED_TITLE = "Forged page sealed with the login key";

type Write = { method: string; path: string; scheme?: string; body: Buffer | null };
const openers: Array<[string, (key: KeyRef, cid: string, bytes: Uint8Array) => Promise<unknown>]> = [["object", decryptObject], ["name", decryptContainerMeta], ["comment", decryptComment]];

/** Every ciphertext a request body could carry: its raw bytes, and each base64 string in a JSON body. */
function bodyBlobs(body: Buffer | null): Uint8Array[] {
  if (!body?.length) return [];
  const blobs: Uint8Array[] = [Uint8Array.from(body)];
  const walk = (value: unknown) => {
    if (typeof value === "string" && value.length >= 24 && /^[A-Za-z0-9+/]+=*$/.test(value)) blobs.push(fromBase64(value));
    else if (value && typeof value === "object") for (const entry of Object.values(value)) walk(entry);
  };
  try { walk(JSON.parse(body.toString("utf8"))); } catch { /* raw ciphertext, not JSON */ }
  return blobs;
}

/** What blob opens as under key in cid: object, name and/or comment. */
async function opensAs(key: KeyRef, cid: string, blob: Uint8Array) {
  const kinds: string[] = [];
  for (const [kind, open] of openers) if (await open(key, cid, blob).then(() => true, () => false)) kinds.push(kind);
  return kinds;
}

/** The title of the server's current copy of id, opened with key. */
const serverTitle = async (page: Page, id: string, key: KeyRef, cid: string) =>
  titleOf(key, cid, await page.evaluate(async (oid) => [...new Uint8Array(await (await fetch(`/api/v1/objects/${oid}`)).arrayBuffer())], id)).catch(() => undefined);

async function p5(owner: Person, editor: Person, cid: string, another: () => Promise<Person>) {
  const editorKey = (await vaultOf(editor.page))!.identity!;
  const editorId = (await ownSettings(editor.page)).userId;
  const senders = new Map([[editorKey.deviceId, Uint8Array.from(editorKey.publicKey)]]);
  const login = loginKey((await vaultOf(editor.page))!.authSecret);

  // 1. A new personal notebook is keyed before anything is written. No request carries anything the
  //    login-derived key opens; the name and pages open only with the container key.
  const writes: Write[] = [];
  const record = (request: Request) => {
    if (request.method() !== "GET") writes.push({ method: request.method(), path: new URL(request.url()).pathname, scheme: request.headers()["x-kynotes-key-scheme"], body: request.postDataBuffer() });
  };
  editor.page.on("request", record);
  await withDialog(editor, { type: "prompt", text: "Notebook name", answer: KEYED }, () => editor.page.getByRole("button", { name: "＋ New notebook" }).click());
  await expect(editor.page.locator(".workspace-title")).toHaveText(KEYED);
  const nid = containerOf(editor.page);
  await writePage(editor.page, "Keyed page", "keyed comment");
  editor.page.off("request", record);
  const created = writes.filter((write) => write.method === "POST" && write.path === "/api/v1/containers");
  expect(created.map((write) => JSON.parse(write.body!.toString()))).toEqual([{ kind: "workbook", teamId: "" }]);
  for (const write of writes.filter((entry) => /^\/api\/v1\/(objects|containers)\//.test(entry.path))) expect(write.scheme, `${write.method} ${write.path}`).toBe("shared-v2");
  const keys = await heldKeys(editor.page, nid, senders);
  expect([...keys.keys()]).toEqual([2]);
  const opened = new Set<string>();
  for (const write of writes) {
    for (const blob of bodyBlobs(write.body)) {
      expect(await opensAs(login, nid, blob), `${write.method} ${write.path}`).toEqual([]);
      for (const kind of await opensAs(keys.get(2)!, nid, blob)) opened.add(kind);
    }
  }
  // The bodies were read: the container key opens the name, the page and the comment in them.
  expect([...opened].sort()).toEqual(["comment", "name", "object"]);
  const copy = await serverCopy(editor.page, "Keyed page");
  expect(copy.generation).toBe(2);
  await expect(titleOf(keys.get(2)!, nid, copy.bytes)).resolves.toBe("Keyed page");
  await expect(titleOf(login, nid, copy.bytes)).rejects.toThrow();
  const meta = await editor.page.evaluate(async (id) => ((await (await fetch("/api/v1/containers")).json()) as Array<{ id: string; metaCiphertext: string }>).find((entry) => entry.id === id)!.metaCiphertext, nid);
  await expect(decryptContainerMeta(keys.get(2)!, nid, fromBase64(meta))).resolves.toMatchObject({ name: KEYED });
  await expect(decryptContainerMeta(login, nid, fromBase64(meta))).rejects.toThrow();
  await shoot(editor.page, "p5", "keyed", editor.page.locator(".workspace-title"));

  // A server that slips in a page sealed with the login key, at a generation this notebook never had a
  // key for: the browser fetches it and never shows it.
  const forged = await encryptNote(login, nid, { type: "page", title: FORGED_TITLE, body: "" });
  const forgedReads: string[] = [];
  const forgedPath = (url: URL) => url.pathname === `/api/v1/objects/${FORGED}`;
  const changesPath = (url: URL) => url.pathname === `/api/v1/containers/${nid}/changes`;
  await editor.page.route(forgedPath, (route) => {
    forgedReads.push(route.request().url());
    return route.fulfill({ status: 200, contentType: "application/octet-stream", headers: { "X-Kynotes-Version": "1", "X-Kynotes-Key-Generation": "1" }, body: Buffer.from(forged) });
  });
  await editor.page.route(changesPath, async (route) => {
    const response = await route.fetch();
    const json = await response.json() as { changes: Array<Record<string, unknown>> };
    if (new URL(route.request().url()).searchParams.get("since") === "0") json.changes.push({ id: FORGED, kind: "object", changeSeq: 1, deleted: false });
    await route.fulfill({ response, json });
  });
  await openTeam(editor.page, KEYED, nid);
  await expect(pageRow(editor.page, "Keyed page")).toBeVisible();
  expect(forgedReads.length).toBeGreaterThan(0);
  await expect(pageRow(editor.page, FORGED_TITLE)).toHaveCount(0);
  await editor.page.unroute(forgedPath);
  await editor.page.unroute(changesPath);

  // 2. The editor saves a recovery code: shown, asked back by a group that changes when it is shown
  //    again, never sent, never stored.
  const sentBodies: string[] = [];
  const recoveryWrites = (request: Request) => { if (request.method() === "PUT" && new URL(request.url()).pathname === "/api/v1/me/identity/recovery") sentBodies.push(request.postData() ?? ""); };
  editor.page.on("request", recoveryWrites);
  await editor.page.getByRole("button", { name: "Settings" }).click();
  const recovery = editor.page.locator("#recovery");
  await recovery.getByRole("button", { name: "Create recovery code" }).click();
  const code = await saveShownCode(recovery, { page: editor.page, phase: "p5", state: "recovery" });
  await expect(recovery.getByText(RECOVERY_SAVED)).toBeVisible({ timeout: 30_000 });
  editor.page.off("request", recoveryWrites);
  expect(sentBodies).toHaveLength(1);
  expect(sentBodies[0]).not.toContain(code);
  expect(sentBodies[0].toUpperCase()).not.toContain(code.replaceAll("-", ""));
  expect(await storageHolds(editor.page, code)).toBe(false);

  // 3. An edit made while the key is missing (no envelopes reach this fresh load) waits sealed with the
  //    waiting key; it survives a password change and is sent once the key arrives. Another browser
  //    signs in with the new password and reads it.
  const waitingRef = waitingKey({ privateKey: Uint8Array.from(editorKey.privateKey) });
  const current = (await decryptObject(keys.get(2)!, nid, Uint8Array.from(copy.bytes)))!;
  const waited = await encryptNote(waitingRef, nid, { ...current, title: WAITED } as Parameters<typeof encryptNote>[2]);
  const envelopesPath = (url: URL) => url.pathname === `/api/v1/containers/${nid}/envelopes`;
  await editor.page.route(envelopesPath, (route) => route.abort("connectionreset"));
  await editor.page.goto("/readyz");
  await queueEdit(editor.page, { id: copy.id, containerID: nid, version: copy.version, payload: [...waited], keyGeneration: 0, owner: editorId });
  await editor.page.goto(`/#/${nid}`);
  await expect(editor.page.locator(".workspace-title")).toHaveText(`Notebook ${nid.slice(4, 10)}`);
  await editor.page.getByRole("button", { name: "Settings" }).click();
  await changeOwnPassword(editor.page, OWN, NEW_OWN);
  const queued = (await storeRows(editor.page, "pending"))!;
  expect(queued).toEqual([expect.objectContaining({ id: copy.id, keyGeneration: 0, owner: editorId })]);
  await expect(titleOf(waitingRef, nid, queued[0].payload as number[])).resolves.toBe(WAITED);
  await editor.page.unroute(envelopesPath);
  await openTeam(editor.page, KEYED, nid);
  await expect.poll(() => serverTitle(editor.page, copy.id, keys.get(2)!, nid), { timeout: 30_000 }).toBe(WAITED);
  await expect.poll(async () => (await storeRows(editor.page, "pending"))!.length).toBe(0);
  const after = await another();
  await signIn(after.page, "editor", NEW_OWN);
  await openTeam(after.page, KEYED, nid);
  await readPage(after.page, WAITED, ["keyed comment"]);
  await openTeam(after.page, TEAM, cid);
  await readPage(after.page, "Owner page", ["owner comment"]);

  // 4. An administrator reset keeps the key: a fresh browser restores it with the code. A typo is refused
  //    before any request, a wrong code and a copy for another key are refused, nothing asks to link, and
  //    the code stays out of storage and the address bar.
  await owner.page.getByRole("button", { name: "Admin" }).click();
  const users = owner.page.locator("#users");
  await users.getByLabel("Confirm your password").fill(OWN);
  await users.getByRole("button", { name: "Authorize user creation and password resets" }).click();
  await expect(users.getByText("Password confirmed for ten minutes.")).toBeVisible();
  const row = owner.page.locator(".admin-user", { has: owner.page.locator("strong", { hasText: /^editor$/ }) });
  owner.expected.push({ type: "prompt", text: "New temporary password for editor", answer: RESET_TEMPORARY });
  await withDialog(owner, { type: "alert", text: ADMIN_RESET }, () => row.getByRole("button", { name: "Reset password" }).click());
  await owner.page.getByRole("button", { name: "← Workspace" }).click();
  const restored = await another();
  const linkWrites: string[] = [];
  const asked: string[] = [];
  restored.page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (request.method() !== "GET" && path.startsWith("/api/v1/me/link-requests")) linkWrites.push(path);
    if (path === "/api/v1/auth/step-up" || path.startsWith("/api/v1/me/identity/recovery")) asked.push(path);
  });
  await signIn(restored.page, "editor", RESET_TEMPORARY);
  await restored.page.getByRole("button", { name: "Settings" }).click();
  await changeOwnPassword(restored.page, RESET_TEMPORARY, OWN);
  const restore = restored.page.locator("#recovery-restore");
  await expect(restore).toBeVisible({ timeout: 30_000 });
  await shoot(restored.page, "p5", "restore", restore);
  const field = restore.getByLabel("Recovery code");
  const restoreButton = restore.getByRole("button", { name: "Restore" });
  asked.length = 0;
  await field.fill(code.slice(0, -1));
  await restoreButton.click();
  await expect(restore.getByText(RECOVERY_TYPO)).toBeVisible();
  expect(asked).toEqual([]);
  await field.fill(newRecoveryCode().code);
  await restoreButton.click();
  await expect(restore.getByText(RECOVERY_WRONG)).toBeVisible({ timeout: 30_000 });
  expect(asked).toContain("/api/v1/me/identity/recovery/fetch");
  // A copy listed for another public key (the owner's) is refused before it is opened.
  const fetchPath = (url: URL) => url.pathname === "/api/v1/me/identity/recovery/fetch";
  const ownerPublic = Buffer.from((await vaultOf(owner.page))!.identity!.publicKey).toString("base64");
  await restored.page.route(fetchPath, async (route) => {
    const response = await route.fetch();
    const json = await response.json() as { publicKey: string };
    await route.fulfill({ response, json: { ...json, publicKey: ownerPublic } });
  });
  await field.fill(code);
  await restoreButton.click();
  await expect(restore.getByText(RECOVERY_STALE)).toBeVisible({ timeout: 30_000 });
  expect((await vaultOf(restored.page))?.identity).toBeUndefined();
  await restored.page.unroute(fetchPath);
  await field.fill(` ${code.toLowerCase()} `);
  await restoreButton.click();
  // The restore card unmounts once the key is held, so Settings says what a link says (main.tsx justLinked).
  await expect(restored.page.getByRole("status").filter({ hasText: "Restored. This browser now holds your encryption key." })).toBeVisible({ timeout: 30_000 });
  await expect(restore).toHaveCount(0);
  const back = (await vaultOf(restored.page))!.identity!;
  expect(back.publicKey).toEqual(editorKey.publicKey);
  expect(back.privateKey).toEqual(editorKey.privateKey);
  expect(linkWrites).toEqual([]);
  expect(restored.page.url()).not.toContain(code);
  expect(await storageHolds(restored.page, code)).toBe(false);
  await restored.page.getByRole("button", { name: "← Workspace" }).click();
  await openTeam(restored.page, KEYED, nid);
  await readPage(restored.page, WAITED, ["keyed comment"]);
  await openTeam(restored.page, TEAM, cid);
  await readPage(restored.page, "Owner page", ["owner comment"]);
  await shoot(restored.page, "p5", "restored", restored.page.locator(".workspace-title"));

  // 5. A browser that ran a build before IndexedDB v6: its cache, queue, uploads and old local queue
  //    (rows sealed with the login key) are dropped on upgrade, never sent or offered.
  const upgraded = await another();
  const stale = [...await encryptNote(login, nid, { type: "page", title: "Old build edit", body: "" })];
  await upgraded.page.goto("/readyz");
  await upgraded.page.evaluate(({ owner, container, payload }) => new Promise<void>((resolve, reject) => {
    localStorage.setItem("kynotes-pending-saves", JSON.stringify([{ id: "obj_old", containerID: container }]));
    const open = indexedDB.open("kynotes-web", 5);
    open.onerror = () => reject(open.error);
    open.onupgradeneeded = () => {
      const db = open.result;
      const row = { id: `obj_${"o".repeat(26)}`, owner, containerID: container, version: 1, payload: new Uint8Array(payload), updatedAt: new Date().toISOString(), keyGeneration: 1 };
      db.createObjectStore("notes", { keyPath: ["owner", "id"] }).put(row);
      db.createObjectStore("pending", { keyPath: ["owner", "id"] }).put(row);
      db.createObjectStore("uploads", { keyPath: "uploadId" }).put({ uploadId: "upl_old", owner, containerID: container, payload: new Uint8Array(payload) });
    };
    open.onsuccess = () => { open.result.close(); resolve(); };
  }), { owner: editorId, container: nid, payload: stale });
  await signIn(upgraded.page, "editor", OWN);
  expect(await upgraded.page.evaluate(() => new Promise<number>((resolve) => { const open = indexedDB.open("kynotes-web"); open.onsuccess = () => { resolve(open.result.version); open.result.close(); }; }))).toBe(6);
  for (const store of ["notes", "pending", "uploads"]) expect(await storeRows(upgraded.page, store), store).toEqual([]);
  expect(await upgraded.page.evaluate(() => localStorage.getItem("kynotes-pending-saves"))).toBeNull();
  await upgraded.page.getByRole("button", { name: "Settings" }).click();
  await expect(upgraded.page.locator("#unsent-edits")).toHaveCount(0);
}

import { expect, type Browser, type BrowserContextOptions, type Locator, type Page } from "@playwright/test";
import { asContentKey, fromBase64, type KeyRef } from "../src/crypto";
import { envelopeSender, unwrapEnvelope } from "../src/teamKeys";

/** decline: dismiss it (a confirm answered Cancel); otherwise it is accepted with answer. */
export type Dialog = { type: string; text: string | RegExp; answer?: string; decline?: boolean; seen?: (defaultValue: string, message: string) => void };
export type Person = { page: Page; expected: Dialog[]; unexpected: string[] };

/** Every dialog must be announced with withDialog; anything else (a fingerprint change included) fails the run. */
export async function person(browser: Browser, options?: BrowserContextOptions): Promise<Person> {
  const page = await (await browser.newContext(options)).newPage();
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

export async function withDialog(who: Person, dialog: Dialog, action: () => Promise<unknown>) {
  who.expected.push(dialog);
  await action();
  // A poll runs no locator handler; this assertion does, so a step-up the action asked for is answered (answerStepUp).
  await expect.poll(async () => { await expect(stepUpPrompt(who.page)).toBeHidden(); return who.expected.length; }, { message: `dialog not shown: ${dialog.text}` }).toBe(0);
}

/** An everyday account on its own password: lands in the workspace. */
export async function signIn(page: Page, username: string, password: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Unlock KyNotes" }).click();
  await expect(page.getByRole("button", { name: "Settings" })).toBeVisible();
  await answerStepUp(page, password);
}

const stepUpPrompt = (page: Page) => page.getByRole("dialog", { name: "Confirm your password" });

/**
 * The vault keeps no login secret, so a reloaded tab asks for the password before it shares keys
 * (stepup.ts stepUpAsking). Answered with password before any action or auto-waiting assertion.
 */
export async function answerStepUp(page: Page, password: string) {
  await page.removeLocatorHandler(stepUpPrompt(page));
  await page.addLocatorHandler(stepUpPrompt(page), async (dialog) => {
    await dialog.getByLabel("Password").fill(password);
    await dialog.getByRole("button", { name: "Confirm" }).click();
  });
}

// Copied from main.tsx: a changed string fails the run.
export const CHOOSE_PASSWORD = "An administrator set this account's password. Choose your own before you continue.";

/** On the change screen: replaces the password an administrator set. */
export async function choosePassword(page: Page, current: string, next: string) {
  await expect(page.getByText(CHOOSE_PASSWORD)).toBeVisible();
  await page.getByLabel("Current password").fill(current);
  await page.getByLabel("New password", { exact: true }).fill(next);
  await page.getByLabel("Confirm new password").fill(next);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByText(CHOOSE_PASSWORD)).toHaveCount(0);
}

/** Signs in on a password an administrator set and replaces it on the change screen; lands in the workspace or console. */
export async function signInAndChoose(page: Page, username: string, temporary: string, own: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password", { exact: true }).fill(temporary);
  await page.getByRole("button", { name: "Unlock KyNotes" }).click();
  await choosePassword(page, temporary, own);
  await answerStepUp(page, own);
}

/** KYNOTES_E2E_SHOTS=<dir>: a state in Busnes Light and Dark at 1280x900 and 390x844 (UI-VERIFICATION.md). */
export async function shoot(prefix: string, page: Page, phase: string, state: string, focus: Locator) {
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
      console.log(`shot ${prefix}-${phase}-${state}-${scheme}-${form}: ${JSON.stringify(measured)}`);
      expect(measured.scrollWidth).toBeLessThanOrEqual(width);
      await page.screenshot({ path: `${dir}/${prefix}-${phase}-${state}-${scheme}-${form}.png` });
    }
  }
  await page.emulateMedia({ colorScheme: null });
  await page.setViewportSize(size);
}

export const ADMIN = { username: "admin", password: "admin horse battery staple" };
export const OWNER = { username: "owner", password: "my own horse battery staple" };

/** The administrator console in page: first-run setup once per server (every e2e file shares it), else a sign-in. */
export async function adminConsole(page: Page) {
  await page.goto("/");
  const required = await page.evaluate(async () => ((await (await fetch("/api/v1/setup")).json()) as { setupRequired: boolean }).setupRequired);
  if (required) {
    await shoot("admin-separation", page, "setup", "first-run", page.getByRole("button", { name: "Initialize KyNotes" }));
    await page.getByLabel("Administrator username").fill(ADMIN.username);
    await page.getByLabel("Administrator password", { exact: true }).fill(ADMIN.password);
    await page.getByLabel("Confirm administrator password").fill(ADMIN.password);
    await page.getByLabel("Everyday username").fill(OWNER.username);
    await page.getByLabel("Everyday password", { exact: true }).fill(OWNER.password);
    await page.getByLabel("Confirm everyday password").fill(OWNER.password);
    await page.getByRole("button", { name: "Initialize KyNotes" }).click();
  } else {
    await page.getByLabel("Username").fill(ADMIN.username);
    await page.getByLabel("Password", { exact: true }).fill(ADMIN.password);
    await page.getByRole("button", { name: "Unlock KyNotes" }).click();
  }
  await expect(page.getByRole("heading", { name: "Administration" })).toBeVisible();
}

/** On the console: the administrator's password step-up for one section's routes (user creation and resets, teams). */
export async function confirmAdmin(page: Page, section: string) {
  const card = page.locator(`#${section}`);
  const field = card.getByLabel("Confirm your password");
  await expect(field).toBeVisible();
  await field.fill(ADMIN.password);
  await card.getByRole("button", { name: /^Authorize / }).click();
  await expect(card.getByText("Password confirmed for ten minutes.")).toBeVisible();
}

export async function createUser(admin: Person, username: string, password: string, kind: "Everyday" | "Administrator" = "Everyday") {
  const { page } = admin;
  await confirmAdmin(page, "users");
  await page.getByPlaceholder("Username").fill(username);
  await page.getByPlaceholder("Temporary password").fill(password);
  await page.getByLabel("Account type").selectOption({ label: kind });
  await page.getByRole("button", { name: "Create user" }).click();
  await expect(page.locator(".admin-user", { hasText: username })).toBeVisible();
}

/** Creates a team owned by ownerName and returns its ID (create() selects the new team). */
export async function createTeamFor(admin: Person, ownerName: string): Promise<string> {
  const { page } = admin;
  await confirmAdmin(page, "teams");
  const before = await page.locator(".admin-teams li").count();
  const owner = page.getByRole("combobox", { name: "Owner", exact: true });
  await owner.selectOption((await owner.locator("option", { hasText: new RegExp(`^${ownerName}$`) }).getAttribute("value"))!);
  await page.getByRole("button", { name: "Create team" }).click();
  await expect(page.locator(".admin-teams li")).toHaveCount(before + 1);
  const team = page.getByRole("combobox", { name: "Team", exact: true });
  await expect(team).not.toHaveValue("");
  return team.inputValue();
}

export async function addToTeam(admin: Person, username: string, teamID: string) {
  const { page } = admin;
  await confirmAdmin(page, "teams");
  await page.getByRole("combobox", { name: "Team", exact: true }).selectOption(teamID);
  const who = page.getByRole("combobox", { name: "Person", exact: true });
  await who.selectOption((await who.locator("option", { hasText: new RegExp(`^${username}$`) }).getAttribute("value"))!);
  await withDialog(admin, { type: "alert", text: "Person added. They get the team's keys once one of its owners approves them." }, () => page.getByRole("button", { name: "Add to team" }).click());
}

// Copied from main.tsx: a changed string fails the run.
export const UNNAMED_TEAM = "An administrator created this team notebook for you. Name it so its members can find it.";

/** The owner opens a team an administrator created for them (its first open mints the key) and names it. */
export async function nameTeam(owner: Person, teamID: string, name: string) {
  const { page } = owner;
  await page.goto("about:blank");
  await page.goto(`/#/${teamID}`);
  await expect(page.getByText(UNNAMED_TEAM)).toBeVisible();
  await withDialog(owner, { type: "prompt", text: "Notebook name", answer: name }, () => page.getByRole("button", { name: "Name notebook", exact: true }).click());
  await expect(page.locator(".workspace-title")).toHaveText(name);
}

/** In the owner's open team: approves an administrator-added member and waits for the key pass. */
export async function approve(owner: Person, username: string) {
  const banner = owner.page.locator(".conflict-banner", { hasText: "was added by an administrator" }).filter({ hasText: username });
  await banner.getByRole("button", { name: "Approve and share keys" }).click();
  await expect(banner).toHaveCount(0);
}

/** fields: the record's stored field names, so a test sees anything kept beyond the identity. */
type Vault = { fields: string[]; sealed: boolean; extractable?: boolean; identity?: { deviceId: string; publicKey: number[]; privateKey: number[] } };

/** This browser's keys vault record; a sealed identity is opened in the page with its device key. Never creates the database. */
export function vaultOf(page: Page) {
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
        const row = (all.result as Array<{ identity?: Stored }>)[0];
        if (!row) { resolve(null); return; }
        const fields = Object.keys(row).sort();
        const stored = row.identity;
        if (!stored) { resolve({ fields, sealed: false }); return; }
        try {
          const privateKey = stored.sealed && stored.deviceKey
            ? new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: stored.sealed.slice(0, 12), additionalData: new TextEncoder().encode(`kynotes/device-identity/v1|${stored.userID}|${stored.deviceId}`) }, stored.deviceKey, stored.sealed.slice(12)))
            : stored.privateKey!;
          resolve({ fields, sealed: Boolean(stored.sealed), extractable: stored.deviceKey?.extractable, identity: { deviceId: stored.deviceId, publicKey: [...stored.publicKey], privateKey: [...privateKey] } });
        } catch (error) { reject(error); }
      };
    };
  }));
}

/**
 * The container keys page's own envelopes open to, by generation. The sender key comes from the
 * identities the three browsers hold, never from the server, so a substituted sender fails here.
 */
export async function heldKeys(page: Page, cid: string, senders: Map<string, Uint8Array>): Promise<Map<number, KeyRef>> {
  const own = (await vaultOf(page))!.identity!;
  const rows = await page.evaluate(async (id) => (await fetch(`/api/v1/containers/${id}/envelopes`)).json(), cid) as Array<{ deviceId: string; keyGeneration: number; envelope: string }>;
  return new Map(rows.filter((row) => row.deviceId === own.deviceId).map((row) => {
    const envelope = fromBase64(row.envelope);
    const sender = senders.get(envelopeSender(envelope));
    if (!sender) throw new Error(`envelope from an unknown sender ${envelopeSender(envelope)} (generation ${row.keyGeneration} for ${own.deviceId}; known: ${[...senders.keys()].join(", ")})`);
    return [row.keyGeneration, asContentKey(unwrapEnvelope(envelope, Uint8Array.from(own.privateKey), cid, row.keyGeneration, own.deviceId, sender))];
  }));
}

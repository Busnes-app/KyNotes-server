import { expect, test } from "@playwright/test";
import { ADMIN, CHOOSE_PASSWORD, OWNER, UNNAMED_TEAM, addToTeam, adminConsole, approve, choosePassword, createTeamFor, createUser, nameTeam, person, shoot, signIn, signInAndChoose, type Person } from "./people";

const TEMPORARY = "temporary sep battery staple";
const ALICE_OWN = "alice own sep battery staple";
const OPS_OWN = "ops own sep battery staple";
const TEAM = "Separated Team E2E";
const WAITING = "This notebook is read-only until its keys reach this browser.";
// Copied from components/AdminConsole.tsx: a changed string fails the run.
const ADMIN_ACCOUNT_NOTE = "This is an administrator account. It manages KyNotes and cannot open notes. Sign in with your everyday account to write.";

const apiStatus = (who: Person, path: string) => who.page.evaluate(async (p) => {
  const response = await fetch(p);
  return { status: response.status, code: ((await response.json().catch(() => ({}))) as { error?: { code?: string } }).error?.code };
}, path);
/** Rows in this browser's keys vault (saved sign-ins and identities); 0 when it was never created. */
const vaultRows = (who: Person) => who.page.evaluate(() => new Promise<number>((resolve) => {
  const open = indexedDB.open("kynotes-web");
  open.onupgradeneeded = () => open.transaction!.abort();
  open.onerror = () => resolve(0);
  open.onsuccess = () => {
    const db = open.result;
    if (!db.objectStoreNames.contains("keys")) { db.close(); resolve(0); return; }
    const count = db.transaction("keys").objectStore("keys").count();
    count.onsuccess = () => { db.close(); resolve(count.result); };
  };
}));

test("administrator and everyday accounts stay apart", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  const alice = await person(browser);
  const ops = await person(browser);
  try {
    // 1. The administrator console: no workspace, no notes, nothing kept in the browser.
    await adminConsole(admin.page);
    await expect(admin.page.getByText(ADMIN_ACCOUNT_NOTE)).toBeVisible();
    await expect(admin.page.getByRole("button", { name: "Settings", exact: true })).toHaveCount(0);
    expect(await apiStatus(admin, "/api/v1/containers")).toEqual({ status: 403, code: "admin_account" });
    expect(await vaultRows(admin)).toBe(0);
    await shoot("admin-separation", admin.page, "console", "admin", admin.page.getByRole("heading", { name: "Administration" }));

    // 2. The everyday owner from setup reaches notes and no administration.
    await signIn(owner.page, OWNER.username, OWNER.password);
    expect(await apiStatus(owner, "/api/v1/admin/users")).toEqual({ status: 403, code: "forbidden" });
    await expect(owner.page.getByRole("button", { name: "Admin" })).toHaveCount(0);

    // 3. Accounts an administrator creates change their password before anything else, even after a reload.
    await createUser(admin, "sep-alice", TEMPORARY);
    await createUser(admin, "sep-ops", TEMPORARY, "Administrator");
    await alice.page.goto("/");
    await alice.page.getByLabel("Username").fill("sep-alice");
    await alice.page.getByLabel("Password", { exact: true }).fill(TEMPORARY);
    await alice.page.getByRole("button", { name: "Unlock KyNotes" }).click();
    await expect(alice.page.getByText(CHOOSE_PASSWORD)).toBeVisible();
    expect(await apiStatus(alice, "/api/v1/containers")).toEqual({ status: 409, code: "password_change_required" });
    await shoot("admin-separation", alice.page, "choose-password", "everyday", alice.page.getByText(CHOOSE_PASSWORD));
    await alice.page.reload();
    await choosePassword(alice.page, TEMPORARY, ALICE_OWN);
    await expect(alice.page.getByRole("button", { name: "Settings" })).toBeVisible();
    expect((await apiStatus(alice, "/api/v1/containers")).status).toBe(200);
    // The identity is created after the change, in the background: wait for it, or the owner's approval wraps for nobody.
    await expect.poll(async () => (await apiStatus(alice, "/api/v1/me/identity")).status, { timeout: 30_000 }).toBe(200);

    // 4. A team for the everyday owner: the owner names it, and approves the person the administrator added.
    const teamID = await createTeamFor(admin, OWNER.username);
    await addToTeam(admin, "sep-alice", teamID);
    await nameTeam(owner, teamID, TEAM);
    await expect(owner.page.getByText(UNNAMED_TEAM)).toHaveCount(0);
    await expect(owner.page.locator(".member-row", { hasText: "sep-alice" })).toContainText("awaiting approval");
    await alice.page.goto("about:blank"); // a fresh load lists the team she was just added to
    await alice.page.goto(`/#/${teamID}`);
    await expect(alice.page.getByText(WAITING)).toBeVisible();
    await shoot("admin-separation", owner.page, "approve", "owner", owner.page.locator(".conflict-banner", { hasText: "sep-alice" }));
    await approve(owner, "sep-alice");
    await expect(owner.page.locator(".member-row", { hasText: "sep-alice" })).toContainText("has key");
    await alice.page.reload();
    await expect(alice.page.locator(".workspace-title")).toHaveText(TEAM);
    await expect(alice.page.getByText(WAITING)).toHaveCount(0);

    // 5. The administrator sees the team's owner and count, never its name.
    await admin.page.reload();
    await expect(admin.page.locator(".admin-teams li", { hasText: teamID })).toContainText(`owner ${OWNER.username}`);
    await expect(admin.page.locator(".admin-teams li", { hasText: teamID })).toContainText("named");
    await expect(admin.page.getByText(TEAM)).toHaveCount(0);

    // 6. A second administrator account also changes its temporary password first, then gets the console.
    await signInAndChoose(ops.page, "sep-ops", TEMPORARY, OPS_OWN);
    await expect(ops.page.getByRole("heading", { name: "Administration" })).toBeVisible();
    expect(await vaultRows(ops)).toBe(0);
    expect(ADMIN.username).not.toBe(OWNER.username);
  } finally {
    for (const who of [admin, owner, alice, ops]) expect(who.unexpected).toEqual([]);
  }
});

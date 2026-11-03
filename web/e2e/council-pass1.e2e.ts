import { expect, test, type Page } from "@playwright/test";
import { OWNER, adminConsole, adminSection, approve, createTeamFor, createUser, nameTeam, openNotebooks, person, signIn, signInAndChoose, vaultOf, withDialog } from "./people";

// Regression checks for the hostile-review pass 1 client fixes.
const TEMPORARY = "temporary horse battery staple";
const READER = "reader-p1";
const TEAM = "Council pass 1 team";

const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());

async function newPage(page: Page, title: string) {
  const created = objectSave(page);
  await page.getByRole("button", { name: "New page" }).click();
  await created;
  const titled = objectSave(page);
  await page.locator(".title-input").fill(title);
  await titled;
}

async function openTeam(page: Page, cid: string) {
  await page.goto("about:blank");
  await page.goto(`/#/${cid}`);
  await expect(page.locator(".workspace-title")).toHaveText(TEAM);
  await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
}

test("client fixes: comment drafts, unsent drafts, read-only roles", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  const reader = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const { page } = owner;
    await openNotebooks(page);
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: "Council pass 1" }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");

    // A comment draft stays with its page.
    await newPage(page, "First page");
    const panel = page.locator("details.comments");
    if (await panel.getAttribute("open") === null) await panel.locator("summary").click();
    await page.getByPlaceholder("Add a comment…").fill("private draft");
    await newPage(page, "Second page");
    if (await panel.getAttribute("open") === null) await panel.locator("summary").click();
    await expect(page.getByPlaceholder("Add a comment…")).toHaveValue("");

    // An edit whose save never reached the server is sent after a reload, not shown as saved.
    // Saves are held until the reload has started, so neither the debounced nor the pagehide save lands.
    let hold = true;
    await page.route((url) => /\/api\/v1\/objects\/obj_/.test(url.pathname), (route) => (route.request().method() === "PUT" && hold ? new Promise(() => {}) : route.fallback()));
    await page.locator(".title-input").fill("Second page, unsent edit");
    // The draft reaches IndexedDB on the keystroke; the held save never answers.
    await page.waitForRequest((request) => request.method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(request.url()));
    const sent = page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok(), { timeout: 30_000 });
    await page.reload({ waitUntil: "commit" });
    hold = false;
    await sent;
    await expect(page.locator(".note-row", { hasText: "Second page, unsent edit" })).toBeVisible();

    // A viewer reads a team page but gets no editable title or canvas.
    await createUser(admin, READER, TEMPORARY);
    await signInAndChoose(reader.page, READER, TEMPORARY, OWNER.password);
    await expect.poll(() => vaultOf(reader.page), { timeout: 30_000 }).toMatchObject({ identity: expect.anything() });
    const teamID = await createTeamFor(admin, OWNER.username);
    await nameTeam(owner, teamID, TEAM);
    await adminSection(admin.page, "Teams");
    await admin.page.getByRole("combobox", { name: "Team", exact: true }).selectOption(teamID);
    const who = admin.page.getByRole("combobox", { name: "Person", exact: true });
    await who.selectOption((await who.locator("option", { hasText: new RegExp(`^${READER}$`) }).getAttribute("value"))!);
    await admin.page.getByRole("combobox", { name: "Role", exact: true }).selectOption("viewer");
    await withDialog(admin, { type: "alert", text: "Person added. They get the team's keys once one of its owners approves them." }, () => admin.page.getByRole("button", { name: "Add to team" }).click());
    await openTeam(owner.page, teamID);
    await approve(owner, READER);
    await newPage(owner.page, "Team page");
    await openTeam(reader.page, teamID);
    await reader.page.locator(".note-row", { hasText: "Team page" }).click();
    await expect(reader.page.locator(".title-input")).toHaveValue("Team page");
    await expect(reader.page.locator(".title-input")).toHaveAttribute("readonly", "");
    for (const who of [admin, owner, reader]) expect(who.unexpected).toEqual([]);
  } finally {
    for (const who of [admin, owner, reader]) await who.page.context().close();
  }
});

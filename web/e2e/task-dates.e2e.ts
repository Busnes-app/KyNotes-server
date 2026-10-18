import { expect, test, type Page } from "@playwright/test";
import { adminConsole, createUser, OWNER, person, shoot, signIn, signInAndChoose, withDialog, type Person } from "./people";

const NOTEBOOK = "Task dates E2E";
const TASK = "Water plants";

const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());
const day = (offset: number, from = new Date()) => {
  const date = new Date(from);
  date.setDate(date.getDate() + offset);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
};
const items = (page: Page) => page.locator('.bn-editor [data-content-type="checkListItem"]');
/** A new notebook with one canvas page "Chores", the cursor in its first text box. */
async function newTextPage(owner: Person, notebook: string) {
  const { page } = owner;
  await withDialog(owner, { type: "prompt", text: "Notebook name", answer: notebook }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
  await expect(page.locator(".workspace-title")).toHaveText(notebook);
  await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
  const created = objectSave(page);
  await page.getByRole("button", { name: "New page" }).click();
  await created;
  const titled = objectSave(page);
  await page.locator(".title-input").fill("Chores");
  await titled;
  await page.getByRole("button", { name: "Add text" }).click();
  await page.locator(".bn-editor").first().click();
}
const queueRow = (page: Page, group: string) => page.locator(`[data-task-group="${group}"] .note-row`, { hasText: TASK });

test("a repeating checklist item rolls forward when ticked, and the work queue groups it by date", async ({ browser }) => {
  const yesterday = day(-1), today = day(0);
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const { page } = owner;
    await newTextPage(owner, NOTEBOOK);
    // "[] " at line start makes a checklist item.
    await page.keyboard.type(`[] ${TASK} due:${yesterday} repeat:daily`);
    await page.keyboard.press("Escape"); // ":" opens the emoji menu
    await expect(items(page)).toHaveCount(1);
    await expect(items(page).first()).toContainText(`${TASK} due:${yesterday} repeat:daily`);

    // The queue reads the open page live: overdue, with its date and the repeat marker.
    await page.getByRole("button", { name: "Work queue" }).click();
    await expect(queueRow(page, "overdue")).toContainText(`Due ${yesterday} · repeats · Chores`);
    await expect(queueRow(page, "overdue").locator("strong")).toHaveText(TASK);

    // Ticking it adds the next occurrence and drops repeat from the done item, in one saved edit.
    await queueRow(page, "overdue").click();
    await expect(items(page)).toHaveCount(1);
    const ticked = objectSave(page);
    await items(page).first().locator('input[type="checkbox"]').check();
    await ticked;
    await expect(items(page)).toHaveCount(2);
    await expect(items(page).nth(0).locator('input[type="checkbox"]')).toBeChecked();
    await expect(items(page).nth(0)).toHaveText(`${TASK} due:${yesterday}`);
    await expect(items(page).nth(1).locator('input[type="checkbox"]')).not.toBeChecked();
    await expect(items(page).nth(1)).toHaveText(`${TASK} due:${today} repeat:daily`);
    await expect(queueRow(page, "today")).toContainText(`Due ${today} · repeats`);
    await expect(queueRow(page, "overdue")).toHaveCount(0);

    // After a reload the saved page holds the same two items: nothing is generated twice.
    // The tick's save can land before the rolled-forward edit's; reload only once both are on the server.
    await expect(page.getByText("● Saved to server")).toBeVisible();
    await page.reload();
    await page.getByRole("button", { name: "Work queue" }).click();
    await expect(queueRow(page, "today")).toHaveCount(1);
    await expect(queueRow(page, "overdue")).toHaveCount(0);
    await queueRow(page, "today").click();
    await expect(items(page)).toHaveCount(2);
    await expect(items(page).nth(0)).toHaveText(`${TASK} due:${yesterday}`);

    // A reminder that passed before this tab opened fires nothing and shows as missed.
    await page.getByRole("button", { name: "Add text" }).click();
    await page.locator(".bn-editor").nth(1).click();
    await page.keyboard.type(`[] Call home remind:${yesterday}T09:00`);
    await page.keyboard.press("Escape"); // ":" opens the emoji menu
    await expect(items(page)).toHaveCount(3);
    const missed = page.locator('[data-task-group="overdue"] .note-row', { hasText: "Call home" });
    await expect(missed).toContainText("missed reminder · Chores");
    await expect(missed.locator("strong")).toHaveText("Call home");
    await page.getByRole("button", { name: "Work queue" }).click();
    await expect(queueRow(page, "today")).toHaveCount(1);
    await shoot("task-dates", page, "queue", "grouped", queueRow(page, "today"));
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

test("an enabled reminder fires once in the open tab, saying only that a task is due", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    const { page } = owner;
    // Records notifications instead of showing them; permission is granted on request and kept across loads.
    await page.addInitScript(() => {
      const shown: Array<{ title: string; body?: string }> = [];
      Object.assign(window, { shown });
      class Recorder { static get permission() { return sessionStorage.getItem("e2e-permission") ?? "default"; } static async requestPermission() { sessionStorage.setItem("e2e-permission", "granted"); return "granted"; } constructor(title: string, options?: NotificationOptions) { shown.push({ title, body: options?.body }); } }
      Object.defineProperty(window, "Notification", { value: Recorder });
    });
    const start = new Date();
    await page.clock.install({ time: start });
    await signIn(page, OWNER.username, OWNER.password);
    await page.getByRole("button", { name: "Settings" }).click();
    await page.getByLabel("Show reminders while KyNotes is open").check();
    await expect(page.getByLabel("Show reminders while KyNotes is open")).toBeChecked();
    await expect(page.getByLabel("Show task text in reminders")).not.toBeChecked();
    await shoot("task-dates", page, "settings", "reminders", page.locator("#reminders"));
    await page.getByRole("button", { name: "← Workspace" }).click();

    await newTextPage(owner, "Reminder E2E");
    const at = new Date(start.getTime() + 5 * 60_000);
    const remind = `${day(0, at)}T${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;
    await page.keyboard.type(`[] Call the vet remind:${remind}`);
    await page.keyboard.press("Escape"); // ":" opens the emoji menu
    await expect(items(page)).toHaveCount(1);
    const shown = () => page.evaluate(() => (window as unknown as { shown: unknown[] }).shown);
    expect(await shown()).toEqual([]);
    await page.clock.fastForward("10:00");
    await expect.poll(shown).toEqual([{ title: "KyNotes", body: "A task is due" }]);
    await page.clock.fastForward("10:00");
    expect(await shown()).toHaveLength(1);
    await page.getByRole("button", { name: "Work queue" }).click();
    // It fired here, so it is not missed: a plain undated task.
    await expect(page.locator('[data-task-group="undated"] .note-row', { hasText: "Call the vet" })).toHaveText("Call the vetChores");

    // The opt-in belongs to the account: another account in this browser starts with both off.
    await createUser(admin, "rem-bob", "temporary rem battery staple");
    await page.getByRole("button", { name: "Lock" }).click();
    await signInAndChoose(page, "rem-bob", "temporary rem battery staple", "bob own rem battery staple");
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByLabel("Show reminders while KyNotes is open")).not.toBeChecked();
    await expect(page.getByLabel("Show task text in reminders")).not.toBeChecked();
    await page.getByRole("button", { name: "Lock" }).click();
    await signIn(page, OWNER.username, OWNER.password);
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByLabel("Show reminders while KyNotes is open")).toBeChecked();
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

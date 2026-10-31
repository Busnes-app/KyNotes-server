import { expect, test, type Page } from "@playwright/test";
import { adminConsole, createUser, OWNER, person, shoot, signIn, signInAndChoose, withDialog, type Person, openNotebooks, backToNotes } from "./people";

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
  await openNotebooks(page);
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
const emojiMenu = (page: Page) => page.locator(".bn-grid-suggestion-menu");
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
    await expect(emojiMenu(page)).toHaveCount(0); // ":" inside a word never opens the emoji menu
    await expect(items(page)).toHaveCount(1);
    await expect(items(page).first()).toContainText(`${TASK} due:${yesterday} repeat:daily`);

    // The queue reads the open page live: overdue, with its date and the repeat marker.
    await openNotebooks(page);
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
    await expect(page.locator(".save-state .ky-status")).toHaveText("Saved to server");
    await page.reload();
    await openNotebooks(page);
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
    await openNotebooks(page);
    await page.getByRole("button", { name: "Work queue" }).click();
    await expect(queueRow(page, "today")).toHaveCount(1);
    await shoot("task-dates", page, "queue", "grouped", queueRow(page, "today"));
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

test("':' opens the emoji menu only where it starts a word and two letters follow", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const { page } = owner;
    await newTextPage(owner, "Emoji menu E2E");
    await page.keyboard.type("due:today at 10:30 :1a");
    await expect(emojiMenu(page)).toHaveCount(0);
    await page.keyboard.type(" :s");
    await expect(emojiMenu(page)).toHaveCount(0);
    await page.keyboard.type("mile");
    // Enter picks nothing until the menu's items have loaded.
    await expect(emojiMenu(page).locator(".bn-grid-suggestion-menu-item").first()).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(emojiMenu(page)).toHaveCount(0);
    await expect(page.locator(".bn-editor").first()).not.toContainText(":smile");
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
    await backToNotes(page);

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
    await openNotebooks(page);
    await page.getByRole("button", { name: "Work queue" }).click();
    // It fired here, so it is not missed: a plain undated task.
    await expect(page.locator('[data-task-group="undated"] .note-row', { hasText: "Call the vet" })).toHaveText("Call the vetChores");

    // The opt-in belongs to the account: another account in this browser starts with both off.
    await createUser(admin, "rem-bob", "temporary rem battery staple");
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await signInAndChoose(page, "rem-bob", "temporary rem battery staple", "bob own rem battery staple");
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByLabel("Show reminders while KyNotes is open")).not.toBeChecked();
    await expect(page.getByLabel("Show task text in reminders")).not.toBeChecked();
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await signIn(page, OWNER.username, OWNER.password);
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByLabel("Show reminders while KyNotes is open")).toBeChecked();
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

test("push reminders send the server only an opaque id and a UTC minute", async ({ browser }) => {
  const admin = await person(browser);
  // Off UTC, so the local reminder time and the UTC minute the server gets are different strings.
  const owner = await person(browser, { timezoneId: "America/New_York" });
  try {
    await adminConsole(admin.page);
    const { page } = owner;
    // Headless Chromium has no push service: subscribe() is stubbed with a fixed FCM-shaped endpoint;
    // notification permission is granted. The service worker itself is the real /sw.js.
    await page.addInitScript(() => {
      class Granted { static permission = "granted"; static async requestPermission() { return "granted"; } }
      Object.defineProperty(window, "Notification", { value: Granted });
      let current: unknown = null;
      PushManager.prototype.subscribe = async function (options?: PushSubscriptionOptionsInit) {
        current = { endpoint: "https://fcm.googleapis.com/fcm/send/e2e-stub", options: { applicationServerKey: options?.applicationServerKey }, unsubscribe: async () => { current = null; return true; } };
        return current as PushSubscription;
      };
      PushManager.prototype.getSubscription = async () => current as PushSubscription | null;
    });
    const sent: Array<{ method: string; url: string; body: string }> = [];
    page.on("request", (request) => {
      if (/\/api\/v1\/(push|reminders)/.test(request.url())) sent.push({ method: request.method(), url: new URL(request.url()).pathname, body: request.postData() ?? "" });
    });
    await signIn(page, OWNER.username, OWNER.password);
    await newTextPage(owner, "Push E2E");
    const remind = `${day(2)}T09:00`;
    await page.keyboard.type(`[] Feed the cat remind:${remind} push:yes`);
    await page.keyboard.press("Escape"); // ":" opens the emoji menu
    await expect(items(page)).toHaveCount(1);
    await openNotebooks(page);
    await page.getByRole("button", { name: "Work queue" }).click();
    const row = page.locator('[data-task-group="undated"] .note-row', { hasText: "Feed the cat" });
    await expect(row).toContainText("push · Chores");
    // Nothing reaches the server until the setting is on.
    expect(sent.filter((request) => request.method !== "GET")).toEqual([]);

    await page.getByRole("button", { name: "Settings" }).click();
    const setting = page.getByLabel("Also remind me when KyNotes is closed (sends reminder times to the server)");
    await expect(setting).not.toBeChecked();
    await setting.click(); // checked once the subscription is registered, so not check()
    await expect(setting).toBeChecked();
    await expect.poll(() => sent.filter((request) => request.method === "PUT" && request.url === "/api/v1/push/web/subscriptions").map((request) => request.body)).toContainEqual('{"endpoint":"https://fcm.googleapis.com/fcm/send/e2e-stub"}');
    expect(await page.evaluate(async () => (await navigator.serviceWorker.getRegistration("/"))?.active?.scriptURL)).toMatch(/\/sw\.js$/);
    await shoot("task-dates", page, "settings", "push", page.locator("#reminders"));
    // Back to the work queue the task row lives in (the Notes tab would open a notebook).
    await page.getByRole("button", { name: "Work queue" }).click();

    // The reconcile after the notebooks load puts exactly one reminder: id and UTC minute only.
    const at = await page.evaluate((value) => { const [d, t] = value.split("T"); const [y, m, day] = d.split("-").map(Number); const [h, min] = t.split(":").map(Number); return new Date(y, m - 1, day, h, min).toISOString().slice(0, 16) + ":00Z"; }, remind);
    const reminderPuts = () => sent.filter((request) => request.method === "PUT" && request.url.startsWith("/api/v1/reminders/"));
    await expect.poll(() => reminderPuts().length).toBe(1);
    const [put] = reminderPuts();
    expect(put.url).toMatch(/^\/api\/v1\/reminders\/[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
    expect(put.body).toBe(JSON.stringify({ at }));
    const listed = await (await page.request.get("/api/v1/reminders")).json();
    expect(listed).toEqual([{ id: put.url.split("/").pop(), at }]);

    // Ticking the task removes the server reminder.
    await row.click();
    const ticked = objectSave(page);
    await items(page).first().locator('input[type="checkbox"]').check();
    await ticked;
    await expect.poll(() => sent.some((request) => request.method === "DELETE" && request.url === put.url)).toBe(true);

    // Turning push off removes this browser's endpoint.
    await page.getByRole("button", { name: "Settings" }).click();
    await setting.uncheck();
    await expect.poll(() => sent.filter((request) => request.method === "DELETE" && request.url === "/api/v1/push/web/subscriptions").map((request) => request.body)).toContainEqual('{"endpoint":"https://fcm.googleapis.com/fcm/send/e2e-stub"}');

    // No push or reminder request carried task text, a page or object ID, or the local reminder time.
    for (const request of sent) {
      expect(request.body + request.url).not.toMatch(/Feed the cat|Chores|obj_|cnt_|push:yes/);
      expect(request.body).not.toContain(remind);
    }
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

import { expect, test, type Page } from "@playwright/test";
import { adminConsole, OWNER, person, signIn, withDialog, openNotebooks } from "./people";

const NOTEBOOK = "Three pane E2E";
const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());

test("formatting comes first, ink sits behind Draw, and sections open their first page", async ({ browser }) => {
  const admin = await person(browser, { viewport: { width: 1440, height: 900 } });
  const owner = await person(browser, { viewport: { width: 1440, height: 900 } });
  const { page } = owner;
  try {
    await adminConsole(admin.page);
    await signIn(page, OWNER.username, OWNER.password);
    await openNotebooks(page);
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: NOTEBOOK }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".workspace-title")).toHaveText(NOTEBOOK);
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    const created = objectSave(page);
    await page.getByRole("button", { name: "New page", exact: true }).click();
    await created;
    const titled = objectSave(page);
    await page.locator(".title-input").fill("Formatting");
    await titled;

    // Text formatting leads the toolbar; ink tools are not shown until Draw is on.
    const tools = page.getByRole("toolbar", { name: "Page tools" });
    const labels = await tools.getByRole("button").evaluateAll((buttons) => buttons.map((button) => button.getAttribute("aria-label") ?? button.textContent?.trim()));
    expect(labels).toEqual(["Heading 1", "Heading 2", "Heading 3", "Bold", "Italic", "Bulleted list", "Numbered list", "Checklist", "Link", "Code", "Add text", "Draw"]);
    await expect(page.getByRole("button", { name: "Pen", exact: true })).toHaveCount(0);

    // On an empty page a block format starts a text box in that format; then formats apply to the box being written in.
    await tools.getByRole("button", { name: "Heading 2" }).click();
    const editor = page.locator(".bn-editor").first();
    await expect(editor).toBeFocused();
    await page.keyboard.type("Plan");
    await expect(editor.locator('[data-content-type="heading"][data-level="2"]')).toHaveText("Plan");
    await page.keyboard.press("End");
    await page.keyboard.press("Enter");
    await tools.getByRole("button", { name: "Checklist" }).click();
    await page.keyboard.type("Buy seeds");
    await expect(editor.locator('[data-content-type="checkListItem"]')).toHaveText("Buy seeds");
    await page.keyboard.press("Shift+Home");
    await tools.getByRole("button", { name: "Bold" }).click();
    await expect(editor.locator("strong")).toHaveText("Buy seeds");
    // Only web and mail links are made.
    await withDialog(owner, { type: "prompt", text: "Link address", answer: "javascript:alert(1)" }, () => tools.getByRole("button", { name: "Link" }).click());
    await expect(editor.locator("a")).toHaveCount(0);
    await withDialog(owner, { type: "prompt", text: "Link address", answer: "example.com" }, () => tools.getByRole("button", { name: "Link" }).click());
    await expect(editor.locator('a[href="https://example.com/"]')).toHaveText("Buy seeds");

    // Draw shows the ink tools; turning it off hides them again.
    const draw = tools.getByRole("button", { name: "Draw" });
    await draw.click();
    await expect(draw).toHaveAttribute("aria-pressed", "true");
    const ink = page.getByRole("toolbar", { name: "Ink tools" });
    await expect(ink.getByRole("button", { name: "Pen", exact: true })).toHaveAttribute("aria-pressed", "true");
    for (const name of ["Highlighter", "Eraser", "Undo ink", "Redo ink"]) await expect(ink.getByRole("button", { name, exact: true })).toBeVisible();
    await draw.click();
    await expect(ink).toHaveCount(0);

    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByText("● Saved to server", { exact: true })).toBeVisible();
    // The list row: title, the page's own text, a date, and the open page highlighted.
    const row = page.locator('#page-navigation .note-row[aria-current="page"]');
    await expect(row.locator("strong")).toHaveText("Formatting");
    await expect(row.locator(".note-snippet")).toContainText("Buy seeds");
    await expect(row.locator("time")).not.toBeEmpty();

    // An empty section shows no page; choosing a section with pages opens its first one, as in OneNote.
    await page.getByRole("button", { name: "Notebook options" }).click();
    await page.getByRole("button", { name: "New section", exact: true }).click();
    await expect(page.locator(".pane-title")).toHaveText("New section");
    await page.locator(".section-tab", { hasText: "Quick Notes" }).click();
    await page.locator(".section-tab", { hasText: "New section" }).click();
    await expect(page.locator(".title-input")).toHaveCount(0);
    await expect(page.locator(".empty-list")).toHaveText("No pages in this section yet.");
    await page.locator(".section-tab", { hasText: "Quick Notes" }).click();
    await expect(page.locator(".pane-title")).toHaveText("Quick Notes");
    await expect(page.locator(".title-input")).toHaveValue("Formatting");
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

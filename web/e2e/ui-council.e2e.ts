import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { adminConsole, OWNER, person, signIn, withDialog, openNotebooks } from "./people";

test.use({ actionTimeout: 15_000 });

// Same real, throwaway server and account helpers as the rest of the browser suite.
// KYNOTES_COUNCIL_STAGE=before captures the incumbent without the new layout assertions.
test("notebook reading, phone page navigation and shared editor typography", async ({ browser }) => {
  const stage = process.env.KYNOTES_COUNCIL_STAGE;
  const round = process.env.KYNOTES_COUNCIL_ROUND ?? "02";
  const output = "../docs/ui-notes-eight/screenshots";
  const files: object[] = [];
  const admin = await person(browser, { viewport: { width: 1280, height: 900 } });
  const owner = await person(browser, { viewport: { width: 1280, height: 900 } });
  const { page } = owner;
    const shot = async (surface: string, device: string, theme: "light" | "dark") => {
      if (!stage) return;
      await mkdir(output, { recursive: true });
      await page.mouse.move(0, 0);
      await page.evaluate(() => document.fonts.ready);
      await page.waitForTimeout(250);
      const file = `kynotes-${round}-${stage}-${surface}-${device}-${theme}.png`;
      const png = await page.screenshot({ path: `${output}/${file}` });
      const facts = await page.evaluate(() => {
        const body = document.querySelector<HTMLElement>(".bn-editor");
        const toolbar = document.querySelector(".canvas-toolbar");
        const line = document.querySelector(".bn-inline-content");
        return {
          viewport: { width: innerWidth, height: innerHeight }, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          bodyFont: body && getComputedStyle(body).font, bodyColor: body && getComputedStyle(body).color,
          toolbarToBody: toolbar && line && Math.round(line.getBoundingClientRect().top - toolbar.getBoundingClientRect().bottom),
          fonts: [...document.fonts].filter((font) => font.status === "loaded").map((font) => font.family),
        };
      });
      files.push({ file, surface, device, theme, sha256: createHash("sha256").update(png).digest("hex"), bytes: png.length, ...facts });
    };
  try {
    await adminConsole(admin.page);
    const containersLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/containers" && response.request().method() === "GET");
    await signIn(page, OWNER.username, OWNER.password);
    await containersLoaded;
    if (stage && Number(round) >= 5) {
      await expect(page.locator(".nav-item", { hasText: "Project Atlas" })).toHaveCount(0);
      for (const theme of ["light", "dark"] as const) {
        for (const [device, width, height] of [["desktop", 1280, 900], ["mobile", 390, 844]] as const) {
          await page.setViewportSize({ width, height });
          await page.emulateMedia({ colorScheme: theme });
          await shot("empty", device, theme);
        }
      }
      await page.setViewportSize({ width: 1280, height: 900 });
    }
    await openNotebooks(page);
    await expect(page.getByRole("button", { name: "＋ New notebook" })).toBeEnabled();
    const existing = page.locator(".nav-item", { hasText: "Project Atlas" }).last();
    const reuse = await existing.count() > 0;
    if (reuse) await existing.click();
    else await withDialog(owner, { type: "prompt", text: "Notebook name", answer: "Project Atlas" }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".workspace-title")).toHaveText("Project Atlas");
    await expect(page.getByRole("button", { name: "Notebooks and account" })).toHaveAttribute("aria-expanded", "false");
    if (stage !== "before") {
      const notice = page.locator(".recovery-notice");
      await notice.locator("summary").focus();
      await page.keyboard.press("Enter");
      await expect(notice.getByRole("status")).toContainText("Save a recovery code so you can get your encryption key back");
      await expect(notice.getByRole("button", { name: "Create recovery code" })).toBeVisible();
      await page.keyboard.press("Enter");
      await expect(notice.getByRole("button", { name: "Create recovery code" })).toBeHidden();
    }
    const savedObject = () => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());
    for (const title of reuse ? [] : ["Research notes", "Team handover", "Next steps", "Launch checklist"]) {
      const created = savedObject();
      await page.getByRole("button", { name: "New page", exact: true }).click();
      await created;
      await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
      await expect(page.locator(".title-input")).toHaveValue("Untitled page");
      const titled = savedObject();
      await page.locator(".title-input").fill(title);
      await titled;
      await page.getByRole("button", { name: "Add text", exact: true }).click();
      await page.locator(".bn-editor").click();
      for (const line of ["## A clear start for everyone", "Confirm the launch plan with the team. Keep decisions close to the work so the next person can pick up where we left off.", "", "## Before Friday", "- Review the first-run checklist", "- Check the owner handover and product links", "- Agree who handles questions after launch"]) {
        await page.keyboard.type(line);
        await page.keyboard.press("Enter");
      }
      await page.getByRole("button", { name: "Save", exact: true }).click();
      await expect(page.getByText("● Saved to server", { exact: true })).toBeVisible();
    }
    if (reuse) await page.locator(".note-row", { hasText: "Launch checklist" }).click();
    await expect(page.locator(".title-input")).toHaveValue("Launch checklist");
    const noteURL = page.url();
    for (const theme of ["light", "dark"] as const) {
      for (const [device, width, height] of [["desktop", 1280, 900], ["mobile", 390, 844]] as const) {
        await page.setViewportSize({ width, height });
        await page.emulateMedia({ colorScheme: theme });
        await page.goto(noteURL);
        await page.reload();
        await expect(page.locator(".title-input")).toHaveValue("Launch checklist");
        await expect(page.locator(".bn-editor")).toContainText("A clear start for everyone");
        await page.evaluate(() => window.scrollTo(0, 0));
        await shot("workspace", device, theme);
        await page.locator(".title-input").scrollIntoViewIfNeeded();
        await shot("editor", device, theme);
        if (stage !== "before") {
          await expect(page.getByRole("textbox", { name: "Page title", exact: true })).toBeVisible();
          const family = await page.locator(".bn-editor").evaluate((el) => getComputedStyle(el).fontFamily);
          expect(family).toContain("Space");
          const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
          expect(overflow).toBe(0);
        }
        if (device === "desktop" && stage !== "before") {
          await expect(page.locator("#notebook-navigation")).toBeHidden();
          const list = await page.locator("#page-navigation").boundingBox();
          const editor = await page.locator(".editor").boundingBox();
          expect(list!.x).toBe(0);
          expect(list!.width).toBe(240);
          expect(editor!.x).toBe(240);
          await openNotebooks(page);
          await expect(page.locator("#page-navigation")).toBeHidden();
          await shot("navigation", device, theme);
          await page.getByRole("button", { name: "Notebooks and account" }).click();
        }
        if (device === "mobile") {
          if (stage !== "before") {
            await expect(page.locator(".note-list")).toBeHidden();
            await page.getByRole("button", { name: "Pages in Project Atlas", exact: true }).click();
            await expect(page.locator(".note-list")).toBeVisible();
            await expect(page.locator(".note-row").first()).toBeInViewport({ ratio: 0.9 });
            await shot("pages", device, theme);
            await page.locator(".note-row", { hasText: "Research notes" }).click();
            await expect(page.locator(".title-input")).toHaveValue("Research notes");
            await expect(page.locator(".note-list")).toBeHidden();
            await expect(page.getByRole("textbox", { name: "Page title" })).toBeFocused();
            await expect(page.getByRole("textbox", { name: "Page title" })).toBeInViewport({ ratio: 1 });
          } else await shot("pages", device, theme);
          await page.getByRole("button", { name: "Notebooks and account" }).click();
          await expect(page.locator("#notebook-navigation")).toBeVisible();
          await shot("navigation", device, theme);
        }
        await page.getByRole("button", { name: "Settings", exact: true }).click();
        await page.getByRole("heading", { name: "Appearance", exact: true }).scrollIntoViewIfNeeded();
        await shot("appearance", device, theme);
      }
    }
    expect(owner.unexpected).toEqual([]);
    if (stage) {
      const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
      const diff = execFileSync("git", ["diff", "HEAD", "--", "src"]);
      const index = await (await page.request.get("/")).body();
      const sourceFiles = Object.fromEntries(await Promise.all(["src/main.tsx", "src/styles.css", "src/NavIcon.tsx", "src/components/SectionTabs.tsx", "src/ky-ui/VERSION", "e2e/ui-council.e2e.ts", "package-lock.json"].map(async (file) => [file, createHash("sha256").update(await readFile(file)).digest("hex")])));
      await writeFile(`${output}/${round}-${stage}-manifest.json`, JSON.stringify({ head, sourceDiffSha256: createHash("sha256").update(diff).digest("hex"), sourceFiles, servedIndexSha256: createHash("sha256").update(index).digest("hex"), stage, captured: new Date().toISOString(), browser: browser.version(), fixture: "real throwaway server; Project Atlas; four populated pages created through UI; synthetic owner; no saved theme choice; OS scheme emulated; scale 1", files }, null, 2) + "\n");
    }
    if (stage !== "before") {
      await page.setViewportSize({ width: 390, height: 844 });
      await page.goto(noteURL);
      await page.reload();
      await expect(page.locator(".title-input")).toHaveValue("Launch checklist");
      let release = () => {};
      let pending = false;
      const held = new Promise<void>((resolve) => { release = resolve; });
      await page.route("**/api/v1/objects/*", async (route) => {
        if (route.request().method() === "PUT") { pending = true; await held; }
        await route.continue();
      });
      try {
        await page.getByRole("textbox", { name: "Page title" }).fill("Launch checklist edited");
        await page.getByRole("button", { name: "Pages in Project Atlas", exact: true }).click();
        await page.locator('.note-row[aria-current="page"]').focus();
        await page.keyboard.press("Enter");
        await expect(page.getByRole("textbox", { name: "Page title" })).toBeFocused();
        await expect(page.getByRole("textbox", { name: "Page title" })).toBeInViewport({ ratio: 1 });
        await expect(page.locator(".sync-dot")).toHaveText("● Unsaved changes");
        await expect.poll(() => pending).toBe(true);
        release();
        await expect(page.locator(".sync-dot")).toHaveText("● Saved to server");
        await page.reload();
        await expect(page.locator(".title-input")).toHaveValue("Launch checklist edited");
      } finally {
        release();
        await page.unroute("**/api/v1/objects/*");
      }
      await page.locator(".title-input").fill("Launch checklist");
      await page.getByRole("button", { name: "Save", exact: true }).click();
      await expect(page.locator(".sync-dot")).toHaveText("● Saved to server");
    }
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});

import { expect, test, type Page } from "@playwright/test";
import { THEME_PALETTES } from "../src/ky-ui/themes";
import { THEME_STORAGE_KEY } from "../src/theme";
import { adminConsole, backToNotes, OWNER, openNotebooks, openSettings, person, signIn, withDialog } from "./people";

const NOTEBOOK = "Nord E2E";
const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());

/** Visible text below WCAG AA: 4.5:1, or 3:1 for large text (24px, or 18.66px bold). Disabled controls are exempt. */
const lowContrast = (page: Page) => page.evaluate(() => {
  const ctx = document.createElement("canvas").getContext("2d", { willReadFrequently: true })!;
  const rgba = (css: string) => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = css; ctx.fillRect(0, 0, 1, 1); return [...ctx.getImageData(0, 0, 1, 1).data]; };
  const over = (top: number[], under: number[]) => { const a = top[3] / 255; return [0, 1, 2].map((i) => top[i] * a + under[i] * (1 - a)).concat(255); };
  const fill = (el: Element | null): number[] => (el ? over(rgba(getComputedStyle(el).backgroundColor), fill(el.parentElement)) : [255, 255, 255, 255]);
  const lum = (c: number[]) => c.slice(0, 3).reduce((sum, v, i) => { v /= 255; return sum + (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4) * [0.2126, 0.7152, 0.0722][i]; }, 0);
  const ratio = (a: number[], b: number[]) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const bad: string[] = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const el = node.parentElement!;
    if (!node.textContent!.trim() || !el.checkVisibility({ opacityProperty: true, visibilityProperty: true }) || el.closest(":disabled, [aria-disabled=true]")) continue;
    const style = getComputedStyle(el);
    const size = parseFloat(style.fontSize);
    const need = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700) ? 3 : 4.5;
    const back = fill(el);
    const got = ratio(over(rgba(style.color), back), back);
    if (got < need) bad.push(`${got.toFixed(2)} < ${need}: "${node.textContent!.trim().slice(0, 40)}" (${el.tagName.toLowerCase()}.${el.className})`);
  }
  return bad;
});

test("Nord Dark and Nord Light theme a notebook with an open page at WCAG AA", async ({ browser }) => {
  const admin = await person(browser, { viewport: { width: 1280, height: 900 } });
  const owner = await person(browser, { viewport: { width: 1280, height: 900 } });
  const { page } = owner;
  try {
    await adminConsole(admin.page);
    await signIn(page, OWNER.username, OWNER.password);
    await openNotebooks(page);
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: NOTEBOOK }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    const created = objectSave(page);
    await page.getByRole("button", { name: "New page", exact: true }).click();
    await created;
    const titled = objectSave(page);
    await page.locator(".title-input").fill("Trip plan");
    await titled;
    await page.getByRole("toolbar", { name: "Page tools" }).getByRole("button", { name: "Heading 2" }).click();
    await page.keyboard.type("Packing");
    await page.keyboard.press("Enter");
    await page.keyboard.type("Rain jacket, maps and a thermos.");
    await expect(page.locator(".bn-editor").first()).toContainText("Rain jacket");

    for (const [id, mode] of [["nord", "Dark"], ["paper", "Light"]] as const) {
      await openSettings(page, "Appearance");
      await page.getByRole("group", { name: "Nord" }).getByRole("radio", { name: mode, exact: true }).check();
      expect(await page.evaluate((key) => localStorage.getItem(key), THEME_STORAGE_KEY)).toBe(id);
      await backToNotes(page);
      await expect(page.locator(".title-input")).toHaveValue("Trip plan");
      const bg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--bg").trim());
      expect(bg).toBe(THEME_PALETTES[id].bg);
      await page.locator(".bn-editor").first().blur();
      await page.evaluate(() => document.fonts.ready);
      expect(await lowContrast(page), `${id} text below WCAG AA`).toEqual([]);
      const dir = process.env.KYNOTES_E2E_SHOTS;
      if (dir) await page.screenshot({ path: `${dir}/kynotes-${id}-open-note.png` });
    }
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});
